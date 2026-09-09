#!/usr/bin/env python3
"""qskms_tlsprobe.py - measured post-quantum TLS capability, not inferred.

WHY RAW SOCKETS
---------------
Python's ssl module cannot set TLS 1.3 supported_groups, and OpenSSL below 3.5
has no ML-KEM. Rather than depend on a specific OpenSSL build, this constructs
the ClientHello byte by byte. It needs nothing but the standard library and it
works identically everywhere, which matters for reproducibility.

THE PROBE
---------
Send a ClientHello offering exactly ONE group in supported_groups, with an
EMPTY key_share list. Per RFC 8446 the server must then either:

  * reply HelloRetryRequest naming that group  -> the server SUPPORTS it
  * reply an alert (handshake_failure etc.)    -> the server does NOT

No ML-KEM implementation is required on the client side: we never have to
produce a key share, only observe which group the server asks for.

This is a capability measurement. It replaces CDN fingerprinting, which cannot
distinguish "this CDN supports PQ somewhere" from "this endpoint negotiates PQ".

TWO INDEPENDENT AXES
--------------------
  Confidentiality readiness  hybrid KEM in the handshake -> HNDL resistance
  Authentication readiness   certificate signature algorithm -> impersonation
                             resistance under a CRQC

Almost every readiness framework collapses these. They are not the same: an
endpoint can negotiate X25519MLKEM768 and still present an RSA-2048 certificate,
making it HNDL-resistant but fully impersonable by a quantum adversary.

Run:
  python3 qskms_tlsprobe.py selftest
  python3 qskms_tlsprobe.py scan --targets targets.txt --out scan.json
  python3 qskms_tlsprobe.py analyse --in scan.json
"""
from __future__ import annotations

import argparse, json, math, os, secrets, socket, ssl, struct, sys, time
from dataclasses import dataclass, asdict, field

# ---------------------------------------------------------------- constants
# IANA TLS Supported Groups. PQ hybrids from draft-kwiatkowski-tls-ecdhe-mlkem.
GROUPS = {
    "X25519MLKEM768":      0x11EC,
    "SecP256r1MLKEM768":   0x11EB,
    "SecP384r1MLKEM1024":  0x11ED,
    "x25519":              0x001D,
    "secp256r1":           0x0017,
    "secp384r1":           0x0018,
    "secp521r1":           0x0019,
    "x448":                0x001E,
}
GROUP_NAME = {v: k for k, v in GROUPS.items()}
PQ_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")

# RFC 8446 4.1.3: ServerHello.random takes this fixed value in a
# HelloRetryRequest. It is how HRR is distinguished from a real ServerHello.
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

ALERTS = {40: "handshake_failure", 47: "illegal_parameter", 70: "protocol_version",
          71: "insufficient_security", 80: "internal_error", 112: "unrecognized_name",
          109: "missing_extension", 50: "decode_error", 51: "decrypt_error"}

CIPHERS = [0x1301, 0x1302, 0x1303]           # AES128-GCM, AES256-GCM, CHACHA20
SIGALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]


# ------------------------------------------------------------ ClientHello
def _ext(kind: int, body: bytes) -> bytes:
    return struct.pack(">HH", kind, len(body)) + body


def build_client_hello(sni: str, groups: list[int]) -> bytes:
    """TLS 1.3 ClientHello with an empty key_share, offering only `groups`."""
    body = b"\x03\x03"                         # legacy_version TLS 1.2
    body += secrets.token_bytes(32)            # random
    sid = secrets.token_bytes(32)              # legacy_session_id (compat mode)
    body += bytes([len(sid)]) + sid
    body += struct.pack(">H", len(CIPHERS) * 2) + b"".join(
        struct.pack(">H", c) for c in CIPHERS)
    body += b"\x01\x00"                        # compression: null

    host = sni.encode()
    sni_ext = struct.pack(">HBH", len(host) + 3, 0, len(host)) + host
    exts = _ext(0, sni_ext)
    exts += _ext(10, struct.pack(">H", len(groups) * 2) +
                 b"".join(struct.pack(">H", g) for g in groups))
    exts += _ext(13, struct.pack(">H", len(SIGALGS) * 2) +
                 b"".join(struct.pack(">H", s) for s in SIGALGS))
    exts += _ext(43, b"\x02\x03\x04")          # supported_versions: TLS 1.3
    exts += _ext(51, b"\x00\x00")              # key_share: empty -> force HRR
    body += struct.pack(">H", len(exts)) + exts

    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


# --------------------------------------------------------------- response
def parse_response(data: bytes) -> dict:
    if len(data) < 5:
        return {"kind": "SHORT", "detail": f"{len(data)} bytes"}
    rtype, _, rlen = struct.unpack(">BHH", data[:5])

    if rtype == 0x15:                                    # alert
        if len(data) < 7:
            return {"kind": "ALERT", "desc": "truncated"}
        return {"kind": "ALERT", "level": data[5], "code": data[6],
                "desc": ALERTS.get(data[6], f"alert_{data[6]}")}
    if rtype != 0x16:
        return {"kind": "NON_HANDSHAKE", "record_type": rtype}

    rec = data[5:5 + rlen]
    if len(rec) < 4 or rec[0] != 0x02:
        return {"kind": "NOT_SERVER_HELLO", "handshake_type": rec[0] if rec else None}

    sh = rec[4:]
    if len(sh) < 35:
        return {"kind": "TRUNCATED_SERVER_HELLO", "length": len(sh)}
    rnd = sh[2:34]
    is_hrr = rnd == HRR_RANDOM
    i = 34
    sid_len = sh[i]; i += 1 + sid_len
    if i + 3 > len(sh):
        return {"kind": "TRUNCATED_SERVER_HELLO", "length": len(sh)}
    cipher = struct.unpack(">H", sh[i:i + 2])[0]; i += 2
    i += 1                                               # compression

    # A TLS 1.2 ServerHello may omit the extensions block entirely.
    if i + 2 > len(sh):
        return {"kind": "SERVER_HELLO", "selected_group": None,
                "selected_group_name": None,
                "cipher_suite": f"0x{cipher:04X}",
                "negotiated_version": f"0x{struct.unpack('>H', sh[:2])[0]:04X}",
                "is_tls13": False, "no_extensions": True}
    ext_len = struct.unpack(">H", sh[i:i + 2])[0]; i += 2
    ext_end, group, version = i + ext_len, None, None

    while i + 4 <= ext_end:
        etype, elen = struct.unpack(">HH", sh[i:i + 4]); i += 4
        ebody = sh[i:i + elen]; i += elen
        if etype == 51 and len(ebody) >= 2:              # key_share
            group = struct.unpack(">H", ebody[:2])[0]
        elif etype == 43 and len(ebody) >= 2:            # supported_versions
            version = struct.unpack(">H", ebody[:2])[0]

    return {"kind": "HELLO_RETRY_REQUEST" if is_hrr else "SERVER_HELLO",
            "selected_group": group,
            "selected_group_name": GROUP_NAME.get(group, f"0x{group:04X}" if group else None),
            "cipher_suite": f"0x{cipher:04X}",
            "negotiated_version": f"0x{version:04X}" if version else None,
            "is_tls13": version == 0x0304}


def build_client_hello_ks(sni: str, groups: list[int]) -> bytes:
    """ClientHello carrying a REAL X25519 key share.

    Some servers reject an empty key_share outright (SBI, CCAvenue observed).
    Offering a genuine share with the PQ group listed FIRST mirrors what
    browsers send: a server preferring the PQ group replies HelloRetryRequest
    asking for it; one that does not simply completes on X25519.
    """
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    body = b"\x03\x03" + secrets.token_bytes(32)
    sid = secrets.token_bytes(32)
    body += bytes([len(sid)]) + sid
    body += struct.pack(">H", len(CIPHERS) * 2) + b"".join(
        struct.pack(">H", c) for c in CIPHERS)
    body += b"\x01\x00"

    host = sni.encode()
    exts = _ext(0, struct.pack(">HBH", len(host) + 3, 0, len(host)) + host)
    exts += _ext(10, struct.pack(">H", len(groups) * 2) +
                 b"".join(struct.pack(">H", g) for g in groups))
    exts += _ext(13, struct.pack(">H", len(SIGALGS) * 2) +
                 b"".join(struct.pack(">H", x) for x in SIGALGS))
    exts += _ext(43, b"\x02\x03\x04")
    share = struct.pack(">HH", GROUPS["x25519"], len(pub)) + pub
    exts += _ext(51, struct.pack(">H", len(share)) + share)
    body += struct.pack(">H", len(exts)) + exts

    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def probe_group_ks(host: str, group_name: str, port: int = 443,
                   timeout: float = 8.0) -> dict:
    """Key-share variant, for servers that reject an empty key_share."""
    gid = GROUPS[group_name]
    groups = [gid] if group_name == "x25519" else [gid, GROUPS["x25519"]]
    out = {"group": group_name, "supported": False, "variant": "keyshare"}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(build_client_hello_ks(host, groups))
            data = b""
            while len(data) < 5:
                c = s.recv(4096)
                if not c:
                    break
                data += c
            if len(data) >= 5:
                need = 5 + struct.unpack(">H", data[3:5])[0]
                while len(data) < need:
                    c = s.recv(4096)
                    if not c:
                        break
                    data += c
        r = parse_response(data)
        out.update(r)
        if group_name == "x25519":
            out["supported"] = r["kind"] == "SERVER_HELLO" and bool(r.get("is_tls13"))
        else:
            out["supported"] = (r["kind"] == "HELLO_RETRY_REQUEST"
                                and r.get("selected_group") == gid)
    except socket.timeout:
        out["kind"] = "TIMEOUT"
    except OSError as e:
        out["kind"] = "NETWORK_ERROR"; out["detail"] = str(e)[:120]
    return out


def probe_group(host: str, group_name: str, port: int = 443,
                timeout: float = 8.0) -> dict:
    """Offer exactly one group; observe whether the server asks for it."""
    gid = GROUPS[group_name]
    out = {"group": group_name, "supported": False}
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(build_client_hello(host, [gid]))
            data = b""
            while len(data) < 5:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            if len(data) >= 5:
                need = 5 + struct.unpack(">H", data[3:5])[0]
                while len(data) < need:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        r = parse_response(data)
        out.update(r)
        # The server asked us to retry with this exact group -> it supports it.
        out["supported"] = (r["kind"] in ("HELLO_RETRY_REQUEST", "SERVER_HELLO")
                            and r.get("selected_group") == gid)
    except socket.timeout:
        out.update({"kind": "TIMEOUT"})
    except OSError as e:
        out.update({"kind": "NETWORK_ERROR", "detail": str(e)[:120]})
    out["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return out


# ------------------------------------------------- authentication axis
def probe_certificate(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Certificate signature algorithm and key type: the authentication axis.

    Uses a normal TLS connection because we need a completed handshake. The
    group probe above and this are deliberately independent measurements.
    """
    out = {"reachable": False}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ts:
                der = ts.getpeercert(binary_form=True)
                out["reachable"] = True
                out["tls_version"] = ts.version()
                out["cipher"] = ts.cipher()[0] if ts.cipher() else None
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives.asymmetric import ec, rsa
                    c = x509.load_der_x509_certificate(der)
                    out["cert_sig_alg"] = c.signature_algorithm_oid._name
                    pk = c.public_key()
                    if isinstance(pk, rsa.RSAPublicKey):
                        out["cert_key"] = f"RSA-{pk.key_size}"
                    elif isinstance(pk, ec.EllipticCurvePublicKey):
                        out["cert_key"] = f"EC-{pk.curve.name}"
                    else:
                        out["cert_key"] = type(pk).__name__
                    out["issuer"] = c.issuer.rfc4514_string()[:120]
                    out["not_after"] = c.not_valid_after_utc.isoformat()
                    # No standardised PQ signature is deployable in WebPKI yet.
                    out["pq_authenticated"] = False
                except Exception as e:
                    out["cert_parse_error"] = str(e)[:120]
    except Exception as e:
        out["error"] = type(e).__name__ + ": " + str(e)[:120]
    return out


def scan_target(label: str, host: str) -> dict:
    r = {"label": label, "host": host,
         "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    # control probe first: classical group confirms reachability + TLS 1.3
    ctrl = probe_group(host, "x25519")
    r["control_x25519"] = ctrl
    r["reachable"] = ctrl["kind"] not in ("TIMEOUT", "NETWORK_ERROR", "SHORT")
    r["tls13"] = ctrl.get("is_tls13", False) or ctrl["kind"] == "HELLO_RETRY_REQUEST"

    r["pq_probes"] = {}
    if r["reachable"]:
        for g in PQ_GROUPS:
            r["pq_probes"][g] = probe_group(host, g)
    r["pq_capable"] = any(p.get("supported") for p in r["pq_probes"].values())
    r["pq_groups_supported"] = [g for g, p in r["pq_probes"].items() if p.get("supported")]
    r["certificate"] = probe_certificate(host) if r["reachable"] else {}
    r["confidentiality_ready"] = r["pq_capable"]
    r["authentication_ready"] = r["certificate"].get("pq_authenticated", False)
    return r


# --------------------------------------------------------------- statistics
def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    """Wilson score interval. Never report a bare proportion."""
    if n == 0:
        return (float("nan"),) * 3
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(p, 4), round(max(0, c - h), 4), round(min(1, c + h), 4)


def fisher_2x2(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact test. Pure Python: no scipy needed."""
    def lf(n): return math.lgamma(n + 1)
    n = a + b + c + d
    def lp(a_, b_, c_, d_):
        return (lf(a_ + b_) + lf(c_ + d_) + lf(a_ + c_) + lf(b_ + d_)
                - lf(a_) - lf(b_) - lf(c_) - lf(d_) - lf(n))
    obs = lp(a, b, c, d)
    tot = 0.0
    for i in range(0, min(a + b, a + c) + 1):
        j, k, l = a + b - i, a + c - i, d - a + i
        if j < 0 or k < 0 or l < 0:
            continue
        p = lp(i, j, k, l)
        if p <= obs + 1e-9:
            tot += math.exp(p)
    return min(1.0, tot)


# ---------------------------------------------------------------- commands
def cmd_selftest(a):
    """Verify ClientHello construction and response parsing without a network."""
    ok = fail = 0
    def ck(n, c, d=""):
        nonlocal ok, fail
        if c: ok += 1; print(f"  PASS  {n}")
        else: fail += 1; print(f"  FAIL  {n} {d}")

    print("ClientHello construction")
    ch = build_client_hello("example.com", [GROUPS["X25519MLKEM768"]])
    ck("record type is handshake", ch[0] == 0x16)
    ck("record version 0x0301", ch[1:3] == b"\x03\x01")
    ck("record length matches body", struct.unpack(">H", ch[3:5])[0] == len(ch) - 5)
    ck("handshake type is client_hello", ch[5] == 0x01)
    ck("handshake length matches", int.from_bytes(ch[6:9], "big") == len(ch) - 9)
    ck("X25519MLKEM768 codepoint 0x11EC present", b"\x11\xec" in ch)
    ck("empty key_share present", _ext(51, b"\x00\x00") in ch)
    ck("supported_versions TLS1.3 present", _ext(43, b"\x02\x03\x04") in ch)
    ck("SNI carried", b"example.com" in ch)

    print("\nHelloRetryRequest parsing")
    def fake(rnd, group, ver=0x0304):
        e = _ext(51, struct.pack(">H", group)) + _ext(43, struct.pack(">H", ver))
        sh = b"\x03\x03" + rnd + b"\x20" + b"\x00" * 32 + b"\x13\x01" + b"\x00"
        sh += struct.pack(">H", len(e)) + e
        hs = b"\x02" + len(sh).to_bytes(3, "big") + sh
        return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs

    r = parse_response(fake(HRR_RANDOM, GROUPS["X25519MLKEM768"]))
    ck("HRR detected via magic random", r["kind"] == "HELLO_RETRY_REQUEST")
    ck("selected group decoded", r["selected_group"] == 0x11EC, r)
    ck("group name resolved", r["selected_group_name"] == "X25519MLKEM768")
    ck("TLS 1.3 flagged", r["is_tls13"] is True)

    r = parse_response(fake(b"\x01" * 32, GROUPS["x25519"]))
    ck("real ServerHello not mistaken for HRR", r["kind"] == "SERVER_HELLO")

    print("\nAlert parsing")
    r = parse_response(b"\x15\x03\x03\x00\x02\x02\x28")
    ck("alert decoded", r["kind"] == "ALERT" and r["desc"] == "handshake_failure", r)

    print("\nStatistics")
    p, lo, hi = wilson(4, 8)
    ck("Wilson point estimate", p == 0.5)
    ck("Wilson interval brackets estimate", lo < 0.5 < hi, f"[{lo},{hi}]")
    ck("Wilson wide at n=8", hi - lo > 0.5, f"width {hi-lo:.3f}")
    p2, lo2, hi2 = wilson(400, 800)
    ck("Wilson narrows at n=800", hi2 - lo2 < 0.08, f"width {hi2-lo2:.3f}")
    pv = fisher_2x2(10, 0, 0, 10)
    ck("Fisher detects perfect association", pv < 0.001, pv)
    pv = fisher_2x2(5, 5, 5, 5)
    ck("Fisher finds no association", pv > 0.5, pv)

    print(f"\n{ok} passed, {fail} failed")
    return 1 if fail else 0


def cmd_scan(a):
    targets = []
    with open(a.targets) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [x.strip() for x in line.split(",")]
            targets.append((parts[0], parts[1] if len(parts) > 1 else parts[0]))

    results = []
    print(f"{'LABEL':<22} {'TLS1.3':<7} {'PQ':<5} {'GROUPS':<20} CERT")
    print("-" * 88)
    for label, host in targets:
        r = scan_target(label, host)
        results.append(r)
        g = ",".join(x.replace("MLKEM", "MK") for x in r["pq_groups_supported"]) or "-"
        c = r["certificate"].get("cert_key", "?")
        print(f"{label:<22} {str(r['tls13']):<7} {str(r['pq_capable']):<5} {g:<20} {c}")

    out = {"meta": {"scanned": len(results), "method":
           "raw TLS 1.3 ClientHello, single group, empty key_share, HRR observed",
           "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
           "results": results}
    with open(a.out, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwritten -> {a.out}")
    return 0


def cmd_analyse(a):
    d = json.load(open(a.infile))
    rs = [r for r in d["results"] if r["reachable"]]
    n = len(rs)
    if not n:
        print("no reachable targets"); return 1

    pq = sum(r["pq_capable"] for r in rs)
    t13 = sum(r["tls13"] for r in rs)
    auth = sum(r["authentication_ready"] for r in rs)

    print(f"Reachable targets: {n} (of {len(d['results'])} scanned)\n")
    for name, k in (("TLS 1.3 support", t13),
                    ("Confidentiality ready (hybrid KEM)", pq),
                    ("Authentication ready (PQ certificate)", auth)):
        p, lo, hi = wilson(k, n)
        print(f"  {name:<40} {k:>3}/{n}  {p:.3f}  95% CI [{lo:.3f}, {hi:.3f}]")

    print("\nPer-group support:")
    for g in PQ_GROUPS:
        k = sum(1 for r in rs if g in r["pq_groups_supported"])
        p, lo, hi = wilson(k, n)
        print(f"  {g:<24} {k:>3}/{n}  {p:.3f}  [{lo:.3f}, {hi:.3f}]")

    print("\nCertificate signature algorithms (authentication axis):")
    sigs: dict = {}
    for r in rs:
        s = r["certificate"].get("cert_sig_alg", "unknown")
        sigs[s] = sigs.get(s, 0) + 1
    for s, k in sorted(sigs.items(), key=lambda x: -x[1]):
        print(f"  {s:<40} {k:>3}/{n}")

    # Consistency check the CDN-inference approach could never do.
    bad = [r["label"] for r in rs if r["pq_capable"] and not r["tls13"]]
    print(f"\nImpossible states (PQ without TLS 1.3): {len(bad)} {bad if bad else ''}")
    print("A non-zero count here means the measurement is wrong, not the finding.")

    if a.out:
        json.dump({"n": n, "tls13": wilson(t13, n), "pq": wilson(pq, n),
                   "auth": wilson(auth, n), "sig_algs": sigs}, open(a.out, "w"), indent=2)
        print(f"\nwritten -> {a.out}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    p = sub.add_parser("scan")
    p.add_argument("--targets", required=True)
    p.add_argument("--out", default="scan.json")
    p = sub.add_parser("analyse")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", default="")
    a = ap.parse_args()
    return {"selftest": cmd_selftest, "scan": cmd_scan, "analyse": cmd_analyse}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
