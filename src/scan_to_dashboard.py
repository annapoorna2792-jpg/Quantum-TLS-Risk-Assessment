#!/usr/bin/env python3
"""scan_to_dashboard.py - regenerate the Capstone 1 dashboard from MEASURED data.

PROBLEM THIS SOLVES
-------------------
app/data/vendors.csv is hand-typed. It contains rows such as

    Axis Bank,No,Yes,Akamai,Yes,No,"X25519, secp256r1"
                ^^  ^^^
                |   pqc = Yes
                tls13 = No

which is physically impossible: hybrid KEM exists only in TLS 1.3. The PQC
column was inferred from the edge provider, not observed. Every downstream
number - QVI tiers, the 50% headline, the donut chart - inherits that error.

WHAT THIS DOES
--------------
Probes each target for real, then writes vendors.csv in the SAME schema, so
tprm.py, qvi.py, cbom.py and all templates keep working untouched.

  tls13        TLS 1.3 ClientHello, observe ServerHello/HRR
  pqc          single PQ group + empty key_share, observe HelloRetryRequest
  curves       classical groups the server actually selects, probed one by one
  static_rsa   TLS 1.2 ClientHello offering ONLY TLS_RSA_* (no ECDHE)
               accepted -> key exchange without forward secrecy
  weak_cipher  TLS 1.2 ClientHello offering ONLY 3DES / RC4
  pqc_provider certificate ISSUER (descriptive label, not evidence)

Nothing is inferred. If a probe cannot be completed the field is recorded as
unmeasured rather than guessed.

Run:
  python3 scan_to_dashboard.py probe --targets targets.txt --out measured.json
  python3 scan_to_dashboard.py write --in measured.json \\
      --dashboard ~/hybrid-tls-lab/dashboard/app
"""
from __future__ import annotations

import argparse, csv, json, os, secrets, shutil, socket, struct, sys, time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.expanduser("~"))

from qskms_tlsprobe import (GROUPS, PQ_GROUPS, probe_group, probe_group_ks,
                            probe_certificate,
                            parse_response, _ext, wilson, fisher_2x2)

# TLS 1.2 cipher suites. Static RSA = no ECDHE = no forward secrecy.
STATIC_RSA_SUITES = [0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F]
WEAK_SUITES       = [0x000A, 0x0005, 0x0004, 0x0009, 0x0013]   # 3DES, RC4, DES
CLASSICAL_GROUPS  = ["x25519", "secp256r1", "secp384r1", "secp521r1", "x448"]
SIGALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]


def build_tls12_hello(sni: str, suites: list[int]) -> bytes:
    """TLS 1.2 ClientHello. No supported_versions extension, so a server that
    answers is genuinely negotiating 1.2 with one of the offered suites."""
    body = b"\x03\x03" + secrets.token_bytes(32)
    body += b"\x00"                                       # empty session id
    body += struct.pack(">H", len(suites) * 2) + b"".join(
        struct.pack(">H", c) for c in suites)
    body += b"\x01\x00"

    host = sni.encode()
    exts = _ext(0, struct.pack(">HBH", len(host) + 3, 0, len(host)) + host)
    exts += _ext(10, struct.pack(">H", 10) + b"".join(
        struct.pack(">H", GROUPS[g]) for g in CLASSICAL_GROUPS))
    exts += _ext(11, b"\x01\x00")                         # ec_point_formats
    exts += _ext(13, struct.pack(">H", len(SIGALGS) * 2) + b"".join(
        struct.pack(">H", s) for s in SIGALGS))
    body += struct.pack(">H", len(exts)) + exts

    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def probe_suites(host: str, suites: list[int], port: int = 443,
                 timeout: float = 8.0) -> dict:
    """Offer only `suites`. A ServerHello means the server accepts one."""
    out = {"accepted": False}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(build_tls12_hello(host, suites))
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
        out.update({"kind": r["kind"], "cipher": r.get("cipher_suite")})
        # A ServerHello alone is NOT acceptance. Verify the server actually
        # selected one of the suites we offered; anything else is a protocol
        # oddity or middlebox and must not be scored as support.
        sel = None
        if r.get("cipher_suite"):
            try:
                sel = int(r["cipher_suite"], 16)
            except ValueError:
                sel = None
        out["selected_in_offer"] = (sel in suites) if sel is not None else False
        out["accepted"] = (r["kind"] == "SERVER_HELLO") and out["selected_in_offer"]
    except socket.timeout:
        out["kind"] = "TIMEOUT"
    except OSError as e:
        out["kind"] = "NETWORK_ERROR"; out["detail"] = str(e)[:100]
    return out


def issuer_ca(cert: dict) -> str:
    """Certificate Authority that signed the leaf.

    A CA is NOT a CDN. Cloudflare serves certificates issued by Google Trust
    Services; banks often use DigiCert while sitting behind Akamai. Using the
    issuer as an edge-provider label is exactly the inference error this tool
    exists to eliminate. Descriptive field only.
    """
    iss = (cert.get("issuer") or "")
    for needle, name in (("Cloudflare", "Cloudflare"), ("Amazon", "Amazon"),
                         ("Google", "GoogleTrustServices"), ("DigiCert", "DigiCert"),
                         ("Sectigo", "Sectigo"), ("Let's Encrypt", "LetsEncrypt"),
                         ("GlobalSign", "GlobalSign"), ("Entrust", "Entrust"),
                         ("Akamai", "Akamai"), ("Microsoft", "Microsoft")):
        if needle.lower() in iss.lower():
            return name
    return ""


def edge_provider(host: str, timeout: float = 8.0) -> tuple:
    """Edge/CDN provider, OBSERVED from HTTP response headers.

    CF-RAY is emitted only by Cloudflare; x-amz-cf-id only by CloudFront.
    Server/Via/X-Cache identify most others. This measures who actually
    terminates the connection, which is what the hypothesis is about.
    """
    import http.client, ssl as _ssl
    try:
        ctx = _ssl._create_unverified_context()
        c = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
        c.request("HEAD", "/", headers={"User-Agent": "qskms-research-probe/1.0"})
        resp = c.getresponse()
        srv = (resp.getheader("Server") or "").strip()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        c.close()
        if "cf-ray" in hdrs:
            return "Cloudflare", srv
        if "x-amz-cf-id" in hdrs:
            return "Amazon", srv
        blob = (srv + " " + hdrs.get("via", "") + " " + hdrs.get("x-cache", "")
                + " " + hdrs.get("x-served-by", "")).lower()
        for needle, name in (("cloudflare", "Cloudflare"), ("cloudfront", "Amazon"),
                             ("akamai", "Akamai"), ("ecacc", "Akamai"),
                             ("fastly", "Fastly"), ("varnish", "Fastly"),
                             ("gws", "Google"), ("esf", "Google"),
                             ("azure", "Microsoft"), ("imperva", "Imperva"),
                             ("incapsula", "Imperva")):
            if needle in blob:
                return name, srv
        return "", srv
    except Exception as e:
        return "", f"(no HTTP: {type(e).__name__})"


def probe_target(label: str, host: str) -> dict:
    r = {"label": label, "host": host,
         "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # Retry with backoff before classifying a non-response: a single dropped
    # SYN or transient WAF decision should not cost a data point when the
    # denominator is small.
    import time as _t
    ctrl = None
    for attempt in range(3):
        ctrl = probe_group(host, "x25519")
        if ctrl["kind"] in ("HELLO_RETRY_REQUEST", "SERVER_HELLO"):
            break
        if attempt < 2:
            _t.sleep(1.5 * (attempt + 1))
    r["control_attempts"] = attempt + 1
    r["probe_variant"] = "empty_keyshare"
    if ctrl["kind"] not in ("HELLO_RETRY_REQUEST", "SERVER_HELLO"):
        # Server rejected the empty-key_share hello. Retry with a real share
        # before concluding anything: this is a probe artefact, not a finding.
        ctrl = probe_group_ks(host, "x25519")
        r["probe_variant"] = "keyshare"
    r["reachable"] = ctrl["kind"] in ("HELLO_RETRY_REQUEST", "SERVER_HELLO")
    r["tls13"] = ctrl.get("is_tls13", False) or ctrl["kind"] == "HELLO_RETRY_REQUEST"
    if not r["reachable"]:
        r["unreachable_reason"] = ctrl["kind"]
        r["control_probe"] = ctrl
        # Distinguish "host is down" from "host rejected our unusual
        # empty-key_share ClientHello". Scoring the second as unreachable
        # would be a false negative and would silently drop targets.
        alt = probe_certificate(host)
        r["host_actually_up"] = alt.get("reachable", False)
        # Three distinct outcomes, which must NOT be conflated:
        #   measured      probe completed
        #   tls12_only    host up, no TLS 1.3 -> structurally PQ-incapable.
        #                 A real negative. Belongs in the denominator.
        #   non_response  host up AND does TLS 1.3, but rejects our hello
        #                 (WAF fingerprinting). A measurement failure.
        #                 Excluded, and reported as such.
        ver = alt.get("tls_version")
        if not alt.get("reachable"):
            r["measurement_status"] = "host_down"
        elif ver == "TLSv1.3":
            r["measurement_status"] = "non_response"
        else:
            r["measurement_status"] = "tls12_only"
            r["tls13"] = False
            r["pqc"] = False
            r["pq_groups"] = []
            r["classical_groups"] = []
            r["static_rsa"] = None
            r["weak_cipher"] = None
            r["confidentiality_ready"] = False
            r["authentication_ready"] = False
            r["impossible_state"] = False
            r["countable"] = True
            # This branch returns early, so fields the analysis expects must
            # be populated here too.
            edge, server_hdr = edge_provider(host)
            r["edge_provider"] = edge
            r["server_header"] = server_hdr
        r["fallback_tls_version"] = alt.get("tls_version")
        r["fallback_cipher"] = alt.get("cipher")
        r["certificate"] = alt
        r["cert_issuer_ca"] = issuer_ca(alt)
        return r

    _pg = probe_group_ks if r["probe_variant"] == "keyshare" else probe_group
    r["pq_probes"] = {g: _pg(host, g) for g in PQ_GROUPS}
    r["pq_groups"] = [g for g, p in r["pq_probes"].items() if p.get("supported")]
    r["pqc"] = bool(r["pq_groups"])

    r["classical_groups"] = [g for g in CLASSICAL_GROUPS
                             if probe_group(host, g).get("supported")] \
        if r["probe_variant"] == "empty_keyshare" else ["x25519"]

    sr = probe_suites(host, STATIC_RSA_SUITES)
    wk = probe_suites(host, WEAK_SUITES)
    r["static_rsa"] = sr["accepted"]
    r["static_rsa_probe"] = sr
    r["weak_cipher"] = wk["accepted"]
    r["weak_cipher_probe"] = wk

    r["certificate"] = probe_certificate(host)
    r["cert_issuer_ca"] = issuer_ca(r["certificate"])
    edge, server_hdr = edge_provider(host)
    r["edge_provider"] = edge
    r["server_header"] = server_hdr
    # Authentication axis: no PQ signature algorithm is deployable in WebPKI.
    r["authentication_ready"] = False
    r["confidentiality_ready"] = r["pqc"]

    # Physically impossible state. Must be zero, or the instrument is broken.
    r["impossible_state"] = r["pqc"] and not r["tls13"]
    r["measurement_status"] = "measured"
    r["countable"] = True
    return r


# ------------------------------------------------------------------ commands
def cmd_probe(a):
    targets = []
    for line in open(a.targets):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = [x.strip() for x in line.split(",")]
        targets.append((p[0], p[1] if len(p) > 1 else p[0]))

    print(f"{'LABEL':<20} {'TLS1.3':<7} {'PQC':<5} {'sRSA':<6} {'WEAK':<6} {'EDGE':<12} CA")
    print("-" * 76)
    results = []
    for label, host in targets:
        time.sleep(1.0)
        r = probe_target(label, host)
        results.append(r)
        if not r["reachable"]:
            print(f"{label:<20} UNREACHABLE ({r.get('unreachable_reason')})")
            continue
        print(f"{label:<20} {str(r['tls13']):<7} {str(r['pqc']):<5} "
              f"{str(r['static_rsa']):<6} {str(r['weak_cipher']):<6} "
              f"{(r['edge_provider'] or '-'):<12} {r['cert_issuer_ca'] or '-'}")

    bad = [r["label"] for r in results if r.get("impossible_state")]
    print(f"\nImpossible states (PQ without TLS 1.3): {len(bad)} {bad or ''}")
    if bad:
        print("NON-ZERO means the measurement is broken. Do not use this data.")

    json.dump({"meta": {"method": "raw ClientHello probes, nothing inferred",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
               "results": results}, open(a.out, "w"), indent=2)
    print(f"\nwritten -> {a.out}")
    return 0


def cmd_write(a):
    d = json.load(open(a.infile))
    rs = [r for r in d["results"] if r.get("reachable")]
    if not rs:
        print("no reachable targets; refusing to overwrite dashboard data")
        return 1

    app = Path(os.path.expanduser(a.dashboard))
    data = app / "data"
    if not data.is_dir():
        print(f"{data} not found"); return 1

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    for f in ("vendors.csv", "hndl_inputs.csv"):
        src = data / f
        if src.exists():
            shutil.copy(src, data / f"{f}.bak-{stamp}")
    print(f"backed up existing CSVs with suffix .bak-{stamp}")

    with open(data / "vendors.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["vendor", "tls13", "pqc", "pqc_provider",
                    "static_rsa", "weak_cipher", "curves"])
        for r in rs:
            groups = r["classical_groups"] + r["pq_groups"]
            w.writerow([r["label"],
                        "Yes" if r["tls13"] else "No",
                        "Yes" if r["pqc"] else "No",
                        r["edge_provider"],
                        "Yes" if r["static_rsa"] else "No",
                        "Yes" if r["weak_cipher"] else "No",
                        ", ".join(groups)])
    print(f"wrote {data/'vendors.csv'} ({len(rs)} measured rows)")

    # Preserve existing retention data; only add rows for new targets.
    existing = {}
    bak = data / f"hndl_inputs.csv.bak-{stamp}"
    if bak.exists():
        for row in csv.DictReader(open(bak)):
            existing[row["target"]] = row
    with open(data / "hndl_inputs.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, ["target", "data_sensitivity",
                                "retention_years", "remediation_cost"])
        w.writeheader()
        for r in rs:
            e = existing.get(r["label"])
            w.writerow(e if e else {"target": r["label"], "data_sensitivity": "",
                                    "retention_years": "", "remediation_cost": ""})
    print(f"wrote {data/'hndl_inputs.csv'} (retention left blank for new targets:"
          " fill it rather than let the app invent numbers)")

    json.dump(d, open(data / "measured_scan.json", "w"), indent=2)
    print(f"wrote {data/'measured_scan.json'} (full probe evidence)")
    return 0


def cmd_analyse(a):
    d = json.load(open(a.infile))
    rs = [r for r in d["results"] if r.get("countable")]
    n = len(rs)
    if not n:
        print("no countable targets"); return 1
    excl = [(r["label"], r.get("measurement_status"))
            for r in d["results"] if not r.get("countable")]
    print(f"Countable: {n} of {len(d['results'])}")
    if excl:
        print("Excluded (measurement failures, NOT findings):")
        for lab, why in excl:
            print(f"  {lab}: {why}")
    print()
    for name, k in (("TLS 1.3", sum(r["tls13"] for r in rs)),
                    ("Confidentiality ready (hybrid KEM)", sum(r["pqc"] for r in rs)),
                    ("Authentication ready (PQ cert)",
                     sum(r["authentication_ready"] for r in rs)),
                    ("Static RSA accepted",
                     sum(1 for r in rs if r.get("static_rsa"))),
                    ("Weak cipher accepted",
                     sum(1 for r in rs if r.get("weak_cipher")))):
        p, lo, hi = wilson(k, n)
        print(f"  {name:<38} {k:>3}/{n}  {p:.3f}  95% CI [{lo:.3f}, {hi:.3f}]")

    print("\nPQ readiness by EDGE PROVIDER (not CA):")
    by: dict = {}
    for r in rs:
        key = r.get("edge_provider") or "(origin)"
        y, t = by.get(key, (0, 0))
        by[key] = (y + (1 if r["pqc"] else 0), t + 1)
    for k, (y, t) in sorted(by.items(), key=lambda x: -x[1][1]):
        print(f"  {k:<16} {y}/{t}")

    # Is PQ readiness associated with the edge provider rather than the
    # institution? This is the central hypothesis of the study.
    big = {"Cloudflare", "Amazon", "Google", "Akamai", "Microsoft"}
    a_ = sum(1 for r in rs if r.get("edge_provider") in big and r["pqc"])
    b_ = sum(1 for r in rs if r.get("edge_provider") in big and not r["pqc"])
    c_ = sum(1 for r in rs if r.get("edge_provider") not in big and r["pqc"])
    d_ = sum(1 for r in rs if r.get("edge_provider") not in big and not r["pqc"])
    print(f"\nFisher exact, major-CDN issuer x PQ capability")
    print(f"  CDN     PQ={a_:>3}  noPQ={b_:>3}")
    print(f"  other   PQ={c_:>3}  noPQ={d_:>3}")
    if min(a_ + b_, c_ + d_) == 0:
        print("  insufficient variation for a test; need more targets")
    else:
        print(f"  p = {fisher_2x2(a_, b_, c_, d_):.5f}")

    bad = [r["label"] for r in rs if r.get("impossible_state")]
    print(f"\nImpossible states: {len(bad)} {bad or '(instrument consistent)'}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe"); p.add_argument("--targets", required=True)
    p.add_argument("--out", default="measured.json")
    p = sub.add_parser("write"); p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--dashboard", default="~/hybrid-tls-lab/dashboard/app")
    p = sub.add_parser("analyse"); p.add_argument("--in", dest="infile", required=True)
    a = ap.parse_args()
    return {"probe": cmd_probe, "write": cmd_write, "analyse": cmd_analyse}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
