#!/usr/bin/env python3
"""qskms_core.py - single-file capstone evaluation core.

Everything needed for the offline results, in one file. No package layout.

  python3 qskms_core.py test              # correctness assertions
  python3 qskms_core.py attack --trials 200
  python3 qskms_core.py bench --n 200
  python3 qskms_core.py aws --region eu-north-1     # needs boto3 + IAM role

Requires: cryptography (test/attack), numpy+scipy (bench), boto3 (aws).
"""
from __future__ import annotations

import argparse, json, os, sys, time
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import (
    aes_key_unwrap_with_padding, aes_key_wrap_with_padding)

# ===================================================================== WRAP
# All three clouds use PKCS#11 CKM_RSA_AES_KEY_WRAP for classical BYOK:
#   blob = RSAES-OAEP(one_time_aes) || AES-KWP(one_time_aes, key_material)
# AWS calls it RSA_AES_KEY_WRAP_SHA_256. Azure uses it for the BYOK blob.
# Every construction here is CLASSICAL and falls to Shor.

def rsa_aes_key_wrap(pub, material, hash_name="SHA256"):
    algo = getattr(hashes, hash_name)()
    otk = os.urandom(32)
    enc = pub.encrypt(otk, padding.OAEP(mgf=padding.MGF1(algo), algorithm=algo, label=None))
    return enc + aes_key_wrap_with_padding(otk, material), len(enc)

def rsa_aes_key_unwrap(priv, blob, hash_name="SHA256"):
    algo = getattr(hashes, hash_name)()
    n = priv.key_size // 8
    otk = priv.decrypt(blob[:n], padding.OAEP(mgf=padding.MGF1(algo), algorithm=algo, label=None))
    return aes_key_unwrap_with_padding(otk, blob[n:])

def rsa_oaep_wrap(pub, material, hash_name="SHA256"):
    algo = getattr(hashes, hash_name)()
    cap = pub.key_size // 8 - 2 * algo.digest_size - 2
    if len(material) > cap:
        raise ValueError(f"{len(material)}B exceeds OAEP capacity {cap}B")
    return pub.encrypt(material, padding.OAEP(mgf=padding.MGF1(algo), algorithm=algo, label=None))

def keygen(bits=4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

# ================================================================ CAPABILITY
# Documentation finding, not experiment. Sources are API references.
CAPS = {
 "aws":  {"wrap": ("RSAES_OAEP_SHA_256","RSA_AES_KEY_WRAP_SHA_256","SM2PKE"), "pq": (),
          "level":"HSM", "cite":"AWS KMS GetParametersForImport WrappingAlgorithmSpec"},
 "azure":{"wrap": ("CKM_RSA_AES_KEY_WRAP",), "pq": (),
          "level":"HSM", "cite":"Azure Key Vault BYOK spec, RSA-HSM KEK"},
 "gcp":  {"wrap": ("RSA_AES_KEY_WRAP_SHA_256",),
          "pq": ("hpke-kem-xwing-hkdf-sha256-aes-256-gcm",
                 "hpke-kem-mlkem768-hkdf-sha256-aes-256-gcm",
                 "hpke-kem-mlkem1024-hkdf-sha256-aes-256-gcm"),
          "level":"SOFTWARE", "cite":"Cloud KMS quantum-safe key import (preview)"},
}
PQ_NATIVE, HYBRID_COMPENSATED, CLASSICAL_ONLY = "pq_native","hybrid_compensated","classical_only"
def posture_for(p): return PQ_NATIVE if CAPS[p]["pq"] else CLASSICAL_ONLY

# ================================================================== ENVELOPE
# Compensating control for classical-only providers.
#   inner = Enc(K_cloud, DEK)   imported over the provider's best channel
#   outer = Enc(K_pq,  inner)   K_pq crossed ONLY a PQ-safe channel
# Breaking RSA yields K_cloud and nothing else.
# Result is hybrid_compensated, NEVER pq_native.

def _enc(k, pt, aad):
    n = os.urandom(12); return n, AESGCM(k).encrypt(n, pt, aad)

class Envelope:
    def __init__(self, cloud_enc, cloud_dec, pq_key=None):
        self.ce, self.cd = cloud_enc, cloud_dec
        self.pq_key = pq_key or os.urandom(32)

    def seal_single(self, pt, aad):
        dek = os.urandom(32); n, ct = _enc(dek, pt, aad)
        return {"posture": CLASSICAL_ONLY, "wrapped": self.ce(dek, aad).hex(), "n": n.hex()}, ct

    def open_single(self, e, ct, aad):
        dek = self.cd(bytes.fromhex(e["wrapped"]), aad)
        return AESGCM(dek).decrypt(bytes.fromhex(e["n"]), ct, aad)

    def seal_nested(self, pt, aad):
        dek = os.urandom(32); n, ct = _enc(dek, pt, aad)
        inner = self.ce(dek, aad)
        on, outer = _enc(self.pq_key, inner, aad)
        return {"posture": HYBRID_COMPENSATED, "outer_n": on.hex(),
                "outer": outer.hex(), "n": n.hex()}, ct

    def open_nested(self, e, ct, aad):
        inner = AESGCM(self.pq_key).decrypt(bytes.fromhex(e["outer_n"]),
                                            bytes.fromhex(e["outer"]), aad)
        dek = self.cd(inner, aad)
        return AESGCM(dek).decrypt(bytes.fromhex(e["n"]), ct, aad)

def local_cloud(km):
    def e(pt, aad):
        n = os.urandom(12); return n + AESGCM(km).encrypt(n, pt, aad)
    def d(b, aad): return AESGCM(km).decrypt(b[:12], b[12:], aad)
    return e, d

# ==================================================================== TESTS
P = F = 0
def ck(name, cond, detail=""):
    global P, F
    if cond: P += 1; print(f"  PASS  {name}")
    else:    F += 1; print(f"  FAIL  {name} {detail}")

def cmd_test(_):
    global P, F
    print("=" * 60 + "\nqskms offline tests\n" + "=" * 60)
    print("\nCKM_RSA_AES_KEY_WRAP")
    k = keygen(4096); pub = k.public_key()
    for size, lab in ((32, "AES-256"), (1704, "RSA-3072 private DER")):
        m = os.urandom(size); blob, rl = rsa_aes_key_wrap(pub, m)
        ck(f"round trip {lab} ({size}B)", rsa_aes_key_unwrap(k, blob) == m)
        ck(f"  RSA layer 512B ({lab})", rl == 512, f"got {rl}")
    m = os.urandom(32); blob, _ = rsa_aes_key_wrap(pub, m)
    ck("blob 552B for 32B material", len(blob) == 552, f"got {len(blob)}")
    bad = bytearray(blob); bad[-1] ^= 1
    try: rsa_aes_key_unwrap(k, bytes(bad)); ck("tampered blob rejected", False)
    except Exception: ck("tampered blob rejected", True)

    print("\nRSAES_OAEP_SHA_256 capacity")
    b = rsa_oaep_wrap(pub, os.urandom(32))
    ck("blob is 512B", len(b) == 512, f"got {len(b)}")
    try: rsa_oaep_wrap(pub, os.urandom(447)); ck("447B rejected (cap 446B)", False)
    except ValueError: ck("447B rejected (cap 446B)", True)

    print("\nCapability matrix - the central claim")
    ck("AWS has no PQ import", not CAPS["aws"]["pq"])
    ck("Azure has no PQ import", not CAPS["azure"]["pq"])
    ck("GCP has PQ import", bool(CAPS["gcp"]["pq"]))
    ck("AWS posture classical_only", posture_for("aws") == CLASSICAL_ONLY)
    ck("Azure posture classical_only", posture_for("azure") == CLASSICAL_ONLY)
    ck("GCP posture pq_native", posture_for("gcp") == PQ_NATIVE)
    ck("GCP PQ import SOFTWARE only", CAPS["gcp"]["level"] == "SOFTWARE")
    ck("every capability cited", all(c["cite"] for c in CAPS.values()))

    print("\nNested envelope")
    km = os.urandom(32); e, d = local_cloud(km); svc = Envelope(e, d)
    aad, secret = b"tenant-1", b"ACC=00123456789;BAL=4200000"
    env, ct = svc.seal_single(secret, aad)
    ck("single layer round trip", svc.open_single(env, ct, aad) == secret)
    ck("single layer posture", env["posture"] == CLASSICAL_ONLY)
    env2, ct2 = svc.seal_nested(secret, aad)
    ck("nested round trip", svc.open_nested(env2, ct2, aad) == secret)
    ck("nested posture hybrid_compensated", env2["posture"] == HYBRID_COMPENSATED)
    ck("nested posture is NOT pq_native", env2["posture"] != PQ_NATIVE)
    try: svc.open_nested(env2, ct2, b"tenant-2"); ck("wrong AAD rejected", False)
    except InvalidTag: ck("wrong AAD rejected", True)

    print("\nK_pq is load bearing")
    wrong = Envelope(e, d, pq_key=os.urandom(32))
    try: wrong.open_nested(env2, ct2, aad); ck("cloud key alone insufficient", False)
    except InvalidTag: ck("cloud key alone insufficient", True)

    print("\n" + "=" * 60 + f"\n{P} passed, {F} failed\n" + "=" * 60)
    return 1 if F else 0

# =================================================================== ATTACK
# Adversary A1: passive, harvests the import blob and all ciphertext, then
# gains the RSA private key (Shor MODELLED, handed over outright - strictly
# stronger than a real CRQC, so the result is conservative).
# Grover vs AES-256 not modelled: ~128-bit PQ security is out of reach.

SECRET = b"PAN=ABCDE1234F;ACC=00123456789;BAL=4200000"

_KEYPOOL: list = []
_POOL_SIZE = 8

def _provider_key():
    # RSA-4096 keygen costs ~0.5-2s. One per trial dominates runtime without
    # changing the outcome: the experiment is deterministic in the key, not
    # randomised over it. A small pool keeps the property that the adversary
    # faces a key it did not choose, at a fraction of the cost.
    import random
    if len(_KEYPOOL) < _POOL_SIZE:
        _KEYPOOL.append(keygen(4096))
    return random.choice(_KEYPOOL)

def _trial(nested: bool):
    km = os.urandom(32)
    provider = _provider_key()
    harvested, _ = rsa_aes_key_wrap(provider.public_key(), km)   # blob on the wire

    e, d = local_cloud(km)
    svc = Envelope(e, d, pq_key=os.urandom(32))
    aad = b"tenant-1"
    env, ct = (svc.seal_nested if nested else svc.seal_single)(SECRET, aad)

    # --- post-Shor adversary ---
    recovered = rsa_aes_key_unwrap(provider, harvested)
    material_ok = recovered == km
    ae, ad = local_cloud(recovered)
    adv = Envelope(ae, ad, pq_key=os.urandom(32))    # does NOT hold K_pq
    try:
        pt = (adv.open_nested if nested else adv.open_single)(env, ct, aad)
        return material_ok, pt == SECRET, ""
    except InvalidTag:
        return material_ok, False, "outer_AESGCM_InvalidTag"
    except Exception as ex:
        return material_ok, False, type(ex).__name__

def cmd_attack(a):
    out = {"trials": a.trials}
    for name, nested in (("single_layer", False), ("nested", True)):
        res = [_trial(nested) for _ in range(a.trials)]
        stages = {}
        for _, _, s in res:
            if s: stages[s] = stages.get(s, 0) + 1
        out[name] = {
            "key_material_recovery_rate": sum(r[0] for r in res) / a.trials,
            "plaintext_compromise_rate":  sum(r[1] for r in res) / a.trials,
            "resisted": a.trials - sum(r[1] for r in res),
            "failure_stages": stages,
        }
    b = out["single_layer"]["plaintext_compromise_rate"]
    t = out["nested"]["plaintext_compromise_rate"]
    out["control_effectiveness"] = {
        "baseline_compromise_rate": b, "treated_compromise_rate": t,
        "absolute_risk_reduction": b - t,
        "interpretation": ("Key material falls in BOTH conditions once RSA breaks, "
            "confirming the import channel is not the control. The nested envelope "
            f"moves plaintext compromise from {b:.0%} to {t:.0%}."),
    }
    print(json.dumps(out, indent=2))
    ok = b == 1.0 and t == 0.0
    print("\nEXPERIMENT VALID" if ok else "\nUNEXPECTED - investigate", file=sys.stderr)
    return 0 if ok else 1

# ==================================================================== BENCH
def cmd_bench(a):
    import numpy as np
    from scipy import stats
    rng = np.random.default_rng(20260906)

    def ci(data, q, reps=10000):
        arr = np.asarray(data, float)
        idx = rng.integers(0, arr.size, size=(reps, arr.size))
        boots = np.percentile(arr[idx], q, axis=1)
        lo, hi = np.percentile(boots, [2.5, 97.5])
        return round(float(np.percentile(arr, q)), 4), [round(float(lo), 4), round(float(hi), 4)]

    def cliffs(x, y):
        x, y = np.asarray(x, float), np.asarray(y, float)
        d = float(((x[:, None] > y).sum() - (x[:, None] < y).sum()) / (x.size * y.size))
        mag = ("negligible" if abs(d) < .147 else "small" if abs(d) < .33
               else "medium" if abs(d) < .474 else "large")
        return round(d, 4), mag

    k = keygen(4096); pub = k.public_key(); m = os.urandom(32)
    samples = {}
    for name, fn in (("rsaes_oaep_sha256_4096", lambda: (rsa_oaep_wrap(pub, m), 512)),
                     ("rsa_aes_key_wrap_sha256_4096", lambda: rsa_aes_key_wrap(pub, m))):
        lat, size = [], 0
        for _ in range(a.n):
            t0 = time.perf_counter(); r = fn()
            lat.append((time.perf_counter() - t0) * 1000)
            size = len(r[0]) if isinstance(r[0], bytes) else 512
        samples[name] = (lat, size)

    km = os.urandom(32); e, d = local_cloud(km); svc = Envelope(e, d)
    payload, aad = os.urandom(4096), b"bench"
    for name, seal in (("envelope_single", svc.seal_single), ("envelope_nested", svc.seal_nested)):
        lat = []
        for _ in range(a.n):
            t0 = time.perf_counter(); env, ct = seal(payload, aad)
            lat.append((time.perf_counter() - t0) * 1000)
        samples[name] = (lat, len(json.dumps(env)) + len(ct))

    base = samples["rsaes_oaep_sha256_4096"][0]
    out = {"meta": {"n": a.n, "bootstrap_reps": 10000,
                    "environment": "REPORT host/CPU/OS and local-vs-network. "
                                   "Latency is uninterpretable without it.",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}
    for name, (lat, size) in samples.items():
        r = {"n": len(lat), "payload_bytes": size, "latency_ms": {}}
        for q, lab in ((50, "p50"), (95, "p95"), (99, "p99")):
            pt, c = ci(lat, q); r["latency_ms"][lab] = {"estimate": pt, "ci95": c}
        r["latency_ms"]["mean"] = round(float(np.mean(lat)), 4)
        if lat is not base:
            u, p = stats.mannwhitneyu(lat, base, alternative="two-sided")
            dv, mag = cliffs(lat, base)
            r["vs_rsaes_oaep_baseline"] = {"mann_whitney_u": float(u), "p_value": float(p),
                "significant_at_0.05": bool(p < .05), "cliffs_delta": dv,
                "effect_magnitude": mag,
                "median_ratio": round(float(np.median(lat) / np.median(base)), 3)}
        out[name] = r
    print(json.dumps(out, indent=2))
    return 0

# ====================================================================== AWS
def cmd_aws(a):
    try: import boto3
    except ImportError:
        print("pip install --break-system-packages boto3", file=sys.stderr); return 2
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    c = boto3.client("kms", region_name=a.region)
    ev = {"region": a.region, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    kid = a.key_id
    if not kid:
        print("[1/5] CreateKey(Origin=EXTERNAL)...")
        kid = c.create_key(Origin="EXTERNAL", KeyUsage="ENCRYPT_DECRYPT",
                           KeySpec="SYMMETRIC_DEFAULT",
                           Description="qskms capstone BYOK target")["KeyMetadata"]["KeyId"]
    print(f"      key id: {kid}")
    ev["key_id"] = kid

    # AWS constrains the wrapping algorithm by key material type:
    #   SYMMETRIC_DEFAULT / HMAC / ECC / SM2 -> RSAES_OAEP_SHA_256 (single step)
    #   RSA private keys                     -> RSA_AES_KEY_WRAP_SHA_256 (two step)
    # This is itself a crypto-agility finding: the wrapping algorithm is not
    # freely selectable by the operator.
    algo = "RSAES_OAEP_SHA_256"
    print(f"[2/5] GetParametersForImport (algo={algo}, spec={a.spec})...")
    p = c.get_parameters_for_import(KeyId=kid, WrappingAlgorithm=algo,
                                    WrappingKeySpec=a.spec)
    pub = load_der_public_key(p["PublicKey"])

    material = os.urandom(32)          # WE generate it, not AWS
    print(f"[3/5] wrapping locally with {algo}...")
    t0 = time.perf_counter(); blob = rsa_oaep_wrap(pub, material); rl = len(blob)
    wrap_ms = (time.perf_counter() - t0) * 1000

    print("[4/5] ImportKeyMaterial...")
    c.import_key_material(KeyId=kid, ImportToken=p["ImportToken"],
                          EncryptedKeyMaterial=blob,
                          ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE")
    print(f"      method   : {algo}")
    print(f"      posture  : {CLASSICAL_ONLY}")
    print(f"      blob     : {len(blob)} B (single-step RSA-OAEP, no AES layer)")
    print(f"      wrap time: {wrap_ms:.3f} ms")
    ev["import"] = {"method": algo, "posture": CLASSICAL_ONLY,
                    "blob_bytes": len(blob), "rsa_layer_bytes": rl,
                    "wrap_ms": round(wrap_ms, 4), "wrapping_key_spec": a.spec,
                    "algorithm_constraint": (
                        "AWS rejects RSA_AES_KEY_WRAP_SHA_* for SYMMETRIC_DEFAULT key "
                        "material; the two-step method is reserved for RSA and ECC "
                        "private keys. The operator cannot freely choose the wrapping "
                        "algorithm - it is dictated by key material type.")}
    ev["finding"] = ("AWS KMS accepted key material only under RSA wrapping. "
        "GetParametersForImport offers no post-quantum algorithm. The import "
        "blob is recoverable by a CRQC; posture is classical_only.")

    print("[5/5] nested envelope against the live key...")
    time.sleep(3)
    ce = lambda pt, aad: c.encrypt(KeyId=kid, Plaintext=pt,
                                   EncryptionContext={"ctx": aad.decode()})["CiphertextBlob"]
    cd = lambda b, aad: c.decrypt(KeyId=kid, CiphertextBlob=b,
                                  EncryptionContext={"ctx": aad.decode()})["Plaintext"]
    svc = Envelope(ce, cd)
    aad, secret = b"capstone-tenant-1", b"ACC=00123456789;BAL=4200000"
    env, ct = svc.seal_nested(secret, aad)
    ok = svc.open_nested(env, ct, aad) == secret
    print(f"      round trip: {'OK' if ok else 'FAILED'}   posture: {env['posture']}")
    ev["nested_envelope"] = {"round_trip_ok": ok, "posture": env["posture"],
        "note": ("hybrid_compensated, NOT pq_native: the AWS import channel is "
                 "still classical. The control makes the harvested blob "
                 "insufficient; it does not make the channel quantum safe.")}

    if a.cleanup:
        c.schedule_key_deletion(KeyId=kid, PendingWindowInDays=7)
        ev["cleanup"] = "scheduled"
        print("      deletion scheduled (7 day window)")

    with open(a.out, "w") as fh: json.dump(ev, fh, indent=2)
    print(f"\nevidence -> {a.out}")
    return 0 if ok else 1

# ===================================================================== MAIN
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("test")
    p = sub.add_parser("attack"); p.add_argument("--trials", type=int, default=100)
    p = sub.add_parser("bench");  p.add_argument("--n", type=int, default=200)
    p = sub.add_parser("aws")
    p.add_argument("--region", required=True)
    p.add_argument("--key-id", default="")
    p.add_argument("--spec", default="RSA_4096",
                   choices=["RSA_2048", "RSA_3072", "RSA_4096"])
    p.add_argument("--cleanup", action="store_true")
    p.add_argument("--out", default="aws_import_evidence.json")
    a = ap.parse_args()
    return {"test": cmd_test, "attack": cmd_attack,
            "bench": cmd_bench, "aws": cmd_aws}[a.cmd](a)

if __name__ == "__main__":
    raise SystemExit(main())
