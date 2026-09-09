# Quantum-Aware TLS Risk Scoring & Quantum-Safe Key Lifecycle Management

Two capstone projects addressing harvest-now-decrypt-later exposure in BFSI from
opposite ends: **measurement** of third-party transit posture, and **mitigation**
through multi-cloud key custody.

## Capstone 1 — Risk Measurement

Post-quantum capability is measured, not inferred. A TLS 1.3 ClientHello is
constructed offering only `X25519MLKEM768` with an empty `key_share`; per RFC 8446
a supporting server must reply HelloRetryRequest naming that group. No client-side
ML-KEM implementation is required.

| Result | Value |
|---|---|
| Endpoints measured | 54 |
| Confidentiality ready (hybrid ML-KEM) | 33/54 = 61.1%, 95% CI [0.478, 0.730] |
| Authentication ready (PQ certificate) | 0/54 = 0.0%, [0.000, 0.066] |
| CDN-fronted vs origin-served | 83.3% vs 43.3%, +40.0pp, Fisher p = 0.00453 |
| Risk bands | 20 critical · 10 high · 24 moderate |

`src/qskms_tlsprobe.py` · `src/scan_to_dashboard.py` · `src/build_c1_model.py`

## Capstone 2 — Risk Mitigation

Post-quantum BYOK import capability is not uniform across cloud providers. Only
Google Cloud KMS accepts key material over an HPKE/ML-KEM channel, and that is
preview and software-protection-level only. AWS and Azure accept RSA wrapping only.

| Result | Value | Evidence class |
|---|---|---|
| Live AWS BYOK import | 512 B blob, 0.909 ms, `classical_only` | Live cloud |
| Nested envelope effectiveness | 200/200 → 0/200 compromised | Simulation |
| Cost of the control | 2.8 µs, 73 bytes | Local measurement |
| Deferred vs naive activation | 793 → 0 consistency violations | Simulation |

`src/qskms_core.py` · `src/qskms_saga.py` · `src/qskms_interlink.py`

## Reproducing

```bash
python3 src/qskms_core.py test
python3 src/qskms_core.py attack --trials 200
python3 src/qskms_saga.py compare --rotations 200
python3 src/qskms_tlsprobe.py selftest
```

## Models

Open `models/index.html` in a browser. Self-contained; no server required.

## Data and ethics

Institutional identities in `evidence/` are anonymised to category codes, matching
the anonymisation used in the dissertations. Measurements were limited to TLS
parameters any ordinary client negotiates; no authentication was attempted, no
vulnerability exploited, no non-public data accessed. Probe volume was rate-limited
to one connection per second per host. Account identifiers and host addresses are
redacted.

## Evidence classes

Results derive from four distinct classes, which are not conflated: **live cloud**
(the AWS import), **local measurement** (benchmarks), **simulation** (adversary model
and fault injection — no cloud API calls), and **documentation** (provider capability
read from vendor API references).

## Limitations

The Google Cloud path was validated against a local RFC 9180 reference implementation,
not the live service; interoperability is not claimed. Saga providers are simulated and
fault rates are a sensitivity range, not a prediction. A compromised orchestration host
defeats every control described here.
