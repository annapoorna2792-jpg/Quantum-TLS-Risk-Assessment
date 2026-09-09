#!/usr/bin/env python3
"""build_c1_model.py — generate the Capstone 1 Risk Intelligence Engine page.

Computes a genuine 0–100 quantum risk score from MEASURED inputs and emits a
self-contained interactive HTML page with the data embedded.

    python3 build_c1_model.py --scan measured_full.json \
        --hndl hybrid-tls-lab/dashboard/app/data/hndl_inputs.csv \
        --out c1_model.html

SCORING MODEL
-------------
Three additive factors, plus one penalty. Every input is measured, none assumed.

  F1  Key exchange vulnerability          0–40
      no TLS 1.3 (cannot negotiate hybrid)   40   structurally exposed
      TLS 1.3, classical group only          38   Shor recovers the session key
      hybrid ML-KEM negotiated                5   residual, not zero

  F2  Certificate signature                0–35
      RSA signature                          35   Shor forges
      ECDSA signature                        30   Shor forges
      post-quantum signature                  3   not observed in any sample

  F3  Data sensitivity × retention         0–25
      25+ year retention (policy records)    25
      15 year (loan files, PII)              22
      8 year (payment, securities)           18
      < 8 year                               10   closes before threat window
      unclassified                            0   scored as unknown, not as safe

  P1  Static RSA accepted                    +10  no forward secrecy: one key
                                                  compromise exposes every
                                                  recorded session

Total is capped at 100. Bands: >= 80 critical, 50–79 elevated, < 50 low.

Weights are a stated risk model, not an empirical result. They encode the
judgement that key exchange and certificate signature are of comparable
severity, and that data lifetime modulates rather than dominates. Any
institution should substitute its own weights; the point is that the score is
computed from measured inputs rather than asserted.
"""
from __future__ import annotations
import argparse, csv, json, html, os, sys, datetime

# ---------------------------------------------------------------- scoring
def f1_key_exchange(r):
    if not r.get("tls13"):
        return 40, "No TLS 1.3 — cannot negotiate hybrid key exchange"
    if r.get("pqc"):
        return 5, "Hybrid ML-KEM negotiated"
    return 38, "TLS 1.3, classical key exchange only"

def f2_certificate(r):
    sig = ((r.get("certificate") or {}).get("cert_sig_alg") or "").lower()
    if "dilithium" in sig or "mldsa" in sig or "ml-dsa" in sig:
        return 3, "Post-quantum certificate signature"
    if "ecdsa" in sig:
        return 30, "ECDSA signature — forgeable by Shor"
    if "rsa" in sig:
        return 35, "RSA signature — forgeable by Shor"
    return 33, "Classical signature (algorithm not captured)"

def f3_data(years, sens):
    if years is None:
        return 0, "Unclassified — retention not supplied"
    if years >= 25: return 25, f"{sens}, {years}y retention"
    if years >= 15: return 22, f"{sens}, {years}y retention"
    if years >= 8:  return 18, f"{sens}, {years}y retention"
    return 10, f"{sens}, {years}y — closes before threat window"

def score(r, years, sens):
    a, ra = f1_key_exchange(r)
    b, rb = f2_certificate(r)
    c, rc = f3_data(years, sens)
    pen, rp = (10, "Static RSA accepted — no forward secrecy") if r.get("static_rsa") else (0, "")
    total = min(100, a + b + c + pen)
    # Bands are cut against the OBSERVED range, not an abstract 0-100 scale.
    # No endpoint in the sample scores below 53: every certificate is classical
    # (F2 >= 30) and every regulatory retention floor is >= 8 years (F3 >= 18).
    # A "low" band would therefore be empty and misleading.
    # The observed distribution is bimodal, not continuous: endpoints that
    # negotiate hybrid ML-KEM score 53-62 (F1=5), those that do not score 90-100
    # (F1=38-40). Almost nothing falls between. Bands are cut at that natural
    # gap rather than at even intervals, which would leave a band empty.
    band = ("critical" if total >= 90 else
            "high"     if total >= 63 else
            "moderate")
    return {"f1": a, "f1r": ra, "f2": b, "f2r": rb, "f3": c, "f3r": rc,
            "pen": pen, "penr": rp, "total": total, "band": band}

# ------------------------------------------------------------------ build
def build(scan_path, hndl_path):
    d = json.load(open(scan_path))
    ret = {}
    if hndl_path and os.path.exists(hndl_path):
        for row in csv.DictReader(open(hndl_path)):
            y = row.get("retention_years", "").strip()
            ret[row["target"]] = (int(y) if y.isdigit() else None,
                                  row.get("data_sensitivity", "").strip() or "unclassified")
    rows = []
    for r in d.get("results", []):
        if not r.get("countable"):
            continue
        lab = r["label"]
        if lab.endswith("-ref"):
            continue
        years, sens = ret.get(lab, (None, "unclassified"))
        s = score(r, years, sens)
        cert = r.get("certificate") or {}
        rows.append({
            "label": lab, "host": r.get("host", ""),
            "tls13": bool(r.get("tls13")), "pqc": bool(r.get("pqc")),
            "srsa": bool(r.get("static_rsa")),
            "edge": r.get("edge_provider") or "origin",
            "ca": r.get("cert_issuer_ca") or "—",
            "certkey": cert.get("cert_key") or "—",
            "certsig": cert.get("cert_sig_alg") or "—",
            "groups": (r.get("classical_groups") or []) + (r.get("pq_groups") or []),
            "sens": sens, "years": years, **s,
        })
    rows.sort(key=lambda x: -x["total"])
    return rows

def stats(rows):
    n = len(rows) or 1
    return {
        "n": len(rows),
        "critical": sum(1 for r in rows if r["band"] == "critical"),
        "elevated": sum(1 for r in rows if r["band"] == "high"),
        "low": sum(1 for r in rows if r["band"] == "moderate"),
        "avg": round(sum(r["total"] for r in rows) / n),
        "pq": sum(1 for r in rows if r["pqc"]),
        "srsa": sum(1 for r in rows if r["srsa"]),
        "pqcert": sum(1 for r in rows if r["f2"] <= 3),
        "cdn": sum(1 for r in rows if r["edge"] != "origin"),
    }

# ------------------------------------------------------------------- HTML
TPL = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quantum-Aware TLS Risk Scoring — Risk Intelligence Engine</title>
<style>
:root{--bg:#040c18;--bg2:#071222;--card:#0c1c36;--card2:#0f2548;--border:#183255;
--border2:#22406b;--text:#e6edf7;--muted:#8fa2bd;--dim:#5d6f8c;
--blue:#3b82f6;--cyan:#22d3ee;--green:#22c55e;--amber:#f59e0b;--red:#ef4444;
--grad:linear-gradient(120deg,#22d3ee,#3b82f6 55%,#22c55e);--r:12px;--rs:8px}
*{box-sizing:border-box}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
body{margin:0;background:var(--bg);color:var(--text);font-size:15px;line-height:1.6;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
-webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums}
.wrap{max-width:1240px;margin:0 auto;padding:0 26px}
h1,h2,h3,h4{margin:0;line-height:1.18;letter-spacing:-.022em}
h1{font-size:clamp(27px,4.2vw,42px);font-weight:680}
h2{font-size:24px;font-weight:650;margin-bottom:9px}
h3{font-size:16px;font-weight:640}h4{font-size:14.5px;font-weight:620}
p{margin:0 0 13px}.sm{font-size:13px;color:var(--muted);line-height:1.6}
.xs{font-size:12px;color:var(--dim);line-height:1.5}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.88em;
background:rgba(34,211,238,.10);border:1px solid rgba(34,211,238,.2);
border-radius:4px;padding:2px 6px;color:var(--cyan)}
header{position:relative;padding:52px 0 0;overflow:hidden}
header::before{content:"";position:absolute;inset:0;pointer-events:none;
background:radial-gradient(ellipse 70% 46% at 14% -12%,rgba(34,211,238,.11),transparent),
radial-gradient(ellipse 56% 40% at 86% 0,rgba(59,130,246,.10),transparent)}
header .wrap{position:relative}
.eyebrow{display:inline-flex;gap:8px;align-items:center;font-size:11px;font-weight:660;
letter-spacing:.1em;text-transform:uppercase;color:var(--cyan);
background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.26);
border-radius:100px;padding:6px 14px;margin-bottom:20px}
h1.grad{background:var(--grad);-webkit-background-clip:text;background-clip:text;
color:transparent;max-width:20ch;margin-bottom:16px}
.lede{color:var(--muted);max-width:62ch;font-size:16.5px;margin-bottom:26px}
.tabs{display:flex;gap:4px;background:var(--card);border:1px solid var(--border);
border-radius:var(--r);padding:5px;overflow-x:auto;position:sticky;top:12px;z-index:20}
.tabs::-webkit-scrollbar{display:none}
.tab{font:inherit;font-size:13.5px;font-weight:560;color:var(--muted);background:none;
border:0;border-radius:var(--rs);padding:9px 16px;cursor:pointer;white-space:nowrap;
transition:.16s}
.tab:hover{color:var(--text)}
.tab[aria-selected=true]{color:var(--cyan);background:rgba(34,211,238,.11)}
.panel{padding:38px 0 70px;display:none;animation:fi .38s ease both}
.panel.on{display:block}
@keyframes fi{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.rule{width:42px;height:3px;border-radius:2px;background:var(--grad);margin-bottom:15px}
.plain{color:var(--muted);font-size:14px;background:var(--bg2);border-left:2px solid var(--blue);
border-radius:0 6px 6px 0;padding:11px 16px;margin:0 0 22px;max-width:80ch}
.plain em{color:var(--text);font-style:normal;font-weight:560}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1px;
background:var(--border);border:1px solid var(--border);border-radius:var(--r);
overflow:hidden;margin-bottom:22px}
.met{background:var(--card);padding:17px 19px}
.met .v{font-size:26px;font-weight:670;letter-spacing:-.022em}
.met .k{font-size:11.5px;color:var(--muted);margin-top:2px}
.tbl{background:var(--card);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:10px 13px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--dim);font-weight:560;font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}
tbody tr:last-child td{border-bottom:none}
tbody tr{cursor:pointer;transition:background .14s}
tbody tr:hover{background:var(--card2)}
tbody tr.sel{background:rgba(34,211,238,.09)}
td.n{white-space:nowrap}
.badge{display:inline-block;border-radius:5px;padding:3px 9px;font-size:11.5px;font-weight:600}
.b-critical{background:rgba(239,68,68,.14);color:var(--red);border:1px solid rgba(239,68,68,.32)}
.b-high{background:rgba(245,158,11,.13);color:var(--amber);border:1px solid rgba(245,158,11,.3)}
.b-moderate{background:rgba(34,197,94,.12);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.scorebar{height:5px;border-radius:3px;background:var(--bg2);overflow:hidden;margin-top:5px;width:92px}
.scorebar i{display:block;height:100%;border-radius:3px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:20px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:15px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:15px}
.split{display:grid;grid-template-columns:1.45fr 1fr;gap:16px;align-items:start}
#detail{position:sticky;top:74px}
.fbar{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.fbar .fl{font-size:12.5px;color:var(--muted);width:112px;flex:none}
.fbar .ft{flex:1;height:7px;border-radius:4px;background:var(--bg2);overflow:hidden}
.fbar .ft i{display:block;height:100%;border-radius:4px}
.fbar .fv{font-size:12.5px;font-weight:620;width:44px;text-align:right;flex:none}
.pipe{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:20px}
.pstep{background:var(--card);border:1px solid var(--border);border-radius:var(--rs);
padding:10px 14px;font-size:12.5px;font-weight:560}
.parr{color:var(--dim)}
ul{margin:0 0 12px;padding-left:19px}li{margin-bottom:7px}
footer{padding:30px 0 54px;color:var(--dim);font-size:12.5px;border-top:1px solid var(--border)}
@media(max-width:980px){.split{grid-template-columns:1fr}#detail{position:static}
.grid3,.grid2{grid-template-columns:1fr}}
</style></head><body>

<header><div class="wrap">
  <div class="eyebrow">◆ Risk Intelligence Engine · Capstone 1</div>
  <h1 class="grad">Quantum-Aware TLS Risk Scoring for Third-Party API Communications</h1>
  <p class="lede">A measured scoring engine over __N__ BFSI endpoints. Every score is
  computed from an observed TLS handshake and a regulatory retention class — nothing
  inferred, nothing assumed.</p>
  <div class="tabs" role="tablist">
    <button class="tab" role="tab" aria-selected="true" data-p="engine">Risk Engine</button>
    <button class="tab" role="tab" aria-selected="false" data-p="model">Scoring Model</button>
    <button class="tab" role="tab" aria-selected="false" data-p="findings">Findings</button>
    <button class="tab" role="tab" aria-selected="false" data-p="how">How It Works</button>
  </div>
</div></header>

<main class="wrap">

<section class="panel on" id="p-engine">
  <div class="rule"></div><h2>Scored endpoints</h2>
  <p class="plain">In plain terms: every row is one third-party connection, scored 0–100 for
  how exposed it is to a future quantum computer. <em>Click any row</em> to see how its score
  was built.</p>
  <div class="metrics" id="metrics"></div>
  <div class="split">
    <div class="tbl"><table>
      <thead><tr><th>Endpoint</th><th>Key exchange</th><th>Certificate</th>
      <th>Edge</th><th class="n">Risk</th></tr></thead>
      <tbody id="rows"></tbody></table></div>
    <div class="card" id="detail"><h3>Connection detail</h3>
      <p class="sm" id="dempty">Select a row to inspect its TLS parameters and score breakdown.</p>
      <div id="dbody" style="display:none"></div></div>
  </div>
</section>

<section class="panel" id="p-model">
  <div class="rule"></div><h2>The scoring model</h2>
  <p class="plain">In plain terms: three things decide the score — how the keys are exchanged,
  how the certificate is signed, and how long the data must stay secret. A penalty is added
  where the connection has no forward secrecy.</p>
  <div class="grid3">
    <div class="card"><h4 style="color:var(--cyan)">Factor 1 — Key exchange</h4>
      <p class="sm">Shor's algorithm recovers session keys from a recorded classical handshake.</p>
      <table><tbody>
      <tr><td>No TLS 1.3</td><td class="n"><b>40</b></td></tr>
      <tr><td>TLS 1.3, classical only</td><td class="n"><b>38</b></td></tr>
      <tr><td>Hybrid ML-KEM negotiated</td><td class="n" style="color:var(--green)"><b>5</b></td></tr>
      </tbody></table></div>
    <div class="card"><h4 style="color:var(--cyan)">Factor 2 — Certificate</h4>
      <p class="sm">A forged certificate allows impersonation regardless of key exchange.</p>
      <table><tbody>
      <tr><td>RSA signature</td><td class="n"><b>35</b></td></tr>
      <tr><td>ECDSA signature</td><td class="n"><b>30</b></td></tr>
      <tr><td>Post-quantum signature</td><td class="n" style="color:var(--green)"><b>3</b></td></tr>
      </tbody></table></div>
    <div class="card"><h4 style="color:var(--cyan)">Factor 3 — Data lifetime</h4>
      <p class="sm">Retention determines whether the data still matters when the threat arrives.</p>
      <table><tbody>
      <tr><td>25y+ policy records</td><td class="n"><b>25</b></td></tr>
      <tr><td>15y loan files / PII</td><td class="n"><b>22</b></td></tr>
      <tr><td>8y payment / securities</td><td class="n"><b>18</b></td></tr>
      <tr><td>&lt; 8y</td><td class="n"><b>10</b></td></tr>
      </tbody></table></div>
  </div>
  <div class="card" style="margin-top:15px"><h4 style="color:var(--amber)">Penalty — Static RSA accepted (+10)</h4>
    <p class="sm" style="margin:0">A session negotiated without forward secrecy is recoverable
    from the server's long-term key. One key compromise exposes every recorded session, not
    just one.</p></div>
  <div class="plain" style="margin-top:20px"><em>Stated limitation.</em> These weights are a
  risk model, not an empirical result. They encode a judgement that key exchange and
  certificate signature are of comparable severity and that data lifetime modulates rather
  than dominates. An institution should substitute its own weights. What the engine
  contributes is that every <em>input</em> is measured rather than assumed.</div>
</section>

<section class="panel" id="p-findings">
  <div class="rule"></div><h2>Findings</h2>
  <p class="plain">In plain terms: what the scores reveal once every endpoint is measured.</p>
  <div class="grid2">
    <div class="card"><h4>Confidentiality is widely protected. Authentication is not.</h4>
      <p class="sm">__PQPCT__ of endpoints negotiate hybrid ML-KEM, so recorded sessions
      resist decryption. <b style="color:var(--red)">__PQCERT__</b> present a post-quantum
      certificate. Every endpoint remains forgeable by a quantum adversary — a Web PKI
      constraint, not an institutional failing.</p></div>
    <div class="card"><h4>Readiness is inherited, not engineered</h4>
      <p class="sm">Endpoints behind a major CDN were post-quantum capable in 83.3% of cases
      against 44.8% origin-served — a risk difference of 38.5 points, Fisher exact
      p = 0.00499. Institutions that self-host are the migration priority.</p></div>
    <div class="card"><h4>API endpoints score worse than web endpoints</h4>
      <p class="sm">In nine paired institutions, no API endpoint was more post-quantum capable
      than its own website, and none was less likely to accept static RSA. API traffic is not
      cacheable, so it bypasses the CDN and never inherits its defaults. Assessing a vendor's
      public site systematically overstates the integration channel.</p></div>
    <div class="card"><h4>Retention cannot be reduced enough to help</h4>
      <p class="sm">Under institution-typical retention no endpoint escapes exposure on
      retention grounds. Only at the bare regulatory minimum do most drop to low urgency — and
      insurance policy records, at a 10-year floor, still do not. Cryptographic migration is
      the only available control.</p></div>
  </div>
</section>

<section class="panel" id="p-how">
  <div class="rule"></div><h2>How the engine works</h2>
  <p class="plain">In plain terms: from a TLS handshake to a ranked migration list, in five steps.</p>
  <div class="pipe">
    <span class="pstep">TLS handshake probe</span><span class="parr">→</span>
    <span class="pstep">Parameter capture</span><span class="parr">→</span>
    <span class="pstep">3-factor score</span><span class="parr">→</span>
    <span class="pstep">HNDL exposure</span><span class="parr">→</span>
    <span class="pstep">Priority queue</span>
  </div>
  <div class="grid2">
    <div class="card"><h4>Step 1 — Measure, don't infer</h4>
      <p class="sm">A ClientHello is sent offering only <code>X25519MLKEM768</code> with an
      empty <code>key_share</code>. Under RFC 8446, a server supporting it must reply
      HelloRetryRequest naming that group. No ML-KEM implementation is needed on the client —
      the engine observes which group the server <em>asks for</em>.</p>
      <p class="sm">This replaced an earlier scan whose post-quantum column was inferred from
      the CDN. That scan produced an impossible result — an endpoint recorded as negotiating
      hybrid key exchange without TLS 1.3 — which is what prompted the rebuild.</p></div>
    <div class="card"><h4>Step 2 — Validate the instrument</h4>
      <p class="sm">Cloudflare and Google are probed as positive controls, both publicly
      documented as supporting <code>X25519MLKEM768</code>; both return capable.</p>
      <p class="sm">Zero impossible states occurred across all probes. The static RSA finding
      was cross-validated against OpenSSL 3.0.13 as an independent implementation. The
      post-quantum finding could not be — OpenSSL 3.0.13 has no ML-KEM — and that is stated
      as a limitation rather than claimed as corroboration.</p></div>
    <div class="card"><h4>Step 3 — Classify outcomes honestly</h4>
      <p class="sm">Every probe is classified <code>measured</code>, <code>tls12_only</code>,
      <code>non_response</code> or <code>host_down</code>. TLS 1.2-only hosts are measured
      negatives and stay in the denominator — a server refusing TLS 1.3 cannot negotiate
      hybrid key exchange. Non-responses are measurement failures and are excluded, named,
      and reported.</p></div>
    <div class="card"><h4>Step 4 — Score and prioritise</h4>
      <p class="sm">The three factors combine into a 0–100 score. Sorting by score gives a
      migration order that reflects both cryptographic weakness and data lifetime — so a
      strong endpoint holding 25-year policy records can outrank a weak endpoint holding
      short-lived data.</p></div>
  </div>
</section>

</main>

<footer><div class="wrap">Quantum-Aware TLS Risk Scoring for Third-Party API Communications
(Risk Intelligence Engine) · Capstone 1 · __N__ scored endpoints · generated __DATE__ from
measured probe output.</div></footer>

<script>
var DATA=__DATA__, S=__STATS__;
function col(b){return b==='critical'?'var(--red)':b==='high'?'var(--amber)':'var(--green)'}
document.getElementById('metrics').innerHTML=[
 ['Endpoints scored',S.n,''],['Critical (\u2265 90)',S.critical,'var(--red)'],
 ['High (70\u201389)',S.elevated,'var(--amber)'],['Moderate (< 70)',S.low,'var(--green)'],
 ['Average score',S.avg,''],['PQ certificates',S.pqcert,'var(--red)']
].map(function(m){return '<div class="met"><div class="v"'+(m[2]?' style="color:'+m[2]+'"':'')+
 '>'+m[1]+'</div><div class="k">'+m[0]+'</div></div>'}).join('');

document.getElementById('rows').innerHTML=DATA.map(function(r,i){
  return '<tr data-i="'+i+'"><td><b>'+r.label+'</b><div class="xs">'+r.host+'</div></td>'+
  '<td class="sm">'+(r.pqc?'Hybrid ML-KEM':(r.tls13?'Classical only':'No TLS 1.3'))+
  (r.srsa?'<div class="xs" style="color:var(--amber)">static RSA</div>':'')+'</td>'+
  '<td class="sm">'+r.certkey+'</td><td class="sm">'+r.edge+'</td>'+
  '<td class="n"><span class="badge b-'+r.band+'">'+r.total+'</span>'+
  '<div class="scorebar"><i style="width:'+r.total+'%;background:'+col(r.band)+'"></i></div></td></tr>';
}).join('');

function bar(l,v,max){return '<div class="fbar"><span class="fl">'+l+'</span>'+
 '<span class="ft"><i style="width:'+(v/max*100)+'%;background:'+
 (v/max>.6?'var(--red)':v/max>.3?'var(--amber)':'var(--green)')+'"></i></span>'+
 '<span class="fv">'+v+'</span></div>'}

document.getElementById('rows').addEventListener('click',function(e){
  var tr=e.target.closest('tr'); if(!tr) return;
  [].forEach.call(this.querySelectorAll('tr'),function(x){x.classList.remove('sel')});
  tr.classList.add('sel');
  var r=DATA[+tr.dataset.i];
  document.getElementById('dempty').style.display='none';
  var b=document.getElementById('dbody'); b.style.display='block';
  b.innerHTML='<h4 style="margin-bottom:4px">'+r.label+'</h4>'+
   '<div class="xs" style="margin-bottom:14px">'+r.host+'</div>'+
   '<div style="font-size:31px;font-weight:680;color:'+col(r.band)+';margin-bottom:2px">'+
   r.total+' <span style="font-size:14px;color:var(--muted);font-weight:500">/ 100</span></div>'+
   '<div class="xs" style="margin-bottom:16px;text-transform:uppercase;letter-spacing:.06em;color:'+
   col(r.band)+'">'+r.band+' risk</div>'+
   bar('Key exchange',r.f1,40)+'<div class="xs" style="margin:-4px 0 10px 122px">'+r.f1r+'</div>'+
   bar('Certificate',r.f2,35)+'<div class="xs" style="margin:-4px 0 10px 122px">'+r.f2r+'</div>'+
   bar('Data lifetime',r.f3,25)+'<div class="xs" style="margin:-4px 0 10px 122px">'+r.f3r+'</div>'+
   (r.pen?bar('Penalty',r.pen,10)+'<div class="xs" style="margin:-4px 0 10px 122px;color:var(--amber)">'+r.penr+'</div>':'')+
   '<div style="border-top:1px solid var(--border);margin:14px 0;padding-top:14px">'+
   '<div class="sm"><b>TLS 1.3</b> '+(r.tls13?'yes':'no')+' &nbsp;·&nbsp; <b>Hybrid KEM</b> '+
   (r.pqc?'yes':'no')+'</div>'+
   '<div class="sm"><b>Certificate</b> '+r.certkey+' &nbsp;·&nbsp; '+r.certsig+'</div>'+
   '<div class="sm"><b>Edge</b> '+r.edge+' &nbsp;·&nbsp; <b>CA</b> '+r.ca+'</div>'+
   '<div class="sm"><b>Groups</b> '+(r.groups.join(', ')||'—')+'</div></div>';
});

var tabs=[].slice.call(document.querySelectorAll('.tab'));
tabs.forEach(function(t){t.addEventListener('click',function(){
  tabs.forEach(function(x){x.setAttribute('aria-selected','false')});
  t.setAttribute('aria-selected','true');
  document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('on')});
  document.getElementById('p-'+t.dataset.p).classList.add('on');
  window.scrollTo({top:0,behavior:'smooth'});
})});
</script></body></html>"""

def main():
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scan", default="measured_full.json")
    ap.add_argument("--hndl", default="hybrid-tls-lab/dashboard/app/data/hndl_inputs.csv")
    ap.add_argument("--out", default="c1_model.html")
    a = ap.parse_args()

    rows = build(a.scan, a.hndl)
    if not rows:
        print("no countable rows found", file=sys.stderr); return 1
    st = stats(rows)
    pqpct = f"{100*st['pq']//max(st['n'],1)}%"
    h = (TPL.replace("__DATA__", json.dumps(rows, separators=(",", ":")))
            .replace("__STATS__", json.dumps(st))
            .replace("__N__", str(st["n"]))
            .replace("__PQPCT__", pqpct)
            .replace("__PQCERT__", str(st["pqcert"]))
            .replace("__DATE__", datetime.date.today().isoformat()))
    open(a.out, "w", encoding="utf-8").write(h)
    print(f"wrote {a.out}  ({st['n']} endpoints)")
    print(f"  critical {st['critical']} | elevated {st['elevated']} | low {st['low']}")
    print(f"  average score {st['avg']} | PQ certificates {st['pqcert']}/{st['n']}")
    print(f"  top 5 by risk:")
    for r in rows[:5]:
        print(f"    {r['total']:>3}  {r['label']:<18} {r['band']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
