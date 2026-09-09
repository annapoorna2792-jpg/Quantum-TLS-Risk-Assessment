#!/usr/bin/env python3
"""qskms_saga.py - multi-provider rotation as a saga, with fault injection.

WHY THIS EXISTS
---------------
Rotating a key across N providers is not a transaction. There is no two-phase
commit across AWS, Azure and GCP. Each import is an independent, individually
committed operation, so any rotation can fail after some providers have
accepted the new material and others have not.

The interesting question is not "does rotation work" (it does, on a good day)
but "what state is the system left in when it does not". This harness answers
that quantitatively.

MODEL
-----
Each rotation is a saga with per-provider phases:

    PREPARE -> WRAP -> IMPORT -> VERIFY        (forward)
    DELETE_MATERIAL                            (compensation)

Compensation is best-effort and can itself fail, which is the realistic case
and the one most papers ignore.

INVARIANTS CHECKED AFTER EVERY ROTATION
---------------------------------------
  I1 AVAILABILITY   at least one version is usable on every provider.
                    Violating this is an outage: data cannot be decrypted.
  I2 CONSISTENCY    a version marked globally ACTIVE is ACTIVE on all
                    providers. A partially-active version means two callers
                    can disagree about which key is current.
  I3 NO_ORPHANS     no provider holds material for a version the orchestrator
                    is not tracking. Orphans are unrotatable, unrevocable, and
                    invisible to the compliance report.
  I4 POSTURE_TRUTH  recorded posture matches what the provider actually
                    supports. Never claim pq_native on a classical provider.

Run:
  python3 qskms_saga.py demo
  python3 qskms_saga.py sweep --rotations 200
  python3 qskms_saga.py sweep --rotations 200 --out saga_results.json
"""
from __future__ import annotations

import argparse, json, random, statistics, sys, time
from dataclasses import dataclass, field, asdict
from enum import Enum

try:
    from qskms_core import CAPS, CLASSICAL_ONLY, PQ_NATIVE, HYBRID_COMPENSATED
except ImportError:
    print("qskms_core.py must be in the same directory", file=sys.stderr)
    raise


class VState(str, Enum):
    PENDING  = "PENDING"     # created, material not yet imported everywhere
    ACTIVE   = "ACTIVE"      # current, used for new encryptions
    RETIRED  = "RETIRED"     # not current, still usable for old ciphertext
    REVOKED  = "REVOKED"     # unusable, material still present
    DESTROYED= "DESTROYED"   # material deleted at the provider


class Phase(str, Enum):
    PREPARE = "PREPARE"
    WRAP    = "WRAP"
    IMPORT  = "IMPORT"
    VERIFY  = "VERIFY"
    COMPENSATE = "COMPENSATE"


@dataclass
class ProviderRecord:
    """What one provider holds for one key version."""
    provider: str
    state: VState
    method: str
    posture: str


@dataclass
class Version:
    version: int
    records: dict = field(default_factory=dict)      # provider -> ProviderRecord
    created_at: float = 0.0

    def global_state(self) -> VState:
        """A version is only ACTIVE if it is ACTIVE everywhere."""
        states = {r.state for r in self.records.values()}
        if not states:
            return VState.PENDING
        if states == {VState.ACTIVE}:
            return VState.ACTIVE
        if VState.ACTIVE in states:
            return VState.PENDING          # partial: not safe to call ACTIVE
        if states == {VState.DESTROYED}:
            return VState.DESTROYED
        return VState.RETIRED


class FaultInjector:
    """Injects failures per (provider, phase) at a configured rate."""

    def __init__(self, rate: float, seed: int = 0, slow_provider: str | None = None):
        self.rate = rate
        self.rng = random.Random(seed)
        self.slow = slow_provider
        self.injected = []

    def maybe_fail(self, provider: str, phase: Phase) -> None:
        r = self.rate * (2.0 if provider == self.slow else 1.0)
        if self.rng.random() < r:
            self.injected.append((provider, phase.value))
            raise RuntimeError(f"injected fault: {provider} during {phase.value}")


class FakeProvider:
    """Provider stand-in that records what material it holds.

    Deliberately NOT a mock of the network. We are measuring orchestrator
    behaviour under partial failure, not provider latency. Using real AWS here
    would add cost and noise without changing what is being measured.
    """

    def __init__(self, name: str):
        self.name = name
        self.cap = CAPS[name]
        self.held: dict[int, VState] = {}     # version -> state

    @property
    def posture(self) -> str:
        return PQ_NATIVE if self.cap["pq"] else CLASSICAL_ONLY

    @property
    def method(self) -> str:
        return self.cap["pq"][0] if self.cap["pq"] else self.cap["wrap"][0]

    def import_material(self, version: int):
        self.held[version] = VState.PENDING

    def activate(self, version: int):
        for v, s in self.held.items():
            if s is VState.ACTIVE:
                self.held[v] = VState.RETIRED
        self.held[version] = VState.ACTIVE

    def delete_material(self, version: int):
        if version in self.held:
            self.held[version] = VState.DESTROYED


@dataclass
class SagaResult:
    rotation: int
    outcome: str                      # COMMITTED | COMPENSATED | INCONSISTENT
    failed_provider: str = ""
    failed_phase: str = ""
    compensations_attempted: int = 0
    compensations_failed: int = 0
    duration_ms: float = 0.0
    violations: list = field(default_factory=list)


class Orchestrator:
    def __init__(self, providers: list[str], injector: FaultInjector,
                 naive: bool = False):
        self.providers = {p: FakeProvider(p) for p in providers}
        self.fi = injector
        self.versions: dict[int, Version] = {}
        self.counter = 0
        # naive=True activates each provider as soon as its import lands, which
        # is the obvious implementation and the one most prototypes use.
        # naive=False defers all activation until every import has succeeded.
        # The difference is the whole point of the experiment.
        self.naive = naive

    # ---------------------------------------------------------- invariants
    def check(self) -> list:
        v = []

        # I1 availability: every provider must hold at least one usable version
        for name, p in self.providers.items():
            usable = [s for s in p.held.values()
                      if s in (VState.ACTIVE, VState.RETIRED)]
            if not usable:
                v.append({"invariant": "I1_AVAILABILITY", "provider": name,
                          "detail": "no usable version; data undecryptable"})

        # I2 consistency: no version ACTIVE on some providers but not others
        for num, ver in self.versions.items():
            actives = {n for n, p in self.providers.items()
                       if p.held.get(num) is VState.ACTIVE}
            if actives and actives != set(self.providers):
                v.append({"invariant": "I2_CONSISTENCY", "version": num,
                          "detail": f"ACTIVE only on {sorted(actives)}"})

        # I3 no orphans: material stuck in PENDING at a provider after a newer
        # version exists. This is abandoned key material: never activated,
        # never deleted, still occupying a provider key slot and still billable.
        newest = max(self.versions) if self.versions else 0
        for name, p in self.providers.items():
            for num, st in p.held.items():
                if st is VState.PENDING and num < newest:
                    v.append({"invariant": "I3_NO_ORPHANS", "provider": name,
                              "version": num,
                              "detail": "abandoned PENDING material: never "
                                        "activated, never cleaned up"})

        # I4 posture truth: never claim pq_native on a classical provider
        for num, ver in self.versions.items():
            for name, rec in ver.records.items():
                if rec.posture == PQ_NATIVE and not self.providers[name].cap["pq"]:
                    v.append({"invariant": "I4_POSTURE_TRUTH", "provider": name,
                              "version": num,
                              "detail": "pq_native claimed on classical provider"})
        return v

    # ------------------------------------------------------------- the saga
    def rotate(self, n: int) -> SagaResult:
        t0 = time.perf_counter()
        self.counter += 1
        num = self.counter
        ver = Version(version=num, created_at=time.time())
        done: list[str] = []
        res = SagaResult(rotation=n, outcome="COMMITTED")

        try:
            # forward path, provider by provider
            for name, p in self.providers.items():
                for ph in (Phase.PREPARE, Phase.WRAP, Phase.IMPORT):
                    self.fi.maybe_fail(name, ph)
                p.import_material(num)
                ver.records[name] = ProviderRecord(name, VState.PENDING,
                                                   p.method, p.posture)
                done.append(name)
                if self.naive:
                    self.fi.maybe_fail(name, Phase.VERIFY)
                    p.activate(num)
                    ver.records[name].state = VState.ACTIVE
                    self.versions[num] = ver

            # verify + activate only after ALL imports land. Activating
            # incrementally would guarantee I2 violations on any later failure.
            if not self.naive:
                for name, p in self.providers.items():
                    self.fi.maybe_fail(name, Phase.VERIFY)
                for name, p in self.providers.items():
                    p.activate(num)
                    ver.records[name].state = VState.ACTIVE
            for prev, pv in self.versions.items():
                for r in pv.records.values():
                    if r.state is VState.ACTIVE:
                        r.state = VState.RETIRED

            self.versions[num] = ver

        except RuntimeError as e:
            msg = str(e)
            res.failed_provider = msg.split()[2]
            res.failed_phase = msg.split()[-1]
            res.outcome = "COMPENSATED"

            # compensation: remove material from providers that accepted it,
            # and stop tracking the version. Compensation can itself fail.
            for name in done:
                res.compensations_attempted += 1
                try:
                    self.fi.maybe_fail(name, Phase.COMPENSATE)
                    self.providers[name].delete_material(num)
                    ver.records.pop(name, None)
                except RuntimeError:
                    res.compensations_failed += 1
                    res.outcome = "INCONSISTENT"
            if ver.records:
                self.versions[num] = ver     # keep partial record: better than orphaning

        res.duration_ms = (time.perf_counter() - t0) * 1000
        res.violations = self.check()
        return res

    def bootstrap(self):
        """Seed v1 with faults disabled, so runs start from a valid state."""
        saved, self.fi.rate = self.fi.rate, 0.0
        self.rotate(0)
        self.fi.rate = saved


# ==================================================================== RUNS
PROVIDERS = ["aws", "azure", "gcp"]


def run_campaign(rate: float, rotations: int, seed: int,
                 naive: bool = False) -> dict:
    fi = FaultInjector(rate, seed=seed, slow_provider="azure")
    orc = Orchestrator(PROVIDERS, fi, naive=naive)
    orc.bootstrap()

    results = [orc.rotate(i + 1) for i in range(rotations)]
    by_outcome: dict[str, int] = {}
    for r in results:
        by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1

    all_v = [v for r in results for v in r.violations]
    by_inv: dict[str, int] = {}
    for v in all_v:
        by_inv[v["invariant"]] = by_inv.get(v["invariant"], 0) + 1

    att = sum(r.compensations_attempted for r in results)
    fail = sum(r.compensations_failed for r in results)
    durs = [r.duration_ms for r in results]

    return {
        "design": "naive_incremental_activate" if naive else "deferred_activate",
        "fault_rate": rate,
        "rotations": rotations,
        "outcomes": by_outcome,
        "success_rate": by_outcome.get("COMMITTED", 0) / rotations,
        "compensation": {
            "attempted": att, "failed": fail,
            "success_rate": round((att - fail) / att, 4) if att else None,
        },
        "rotations_with_violations": sum(1 for r in results if r.violations),
        "violations_by_invariant": by_inv,
        "duration_ms": {
            "median": round(statistics.median(durs), 4),
            "p95": round(sorted(durs)[int(.95 * len(durs))], 4),
        },
        "faults_injected": len(fi.injected),
    }


def cmd_demo(a):
    print("Single rotation campaign at 15% fault rate, 3 providers\n")
    fi = FaultInjector(0.15, seed=7, slow_provider="azure")
    orc = Orchestrator(PROVIDERS, fi)
    orc.bootstrap()
    print(f"{'#':>3} {'OUTCOME':<14} {'FAILED AT':<22} {'COMP':<7} VIOLATIONS")
    print("-" * 78)
    for i in range(12):
        r = orc.rotate(i + 1)
        at = f"{r.failed_provider}/{r.failed_phase}" if r.failed_provider else "-"
        comp = f"{r.compensations_attempted - r.compensations_failed}/{r.compensations_attempted}" \
               if r.compensations_attempted else "-"
        viol = ", ".join(sorted({v["invariant"] for v in r.violations})) or "none"
        print(f"{i+1:>3} {r.outcome:<14} {at:<22} {comp:<7} {viol}")
    print("\nfinal provider state:")
    for n, p in orc.providers.items():
        print(f"  {n:<6} {dict(sorted(p.held.items()))}")
    return 0


def cmd_compare(a):
    """Head to head: naive incremental activation vs deferred activation."""
    print(f"Design comparison, {a.rotations} rotations per cell, 3 providers\n")
    print(f"{'RATE':>6}  {'DESIGN':<28} {'SUCCESS':>8} {'I1':>5} {'I2':>5} {'I3':>5}")
    print("-" * 68)
    rows = []
    for rate in (0.0, 0.05, 0.10, 0.20, 0.35):
        for naive in (True, False):
            c = run_campaign(rate, a.rotations, a.seed, naive=naive)
            bi = c["violations_by_invariant"]
            print(f"{rate:>6}  {c['design']:<28} {c['success_rate']:>8.3f} "
                  f"{bi.get('I1_AVAILABILITY',0):>5} {bi.get('I2_CONSISTENCY',0):>5} "
                  f"{bi.get('I3_NO_ORPHANS',0):>5}")
            rows.append(c)
        print()
    n_i2 = sum(r["violations_by_invariant"].get("I2_CONSISTENCY", 0)
               for r in rows if r["design"].startswith("naive"))
    d_i2 = sum(r["violations_by_invariant"].get("I2_CONSISTENCY", 0)
               for r in rows if r["design"].startswith("deferred"))
    print(f"I2 consistency violations  naive={n_i2}  deferred={d_i2}")
    print("Deferring activation until every import succeeds eliminates the "
          "split-brain\nstate in which callers disagree about the current key.")
    if a.out:
        with open(a.out, "w") as fh:
            json.dump({"comparison": rows, "i2_naive": n_i2,
                       "i2_deferred": d_i2}, fh, indent=2)
        print(f"\nwritten -> {a.out}")
    return 0


def cmd_sweep(a):
    out = {"meta": {
        "providers": PROVIDERS, "rotations_per_rate": a.rotations, "seed": a.seed,
        "note": ("Fault injection targets the orchestrator's failure handling, "
                 "not provider latency. azure is configured with 2x the base "
                 "fault rate to model an unevenly reliable estate."),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        "campaigns": []}
    for rate in (0.0, 0.02, 0.05, 0.10, 0.20, 0.35):
        c = run_campaign(rate, a.rotations, a.seed)
        out["campaigns"].append(c)
        print(f"rate={rate:<5} success={c['success_rate']:.3f} "
              f"comp_success={c['compensation']['success_rate']} "
              f"violating_rotations={c['rotations_with_violations']:>4}/{a.rotations} "
              f"{c['violations_by_invariant'] or ''}", file=sys.stderr)

    zero = out["campaigns"][0]
    out["headline"] = {
        "clean_run_success_rate": zero["success_rate"],
        "clean_run_violations": zero["rotations_with_violations"],
        "interpretation": (
            "With no injected faults the saga commits every rotation and holds "
            "all four invariants. As the fault rate rises, rotations fail but "
            "compensation prevents availability loss; the residual risk is "
            "compensation itself failing, which is what produces INCONSISTENT "
            "outcomes and is unavoidable without provider-side transactions."),
    }
    if a.out:
        with open(a.out, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwritten -> {a.out}", file=sys.stderr)
    else:
        print(json.dumps(out, indent=2))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo")
    p = sub.add_parser("compare")
    p.add_argument("--rotations", type=int, default=200)
    p.add_argument("--seed", type=int, default=20260906)
    p.add_argument("--out", default="")
    p = sub.add_parser("sweep")
    p.add_argument("--rotations", type=int, default=200)
    p.add_argument("--seed", type=int, default=20260906)
    p.add_argument("--out", default="")
    a = ap.parse_args()
    return {"demo": cmd_demo, "compare": cmd_compare,
            "sweep": cmd_sweep}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
