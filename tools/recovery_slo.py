"""Predeclared two-hop recovery measurements from the disposable Android emulator."""
import json
import time
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "app/build/outputs/syn443-recovery/attempts.json"
HOPS = ("ingress", "egress")
DEADLINE_MS = 110_000
TIMED = {"passed", "late", "failed", "timeout"}
UNTIMED = {"not_started", "observing", "setup_failed"}


class RecoveryTimeout(AssertionError):
    pass


def initial():
    return [{"hop": hop, "outcome": "not_started", "elapsedMs": None} for hop in HOPS]


def write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(rows, separators=(",", ":")), encoding="utf-8")
    temp.replace(path)


class Campaign:
    def __init__(self, path=RAW, clock=time.monotonic_ns):
        self.path = path
        self.clock = clock
        self.rows = initial()
        write(self.path, self.rows)

    def setup_failed(self, hop):
        row = self.rows[HOPS.index(hop)]
        if row["outcome"] == "not_started":
            row["outcome"] = "setup_failed"
            write(self.path, self.rows)

    @contextmanager
    def measure(self, hop):
        row = self.rows[HOPS.index(hop)]
        if row["outcome"] != "not_started":
            raise ValueError("A planned recovery sample can only start once")
        row["outcome"] = "observing"
        write(self.path, self.rows)
        start = self.clock()
        outcome = None
        try:
            yield
        except RecoveryTimeout:
            outcome = "timeout"
            raise
        except Exception:
            outcome = "failed"
            raise
        else:
            outcome = "passed"
        finally:
            # Abrupt process termination leaves the started sample visible.
            delta = self.clock() - start
            if delta < 0:
                raise ValueError("Recovery observation clock moved back")
            elapsed = (delta + 999_999) // 1_000_000
            if outcome is not None:
                if outcome == "passed" and elapsed > DEADLINE_MS:
                    outcome = "late"
                row.update(outcome=outcome, elapsedMs=elapsed)
                write(self.path, self.rows)


def summarize(rows):
    if not isinstance(rows, list) or len(rows) != len(HOPS):
        raise ValueError("Invalid sample set")
    clean = []
    for hop, row in zip(HOPS, rows):
        if not isinstance(row, dict) or set(row) != {"hop", "outcome", "elapsedMs"} or row["hop"] != hop:
            raise ValueError("Invalid planned sample")
        outcome, elapsed = row["outcome"], row["elapsedMs"]
        if type(outcome) is not str or outcome not in TIMED | UNTIMED:
            raise ValueError("Unknown recovery outcome")
        if outcome in TIMED:
            if type(elapsed) is not int or not 0 <= elapsed <= 86_400_000:
                raise ValueError("Invalid elapsed duration")
            if ((outcome == "passed" and elapsed > DEADLINE_MS) or
                    (outcome == "late" and elapsed <= DEADLINE_MS) or
                    (outcome == "timeout" and elapsed < DEADLINE_MS)):
                raise ValueError("Duration and result disagree")
        elif elapsed is not None:
            raise ValueError("Unobserved sample includes a duration")
        clean.append({"hop": hop, "outcome": outcome, "elapsedMs": elapsed})
    observed = sorted(r["elapsedMs"] for r in clean if r["outcome"] in {"passed", "late"})
    rank = (95 * len(HOPS) + 99) // 100
    return {"schemaVersion": 1, "scenario": "two_hop_proxy_restoration",
            "start": "assigned_hop_restored", "end": "fresh_204_and_online_with_original_engine_and_intent",
            "pathAvailability": "controlled_fixture", "deadlineMs": DEADLINE_MS,
            "percentileRule": "nearest_rank", "denominator": len(HOPS),
            "completedWithinDeadline": sum(r["outcome"] == "passed" for r in clean),
            "p95Ms": observed[rank - 1] if len(observed) >= rank else None, "samples": clean}


def unique_fields(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate recovery sample field")
    return result


def publish(raw, dest, require_success=False):
    if raw.is_symlink() or raw.exists() and (not raw.is_file() or raw.stat().st_size > 512):
        raise ValueError("Invalid recovery report file")
    rows = json.loads(raw.read_text(encoding="utf-8"), object_pairs_hook=unique_fields) if raw.exists() else initial()
    report = summarize(rows)
    if require_success and report["completedWithinDeadline"] != report["denominator"]:
        raise ValueError("The completed emulator suite lacks its two in-time recovery samples")
    write(dest, report)


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--require-success"]):
        raise SystemExit("Unknown recovery report argument")
    publish(RAW, ROOT / "public-evidence/recovery/recovery-slo.json", bool(sys.argv[1:]))
