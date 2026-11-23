"""Known signed-policy startup on a controlled Wi-Fi network; no operator data."""
import json
import sys
from pathlib import Path

from recovery_slo import ROOT, unique_fields, write

RAW = ROOT / "app/build/outputs/syn443-known-start/attempts.json"
SAMPLES = 3
TARGET_MS = 10_000
UNMEASURED = {"not_started", "observing", "failed"}


def initial():
    return [{"outcome": "not_started", "elapsedMs": None} for _ in range(SAMPLES)]


class StartupCampaign:
    def __init__(self, path=RAW):
        self.path = path
        self.rows = initial()
        write(self.path, self.rows)

    def start(self, index):
        if self.rows[index]["outcome"] != "not_started":
            raise ValueError("Repeated startup trial")
        self.rows[index]["outcome"] = "observing"
        write(self.path, self.rows)

    def finish(self, index, elapsed_ns=None):
        if self.rows[index]["outcome"] != "observing":
            raise ValueError("Startup trial was not opened")
        if elapsed_ns is None:
            self.rows[index]["outcome"] = "failed"
        else:
            if type(elapsed_ns) is not int or elapsed_ns < 0:
                raise ValueError("Invalid monotonic interval")
            elapsed_ms = (elapsed_ns + 999_999) // 1_000_000
            self.rows[index] = {"outcome": "passed" if elapsed_ms <= TARGET_MS else "late",
                                "elapsedMs": elapsed_ms}
        write(self.path, self.rows)


def summarize(rows):
    if not isinstance(rows, list) or len(rows) != SAMPLES:
        raise ValueError("Every planned trial needs an entry")
    times = []
    for row in rows:
        if type(row) is not dict or row.keys() != {"outcome", "elapsedMs"}:
            raise ValueError("Invalid startup entry")
        outcome, elapsed = row["outcome"], row["elapsedMs"]
        if outcome in {"passed", "late"}:
            if type(elapsed) is not int or not 0 <= elapsed <= 3_600_000 or (elapsed <= TARGET_MS) != (outcome == "passed"):
                raise ValueError("Invalid startup measurement")
            times.append(elapsed)
        elif outcome not in UNMEASURED or elapsed is not None:
            raise ValueError("Invalid unmeasured startup")
    rank = (95 * SAMPLES + 99) // 100
    return {"scenario": "known_signed_policy_wifi_start", "schemaVersion": 1, "denominator": SAMPLES,
            "start": "normal_connect_requested_after_confirmed_off",
            "end": "app_uid_received_challenge_204_through_assigned_proxy",
            "targetMs": TARGET_MS, "withinTarget": sum(value <= TARGET_MS for value in times),
            "p95Ms": sorted(times)[rank-1] if len(times) >= rank else None, "samples": rows}


def publish(raw, destination, require_target=False):
    if raw.is_symlink() or raw.exists() and (not raw.is_file() or raw.stat().st_size > 1024):
        raise ValueError("Invalid startup report")
    rows = json.loads(raw.read_bytes(), object_pairs_hook=unique_fields) if raw.exists() else initial()
    report = summarize(rows)
    write(destination, report)
    if require_target and (report["p95Ms"] is None or report["p95Ms"] > TARGET_MS):
        raise ValueError("Known-policy startup target missed or unmeasured")


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--require-target"]):
        raise SystemExit("Unexpected startup report option")
    publish(RAW, ROOT / "public-evidence/known-start/known-start.json", bool(sys.argv[1:]))
