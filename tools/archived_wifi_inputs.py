"""Resolve a prior build explicitly selected by an operator for a disposable Wi-Fi replay."""
import json
import os
import re
import subprocess
from pathlib import Path

from protected_upgrade_inputs import REPOSITORY, api, collect, run_number


def main():
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ValueError("Project workflow dispatch required")
    number = run_number("WIFI_RUN")
    source = os.environ["WIFI_SOURCE"]
    if not number or not re.fullmatch(r"[a-f0-9]{40}", source):
        raise ValueError("Expected an exact build and commit")
    item = api(f"actions/runs/{number}")
    if (item["id"] != number or item["head_repository"]["full_name"] != REPOSITORY or
            item["path"] != ".github/workflows/ci.yml" or item["head_sha"] != source or
            item["event"] not in ("pull_request", "push")):
        raise ValueError("Build is from another workflow, repository or revision")
    subprocess.run(["git", "merge-base", "--is-ancestor", source, "HEAD"], check=True)
    jobs = api(f"actions/runs/{number}/jobs?per_page=100")["jobs"]
    for name in ("public-data", "native", "jvm-and-apk"):
        if [j["conclusion"] for j in jobs if j["name"] == name] != ["success"]:
            raise ValueError("Build inputs did not pass their required job")
    work = Path(os.environ["RUNNER_TEMP"]) / "wifi-replay"
    receipt = collect(work, item, include_driver=True)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
