#!/usr/bin/env python3

import hashlib
import json
import subprocess
from pathlib import Path

OUT = Path("tests/reproducibility-results.json")

COMMANDS = [
    ["python3", "timeline-builder/recover_archive.py"],
    ["python3", "timeline-builder/build_timeline.py"],
    ["python3", "timeline-builder/build_case_findings.py"],
    ["python3", "timeline-builder/build_evidence_index.py"],
    ["python3", "tests/run_detection_regression.py"],
    ["python3", "tests/run_detection_on_case.py"],
]

OUTPUTS = [
    Path("recovered/case-export.zip"),
    Path("recovered/recovery-metadata.json"),
    Path("timeline.csv"),
    Path("evidence/case-findings.json"),
    Path("evidence-index.csv"),
    Path("ioc-set.csv"),
    Path("tests/detection-results.json"),
    Path("tests/case-detection-result.json"),
]


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_pipeline(run_number):
    commands = []

    for command in COMMANDS:
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
        )

        commands.append({
            "command": command,
            "returncode": proc.returncode,
        })

        if proc.returncode != 0:
            print(
                f"FAIL: run {run_number}: "
                + " ".join(command)
            )
            if proc.stdout:
                print(proc.stdout)
            if proc.stderr:
                print(proc.stderr)
            raise SystemExit(proc.returncode)

    hashes = {}

    for path in OUTPUTS:
        if not path.is_file():
            raise SystemExit(
                f"FAIL: expected output missing after run "
                f"{run_number}: {path}"
            )

        hashes[str(path)] = sha256_file(path)

    return {
        "run": run_number,
        "commands": commands,
        "hashes": hashes,
    }


def main():
    print("=== REPRODUCIBILITY RUN 1 ===")
    run1 = run_pipeline(1)

    for path, digest in run1["hashes"].items():
        print(digest, path)

    print("\n=== REPRODUCIBILITY RUN 2 ===")
    run2 = run_pipeline(2)

    for path, digest in run2["hashes"].items():
        print(digest, path)

    comparisons = {}

    for path in run1["hashes"]:
        comparisons[path] = {
            "run_1_sha256": run1["hashes"][path],
            "run_2_sha256": run2["hashes"][path],
            "identical": (
                run1["hashes"][path]
                == run2["hashes"][path]
            ),
        }

    all_identical = all(
        x["identical"]
        for x in comparisons.values()
    )

    report = {
        "schema_version": "1",
        "runs_completed": 2,
        "outputs_compared": len(comparisons),
        "all_outputs_identical": all_identical,
        "run_1": run1,
        "run_2": run2,
        "comparisons": comparisons,
    }

    OUT.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("\n=== COMPARISON ===")

    for path, result in comparisons.items():
        print(
            "PASS" if result["identical"] else "FAIL",
            path,
            result["run_1_sha256"],
            result["run_2_sha256"],
        )

    print(
        "\nall_outputs_identical:",
        all_identical,
    )

    if not all_identical:
        raise SystemExit(
            "FAIL: deterministic rebuild check failed"
        )

    print(
        "PASS: two complete rebuilds produced "
        "identical output hashes"
    )


if __name__ == "__main__":
    main()
