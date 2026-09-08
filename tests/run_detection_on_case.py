#!/usr/bin/env python3

import importlib.util
import json
from pathlib import Path

RULE = Path("detections/office-powershell-archive-egress.json")
SYSMON = Path(
    "working/evidence/sealed-evidence/evidence/host/sysmon.jsonl"
)
POWERSHELL = Path(
    "working/evidence/sealed-evidence/evidence/host/"
    "powershell-operational.jsonl"
)
RUNNER = Path("tests/run_detection_regression.py")
OUT = Path("tests/case-detection-result.json")


def load_detector():
    spec = importlib.util.spec_from_file_location(
        "detection_runner",
        RUNNER,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.detect


def main():
    rule = json.loads(RULE.read_text())

    ps_rows = [
        json.loads(line)
        for line in POWERSHELL.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    bindings = {
        str(row.get("binding", "")).strip()
        for row in ps_rows
        if str(row.get("binding", "")).strip()
    }

    if len(bindings) != 1:
        raise RuntimeError(
            "Expected exactly one unique PowerShell evidence binding; "
            f"found {len(bindings)}"
        )

    binding = next(iter(bindings))

    case_events = []

    with SYSMON.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            event = json.loads(line)

            if event.get("evidence_binding") != binding:
                continue

            event["_source_line"] = line_number
            case_events.append(event)

    if not case_events:
        raise RuntimeError(
            "No Sysmon events matched the derived evidence binding"
        )

    detect = load_detector()
    result = detect(case_events, rule)

    matched_events = []

    for index in result["matched_event_indexes"]:
        event = case_events[index]

        matched_events.append({
            "source_line": event["_source_line"],
            "timestamp": event.get("timestamp"),
            "computer": event.get("computer"),
            "user": event.get("user"),
            "event_type": event.get("event_type"),
            "image": event.get("image"),
            "parent_image": event.get("parent_image"),
            "detail": event.get("detail"),
            "event_id": event.get("event_id"),
        })

    report = {
        "rule_id": rule["rule_id"],
        "binding_source": str(POWERSHELL),
        "binding_derivation": (
            "Unique non-empty binding parsed from PowerShell source; "
            "value intentionally omitted from report."
        ),
        "sysmon_source": str(SYSMON),
        "case_events_examined": len(case_events),
        "alert": result["alert"],
        "elapsed_seconds": result["elapsed_seconds"],
        "matched_events": matched_events,
    }

    OUT.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("rule_id:", report["rule_id"])
    print("case_events_examined:", len(case_events))
    print("alert:", result["alert"])
    print("elapsed_seconds:", result["elapsed_seconds"])

    print("\n=== MATCHED EVENTS ===")
    for event in matched_events:
        print(
            f"line {event['source_line']} | "
            f"{event['timestamp']} | "
            f"{event['image']} <- {event['parent_image']} | "
            f"{event['detail']}"
        )

    if not result["alert"]:
        raise SystemExit(
            "FAIL: generic detection did not alert on case evidence"
        )

    if len(matched_events) != 3:
        raise SystemExit(
            "FAIL: expected a three-stage correlated match"
        )

    print("\nPASS: generic rule alerted on evidence-derived case events")


if __name__ == "__main__":
    main()
