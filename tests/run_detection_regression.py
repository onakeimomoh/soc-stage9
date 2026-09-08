#!/usr/bin/env python3

import json
from datetime import datetime
from pathlib import Path

RULE = Path("detections/office-powershell-archive-egress.json")
FIXTURES = Path("tests/detection-fixtures.json")
RESULTS = Path("tests/detection-results.json")


def dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def lower(value):
    return str(value or "").lower()


def match_stage(event, stage):
    if event.get("event_type") != stage["event_type"]:
        return False

    if "image" in stage:
        if lower(event.get("image")) not in {
            lower(x) for x in stage["image"]
        }:
            return False

    if "parent_image" in stage:
        if lower(event.get("parent_image")) not in {
            lower(x) for x in stage["parent_image"]
        }:
            return False

    return True


def detect(events, rule):
    stages = rule["stages"]
    window = rule["max_window_seconds"]

    ordered = sorted(events, key=lambda x: dt(x["timestamp"]))

    for i, first in enumerate(ordered):
        if not match_stage(first, stages["office_powershell"]):
            continue

        for j in range(i + 1, len(ordered)):
            second = ordered[j]

            if second.get("computer") != first.get("computer"):
                continue
            if second.get("user") != first.get("user"):
                continue
            if not match_stage(second, stages["archive_staging"]):
                continue

            for k in range(j + 1, len(ordered)):
                third = ordered[k]

                if third.get("computer") != first.get("computer"):
                    continue
                if third.get("user") != first.get("user"):
                    continue
                if not match_stage(third, stages["network_egress"]):
                    continue

                elapsed = (
                    dt(third["timestamp"]) -
                    dt(first["timestamp"])
                ).total_seconds()

                if 0 <= elapsed <= window:
                    return {
                        "alert": True,
                        "matched_event_indexes": [i, j, k],
                        "elapsed_seconds": elapsed
                    }

    return {
        "alert": False,
        "matched_event_indexes": [],
        "elapsed_seconds": None
    }


def main():
    rule = json.loads(RULE.read_text())
    fixtures = json.loads(FIXTURES.read_text())["fixtures"]

    results = []
    passed = 0

    for fixture in fixtures:
        detection = detect(fixture["events"], rule)
        actual = detection["alert"]
        expected = fixture["expected_alert"]
        ok = actual == expected

        if ok:
            passed += 1

        results.append({
            "fixture_id": fixture["fixture_id"],
            "expected_alert": expected,
            "actual_alert": actual,
            "pass": ok,
            "matched_event_indexes": detection["matched_event_indexes"],
            "elapsed_seconds": detection["elapsed_seconds"]
        })

    report = {
        "rule_id": rule["rule_id"],
        "fixtures_total": len(fixtures),
        "fixtures_passed": passed,
        "fixtures_failed": len(fixtures) - passed,
        "results": results
    }

    RESULTS.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )

    for r in results:
        print(
            "PASS" if r["pass"] else "FAIL",
            r["fixture_id"],
            "expected=" + str(r["expected_alert"]),
            "actual=" + str(r["actual_alert"])
        )

    print(
        f"summary: {passed}/{len(fixtures)} passed"
    )

    if passed != len(fixtures):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
