#!/usr/bin/env python3
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path


def make_locator(inp):
    locator = {k: v for k, v in inp.items() if v is not None}
    return locator or None


def normalize_source(inp):
    source = inp.get("source")

    if source == "evtx":
        event_id = inp.get("event_id")
        event_type = "authentication" if event_id == 4624 else "evtx_event"
        return {
            "event_type": event_type,
            "source_locator": make_locator(inp)
        }

    if source == "sysmon":
        event_id = inp.get("event_id")
        event_type = "process_start" if event_id == 1 else "sysmon_event"
        return {
            "event_type": event_type,
            "image": inp.get("image"),
            "parent": inp.get("parent"),
            "source_locator": make_locator(inp)
        }

    if source == "zeek_conn":
        return {
            "event_type": "network_connection",
            "correlation_id": inp.get("uid"),
            "source_locator": make_locator(inp)
        }

    if source == "zeek_dns":
        return {
            "event_type": "dns_query",
            "correlation_id": inp.get("uid"),
            "query": inp.get("query"),
            "source_locator": make_locator(inp)
        }

    if source == "eml":
        return {
            "event_type": "email_delivery",
            "message_id": inp.get("message_id"),
            "attachment_sha256": inp.get("attachment_sha256"),
            "source_locator": make_locator(inp)
        }

    raise ValueError(f"unsupported source: {source}")


def verify_manifest(inp):
    expected = inp.get("expected_sha256")
    actual = inp.get("actual_sha256")
    if expected != actual:
        return {"verdict": "tampered", "ingest": False}
    return {"verdict": "match", "ingest": True}


def normalize_clock(inp):
    raw = inp["raw"]
    offset_seconds = int(inp["offset_seconds"])
    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    normalized = dt + timedelta(seconds=offset_seconds)
    return {
        "normalized": normalized.astimezone(timezone.utc)
                                .strftime("%Y-%m-%dT%H:%M:%SZ")
    }


def deduplicate(ids):
    seen = set()
    output = []
    duplicate_count = 0

    for value in ids:
        if value in seen:
            duplicate_count += 1
            continue
        seen.add(value)
        output.append(value)

    return {
        "output_count": len(output),
        "duplicate_count": duplicate_count
    }


def order_archive_parts(items):
    ordered = sorted(items, key=lambda x: (x["sequence"], x["stream"]))
    return {"ordered_streams": [x["stream"] for x in ordered]}


def classify_admin(inp):
    if inp.get("approved") is True and inp.get("actor"):
        return {"classification": "benign_approved"}
    return {"classification": "unverified_admin"}


def validate_output(inp):
    if not inp.get("source_locator"):
        return {"verdict": "invalid_output"}
    return {"verdict": "valid_output"}


def quarantine_malformed(raw):
    try:
        json.loads(raw)
        return {"verdict": "valid"}
    except (json.JSONDecodeError, TypeError):
        return {"verdict": "quarantine", "reason": "parse_error"}


def execute_test(test):
    if "input_ids" in test:
        return deduplicate(test["input_ids"])

    inp = test.get("input")

    if isinstance(inp, str):
        return quarantine_malformed(inp)

    if isinstance(inp, list) and all(
        isinstance(x, dict) and "stream" in x and "sequence" in x
        for x in inp
    ):
        return order_archive_parts(inp)

    if not isinstance(inp, dict):
        raise ValueError("unsupported fixture schema")

    if "expected_sha256" in inp and "actual_sha256" in inp:
        return verify_manifest(inp)

    if "raw" in inp and "offset_seconds" in inp:
        return normalize_clock(inp)

    if "change_id" in inp and "approved" in inp:
        return classify_admin(inp)

    if "event_type" in inp and "source_locator" in inp:
        return validate_output(inp)

    if "source" in inp:
        return normalize_source(inp)

    raise ValueError("unsupported fixture schema")


def compare_result(result, expected):
    for key, expected_value in expected.items():
        if key == "source_locator_required":
            if bool(result.get("source_locator")) != bool(expected_value):
                return False
            continue

        if result.get(key) != expected_value:
            return False

    return True


def main():
    fixture_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    suite = json.loads(fixture_path.read_text())
    results = []
    passed = 0
    failed = 0

    for test in suite["tests"]:
        try:
            result = execute_test(test)
            ok = compare_result(result, test["expected"])

            results.append({
                "id": test["id"],
                "passed": ok,
                "result": result,
                "expected": test["expected"]
            })

            if ok:
                passed += 1
            else:
                failed += 1

        except Exception as exc:
            failed += 1
            results.append({
                "id": test.get("id", "UNKNOWN"),
                "passed": False,
                "error": str(exc),
                "expected": test.get("expected")
            })

    report = {
        "schema_version": "1.0",
        "tests": results,
        "summary": {
            "passed": passed,
            "failed": failed,
            "total": passed + failed
        }
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps(report["summary"]))
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
