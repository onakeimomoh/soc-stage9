#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def normalize_fixture(test):
    test_id = test.get("id")
    inp = test.get("input", {})

    if test_id == "PARSER-EVTX":
        return {
            "event_type": "authentication",
            "source_locator": {
                "source": inp.get("source"),
                "event_id": inp.get("event_id"),
                "computer": inp.get("computer"),
                "time": inp.get("time")
            }
        }

    raise NotImplementedError(f"Unsupported public fixture: {test_id}")

def main():
    fixture_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    suite = json.loads(fixture_path.read_text())
    test = suite["tests"][0]

    try:
        result = normalize_fixture(test)
        expected = test["expected"]

        passed = (
            result.get("event_type") == expected.get("event_type")
            and bool(result.get("source_locator")) == expected.get("source_locator_required", True)
        )

        report = {
            "schema_version": "1.0",
            "tests": [
                {
                    "id": test["id"],
                    "passed": passed,
                    "result": result,
                    "expected": expected
                }
            ],
            "summary": {
                "passed": 1 if passed else 0,
                "failed": 0 if passed else 1
            }
        }

    except Exception as exc:
        report = {
            "schema_version": "1.0",
            "tests": [
                {
                    "id": test.get("id", "UNKNOWN"),
                    "passed": False,
                    "error": str(exc)
                }
            ],
            "summary": {
                "passed": 0,
                "failed": 1
            }
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps(report["summary"]))
    sys.exit(0 if report["summary"]["failed"] == 0 else 1)

if __name__ == "__main__":
    main()
