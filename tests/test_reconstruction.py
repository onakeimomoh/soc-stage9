#!/usr/bin/env python3

import csv
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(".")

RECOVERY = ROOT / "recovered/recovery-metadata.json"
TIMELINE = ROOT / "timeline.csv"
CLOCKS = ROOT / "evidence/clock-offsets.json"
RECOVERED_DIR = ROOT / "recovered/extracted"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_iso(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def main():
    failures = []

    recovery = json.loads(RECOVERY.read_text())
    clocks = json.loads(CLOCKS.read_text())

    if recovery.get("parser_status") != "ok":
        failures.append("recovery parser status is not ok")

    request = recovery.get("http_request", {})
    response = recovery.get("http_response", {})
    rec = recovery.get("recovery", {})

    req_frame = request.get("frame_number")
    resp_frame = response.get("frame_number")

    if not isinstance(req_frame, int) or req_frame <= 0:
        failures.append("HTTP request frame number is invalid")

    if not isinstance(resp_frame, int) or resp_frame <= req_frame:
        failures.append("HTTP response frame does not follow request frame")

    status = response.get("status_code")
    if not isinstance(status, int) or not (200 <= status < 300):
        failures.append("HTTP response is not successful 2xx")

    if not rec.get("content_length_match"):
        failures.append("recovered body does not match Content-Length")

    if not rec.get("zip_valid"):
        failures.append("recovered archive is not valid ZIP")

    members = rec.get("members", [])

    if rec.get("member_count") != len(members):
        failures.append("member_count does not match recovered member list")

    if not members:
        failures.append("recovered archive has no members")

    csv_members = [
        x for x in members
        if str(x.get("name", "")).lower().endswith(".csv")
    ]

    if len(csv_members) != 1:
        failures.append("expected exactly one recovered CSV member")
    else:
        csv_member = csv_members[0]
        csv_path = RECOVERED_DIR / csv_member["name"]

        if not csv_path.exists():
            failures.append("recovered CSV member is missing from extracted output")
        else:
            with csv_path.open(newline="", encoding="utf-8") as f:
                actual_records = sum(1 for _ in csv.reader(f)) - 1

            metadata_records = csv_member.get("csv_data_records")

            if metadata_records != actual_records:
                failures.append(
                    "recovered CSV metadata count does not match extracted CSV"
                )

            if actual_records <= 0:
                failures.append("recovered CSV contains no data records")

    non_csv_members = [x for x in members if x not in csv_members]
    if not non_csv_members:
        failures.append("no non-CSV evidence member recovered")

    with TIMELINE.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        failures.append("timeline is empty")

    try:
        parsed_times = [parse_iso(r["utc_time"]) for r in rows]
        if parsed_times != sorted(parsed_times):
            failures.append("timeline is not chronologically sorted")
    except Exception as exc:
        failures.append(f"timeline timestamp parse failure: {exc}")

    activities = [r.get("activity", "").lower() for r in rows]

    required_behaviors = {
        "office attachment activity": lambda a: (
            "process_start:" in a and "winword" in a
        ),
        "powershell execution": lambda a: (
            "process_start:" in a and "powershell" in a
        ),
        "scheduled task creation": lambda a: "scheduled_task_create:" in a,
        "archive staging": lambda a: (
            "process_start:" in a and "tar.exe" in a
        ),
        "network connection": lambda a: "network_connect:" in a,
        "HTTP POST": lambda a: "http post " in a,
        "archive deletion": lambda a: "file_delete:" in a,
        "HTTP response": lambda a: "http response " in a,
    }

    for label, predicate in required_behaviors.items():
        if not any(predicate(a) for a in activities):
            failures.append(f"timeline missing behavioral stage: {label}")

    for row in rows:
        original = row.get("original_time", "")
        utc_time = row.get("utc_time", "")
        artifact = row.get("artifact_path", "")

        if not original or not utc_time:
            continue

        try:
            if artifact.endswith("sysmon.jsonl"):
                expected = (
                    parse_iso(original)
                    + timedelta(
                        seconds=clocks["sysmon"]["offset_seconds_applied"]
                    )
                )
                if parse_iso(utc_time) != expected:
                    failures.append(
                        "Sysmon timeline row does not match clock model"
                    )

            elif artifact.endswith("powershell-operational.jsonl"):
                expected = (
                    parse_iso(original)
                    + timedelta(
                        seconds=clocks["powershell"]["offset_seconds_applied"]
                    )
                )
                if parse_iso(utc_time) != expected:
                    failures.append(
                        "PowerShell timeline row does not match clock model"
                    )
        except Exception as exc:
            failures.append(f"clock-model validation failure: {exc}")

    post_rows = [
        r for r in rows
        if r.get("activity", "").lower().startswith("http post ")
    ]
    response_rows = [
        r for r in rows
        if r.get("activity", "").lower().startswith("http response ")
    ]

    if len(post_rows) != 1:
        failures.append("expected exactly one HTTP POST timeline row")
    else:
        locator = post_rows[0].get("exact_locator", "")
        if f"frame {req_frame}" not in locator:
            failures.append("POST timeline locator disagrees with recovery metadata")

    if len(response_rows) != 1:
        failures.append("expected exactly one HTTP response timeline row")
    else:
        locator = response_rows[0].get("exact_locator", "")
        if f"frame {resp_frame}" not in locator:
            failures.append(
                "response timeline locator disagrees with recovery metadata"
            )

    if failures:
        print("FAIL")
        for f in failures:
            print("-", f)
        raise SystemExit(1)

    print("PASS: reconstruction validation")
    print("timeline_rows:", len(rows))
    print("archive_sha256:", rec["archive_sha256"])
    print("timeline_sha256:", sha256_file(TIMELINE))


if __name__ == "__main__":
    main()
