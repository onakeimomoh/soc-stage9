#!/usr/bin/env python3

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(".")

RECOVERY = ROOT / "recovered/recovery-metadata.json"
TIMELINE = ROOT / "timeline.csv"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    failures = []

    recovery = json.loads(RECOVERY.read_text())

    if recovery["parser_status"] != "ok":
        failures.append("recovery parser status is not ok")

    if recovery["http_request"]["frame_number"] != 49:
        failures.append("POST frame is not 49")

    if recovery["http_response"]["frame_number"] != 50:
        failures.append("HTTP response frame is not 50")

    if recovery["http_response"]["status_code"] != 201:
        failures.append("HTTP response status is not 201")

    if not recovery["recovery"]["content_length_match"]:
        failures.append("recovered body does not match Content-Length")

    if not recovery["recovery"]["zip_valid"]:
        failures.append("recovered archive is not valid ZIP")

    if recovery["recovery"]["member_count"] != 2:
        failures.append("recovered archive member count is not 2")

    csv_members = [
        x for x in recovery["recovery"]["members"]
        if x["name"] == "synthetic-records.csv"
    ]

    if len(csv_members) != 1:
        failures.append("synthetic-records.csv not uniquely recovered")
    else:
        if csv_members[0].get("csv_data_records") != 5137:
            failures.append("synthetic-records.csv record count mismatch")

    marker_members = [
        x for x in recovery["recovery"]["members"]
        if x["name"] == "evidence-marker.txt"
    ]

    if len(marker_members) != 1:
        failures.append("evidence-marker.txt not uniquely recovered")

    with TIMELINE.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    ids = {r["event_id"] for r in rows}

    required = {
        "attack-01",
        "attack-02",
        "attack-03",
        "attack-04",
        "attack-05",
        "attack-06",
        "powershell-1",
        "pcap-http-post",
        "pcap-http-response",
    }

    missing = required - ids
    if missing:
        failures.append(
            "timeline missing events: " + ", ".join(sorted(missing))
        )

    times = {
        r["event_id"]: r["utc_time"]
        for r in rows
    }

    if times.get("attack-05") != "2026-07-14T12:00:49Z":
        failures.append("Sysmon attack-05 clock normalization mismatch")

    if times.get("powershell-1") != "2026-07-14T12:00:42Z":
        failures.append("PowerShell clock normalization mismatch")

    if failures:
        print("FAIL")
        for f in failures:
            print("-", f)
        raise SystemExit(1)

    print("PASS: reconstruction validation")
    print("timeline_rows:", len(rows))
    print("archive_sha256:", recovery["recovery"]["archive_sha256"])
    print("timeline_sha256:", sha256_file(TIMELINE))


if __name__ == "__main__":
    main()
