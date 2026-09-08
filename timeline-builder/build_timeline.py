#!/usr/bin/env python3

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(".")

SYSMON = Path(
    "working/evidence/sealed-evidence/evidence/host/sysmon.jsonl"
)
POWERSHELL = Path(
    "working/evidence/sealed-evidence/evidence/host/powershell-operational.jsonl"
)
RECOVERY = Path("recovered/recovery-metadata.json")

OUT = Path("timeline.csv")
CLOCKS = Path("evidence/clock-offsets.json")


def parse_z(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def fmt(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# Evidence-derived source clock model.
#
# Sysmon attack-05 records the curl network connection at:
#   2026-07-15T11:46:49Z
#
# PCAP frame 49 records the matching HTTP POST at:
#   2026-07-14T12:00:49.049Z
#
# The near-identical seconds and exact host/case binding support a
# Sysmon clock correction of -23h46m.
CLOCK_MODEL = {
    "sysmon": {
        "offset_seconds_applied": -(23 * 3600 + 46 * 60),
        "basis": (
            "Correlated Sysmon attack-05 curl connection to "
            "sync-v1.updates-example.invalid:8443 with PCAP frame 49 "
            "HTTP POST to the same host/case binding."
        ),
        "confidence": "high",
    },
    "powershell": {
        "offset_seconds_applied": 38,
        "basis": (
            "Correlated PowerShell Event 4104 for "
            "Invoke-SyntheticCaseSimulation.ps1 with Sysmon attack-02 "
            "for the same PowerShell execution and evidence binding. "
            "After Sysmon normalization, attack-02 is 2026-07-14T12:00:42Z; "
            "PowerShell reports 2026-07-14T12:00:04Z."
        ),
        "confidence": "high",
    },
    "pcap": {
        "offset_seconds_applied": 0,
        "basis": "PCAP epoch timestamps used as the reference network timebase.",
        "confidence": "high",
    },
}


def corrected(ts, source):
    dt = parse_z(ts)
    seconds = CLOCK_MODEL[source]["offset_seconds_applied"]
    return dt + timedelta(seconds=seconds)


rows = []

# PowerShell
for line_no, line in enumerate(POWERSHELL.open(), 1):
    o = json.loads(line)

    rows.append({
        "event_id": f"powershell-{line_no}",
        "utc_time": fmt(corrected(o["timestamp"], "powershell")),
        "original_time": o["timestamp"],
        "source_timezone": "UTC; offset_applied=+00:00:38",
        "host": "",
        "user": "",
        "activity": (
            f"PowerShell script block {o['script_name']}: "
            f"{o['script_block']}"
        ),
        "artifact_path": str(POWERSHELL),
        "exact_locator": f"JSONL line {line_no}; event_id={o['event_id']}",
        "attack_technique": "",
        "confidence": "high",
        "primary_or_supporting": "supporting",
        "alternative_interpretation": (
            "Artifact explicitly describes a training simulation and "
            "local collector."
        ),
        "notes": f"evidence_binding={o.get('binding', '')}",
    })


# Relevant Sysmon rows
for line_no, line in enumerate(SYSMON.open(), 1):
    o = json.loads(line)

    if o.get("evidence_binding") != "8d919c5bfb955d01":
        continue

    raw = o["timestamp"]
    corr = corrected(raw, "sysmon")

    technique = ""
    if o["event_id"] == "attack-03":
        technique = "T1053.005 Scheduled Task/Job: Scheduled Task"
    elif o["event_id"] == "attack-04":
        technique = "T1560 Archive Collected Data"
    elif o["event_id"] == "attack-05":
        technique = "T1041 Exfiltration Over C2 Channel"

    rows.append({
        "event_id": o["event_id"],
        "utc_time": fmt(corr),
        "original_time": raw,
        "source_timezone": "UTC; offset_applied=-23:46:00",
        "host": o.get("computer", ""),
        "user": o.get("user", ""),
        "activity": (
            f"{o.get('event_type', '')}: "
            f"{o.get('image', '')} | {o.get('detail', '')}"
        ),
        "artifact_path": str(SYSMON),
        "exact_locator": f"JSONL line {line_no}; event_id={o['event_id']}",
        "attack_technique": technique,
        "confidence": "high",
        "primary_or_supporting": "primary",
        "alternative_interpretation": (
            "Events may belong to the explicitly labelled synthetic "
            "training simulation rather than real malicious activity."
        ),
        "notes": (
            f"parent_image={o.get('parent_image', '')}; "
            f"evidence_binding={o.get('evidence_binding', '')}; "
            f"marker={o.get('marker', '') or ''}"
        ),
    })


# PCAP POST recovery event
m = json.loads(RECOVERY.read_text())

req = m["http_request"]
loc = m["source"]["exact_locator"]

rows.append({
    "event_id": "pcap-http-post",
    "utc_time": req["observed_utc_from_epoch"],
    "original_time": req["raw_epoch"],
    "source_timezone": "Unix epoch/UTC; offset_applied=+00:00:00",
    "host": req["source_ip"],
    "user": "",
    "activity": (
        f"HTTP POST {req['uri']} to "
        f"{req['host']} ({req['destination_ip']}:{req['destination_port']}); "
        f"{req['content_length']} byte body"
    ),
    "artifact_path": m["source"]["artifact_path"],
    "exact_locator": (
        f"frame {loc['frame_number']}; tcp.stream {loc['tcp_stream']}"
    ),
    "attack_technique": "T1041 Exfiltration Over C2 Channel",
    "confidence": "high",
    "primary_or_supporting": "primary",
    "alternative_interpretation": (
        "The PowerShell artifact describes the activity as a training "
        "simulation sending records to a collector."
    ),
    "notes": (
        f"Recovered archive sha256="
        f"{m['recovery']['archive_sha256']}; "
        f"member_count={m['recovery']['member_count']}"
    ),
})


# PCAP HTTP response event
resp = m.get("http_response")

if resp:
    rows.append({
        "event_id": "pcap-http-response",
        "utc_time": resp["observed_utc_from_epoch"],
        "original_time": resp["raw_epoch"],
        "source_timezone": "Unix epoch/UTC; offset_applied=+00:00:00",
        "host": req["destination_ip"],
        "user": "",
        "activity": (
            f"HTTP response {resp['status_code']} {resp['reason']} "
            f"for recovered archive transfer"
        ),
        "artifact_path": m["source"]["artifact_path"],
        "exact_locator": (
            f"frame {resp['frame_number']}; "
            f"tcp.stream {resp['tcp_stream']}"
        ),
        "attack_technique": "",
        "confidence": "high",
        "primary_or_supporting": "supporting",
        "alternative_interpretation": (
            "A successful HTTP response confirms server acceptance of "
            "the POST body, but does not by itself establish malicious intent."
        ),
        "notes": "Server returned successful creation response.",
    })


rows.sort(
    key=lambda r: (
        parse_z(r["utc_time"]),
        r["event_id"],
    )
)

fields = [
    "event_id",
    "utc_time",
    "original_time",
    "source_timezone",
    "host",
    "user",
    "activity",
    "artifact_path",
    "exact_locator",
    "attack_technique",
    "confidence",
    "primary_or_supporting",
    "alternative_interpretation",
    "notes",
]

with OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

CLOCKS.parent.mkdir(parents=True, exist_ok=True)
CLOCKS.write_text(
    json.dumps(CLOCK_MODEL, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

print("timeline_rows:", len(rows))
print("timeline_path:", OUT)
print("clock_model:", CLOCKS)

print("\n=== NORMALIZED TIMELINE ===")
for r in rows:
    print(
        r["utc_time"],
        "|",
        r["event_id"],
        "|",
        r["activity"]
    )
