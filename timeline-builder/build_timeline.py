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
# The case-correlated Sysmon curl network connection occurs at
# 2026-07-15T11:46:49Z, while the matching PCAP HTTP POST occurs at
# 2026-07-14T12:00:49.049Z.
#
# The matching transfer behavior, destination context, and case binding
# support a Sysmon clock correction of -23h46m.
CLOCK_MODEL = {
    "sysmon": {
        "offset_seconds_applied": -(23 * 3600 + 46 * 60),
        "basis": (
            "Correlated Sysmon curl network connection with the "
            "matching PCAP HTTP POST using destination context and "
            "the same case binding."
        ),
        "confidence": "high",
    },
    "powershell": {
        "offset_seconds_applied": 38,
        "basis": (
            "Correlated PowerShell Event 4104 with the matching "
            "Sysmon PowerShell process execution using script context "
            "and the same evidence binding. After Sysmon normalization, "
            "the process event is 2026-07-14T12:00:42Z; PowerShell "
            "reports 2026-07-14T12:00:04Z."
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

# Derive the case correlation binding from the PowerShell evidence rather
# than embedding a case-specific value in the timeline builder.
powershell_rows = [
    (line_no, json.loads(line))
    for line_no, line in enumerate(POWERSHELL.open(), 1)
    if line.strip()
]

case_bindings = {
    str(o.get("binding", "")).strip()
    for _, o in powershell_rows
    if str(o.get("binding", "")).strip()
}

if len(case_bindings) != 1:
    raise RuntimeError(
        "Expected exactly one unique non-empty PowerShell evidence binding; "
        f"found {len(case_bindings)}"
    )

case_binding = next(iter(case_bindings))

# PowerShell
for line_no, o in powershell_rows:

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

    if o.get("evidence_binding") != case_binding:
        continue

    raw = o["timestamp"]
    corr = corrected(raw, "sysmon")

    technique = ""

    event_type = str(o.get("event_type", "")).lower()
    image_name = (
        str(o.get("image", ""))
        .replace("\\", "/")
        .rsplit("/", 1)[-1]
        .lower()
    )
    detail_lower = str(o.get("detail", "")).lower()

    if event_type == "scheduled_task_create":
        technique = "T1053.005 Scheduled Task/Job: Scheduled Task"

    elif (
        event_type == "process_start"
        and (
            image_name in {"tar.exe", "7z.exe", "7za.exe", "rar.exe"}
            or "archive" in detail_lower
        )
    ):
        technique = "T1560 Archive Collected Data"

    elif (
        event_type == "network_connect"
        and image_name in {"curl.exe", "powershell.exe", "pwsh.exe"}
    ):
        technique = (
            "T1041 Exfiltration Over C2 Channel "
            "(behavioral mapping; malicious intent not established)"
        )

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
    "attack_technique": (
        "T1041 Exfiltration Over C2 Channel "
        "(behavioral mapping; malicious intent not established)"
    ),
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
