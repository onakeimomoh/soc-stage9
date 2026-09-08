#!/usr/bin/env python3

import csv
import hashlib
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path

RECOVERY = Path("recovered/recovery-metadata.json")
TIMELINE = Path("timeline.csv")
OUT = Path("evidence/case-findings.json")
IOC = Path("ioc-set.csv")

SYSMON = Path(
    "working/evidence/sealed-evidence/evidence/host/sysmon.jsonl"
)
POWERSHELL = Path(
    "working/evidence/sealed-evidence/evidence/host/powershell-operational.jsonl"
)
EMAIL = Path(
    "working/evidence/sealed-evidence/evidence/mail/initial-access.eml"
)
PCAP = Path(
    "working/evidence/sealed-evidence/evidence/network/incident.pcap"
)


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


recovery = json.loads(RECOVERY.read_text())

# Derive the case binding from source evidence rather than hard-coding it.
powershell_rows = [
    json.loads(line)
    for line in POWERSHELL.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

bindings = {
    str(row.get("binding", "")).strip()
    for row in powershell_rows
    if str(row.get("binding", "")).strip()
}

if len(bindings) != 1:
    raise RuntimeError(
        f"Expected one unique PowerShell evidence binding, found {len(bindings)}"
    )

case_binding = next(iter(bindings))

message = BytesParser(policy=policy.default).parsebytes(
    EMAIL.read_bytes()
)

decoded_email_parts = []

for part in message.walk():
    if part.is_multipart():
        continue

    payload = part.get_payload(decode=True)

    if payload is None:
        text = str(part.get_payload())
    else:
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")

    decoded_email_parts.append(text)

email_decoded_text = "\n".join(decoded_email_parts)

if case_binding not in email_decoded_text:
    raise RuntimeError(
        "Derived PowerShell binding is not present in decoded email content"
    )

with TIMELINE.open(newline="", encoding="utf-8") as f:
    timeline = list(csv.DictReader(f))

events = {r["event_id"]: r for r in timeline}

csv_member = next(
    x for x in recovery["recovery"]["members"]
    if x["name"] == "synthetic-records.csv"
)

marker_member = next(
    x for x in recovery["recovery"]["members"]
    if x["name"] == "evidence-marker.txt"
)

findings = {
    "schema_version": "1",
    "case_binding": case_binding,
    "findings": [
        {
            "question": 1,
            "topic": "initial_access",
            "status": "confirmed",
            "finding": (
                "Case delivery is represented by the email attachment "
                "case-instructions-8d919c5b.txt. Host execution begins with "
                "WINWORD.EXE and is immediately followed by powershell.exe "
                "running Invoke-SyntheticCaseSimulation -Mode Training."
            ),
            "evidence": [
                {
                    "artifact": str(EMAIL),
                    "locator": (
                        "Subject: Case export reconciliation 8d919c5b; "
                        "attachment case-instructions-8d919c5b.txt"
                    ),
                },
                {
                    "artifact": str(SYSMON),
                    "locator": "JSONL lines 50001-50002; attack-01, attack-02",
                },
            ],
        },
        {
            "question": 2,
            "topic": "transfer_infrastructure",
            "status": "confirmed",
            "finding": (
                "The transfer endpoint is "
                "sync-v1.updates-example.invalid:8443 at "
                "203.0.113.195:8443. The confirmed HTTP transfer occurs "
                "between the POST at frame 49 and 201 response at frame 50."
            ),
            "evidence": [
                {
                    "artifact": str(SYSMON),
                    "locator": "JSONL line 50005; attack-05",
                },
                {
                    "artifact": str(PCAP),
                    "locator": "frames 49-50; tcp.stream 0",
                },
            ],
        },
        {
            "question": 3,
            "topic": "privilege_increase",
            "status": "not_confirmed",
            "finding": (
                "No privilege increase is established by the available "
                "case evidence. The six non-noise Sysmon events remain under "
                "northstar\\analyst1 and provide no confirmed administrator, "
                "SYSTEM, token-elevation, or credential-transition evidence."
            ),
            "evidence": [
                {
                    "artifact": str(SYSMON),
                    "locator": "JSONL lines 50001-50006",
                }
            ],
        },
        {
            "question": 4,
            "topic": "lateral_movement",
            "status": "not_confirmed",
            "finding": (
                "No host-to-host lateral movement is established. All six "
                "non-noise case events occur on NS-WKS-101; the confirmed "
                "network activity is toward the transfer endpoint rather "
                "than another internal case host."
            ),
            "evidence": [
                {
                    "artifact": str(SYSMON),
                    "locator": "JSONL lines 50001-50006",
                },
                {
                    "artifact": str(PCAP),
                    "locator": "tcp.stream 0",
                },
            ],
        },
        {
            "question": 5,
            "topic": "data_access_staging_transfer",
            "status": "confirmed",
            "finding": (
                "synthetic-records.csv was staged into case-export.zip and "
                "the exact ZIP body was recovered from the HTTP POST. "
                "The server returned HTTP 201 Created."
            ),
            "evidence": [
                {
                    "artifact": str(SYSMON),
                    "locator": "JSONL line 50004; attack-04",
                },
                {
                    "artifact": str(PCAP),
                    "locator": "frames 49-50; tcp.stream 0",
                },
                {
                    "artifact": str(RECOVERY),
                    "locator": "recovery and http_response objects",
                },
            ],
        },
        {
            "question": 6,
            "topic": "recovered_records",
            "status": "confirmed",
            "finding": (
                f"Recovered synthetic-records.csv contains exactly "
                f"{csv_member['csv_data_records']} data records."
            ),
            "evidence": [
                {
                    "artifact": str(RECOVERY),
                    "locator": (
                        "recovery.members[name=synthetic-records.csv]."
                        "csv_data_records"
                    ),
                }
            ],
        },
        {
            "question": 7,
            "topic": "alternative_hypothesis",
            "status": "confirmed",
            "finding": (
                "The strongest evidence challenging a malicious-incident "
                "interpretation is the PowerShell record explicitly labeling "
                "the activity a training simulation sending synthetic records "
                "to a local collector, reinforced by Sysmon '-Mode Training'."
            ),
            "evidence": [
                {
                    "artifact": str(POWERSHELL),
                    "locator": "JSONL line 1; Event 4104",
                },
                {
                    "artifact": str(SYSMON),
                    "locator": "JSONL line 50002; attack-02",
                },
            ],
        },
    ],
    "recovery_summary": {
        "archive_sha256": recovery["recovery"]["archive_sha256"],
        "archive_size": recovery["recovery"]["archive_size"],
        "member_count": recovery["recovery"]["member_count"],
        "record_count": csv_member["csv_data_records"],
        "csv_sha256": csv_member["sha256"],
        "marker": marker_member["marker_value"],
        "post_frame": recovery["http_request"]["frame_number"],
        "response_frame": recovery["http_response"]["frame_number"],
        "response_code": recovery["http_response"]["status_code"],
    },
    "alternative_hypothesis": {
        "state": "supported",
        "description": (
            "Observed behavior may be an authorized synthetic training "
            "simulation rather than an actual malicious compromise."
        ),
    },
}

OUT.write_text(
    json.dumps(findings, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

ioc_fields = [
    "ioc_id",
    "type",
    "value",
    "first_seen_utc",
    "last_seen_utc",
    "host_or_context",
    "artifact_path",
    "exact_locator",
    "confidence",
    "handling",
    "expiry_or_review_date",
    "false_positive_risk",
]

iocs = [
    {
        "ioc_id": "IOC-001",
        "type": "domain",
        "value": recovery["http_request"]["host"],
        "first_seen_utc": events["attack-05"]["utc_time"],
        "last_seen_utc": recovery["http_response"]["observed_utc_from_epoch"],
        "host_or_context": "NS-WKS-101 transfer endpoint",
        "artifact_path": str(PCAP),
        "exact_locator": "frames 49-50; tcp.stream 0",
        "confidence": "high",
        "handling": "case-scoped indicator; validate context before blocking",
        "expiry_or_review_date": "",
        "false_positive_risk": (
            "high outside this case because evidence labels activity training"
        ),
    },
    {
        "ioc_id": "IOC-002",
        "type": "ipv4",
        "value": recovery["http_request"]["destination_ip"],
        "first_seen_utc": events["attack-05"]["utc_time"],
        "last_seen_utc": recovery["http_response"]["observed_utc_from_epoch"],
        "host_or_context": "NS-WKS-101 transfer endpoint port 8443",
        "artifact_path": str(PCAP),
        "exact_locator": "frames 49-50; tcp.stream 0",
        "confidence": "high",
        "handling": "case-scoped indicator; validate context before blocking",
        "expiry_or_review_date": "",
        "false_positive_risk": (
            "high outside this case because evidence labels activity training"
        ),
    },
    {
        "ioc_id": "IOC-003",
        "type": "sha256",
        "value": recovery["recovery"]["archive_sha256"],
        "first_seen_utc": events["attack-04"]["utc_time"],
        "last_seen_utc": recovery["http_response"]["observed_utc_from_epoch"],
        "host_or_context": "case-export.zip",
        "artifact_path": str(RECOVERY),
        "exact_locator": "recovery.archive_sha256",
        "confidence": "high",
        "handling": "case-specific recovered artifact hash",
        "expiry_or_review_date": "",
        "false_positive_risk": "low for exact artifact; not proof of maliciousness",
    },
]

with IOC.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=ioc_fields)
    w.writeheader()
    w.writerows(iocs)

print("case_findings:", OUT)
print("ioc_set:", IOC)
print("findings:", len(findings["findings"]))
print("iocs:", len(iocs))
