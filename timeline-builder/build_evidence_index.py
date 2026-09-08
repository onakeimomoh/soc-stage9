#!/usr/bin/env python3

import csv
import hashlib
import json
from pathlib import Path

OUT = Path("evidence-index.csv")

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

RECOVERY = Path("recovered/recovery-metadata.json")
RECOVERED_ZIP = Path("recovered/case-export.zip")
RECOVERED_CSV = Path("recovered/extracted/synthetic-records.csv")
TIMELINE = Path("timeline.csv")
CLOCK = Path("evidence/clock-offsets.json")
FINDINGS = Path("evidence/case-findings.json")
ASSIGNMENT = Path("evidence/assignment-context.json")


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def row(
    claim_id,
    report_section,
    claim,
    artifact_path,
    exact_locator,
    proves,
    does_not_prove,
    confidence,
    alternative_considered,
    disposition,
):
    p = Path(artifact_path)

    return {
        "claim_id": claim_id,
        "report_section": report_section,
        "claim": claim,
        "artifact_path": artifact_path,
        "exact_locator": exact_locator,
        "collection_time_utc": "not_provided_in_source",
        "sha256": sha256_file(p),
        "proves": proves,
        "does_not_prove": does_not_prove,
        "confidence": confidence,
        "alternative_considered": alternative_considered,
        "disposition": disposition,
    }


recovery = json.loads(RECOVERY.read_text())
findings = json.loads(FINDINGS.read_text())
assignment = json.loads(ASSIGNMENT.read_text())

csv_member = next(
    x for x in recovery["recovery"]["members"]
    if x["name"] == "synthetic-records.csv"
)
record_count = csv_member["csv_data_records"]

rows = [
    row(
        "Q1-A",
        "Initial Access",
        "Email delivered the case-linked attachment context.",
        str(EMAIL),
        (
            "From: Northstar Support <support-v1@example.invalid>; "
            "To: analyst1@northstar.invalid; "
            "Subject: Case export reconciliation; "
            "attachment case-instructions-*.txt"
        ),
        "The email contains the same evidence binding used by host artifacts.",
        "It does not independently prove the text attachment executed code.",
        "high",
        "The attachment itself contains only binding/marker text.",
        "confirmed_delivery_context",
    ),
    row(
        "Q1-B",
        "Initial Access",
        "WINWORD launched the case execution chain and spawned PowerShell.",
        str(SYSMON),
        "JSONL lines 50001-50002",
        (
            "WINWORD.EXE opened the synthetic case attachment and "
            "powershell.exe followed under the same user/binding."
        ),
        "It does not prove privilege escalation.",
        "high",
        "The sequence may be an authorized training simulation.",
        "confirmed",
    ),
    row(
        "Q2-A",
        "Network Infrastructure",
        "Case-linked network connection targeted the collector endpoint.",
        str(SYSMON),
        "JSONL line 50005",
        "curl.exe connected to sync-v1.updates-example.invalid:8443.",
        "It does not by itself prove malicious command-and-control.",
        "high",
        "Training/local-collector interpretation remains supported.",
        "confirmed",
    ),
    row(
        "Q2-B",
        "Network Infrastructure",
        "The archive was transferred by HTTP POST and accepted by the server.",
        str(PCAP),
        "frames 49-50; tcp.stream 0",
        (
            "Frame 49 carries the archive POST body and frame 50 "
            "returns HTTP 201 Created."
        ),
        "A successful transfer does not establish malicious intent.",
        "high",
        "The endpoint may be an authorized synthetic collector.",
        "confirmed",
    ),
    row(
        "Q3",
        "Privilege",
        "No privilege increase is confirmed in the case evidence.",
        str(SYSMON),
        "JSONL lines 50001-50006",
        (
            "All six non-noise case events remain under "
            "northstar\\analyst1 with no demonstrated identity transition."
        ),
        (
            "Absence in the supplied telemetry cannot prove that elevation "
            "was impossible outside the evidence set."
        ),
        "high",
        "Scheduled-task creation alone was considered but rejected as proof.",
        "not_confirmed",
    ),
    row(
        "Q4",
        "Lateral Movement",
        "No host-to-host lateral movement is confirmed.",
        str(SYSMON),
        "JSONL lines 50001-50006",
        "All six non-noise case events occur on NS-WKS-101.",
        (
            "This does not prove no movement occurred outside the supplied "
            "telemetry."
        ),
        "high",
        (
            "The collector connection was considered but is not evidence "
            "of internal host-to-host movement."
        ),
        "not_confirmed",
    ),
    row(
        "Q5-A",
        "Data Staging",
        "synthetic-records.csv was staged into case-export.zip.",
        str(SYSMON),
        "JSONL line 50004",
        "tar.exe created case-export.zip from synthetic-records.csv.",
        "The process event alone does not prove successful transfer.",
        "high",
        "Could be authorized training activity.",
        "confirmed",
    ),
    row(
        "Q5-B",
        "Data Transfer",
        "The staged ZIP was successfully transferred.",
        str(RECOVERY),
        "http_request, http_response, recovery objects",
        (
            "Recovered POST body is a valid ZIP matching the HTTP "
            "Content-Length and the server returned 201 Created."
        ),
        "It does not prove malicious intent.",
        "high",
        "Authorized simulation remains plausible.",
        "confirmed",
    ),
    row(
        "Q6",
        "Impact / Recovery",
        f"Recovered CSV contains exactly {record_count} data records.",
        str(RECOVERED_CSV),
        "CSV header plus all recovered data rows",
        f"Exact recovered synthetic record count is {record_count}.",
        "It does not prove real customer data was involved.",
        "high",
        "Artifact names and script text explicitly describe synthetic records.",
        "confirmed",
    ),
    row(
        "Q7-A",
        "Alternative Hypothesis",
        "PowerShell explicitly labels the activity a training simulation.",
        str(POWERSHELL),
        "JSONL line 1; Event 4104",
        (
            "Script block states training simulation and sending synthetic "
            "records to the local collector."
        ),
        "It does not negate the fact that the technical transfer occurred.",
        "high",
        "Primary malicious-compromise hypothesis is materially weakened.",
        "confirmed",
    ),
    row(
        "CLOCK-1",
        "Timeline Reconstruction",
        "Sysmon timestamps require a -23:46:00 normalization.",
        str(CLOCK),
        "sysmon.offset_seconds_applied",
        "Documents the correlation-derived Sysmon clock correction.",
        "It is not direct NTP/system-clock telemetry.",
        "high",
        "Uncorrected Sysmon timing was rejected as inconsistent with PCAP.",
        "confirmed",
    ),
    row(
        "CLOCK-2",
        "Timeline Reconstruction",
        "PowerShell timestamps require a +00:00:38 normalization.",
        str(CLOCK),
        "powershell.offset_seconds_applied",
        "Documents the second independent source-clock correction.",
        "It is not direct operating-system clock metadata.",
        "high",
        "Zero correction was considered and rejected after correlation.",
        "confirmed",
    ),
    row(
        "RECOVERY-1",
        "Recovery",
        "Recovered archive identity is fixed by SHA-256.",
        str(RECOVERED_ZIP),
        "entire file",
        (
            "Provides exact cryptographic identity of the reconstructed "
            "case-export.zip."
        ),
        "A hash alone does not establish maliciousness.",
        "high",
        "None",
        "confirmed",
    ),
    row(
        "SETUP-1",
        "Assessment Setup",
        "Private assignment marker is present in final evidence.",
        str(ASSIGNMENT),
        "private_marker",
        (
            f"Records intern {assignment['intern_id']}, variant "
            f"{assignment['variant']}, assignment set "
            f"{assignment['private_assignment_set']}, and private marker."
        ),
        "It does not provide incident-behavior evidence.",
        "high",
        "None",
        "confirmed",
    ),
]

fields = [
    "claim_id",
    "report_section",
    "claim",
    "artifact_path",
    "exact_locator",
    "collection_time_utc",
    "sha256",
    "proves",
    "does_not_prove",
    "confidence",
    "alternative_considered",
    "disposition",
]

with OUT.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)

print("evidence_index:", OUT)
print("rows:", len(rows))
print("private_marker:", assignment["private_marker"])
