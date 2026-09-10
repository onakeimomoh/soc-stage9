# Continuity Record

Candidate: UBI-2026-0246
Variant: V1
Project: SOC-A1
Private assignment set: D1
Private marker: UBI-A9-12824675BE8D
Analytical freeze commit: 5ed6a6a

## Environment

- Kali GNU/Linux Rolling 2025.2
- Python 3.13.9
- Git 2.47.2
- TShark 4.4.6
- Zeek: not installed

## Assigned Evidence

Archive:

soc-analysis-stage-9-shared-b1.tar.gz

SHA-256:

df8fb093a6a69ca885a0f22518f842cf6a470232a6df821fb759a507389f2022

The archive was verified before extraction. All four sealed evidence artifacts
match their expected integrity metadata.

## Reconstruction State

Recovered archive SHA-256:

8e994147097a29a84a1b162cc2aaae6f5592ff135406aaca9c1668d512b98825

Recovered synthetic-record count:

5137

Timeline SHA-256:

f1dca03c35cf28e3814f58141591abc2048f223dfb9d1be793f19860abd7253f

Evidence-index SHA-256:

7b812f9dc92b9641446ef412de5808fece412e6c4a44bdaf9b759d874a3f51b8

IOC-set SHA-256:

58d6667a34c0ca0eff86b108aa94b64b9dbbd7b8a2c71e3f8a5a956d9c28e421

## Clock Model

- Sysmon correction: -23:46:00
- PowerShell correction: +00:00:38
- PCAP: reference clock

The corrections are correlation-derived because direct clock-synchronization
telemetry was not supplied.

## Validation State

Public fixture suite:

- Passed: 12
- Failed: 0

Detection regression:

- Passed: 4
- Failed: 0

Two-run reproducibility:

- Outputs compared: 8
- All outputs identical: true

## Case Disposition

- Email delivery context: confirmed
- Office-to-PowerShell execution sequence: confirmed
- Scheduled-task creation: confirmed
- Archive staging: confirmed
- Technical HTTP transfer: confirmed
- Recovered synthetic records: 5137
- Privilege escalation: not confirmed
- Host-to-host lateral movement: not confirmed
- Malicious intent: not established

The training/synthetic language present in the PowerShell and Sysmon evidence
is retained as the strongest alternative explanation and is not suppressed.

## Handoff

The analytical reconstruction, recovery, evidence indexing, behavioral
detection, regression tests, reproducibility checks, incident report, and
executive brief are complete.

The live-defense recording is complete and its URL is recorded in
video-url.txt. The final submission integrity manifest remains the last
packaging step before submission.
