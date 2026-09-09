# Stage 9A — Full Incident Response

Candidate: UBI-2026-0246
Variant: V1
Project: SOC-A1
Analytical freeze commit: 5ed6a6a

## Overview

This repository contains the reproducible investigation, timeline reconstruction,
artifact recovery, detection engineering, evidence indexing, and reporting for
Stage 9A Full Incident Response.

Evidence types used:

- Sysmon JSONL
- PowerShell Operational JSONL
- Email evidence
- Network PCAP
- Recovered archive contents

Assigned archive:

- File: soc-analysis-stage-9-shared-b1.tar.gz
- SHA-256: df8fb093a6a69ca885a0f22518f842cf6a470232a6df821fb759a507389f2022
- Manifest signature: aa55207a99e0b259ba498d1191bd324c78fd053e4d6724e3fa96f899700c94fe
- Verified before use: yes

## Environment

- Kali GNU/Linux Rolling 2025.2
- Python 3.13.9
- Git 2.47.2
- TShark 4.4.6
- Zeek: not installed

TShark was used for packet analysis because Zeek was not available in the
analysis environment.

## Evidence Integrity

The sealed evidence contains four artifacts. All four match their expected
sizes and SHA-256 values. No sealed artifact is missing and no mismatch was
detected.

The public fixture suite separately demonstrates rejection of manifest-tampered
input and quarantine of damaged rows.

## Rebuild

Run from the repository root:

    python3 timeline-builder/recover_archive.py
    python3 timeline-builder/build_timeline.py
    python3 timeline-builder/build_case_findings.py
    python3 timeline-builder/build_evidence_index.py
    python3 tests/run_detection_regression.py
    python3 tests/run_detection_on_case.py

## Validation

Public suite:

    python3 timeline-builder/public_suite_runner.py

Result: 12 passed, 0 failed.

Reconstruction:

    python3 tests/test_reconstruction.py

Detection regression:

    python3 tests/run_detection_regression.py

Two-run reproducibility:

    python3 tests/run_reproducibility_check.py

Result: all eight compared outputs were identical across both complete rebuilds.
