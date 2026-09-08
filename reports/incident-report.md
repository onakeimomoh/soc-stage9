# Incident Report

## Case Identification

- Intern ID: UBI-2026-0246
- Variant: V1
- Private assignment set: D1
- Private marker: UBI-A9-12824675BE8D
- Case type: Full Incident Response
- Evidence set: soc-analysis-stage-9-shared-b1.tar.gz

## Executive Summary

The supplied evidence confirms a short sequence in which an Office process was followed by PowerShell execution, scheduled-task creation, archive staging, command-line network communication, an HTTP POST containing the staged archive, deletion of the local archive, and an HTTP 201 response.

The recovered HTTP POST body reconstructed successfully as a valid ZIP archive containing 5,137 synthetic data records and an evidence marker. The reconstructed archive SHA-256 is:

`8e994147097a29a84a1b162cc2aaae6f5592ff135406aaca9c1668d512b98825`

The technical transfer is confirmed. However, the supplied PowerShell telemetry explicitly describes the action as a training simulation involving synthetic records and a local collector, and the Sysmon PowerShell command includes `-Mode Training`. Therefore, the evidence supports the occurrence of the technical behavior but does not establish malicious intent.

Privilege escalation is not confirmed. Host-to-host lateral movement is not confirmed.

## Scope and Evidence Reviewed

The analysis used the following evidence types:

1. PowerShell Operational JSONL
2. Sysmon JSONL
3. Email message and attachment
4. Network PCAP
5. Recovered archive and extracted CSV content

The sealed evidence manifest was independently verified. All four sealed source artifacts matched their expected SHA-256 values.

## Integrity and Reproducibility

The original assignment archive was verified before extraction.

Archive SHA-256:

`df8fb093a6a69ca885a0f22518f842cf6a470232a6df821fb759a507389f2022`

A streaming integrity ledger independently validated the sealed source evidence.

The reconstruction pipeline was executed twice. Eight generated outputs were compared by SHA-256 and all outputs were identical across both runs.

See:
- `evidence/integrity-ledger.json`
- `tests/reproducibility-results.json`

## Clock Normalization

The supplied evidence does not contain explicit authoritative clock-offset metadata.

Two correlation-derived offsets were applied:

### Sysmon

Applied correction: `-23:46:00`

Basis: the case-correlated Sysmon curl network event aligns with the PCAP HTTP POST using transfer behavior, destination context, and the same evidence binding.

Confidence: high.

### PowerShell

Applied correction: `+00:00:38`

Basis: the PowerShell Event 4104 script block aligns with the corresponding Sysmon PowerShell execution using script context and the same evidence binding.

Confidence: high.

PCAP epoch timestamps were used as the reference network timebase.

Full model: `evidence/clock-offsets.json`

## Reconstructed Timeline

The parser-generated normalized timeline contains nine events.

### 2026-07-14T12:00:41Z

`WINWORD.EXE` opened the synthetic case attachment.

Evidence:
`host/sysmon.jsonl`, JSONL line 50001.

### 2026-07-14T12:00:42Z

`WINWORD.EXE` spawned `powershell.exe`.

Command detail:

`Invoke-SyntheticCaseSimulation -Mode Training`

Evidence:
`host/sysmon.jsonl`, JSONL line 50002.

### 2026-07-14T12:00:42Z

PowerShell Event 4104 recorded:

`Training simulation: archive synthetic records and send them to the local collector.`

Evidence:
`host/powershell-operational.jsonl`, JSONL line 1.

### 2026-07-14T12:00:45Z

A scheduled task named `Northstar Support Sync` was created through `schtasks.exe`.

Behavioral ATT&CK mapping:
T1053.005 — Scheduled Task/Job: Scheduled Task.

Evidence:
`host/sysmon.jsonl`, JSONL line 50003.

### 2026-07-14T12:00:46Z

`tar.exe` created:

`case-export.zip`

from:

`synthetic-records.csv`

Behavioral ATT&CK mapping:
T1560 — Archive Collected Data.

Evidence:
`host/sysmon.jsonl`, JSONL line 50004.

### 2026-07-14T12:00:49Z

`curl.exe` initiated a network connection to:

`sync-v1.updates-example.invalid:8443`

Behavioral ATT&CK mapping:
T1041 — Exfiltration Over C2 Channel.

This is a behavioral mapping only; malicious C2 intent is not established.

Evidence:
`host/sysmon.jsonl`, JSONL line 50005.

### 2026-07-14T12:00:49.049000Z

PCAP frame 49 recorded an HTTP POST to:

`/collect/8d919c5bfb955d01/case-export.zip`

Destination:
- Host: `sync-v1.updates-example.invalid`
- IP: `203.0.113.195`
- Port: `8443`
- TCP stream: `0`
- Content-Length: `53891`

The POST body was reconstructed into a valid ZIP archive.

Evidence:
`network/incident.pcap`, frame 49, TCP stream 0.

### 2026-07-14T12:00:50Z

PowerShell deleted:

`case-export.zip`

Evidence:
`host/sysmon.jsonl`, JSONL line 50006.

### 2026-07-14T12:00:50.050000Z

The server returned:

`HTTP 201 Created`

Evidence:
`network/incident.pcap`, frame 50, TCP stream 0.

## Initial Access and Execution

The email artifact was sent from:

`Northstar Support <support-v1@example.invalid>`

to:

`analyst1@northstar.invalid`

with subject:

`Case export reconciliation 8d919c5b`

The attachment was:

`case-instructions-8d919c5b.txt`

The decoded attachment contained the case evidence binding and marker.

The evidence supports delivery context through email.

The evidence does not prove that the `.txt` attachment itself executed. Host telemetry instead shows `WINWORD.EXE` opening the synthetic case attachment and then spawning PowerShell.

Disposition: confirmed delivery context and confirmed subsequent execution chain.

## Persistence

A scheduled task named:

`Northstar Support Sync`

was created shortly after PowerShell execution.

This is consistent with scheduled-task persistence behavior.

Disposition: confirmed scheduled-task creation.

The evidence does not establish whether the task later executed.

## Privilege Escalation

No supplied case-correlated evidence confirms:

- SYSTEM execution
- administrator token use
- privilege transition
- explicit elevation
- credential theft
- elevated remote service execution

Scheduled-task creation alone is insufficient to establish privilege escalation.

Disposition: not confirmed.

## Lateral Movement

All six case-correlated Sysmon events occur on:

`NS-WKS-101`

No supplied case-correlated evidence confirms movement to another internal host through SMB, RDP, WinRM, WMI, PsExec, remote services, or administrative shares.

The external/collector network connection is not lateral movement.

Disposition: not confirmed.

## Data Staging

The evidence confirms archive staging through:

`tar -a -c -f case-export.zip synthetic-records.csv`

Disposition: confirmed.

## Data Transfer

The evidence confirms a technical transfer.

Supporting evidence:

1. Sysmon records `curl.exe` network communication.
2. PCAP records an HTTP POST with a 53,891-byte body.
3. The POST body reconstructs into a valid ZIP.
4. The ZIP contains the expected synthetic records and evidence marker.
5. The server returned HTTP `201 Created`.

Disposition: confirmed technical transfer.

The evidence does not establish malicious intent because the PowerShell telemetry explicitly labels the action as a training simulation sending synthetic records to a local collector.

## Recovery and Impact

Recovered archive:

`recovered/case-export.zip`

SHA-256:

`8e994147097a29a84a1b162cc2aaae6f5592ff135406aaca9c1668d512b98825`

Recovered members:

- `synthetic-records.csv`
- `evidence-marker.txt`

The CSV contains exactly:

`5,137`

data records excluding the header.

The recovered marker is:

`UBI-A9-SHARED-B1`

Disposition: archive reconstruction and record recovery confirmed.

## Indicators of Interest

### Domain

`sync-v1.updates-example.invalid`

### IPv4

`203.0.113.195`

### Recovered archive SHA-256

`8e994147097a29a84a1b162cc2aaae6f5592ff135406aaca9c1668d512b98825`

These values should be treated as case-scoped indicators. The evidence itself identifies the activity as synthetic/training, so they should not be globally classified as malicious based on this case alone.

Full IOC set:
`ioc-set.csv`

## Detection Engineering

A generic behavioral detection was created for:

Office → PowerShell → archive staging → command-line network egress

Rule:

`DETECT-OFFICE-PS-ARCHIVE-EGRESS`

The detector does not rely on the private marker, case binding, exact event IDs, domain, IP address, or recovered-record count.

Regression results:

- positive fixture: pass
- benign administrative archive fixture: pass
- different-user correlation fixture: pass
- outside-window fixture: pass

Total: 4/4 passed.

The same generic detector was run against the real case-correlated Sysmon events and alerted successfully.

Matched sequence:

- `powershell.exe <- WINWORD.EXE`
- `tar.exe <- powershell.exe`
- `curl.exe <- powershell.exe`

Elapsed correlation time: 7 seconds.

## Competing Hypotheses

### Hypothesis 1 — Malicious compromise with data exfiltration

Evidence supporting:
- Office-to-PowerShell execution chain
- scheduled-task creation
- archive staging
- command-line transfer utility
- HTTP POST of staged archive
- local archive deletion

Evidence challenging:
- PowerShell explicitly labels the activity a training simulation
- command includes `-Mode Training`
- transferred data is synthetic
- destination is described as a local collector
- no privilege escalation confirmed
- no lateral movement confirmed

Assessment:
Technically plausible from behavior alone, but malicious intent is not established.

### Hypothesis 2 — Authorized synthetic training simulation

Evidence supporting:
- PowerShell Event 4104 explicitly identifies a training simulation
- PowerShell command uses `-Mode Training`
- transferred records are synthetic
- recovered marker identifies a training evidence set
- behavior occurs in a short, internally consistent sequence

Evidence challenging:
- the behavior intentionally resembles real attacker tradecraft
- scheduled-task creation, staging, transfer, and deletion would warrant investigation in a production environment

Assessment:
Best-supported interpretation of the supplied evidence.

## Response Recommendations

If this pattern occurs in a live environment without confirmed authorization:

1. Isolate the affected endpoint.
2. Preserve volatile and endpoint evidence.
3. Validate the Office document source and user action.
4. Review the scheduled task and disable it if unauthorized.
5. Identify and preserve any staged archives before deletion.
6. Block or contain the destination after validating business impact.
7. Review account activity and reset credentials if compromise is suspected.
8. Hunt for the same behavioral sequence across other hosts.
9. Review proxy, EDR, DNS, and network telemetry for additional transfers.
10. Do not suppress the detection broadly; use narrowly scoped allow-list conditions for approved training or automation.

## Analytical Limitations

The supplied evidence set does not establish:
- whether activity occurred outside the evidence window;
- whether credentials were compromised;
- whether the scheduled task later executed;
- whether privilege escalation occurred outside supplied telemetry;
- whether lateral movement occurred outside supplied telemetry;
- whether the collector infrastructure should be considered malicious outside this synthetic case.

Absence of evidence in the supplied dataset is not proof that an activity was impossible.

## Final Assessment

The evidence confirms a complete technical chain from document-associated execution through PowerShell, scheduled-task creation, archive staging, outbound transfer, archive reconstruction, and post-transfer deletion.

The transferred ZIP was reconstructed exactly and contains 5,137 synthetic records.

The strongest-supported interpretation is an authorized or synthetic training simulation rather than a real malicious compromise, because the evidence explicitly labels the activity as training and synthetic.

Technical transfer: confirmed.

Malicious exfiltration intent: not established.

Privilege escalation: not confirmed.

Lateral movement: not confirmed.
