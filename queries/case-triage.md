# Stage 9 Case Triage Queries

## Purpose

These queries are intended to validate the correlated behavioral sequence detected by
`DETECT-OFFICE-PS-ARCHIVE-EGRESS` without relying on case-specific event IDs,
private markers, bindings, domains, IP addresses, or record counts.

## Query 1 — Office spawning PowerShell

Search for process-start events where PowerShell or PowerShell Core is spawned by
a Microsoft Office parent.

Pseudo-query:

event_type = "process_start"
AND image IN ("powershell.exe", "pwsh.exe")
AND parent_image IN (
  "winword.exe",
  "excel.exe",
  "powerpnt.exe",
  "outlook.exe"
)

Analyst validation:
- confirm host
- confirm user
- review command or process detail
- determine whether the activity is expected automation or user-driven execution

## Query 2 — Archive creation shortly after PowerShell

Search the same host and user for archive utilities shortly after the Office-to-
PowerShell event.

Pseudo-query:

event_type = "process_start"
AND image IN (
  "tar.exe",
  "7z.exe",
  "7za.exe",
  "rar.exe"
)

Correlate within 120 seconds of Query 1.

Analyst validation:
- identify archive name
- identify source files/directories
- determine whether the archive is expected for the user's role
- locate matching file-write telemetry where available

## Query 3 — Command-line network egress

Search the same host and user for command-line transfer tools following archive
staging.

Pseudo-query:

event_type = "network_connect"
AND image IN (
  "curl.exe",
  "powershell.exe",
  "pwsh.exe"
)

Correlate within 120 seconds of the initial Office-to-PowerShell event.

Analyst validation:
- destination hostname
- destination IP
- destination port
- protocol
- whether the destination is internal, approved, or external
- whether PCAP/proxy telemetry confirms content transfer

## Query 4 — Privilege transition check

Search the correlated host and user for evidence of identity or privilege change.

Look for:
- SYSTEM execution
- administrator context
- runas
- token elevation
- credential use
- service creation associated with elevated execution
- explicit logon/session changes

Do not classify scheduled-task creation alone as privilege escalation.

## Query 5 — Lateral movement check

Search for communication from the affected host to other internal hosts using
remote-management or administrative mechanisms.

Look for:
- SMB
- WinRM
- RDP
- PsExec
- WMI
- remote service creation
- administrative shares
- explicit remote logons

External collector communication is not, by itself, lateral movement.

## Case-specific disposition

For the supplied Stage 9 evidence:
- Office-to-PowerShell behavior is confirmed.
- Archive staging is confirmed.
- Network egress is confirmed.
- Exact HTTP POST transfer is confirmed from PCAP reconstruction.
- Privilege increase is not confirmed.
- Host-to-host lateral movement is not confirmed.
- Evidence explicitly labels the activity as a synthetic training simulation,
  so malicious intent remains challenged despite the confirmed technical transfer.
