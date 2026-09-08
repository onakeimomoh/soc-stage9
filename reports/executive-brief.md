# Executive Incident Brief

## Summary

The investigation confirmed a short sequence on workstation `NS-WKS-101` involving an Office process, PowerShell, scheduled-task creation, archive staging, command-line network transfer, and deletion of the staged archive.

Network evidence confirms that a 53,891-byte ZIP archive was transmitted over HTTP to a collector endpoint and accepted with an HTTP `201 Created` response.

The archive was reconstructed successfully and contained exactly 5,137 synthetic records.

## Business Impact

The supplied evidence confirms transfer of synthetic case records.

No evidence confirms:
- privilege escalation;
- lateral movement;
- credential compromise;
- transfer of real production customer data.

The recovered data is explicitly synthetic.

## Key Assessment

The activity resembles attacker tradecraft and would warrant urgent investigation if observed unexpectedly in a production environment.

However, the strongest evidence explicitly identifies the activity as a training simulation:

`Training simulation: archive synthetic records and send them to the local collector.`

The PowerShell command also uses:

`-Mode Training`

Therefore:

- Technical data transfer: confirmed
- Malicious intent: not established
- Privilege escalation: not confirmed
- Lateral movement: not confirmed

## Confirmed Sequence

1. Office-associated attachment activity
2. PowerShell execution
3. Scheduled-task creation
4. ZIP archive staging
5. Command-line network connection
6. HTTP POST of the archive
7. Local archive deletion
8. HTTP `201 Created` response

## Recovered Data

Recovered records: `5,137`

Archive SHA-256:

`8e994147097a29a84a1b162cc2aaae6f5592ff135406aaca9c1668d512b98825`

## Detection Coverage

A generic behavioral rule was developed for:

Office → PowerShell → archive staging → command-line egress

The rule passed all positive and negative regression fixtures and also alerted on the supplied case evidence.

## Recommended Action

For a real production alert with the same behavior:

- isolate the host if activity is unauthorized;
- preserve endpoint and network evidence;
- validate the Office document and user action;
- review and remove unauthorized scheduled tasks;
- identify staged archives and transfer destinations;
- investigate account compromise;
- hunt for the same sequence across other endpoints;
- retain the behavioral detection with narrowly scoped allow-listing for approved automation or training.

## Executive Conclusion

The technical behavior is fully reconstructed and reproducible.

The evidence confirms data staging and transfer, but the strongest-supported interpretation is a synthetic training exercise rather than a malicious incident.
