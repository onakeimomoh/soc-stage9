# Response Playbook — Office PowerShell Archive Egress

## Trigger

Use this playbook when `DETECT-OFFICE-PS-ARCHIVE-EGRESS` fires.

## Initial validation

1. Confirm the three-stage sequence:
   - Office application spawned PowerShell.
   - Archive utility staged data.
   - Command-line process initiated network egress.

2. Confirm the sequence occurred:
   - on the same host,
   - under the same user,
   - in chronological order,
   - within the configured correlation window.

3. Review command details, destination context, and any available packet,
   proxy, EDR, or file telemetry.

## Containment

If the activity is unauthorized or malicious:
- isolate the affected endpoint from the network;
- block or sinkhole the destination only after validating scope and business impact;
- disable or restrict the affected account if credential compromise is suspected;
- preserve volatile and endpoint evidence before destructive remediation where feasible;
- stop scheduled or recurring execution mechanisms associated with the activity.

If the activity is confirmed authorized:
- document the business/training justification;
- tune only with specific, defensible allow-list conditions;
- do not broadly suppress Office-to-PowerShell behavior.

## Eradication

Where malicious activity is confirmed:
- remove unauthorized scheduled tasks or persistence;
- remove staged archives and malicious scripts after evidence preservation;
- rotate exposed credentials;
- remove unauthorized tooling;
- identify and remediate the original execution vector.

## Recovery

- restore the endpoint to trusted operational state;
- re-enable network access only after validation;
- monitor the affected user and host for recurrence;
- validate that persistence and transfer behavior no longer occurs.

## Detection follow-up

Retain the generic behavioral correlation.

Recommended enrichment:
- destination reputation/context;
- archive filename and source path;
- signed/unsigned process metadata;
- Office document provenance;
- user baseline;
- proxy or packet confirmation of upload volume.

## False-positive considerations

Legitimate administrative or training activity may produce similar behavior.

A high-confidence alert should not automatically be treated as proof of malicious
intent. Analysts must distinguish:
- technical behavior,
- authorization,
- business context,
- and malicious intent.

For the supplied Stage 9 case, the PowerShell evidence explicitly identifies the
activity as a training simulation involving synthetic records and a local collector.
This materially weakens the malicious-compromise hypothesis while leaving the
technical transfer itself confirmed.
