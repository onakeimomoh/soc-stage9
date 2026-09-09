# Integrity Attestation

Candidate: UBI-2026-0246
Variant: V1
Private assignment set: D1
Private marker: UBI-A9-12824675BE8D
Analytical freeze commit: 5ed6a6a

## Evidence Handling

I verified the assigned archive before extraction and analysis.

Assigned archive:

- File: soc-analysis-stage-9-shared-b1.tar.gz
- Size: 2723254 bytes
- SHA-256: df8fb093a6a69ca885a0f22518f842cf6a470232a6df821fb759a507389f2022
- Manifest signature: aa55207a99e0b259ba498d1191bd324c78fd053e4d6724e3fa96f899700c94fe

I retained a separate copy of the original assigned archive outside the
working analysis tree.

I independently verified the sealed evidence against its supplied integrity
metadata.

Results:

- Total artifacts: 4
- Matching artifacts: 4
- Tampered or mismatched: 0
- Missing: 0

I found no hash mismatch in the actual sealed case evidence.

The public manifest-tamper fixture separately demonstrates that tampered input
is rejected. The damaged-row fixture demonstrates quarantine of malformed
input. I do not claim that the actual sealed case evidence was tampered with.

## Reproducibility

I executed the complete reconstruction pipeline twice and cryptographically
compared eight generated outputs between the two runs.

Results:

- Outputs compared: 8
- Identical outputs: 8
- Non-identical outputs: 0
- all_outputs_identical: true

The reconstruction checks and evidence locators derive case-specific values
from the supplied artifacts rather than embedding private expected answers.

## Investigation Accuracy

I distinguish observed technical behavior from conclusions about intent.

The evidence confirms archive staging and technical HTTP transfer.

The supplied evidence does not confirm privilege escalation.

The supplied evidence does not confirm host-to-host lateral movement.

The PowerShell and Sysmon evidence explicitly describe training/synthetic
activity. I therefore do not assert malicious intent as an established fact.

## AI Assistance Declaration

I used OpenAI ChatGPT as a supporting tool during this project, including
assistance with troubleshooting and documentation.

I executed and validated the commands and analysis workflows used for this
submission in my own environment. I verified the findings and conclusions
against the supplied evidence and reproducible project outputs.

I remain responsible for the investigation, interpretation, and final
submitted work.
