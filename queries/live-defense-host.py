#!/usr/bin/env python3

import json
import re
from pathlib import Path

ps_path = Path("working/evidence/sealed-evidence/evidence/host/powershell-operational.jsonl")
sysmon_path = Path("working/evidence/sealed-evidence/evidence/host/sysmon.jsonl")

# Derive the case binding from the supplied PowerShell evidence.
binding = None

with ps_path.open(encoding="utf-8-sig") as f:
    for line in f:
        if not line.strip():
            continue

        event = json.loads(line)

        text = json.dumps(event, ensure_ascii=False)
        match = re.search(r"\b[0-9a-fA-F]{16}\b", text)

        if match:
            binding = match.group(0)
            break

if not binding:
    raise SystemExit("ERROR: no case binding derived from PowerShell evidence")

print(f"Derived case binding: {binding}")
print()
print("Matching raw Sysmon events:")
print("=" * 80)

matches = 0

with sysmon_path.open(encoding="utf-8-sig") as f:
    for line_number, line in enumerate(f, start=1):
        if not line.strip():
            continue

        if binding.lower() not in line.lower():
            continue

        event = json.loads(line)
        matches += 1

        print(f"JSONL line: {line_number}")
        print(json.dumps(event, indent=2, ensure_ascii=False))
        print("-" * 80)

print(f"Total matching Sysmon events: {matches}")
