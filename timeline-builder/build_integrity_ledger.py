#!/usr/bin/env python3
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path.home() / "soc-stage9"
SEALED = ROOT / "working/evidence/sealed-evidence"
MANIFEST = SEALED / "case-manifest.csv"
OUT = ROOT / "evidence/integrity-ledger.json"

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

rows = []

with MANIFEST.open(newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)

    for row in reader:
        artifact = row["artifact"].strip()
        expected_size = int(row["size"].strip())
        expected_sha256 = row["sha256"].strip()

        path = SEALED / artifact

        record = {
            "artifact": artifact,
            "path": str(path.relative_to(ROOT)),
            "expected_size": expected_size,
            "expected_sha256": expected_sha256,
            "exists": path.exists(),
            "actual_size": None,
            "actual_sha256": None,
            "size_match": False,
            "hash_match": False,
            "verdict": "missing"
        }

        if path.exists():
            actual_size = path.stat().st_size
            actual_sha256 = sha256_file(path)

            record["actual_size"] = actual_size
            record["actual_sha256"] = actual_sha256
            record["size_match"] = actual_size == expected_size
            record["hash_match"] = actual_sha256 == expected_sha256

            if record["size_match"] and record["hash_match"]:
                record["verdict"] = "match"
            else:
                record["verdict"] = "tampered_or_mismatch"

        rows.append(record)

summary = {
    "total": len(rows),
    "match": sum(r["verdict"] == "match" for r in rows),
    "tampered_or_mismatch": sum(r["verdict"] == "tampered_or_mismatch" for r in rows),
    "missing": sum(r["verdict"] == "missing" for r in rows)
}

report = {
    "schema_version": "1.0",
    "manifest": str(MANIFEST.relative_to(ROOT)),
    "artifacts": rows,
    "summary": summary
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(report, indent=2) + "\n")

print(json.dumps(summary))
