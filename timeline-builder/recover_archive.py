#!/usr/bin/env python3

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_tshark(pcap: Path, fields):
    cmd = [
        "tshark",
        "-r", str(pcap),
        "-Y", 'http.request.method == "POST"',
        "-T", "fields",
        "-E", "separator=\t",
    ]
    for field in fields:
        cmd += ["-e", field]

    result = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
    )

    return [line for line in result.stdout.splitlines() if line.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--pcap",
        default="working/evidence/sealed-evidence/evidence/network/incident.pcap",
    )
    ap.add_argument(
        "--archive",
        default="recovered/case-export.zip",
    )
    ap.add_argument(
        "--extract-dir",
        default="recovered/extracted",
    )
    ap.add_argument(
        "--metadata",
        default="recovered/recovery-metadata.json",
    )
    args = ap.parse_args()

    pcap = Path(args.pcap)
    archive = Path(args.archive)
    extract_dir = Path(args.extract_dir)
    metadata_path = Path(args.metadata)

    errors = []
    warnings = []

    fields = [
        "frame.number",
        "frame.time_epoch",
        "tcp.stream",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.content_length",
        "http.file_data",
    ]

    lines = run_tshark(pcap, fields)

    if len(lines) != 1:
        raise RuntimeError(
            f"Expected exactly one HTTP POST, found {len(lines)}"
        )

    parts = lines[0].split("\t")
    if len(parts) != len(fields):
        raise RuntimeError(
            f"Unexpected tshark field count: {len(parts)} != {len(fields)}"
        )

    row = dict(zip(fields, parts))

    hex_body = "".join(
        c for c in row["http.file_data"]
        if c not in " :\r\n\t"
    )

    try:
        body = bytes.fromhex(hex_body)
    except ValueError as e:
        raise RuntimeError(f"POST body is not valid hexadecimal: {e}")

    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(body)

    advertised_length = int(row["http.content_length"])
    actual_length = len(body)

    if actual_length != advertised_length:
        errors.append(
            f"HTTP Content-Length {advertised_length} "
            f"does not match recovered body {actual_length}"
        )

    if not zipfile.is_zipfile(archive):
        errors.append("Recovered POST body is not a valid ZIP archive")

    members = []

    if not errors:
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True)

        with zipfile.ZipFile(archive) as zf:
            bad_member = zf.testzip()
            if bad_member:
                errors.append(f"ZIP integrity failure: {bad_member}")
            else:
                zf.extractall(extract_dir)

            for info in sorted(zf.infolist(), key=lambda x: x.filename):
                if info.is_dir():
                    continue

                path = extract_dir / info.filename

                member = {
                    "name": info.filename,
                    "compressed_size": info.compress_size,
                    "uncompressed_size": info.file_size,
                    "sha256": sha256_file(path),
                }

                if info.filename.lower().endswith(".csv"):
                    with path.open(
                        newline="",
                        encoding="utf-8-sig"
                    ) as f:
                        reader = csv.DictReader(f)
                        records = list(reader)

                    member["csv_columns"] = reader.fieldnames
                    member["csv_data_records"] = len(records)

                if info.filename == "evidence-marker.txt":
                    member["marker_value"] = (
                        path.read_text(encoding="utf-8").strip()
                    )

                members.append(member)

    epoch = row["frame.time_epoch"]
    observed_utc = datetime.fromtimestamp(
        float(epoch),
        tz=timezone.utc
    ).isoformat().replace("+00:00", "Z")

    metadata = {
        "schema_version": "1",
        "source": {
            "artifact_path": str(pcap),
            "sha256": sha256_file(pcap),
            "exact_locator": {
                "frame_number": int(row["frame.number"]),
                "tcp_stream": int(row["tcp.stream"]),
            },
        },
        "http_request": {
            "frame_number": int(row["frame.number"]),
            "raw_epoch": epoch,
            "observed_utc_from_epoch": observed_utc,
            "source_ip": row["ip.src"],
            "source_port": int(row["tcp.srcport"]),
            "destination_ip": row["ip.dst"],
            "destination_port": int(row["tcp.dstport"]),
            "method": row["http.request.method"],
            "host": row["http.host"],
            "uri": row["http.request.uri"],
            "content_length": advertised_length,
        },
        "recovery": {
            "archive_path": str(archive),
            "archive_size": actual_length,
            "archive_sha256": sha256_file(archive),
            "content_length_match": actual_length == advertised_length,
            "zip_valid": zipfile.is_zipfile(archive),
            "member_count": len(members),
            "members": members,
        },
        "parser_status": "ok" if not errors else "error",
        "warnings": warnings,
        "errors": errors,
    }

    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(metadata, indent=2, sort_keys=True))

    if errors:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
