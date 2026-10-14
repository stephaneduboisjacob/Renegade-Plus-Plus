#!/usr/bin/env python3
"""Create a read-only inventory of a legacy Renegade data directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

KNOWN_FILES = {
    "USERS.DAT": "user_records",
    "USERS.IDX": "legacy_user_name_index",
    "RENEGADE.DAT": "general_configuration",
    "MBASES.DAT": "message_area_records",
    "FBASES.DAT": "file_area_records",
    "MULTNODE.DAT": "node_records",
}


def classify(name: str) -> str:
    upper = name.upper()
    if upper in KNOWN_FILES:
        return KNOWN_FILES[upper]
    extension = Path(upper).suffix
    if extension == ".HDR":
        return "message_headers_or_other_header_records"
    if extension == ".DIR":
        return "file_listing_records"
    if extension == ".SCN":
        return "message_scan_records"
    if extension in {".DAT", ".IDX", ".PTR"}:
        return "legacy_binary_data_unclassified"
    return "other"


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OSError("file changed while it was being inventoried")

        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        ):
            raise OSError("file changed while it was being inventoried")
        return digest.hexdigest(), opened.st_size
    finally:
        os.close(descriptor)


def inventory(root: Path) -> dict[str, object]:
    records: list[dict[str, object]] = []
    directories = [root]
    while directories:
        current = directories.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name.casefold(), reverse=True)
        except OSError as error:
            records.append({
                "path": current.relative_to(root).as_posix() or ".",
                "kind": "unreadable_directory",
                "error": type(error).__name__,
            })
            continue

        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    records.append({"path": relative, "kind": "symlink", "classification": "not_followed"})
                elif stat.S_ISDIR(mode):
                    directories.append(path)
                elif stat.S_ISREG(mode):
                    checksum, byte_count = sha256_file(path)
                    records.append({
                        "path": relative,
                        "kind": "file",
                        "classification": classify(path.name),
                        "bytes": byte_count,
                        "sha256": checksum,
                    })
                else:
                    records.append({"path": relative, "kind": "other_filesystem_entry"})
            except OSError as error:
                records.append({
                    "path": relative,
                    "kind": "unreadable",
                    "error": type(error).__name__,
                })

    header_records: dict[str, list[dict[str, object]]] = {}
    body_records: dict[str, list[dict[str, object]]] = {}
    scan_records: dict[str, list[dict[str, object]]] = {}
    for record in records:
        if record.get("kind") != "file":
            continue
        relative = PurePosixPath(str(record["path"]))
        stem = relative.with_suffix("").as_posix().casefold()
        if relative.suffix.casefold() == ".hdr":
            header_records.setdefault(stem, []).append(record)
        elif relative.suffix.casefold() == ".dat":
            body_records.setdefault(stem, []).append(record)
        elif relative.suffix.casefold() == ".scn":
            scan_records.setdefault(stem, []).append(record)

    for stem, headers in header_records.items():
        bodies = body_records.get(stem, [])
        if len(headers) == 1 and len(bodies) == 1:
            header, body = headers[0], bodies[0]
            header["classification"] = "message_header_candidate"
            header["related_file"] = body["path"]
            body["classification"] = "message_body_stream_candidate"
            body["related_file"] = header["path"]
            scans = scan_records.get(stem, [])
            if len(scans) == 1:
                scan = scans[0]
                scan["classification"] = "message_scan_candidate"
                scan["related_files"] = [header["path"], body["path"]]
                header["related_scan_file"] = scan["path"]
                body["related_scan_file"] = scan["path"]

    records.sort(key=lambda record: str(record["path"]).casefold())
    counts: dict[str, int] = {}
    total_bytes = 0
    for record in records:
        classification = str(record.get("classification", record["kind"]))
        counts[classification] = counts.get(classification, 0) + 1
        total_bytes += int(record.get("bytes", 0))

    return {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root_name": root.name,
        "read_only": True,
        "file_count": sum(record.get("kind") == "file" for record in records),
        "total_file_bytes": total_bytes,
        "counts": counts,
        "files": records,
    }


def write_private_report(output: Path, report: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o600)
    identity = os.fstat(descriptor)
    try:
        data = memoryview(report.encode("utf-8"))
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("inventory report write made no progress")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            current = output.lstat()
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                output.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_directory", type=Path, help="root directory of the original Renegade data")
    parser.add_argument("--output", type=Path, help="write JSON here; defaults to standard output")
    args = parser.parse_args()

    root = args.data_directory.resolve()
    if not root.is_dir():
        parser.error(f"data directory does not exist or is not a directory: {root}")
    if args.output is not None:
        requested_output = args.output.expanduser().absolute()
        output_parent = requested_output.parent.resolve()
        try:
            output_parent.relative_to(root)
        except ValueError:
            pass
        else:
            parser.error("report output must be outside the source data directory")
        output = output_parent / requested_output.name

    try:
        report = json.dumps(inventory(root), indent=2, ensure_ascii=True) + "\n"
        if args.output is None:
            sys.stdout.write(report)
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            write_private_report(output, report)
    except FileExistsError:
        print(f"Refusing to overwrite an existing inventory report: {args.output}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Could not inventory {root}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
