#!/usr/bin/env python3
"""Read one length-prefixed message body from a Renegade .DAT byte stream."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

MAX_TEXT_SIZE = 65535


def read_slice(path: Path, pointer: int, text_size: int) -> bytes:
    if pointer < 1:
        raise ValueError("message pointer must be a one-based positive byte offset")
    if text_size < 0 or text_size > MAX_TEXT_SIZE:
        raise ValueError(f"text size must be between 0 and {MAX_TEXT_SIZE} bytes")

    start = pointer - 1
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("message body source is not a regular file")
        end = start + text_size
        if end > before.st_size:
            raise ValueError(
                f"message body range ends at byte {end}, beyond file size {before.st_size}"
            )

        chunks: list[bytes] = []
        offset = start
        remaining = text_size
        while remaining > 0:
            chunk = os.pread(descriptor, remaining, offset)
            if not chunk:
                raise OSError("message body source ended before the requested range was read")
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)

        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
        )
        after_identity = (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        )
        if before_identity != after_identity:
            raise OSError("message body source changed while it was being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def decode_pascal_shortstrings(data: bytes) -> list[bytes]:
    lines: list[bytes] = []
    cursor = 0
    while cursor < len(data):
        line_length = data[cursor]
        cursor += 1
        end = cursor + line_length
        if end > len(data):
            raise ValueError(
                f"truncated Pascal short string at body byte {cursor - 1}: "
                f"length byte says {line_length}, only {len(data) - cursor} remain"
            )
        lines.append(data[cursor:end])
        cursor = end
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("body_file", type=Path, help="message area .DAT file")
    parser.add_argument("--pointer", type=int, required=True, help="one-based MHeaderRec.Pointer")
    parser.add_argument("--text-size", type=int, required=True, help="MHeaderRec.TextSize in bytes")
    args = parser.parse_args()
    body_path = args.body_file.expanduser().absolute()

    try:
        payload = read_slice(body_path, args.pointer, args.text_size)
        lines = decode_pascal_shortstrings(payload)
        report = {
            "source_file": body_path.name,
            "pointer_1_based": args.pointer,
            "text_size": args.text_size,
            "record_count": len(lines),
            "lines_cp437": [line.decode("cp437") for line in lines],
        }
        sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    except (OSError, ValueError) as error:
        print(f"Could not decode message body: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
