#!/usr/bin/env python3
"""Safely import .ANS and .ASC artwork from nested ZIP collections."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

MAX_DEPTH = 5
MAX_ARCHIVE_MEMBER = 64 * 1024 * 1024
MAX_ARTWORK_FILE = 1024 * 1024
MAX_TOTAL_ARTWORK = 20 * 1024 * 1024
ART_EXTENSIONS = {".ans", ".asc"}


def safe_parts(raw_name: str) -> tuple[str, ...] | None:
    """Return normalized relative path parts, or None for an unsafe name."""
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        return None
    if path.parts[0].endswith(":"):
        return None
    return path.parts


def safe_component(value: str) -> str:
    ascii_value = value.encode("ascii", "replace").decode("ascii")
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", ascii_value).strip("._")
    return cleaned[:100] or "art"


def is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return (mode & 0o170000) == 0o120000


class ArtImporter:
    def __init__(self, output: Path) -> None:
        self.output = output
        self.records: list[dict[str, object]] = []
        self.skipped_archives: list[dict[str, str]] = []
        self.seen_paths: set[str] = set()
        self.total_bytes = 0

    def visit(self, archive: zipfile.ZipFile, chain: tuple[str, ...], depth: int) -> None:
        for info in archive.infolist():
            if info.is_dir() or is_symlink(info):
                continue
            parts = safe_parts(info.filename)
            if parts is None or info.flag_bits & 1:
                continue

            filename = parts[-1]
            extension = PurePosixPath(filename).suffix.lower()
            if extension in ART_EXTENSIONS:
                if info.file_size > MAX_ARTWORK_FILE:
                    continue
                if self.total_bytes + info.file_size > MAX_TOTAL_ARTWORK:
                    raise ValueError("artwork exceeded the configured total import size")
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise ValueError(f"unexpected size while reading {info.filename!r}")
                self.write_art(chain, parts, data, extension)
                continue

            if extension != ".zip" or depth >= MAX_DEPTH or info.file_size > MAX_ARCHIVE_MEMBER:
                continue

            label = "/".join(chain + (filename,))
            try:
                nested_data = archive.read(info)
                with zipfile.ZipFile(io.BytesIO(nested_data)) as nested:
                    self.visit(nested, chain + (safe_component(PurePosixPath(filename).stem),), depth + 1)
            except (zipfile.BadZipFile, OSError, RuntimeError) as error:
                self.skipped_archives.append({"path": label, "reason": type(error).__name__})

    def write_art(self, chain: tuple[str, ...], parts: tuple[str, ...], data: bytes, extension: str) -> None:
        source_relative = "/".join(parts)
        output_parts = tuple(safe_component(part) for part in chain + parts[:-1])
        original_name = parts[-1]
        stem = PurePosixPath(original_name).stem
        output_name = safe_component(stem) + extension.upper()
        output_path = Path(*output_parts, output_name)
        digest = hashlib.sha256(data).hexdigest()
        collision_key = output_path.as_posix().casefold()
        if collision_key in self.seen_paths:
            output_path = output_path.with_name(f"{output_path.stem}~{digest[:10]}{output_path.suffix}")
            collision_key = output_path.as_posix().casefold()
            duplicate = 2
            while collision_key in self.seen_paths:
                output_path = output_path.with_name(
                    f"{output_path.stem.rsplit('~', 1)[0]}~{digest[:10]}-{duplicate}{output_path.suffix}"
                )
                collision_key = output_path.as_posix().casefold()
                duplicate += 1
        self.seen_paths.add(collision_key)

        target = self.output / output_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise FileExistsError(f"refusing to overwrite existing artwork: {target}")
        target.write_bytes(data)
        self.total_bytes += len(data)
        self.records.append({
            "path": output_path.as_posix(),
            "source_chain": list(chain),
            "source_path": source_relative,
            "bytes": len(data),
            "sha256": digest,
        })


def main() -> int:
    project_dir = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, nargs="?", default=project_dir.parent / "Archive.zip")
    parser.add_argument("--output", type=Path, default=project_dir / "assets/ansi/imported")
    args = parser.parse_args()

    archive_path = args.archive.resolve()
    output = args.output.resolve()
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        parser.error(f"manifest already exists; choose another output directory: {output}")
    if output.exists() and any(output.iterdir()):
        parser.error(f"output directory is not empty: {output}")

    importer = ArtImporter(output)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            importer.visit(archive, (), 0)
    except (OSError, zipfile.BadZipFile, ValueError) as error:
        print(f"Import failed: {error}", file=sys.stderr)
        return 1

    importer.records.sort(key=lambda item: str(item["path"]).casefold())
    manifest = {
        "source_archive": archive_path.name,
        "artwork_files": len(importer.records),
        "artwork_bytes": importer.total_bytes,
        "files": importer.records,
        "skipped_nested_archives": importer.skipped_archives,
    }
    output.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"Imported {len(importer.records)} artwork files ({importer.total_bytes:,} bytes).")
    print(f"Manifest: {manifest_path}")
    if importer.skipped_archives:
        print(f"Skipped {len(importer.skipped_archives)} unreadable nested archive(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
