#!/usr/bin/env python3
"""Disclosure scan: fail if anything that looks like a real identifier is in the tree.

Usage: python scripts/scan_identifiers.py [--denylist PATH] [PATH ...]

The denylist is a plain text file, one term per line, kept OUTSIDE this repository
(it would otherwise be the leak). Built-in patterns catch the generic shapes: 12-digit
account ids, ARNs, access-key ids, internal hostnames, private IPs, JWT-like blobs.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BUILTIN_PATTERNS: dict[str, re.Pattern[str]] = {
    "12-digit-account-id": re.compile(r"(?<![\w-])\d{12}(?![\w-])"),
    "arn": re.compile(r"arn:aws[a-z-]*:", re.IGNORECASE),
    "access-key-id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "internal-host": re.compile(
        r"\b[\w.-]+\.(?:amazon\.com|amazon\.dev|a2z\.com|aws\.dev)\b", re.IGNORECASE
    ),
    "private-ip": re.compile(
        r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?:\.\d{1,3})?\b"
    ),
    "jwt-like": re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b"),
}
ALLOWED_HOSTS = {"docs.aws.amazon.com", "aws.amazon.com", "github.com"}
SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "node_modules",
}
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".json",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
    ".cfg",
    ".ini",
    ".sh",
    ".lock",
    "",
}


def iter_files(paths: list[Path]):
    for root in paths:
        if root.is_file():
            yield root
            continue
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and path.suffix in TEXT_SUFFIXES:
                yield path


def load_denylist(path: Path | None) -> list[str]:
    if path is None:
        return []
    if not path.exists():
        raise SystemExit(
            f"denylist not found: {path} (refusing to scan with built-ins only; drop --denylist to do that explicitly)"
        )
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def scan(
    paths: list[Path], denylist: list[str], self_path: Path
) -> list[tuple[Path, int, str, str]]:
    hits: list[tuple[Path, int, str, str]] = []
    deny_res = [(term, re.compile(re.escape(term), re.IGNORECASE)) for term in denylist]
    for path in iter_files(paths):
        if path.resolve() == self_path:
            continue
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            for name, pattern in BUILTIN_PATTERNS.items():
                for match in pattern.finditer(line):
                    if name == "internal-host" and match.group(0).lower() in ALLOWED_HOSTS:
                        continue
                    hits.append((path, lineno, name, match.group(0)))
            for term, pattern in deny_res:
                if pattern.search(line):
                    hits.append((path, lineno, "denylist", term))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("paths", nargs="*", default=["."], type=Path)
    parser.add_argument("--denylist", type=Path, default=None)
    args = parser.parse_args(argv)

    denylist = load_denylist(args.denylist)
    hits = scan(args.paths, denylist, Path(__file__).resolve())
    for path, lineno, kind, text in hits:
        shown = text if kind != "denylist" else "<denylisted term>"
        print(f"{path}:{lineno}: {kind}: {shown}")
    mode = f"{len(denylist)} denylist terms" if args.denylist else "no denylist"
    print(f"scanned with {len(BUILTIN_PATTERNS)} built-in patterns, {mode} → {len(hits)} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
