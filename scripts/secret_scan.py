#!/usr/bin/env python3
"""
Lightweight secret scanner for local pre-push checks.
Usage: python scripts/secret_scan.py
Exit code 1 when potential secrets are found.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

IGNORE_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    "launcher.build",
    "launcher.dist",
    "launcher.onefile-build",
    ".cursor",
}

IGNORE_FILES = {
    "devices.json",
    "topology.json",
    "snmp_config.json",
}

PATTERNS = [
    re.compile(r"BEGIN\s+PRIVATE\s+KEY", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),  # GitHub token
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+[a-z0-9\-_\.]{12,}"),
]


def should_skip(path: Path) -> bool:
    parts = set(path.parts)
    if parts.intersection(IGNORE_DIRS):
        return True
    if path.suffix.lower() in {".dll", ".pyd", ".o", ".bin", ".exe"}:
        return True
    return path.name in IGNORE_FILES


def scan_file(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings
    for i, line in enumerate(text.splitlines(), start=1):
        for pattern in PATTERNS:
            if pattern.search(line):
                findings.append(f"{path.relative_to(ROOT)}:{i}: potential secret pattern")
                break
    return findings


def main() -> int:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or should_skip(path):
            continue
        findings.extend(scan_file(path))
    if findings:
        print("Potential secrets found:")
        for f in findings[:100]:
            print(f"- {f}")
        if len(findings) > 100:
            print(f"...and {len(findings) - 100} more")
        return 1
    print("No obvious secret patterns found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
