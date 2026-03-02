#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Quick Suspicious File Scanner (Python CLI)

- Fast recursive scan (os.walk)
- Scans selected extensions
- Reads head+tail for large files (speed)
- Flags common webshell/obfuscation/dangerous function patterns
- Outputs JSON to stdout or file

Usage:
  python3 quick_scan.py /path/to/scan --exclude /proc --exclude /sys --exclude /dev --out report.json
"""

import os
import re
import json
import argparse
from pathlib import Path


DEFAULT_EXTS = {
    ".php", ".phtml", ".php5", ".php7", ".inc",
    ".js", ".html", ".htm",
    ".py", ".sh", ".pl",
    ".asp", ".aspx", ".jsp",
}

SUSPICIOUS_PATTERNS = [
    # PHP
    ("php_eval", re.compile(r"\beval\s*\(", re.IGNORECASE)),
    ("php_assert", re.compile(r"\bassert\s*\(", re.IGNORECASE)),
    ("php_base64_decode", re.compile(r"\bbase64_decode\s*\(", re.IGNORECASE)),
    ("php_gzinflate", re.compile(r"\bgzinflate\s*\(", re.IGNORECASE)),
    ("php_str_rot13", re.compile(r"\bstr_rot13\s*\(", re.IGNORECASE)),
    ("php_create_function", re.compile(r"\bcreate_function\s*\(", re.IGNORECASE)),
    ("php_shell_exec", re.compile(r"\bshell_exec\s*\(", re.IGNORECASE)),
    ("php_system", re.compile(r"\bsystem\s*\(", re.IGNORECASE)),
    ("php_passthru", re.compile(r"\bpassthru\s*\(", re.IGNORECASE)),
    ("php_exec", re.compile(r"\bexec\s*\(", re.IGNORECASE)),
    ("php_proc_open", re.compile(r"\bproc_open\s*\(", re.IGNORECASE)),
    ("php_popen", re.compile(r"\bpopen\s*\(", re.IGNORECASE)),
    ("php_fsockopen", re.compile(r"\bfsockopen\s*\(", re.IGNORECASE)),
    ("php_curl_exec", re.compile(r"\bcurl_exec\s*\(", re.IGNORECASE)),
    ("php_preg_replace_e", re.compile(r"preg_replace\s*\(.*?/e[\"']", re.IGNORECASE | re.DOTALL)),
    ("php_superglobals", re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\b", re.IGNORECASE)),
    ("php_php_input", re.compile(r"php:\/\/input", re.IGNORECASE)),

    # Command indicators
    ("cmd_wget_curl", re.compile(r"\b(wget|curl)\b", re.IGNORECASE)),
    ("cmd_powershell", re.compile(r"\bpowershell\b", re.IGNORECASE)),
    ("cmd_nc_netcat", re.compile(r"\b(nc|netcat)\b", re.IGNORECASE)),

    # Python / JS
    ("python_exec_eval", re.compile(r"\b(exec|eval)\s*\(", re.IGNORECASE)),
    ("js_eval", re.compile(r"\beval\s*\(", re.IGNORECASE)),
    ("js_function_ctor", re.compile(r"new\s+Function\s*\(", re.IGNORECASE)),
]

# Long base64 blob often indicates obfuscation
BASE64_LONG = re.compile(r"(?:[A-Za-z0-9+/]{200,}={0,2})")


def norm_path(p: Path) -> str:
    try:
        return str(p.resolve())
    except Exception:
        return str(p)


def is_excluded(p: Path, exclude_prefixes: list[str]) -> bool:
    sp = norm_path(p)
    for ex in exclude_prefixes:
        if sp.startswith(ex):
            return True
    return False


def read_head_and_tail(file_path: Path, max_bytes: int) -> bytes | None:
    try:
        size = file_path.stat().st_size
        with file_path.open("rb") as f:
            if size <= max_bytes:
                return f.read()
            half = max_bytes // 2
            head = f.read(half)
            f.seek(max(0, size - half))
            tail = f.read(half)
            return head + b"\n...\n" + tail
    except Exception:
        return None


def scan_file(file_path: Path, max_bytes: int) -> dict | None:
    data = read_head_and_tail(file_path, max_bytes)
    if not data:
        return None

    text = data.decode("utf-8", errors="ignore")
    hits: list[str] = []

    for name, rx in SUSPICIOUS_PATTERNS:
        if rx.search(text):
            hits.append(name)

    if BASE64_LONG.search(text):
        hits.append("long_base64_blob")

    if hits:
        try:
            size = file_path.stat().st_size
        except Exception:
            size = -1
        return {
            "path": str(file_path),
            "size": size,
            "hits": sorted(set(hits)),
        }

    return None


def iter_files(root: Path, exts: set[str], exclude_prefixes: list[str]):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)

        # Fast directory-level exclude
        if is_excluded(dp, exclude_prefixes):
            dirnames[:] = []
            continue

        for fn in filenames:
            fp = dp / fn
            if is_excluded(fp, exclude_prefixes):
                continue
            if fp.is_symlink():
                continue
            if fp.suffix.lower() not in exts:
                continue
            yield fp


def main():
    ap = argparse.ArgumentParser(description="Quick Suspicious File Scanner (Python CLI)")
    ap.add_argument("root", help="Root path to scan")
    ap.add_argument("--exclude", action="append", default=[], help="Exclude path prefix (repeatable)")
    ap.add_argument("--max-bytes", type=int, default=512 * 1024, help="Read at most this many bytes per file (default 512KB)")
    ap.add_argument("--max-size", type=int, default=10 * 1024 * 1024, help="Skip files larger than this (default 10MB)")
    ap.add_argument("--ext", action="append", default=[], help="Extra extension to include (e.g. --ext .txt)")
    ap.add_argument("--out", default="", help="Write JSON report to file")
    args = ap.parse_args()

    root = Path(args.root)
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Invalid root directory: {args.root}")

    exts = set(DEFAULT_EXTS)
    for e in args.ext:
        e = e.strip()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        exts.add(e.lower())

    exclude_prefixes = [norm_path(Path(x)) for x in args.exclude]

    scanned = 0
    skipped = 0
    findings: list[dict] = []

    for fp in iter_files(root.resolve(), exts, exclude_prefixes):
        try:
            size = fp.stat().st_size
        except Exception:
            skipped += 1
            continue

        if size > args.max_size:
            skipped += 1
            continue

        scanned += 1
        res = scan_file(fp, args.max_bytes)
        if res:
            findings.append(res)

    findings.sort(key=lambda x: (len(x.get("hits", [])), x.get("size", 0)), reverse=True)

    report = {
        "root": str(root.resolve()),
        "scanned_files": scanned,
        "skipped_entries": skipped,
        "findings": findings,
    }

    out_json = json.dumps(report, ensure_ascii=False, indent=2)

    if args.out:
        Path(args.out).write_text(out_json, encoding="utf-8")
        print(f"Wrote report: {args.out}")
    else:
        print(out_json)


if __name__ == "__main__":
    main()
