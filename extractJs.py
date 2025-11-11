#!/usr/bin/env python3
"""
extractJs.py — fast extractor for JavaScript URLs from any readable files.

Usage:
  ./extractJs.py -f /path/to/file.html -o js.urls
  ./extractJs.py -d /path/to/dir -o js.urls

Options:
  -f, --file   Single file to scan.
  -d, --dir    Directory to scan recursively (all readable files).
  -o, --output Output file (default: js_urls.txt)
  -j, --jobs   Number of threads (default: 8)
"""

import argparse
import re
import sys
import html
from pathlib import Path
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_WORKERS = 8
SKIP_SCHEMES = ("javascript:", "data:", "mailto:", "tel:", "#")

# --- Regex patterns
PATTERNS = [
    re.compile(r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\bimport\s*\(\s*["\']([^"\']+)["\']\s*\)', re.I),
    re.compile(r'\bimport\s+["\']([^"\']+)["\']', re.I),
    re.compile(r'\bfetch\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\baxios\.\w+\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'xhr\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I),
]

DOMAIN_TOKEN_RE = re.compile(r'([a-z0-9\-]+\.)+[a-z]{2,}', re.I)

# --- Helpers

def infer_domain_from_path(p: Path) -> str:
    """Guess domain from file path."""
    m = DOMAIN_TOKEN_RE.search(str(p))
    if m:
        return m.group(0)
    base = p.stem.replace("_", ".")
    m2 = DOMAIN_TOKEN_RE.search(base)
    if m2:
        return m2.group(0)
    return "localhost"

def normalize_url(base: str, candidate: str) -> str:
    """Normalize relative → absolute URL and clean encoded characters."""
    c = html.unescape(candidate.strip())
    if not c or any(c.lower().startswith(s) for s in SKIP_SCHEMES):
        return ""

    # Remove leading/trailing commas or HTML artifacts
    c = c.strip(",;<> ")

    # Unescape escaped slashes (\/ → /)
    c = c.replace("\\/", "/")

    # Remove stray fragments like '</' or '>;'
    c = re.sub(r"[<>\s]*$", "", c)

    try:
        if c.startswith("//"):
            return "https:" + c
        return urljoin(base, c)
    except Exception:
        return ""

def extract_candidates(text: str):
    """Extract possible JS URLs from text."""
    for rx in PATTERNS:
        for m in rx.findall(text):
            yield m.strip()

def read_text_safe(path: Path, max_size=5 * 1024 * 1024) -> str:
    """Safely read file as text, skip large/binary files."""
    try:
        if path.stat().st_size > max_size:
            return ""
        with open(path, "rb") as f:
            chunk = f.read(2048)
            if b"\x00" in chunk:
                return ""  # binary file
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def process_file(path: Path):
    """Process one file, return set of JS URLs."""
    text = read_text_safe(path)
    if not text:
        return set()
    domain = infer_domain_from_path(path)
    base = f"https://{domain}/"
    results = set()
    for cand in extract_candidates(text):
        full = normalize_url(base, cand)
        if full:
            results.add(full)
    return results

# --- Main

def gather_files(single: Path = None, directory: Path = None):
    files = []
    if single and single.is_file():
        files.append(single)
    if directory:
        for p in directory.rglob("*"):
            if p.is_file() and os.access(p, os.R_OK):
                files.append(p)
    return files

def main(argv):
    parser = argparse.ArgumentParser(description="Extract JavaScript URLs from files.")
    parser.add_argument("-f", "--file", type=Path, help="Single input file")
    parser.add_argument("-d", "--dir", type=Path, help="Directory to scan recursively")
    parser.add_argument("-o", "--output", type=Path, default=Path("js_urls.txt"), help="Output file")
    parser.add_argument("-j", "--jobs", type=int, default=MAX_WORKERS, help="Number of threads (default: 8)")
    args = parser.parse_args(argv[1:])

    if not args.file and not args.dir:
        parser.error("Provide -f or -d")

    files = gather_files(args.file, args.dir)
    if not files:
        print("No readable files found.")
        return 1

    print(f"[*] Scanning {len(files)} file(s)...")

    results = set()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures = {ex.submit(process_file, f): f for f in files}
        for fut in as_completed(futures):
            f = futures[fut]
            try:
                res = fut.result()
                if res:
                    results.update(res)
            except Exception as e:
                print(f"[!] Error processing {f}: {e}", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for u in sorted(results):
            fh.write(u + "\n")

    print(f"[+] Found {len(results)} unique JS URLs → {args.output}")
    return 0

if __name__ == "__main__":
    import os
    sys.exit(main(sys.argv))
