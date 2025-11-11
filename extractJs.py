#!/usr/bin/env python3
"""
extract_js_fast.py

Fast extractor for JavaScript URLs from many downloaded HTML/text files.

Usage:
  ./extract_js_fast.py -f /path/to/file.txt -o js.urls
  ./extract_js_fast.py -d /path/to/dir -o js.urls

Notes:
 - Directory search is recursive.
 - Domain is inferred from the path (first domain-like token found), default scheme is https.
 - Skips data:, javascript:, mailto:, tel:, and fragment-only strings.
"""

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Config
MAX_WORKERS = 8  # adjust to number of CPU cores / I/O
FILE_READ_CHUNK = 64 * 1024  # not used but can be used for streaming large files

# Precompile regex patterns (case-insensitive)
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

SKIP_SCHEMES = ("javascript:", "data:", "mailto:", "tel:", "#")

DOMAIN_TOKEN_RE = re.compile(r'([a-z0-9\-]+\.)+[a-z]{2,}', re.I)

# --- Helpers

def infer_domain_from_path(p: Path) -> str:
    """Best-effort domain inference from path string."""
    s = str(p)
    m = DOMAIN_TOKEN_RE.search(s)
    if m:
        return m.group(0)
    # fallback: basename before extension, underscores -> dots
    base = p.stem
    if "_" in base:
        cand = base.replace("_", ".")
        if DOMAIN_TOKEN_RE.search(cand):
            return cand
    # final fallback
    return "localhost"

def normalize_url(base: str, candidate: str) -> str:
    """Return absolute canonical URL, or empty string if invalid/skip."""
    cand = candidate.strip()
    if not cand:
        return ""
    low = cand.lower()
    if any(low.startswith(s) for s in SKIP_SCHEMES):
        return ""
    try:
        if cand.startswith("//"):
            return "https:" + cand
        # if candidate already has scheme, urljoin will keep it
        return urljoin(base, cand)
    except Exception:
        return ""

def extract_from_text(text: str):
    """Yield raw matched URL candidates (not normalized)."""
    for rx in PATTERNS:
        for m in rx.findall(text):
            # rx.findall returns str or tuple (for groups) depending on pattern
            if isinstance(m, tuple):
                # in case of multiple groups, pick last non-empty (not expected here)
                for part in reversed(m):
                    if part:
                        yield part
                        break
            else:
                yield m

def process_file(path: Path):
    """
    Read file content and extract normalized JS URLs.
    Returns set of URLs found in this file.
    """
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except Exception:
        return set()

    domain = infer_domain_from_path(path)
    base = f"https://{domain}/"

    found = set()
    for candidate in extract_from_text(text):
        full = normalize_url(base, candidate)
        if full:
            found.add(full)
    return found

# --- Main CLI

def gather_files(single: Path=None, directory: Path=None):
    files = []
    if single:
        if single.is_file():
            files.append(single)
    if directory:
        files.extend([p for p in directory.rglob("*.txt") if p.is_file()])
    return files

def main(argv):
    ap = argparse.ArgumentParser(prog=Path(argv[0]).name)
    ap.add_argument("-f", "--file", type=Path, help="Single input file (.txt)")
    ap.add_argument("-d", "--dir", type=Path, help="Directory to search recursively for .txt files")
    ap.add_argument("-o", "--output", type=Path, default=Path("js_urls.txt"), help="Output file")
    ap.add_argument("-j", "--jobs", type=int, default=MAX_WORKERS, help="Number of worker threads")
    args = ap.parse_args(argv[1:])

    if not args.file and not args.dir:
        ap.error("Provide -f or -d")

    files = gather_files(args.file, args.dir)
    if not files:
        print("No files found to process.", file=sys.stderr)
        return 1

    # Use thread pool - file IO is the main cost
    results = set()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures = {ex.submit(process_file, p): p for p in files}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                res = fut.result()
                if res:
                    results.update(res)
            except Exception as e:
                # keep going on errors
                print(f"[!] Error processing {p}: {e}", file=sys.stderr)

    # Write sorted unique results
    outpath = args.output
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with outpath.open("w", encoding="utf-8")
