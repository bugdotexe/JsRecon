#!/usr/bin/env python3
"""
extractJs.py — Extract JS URLs from local files, download JS files, and extract REAL sourcemaps from JS URLs.

Usage Examples:
  1. Extract JS URLs:
      python3 extractJs.py -d ./responses -o js_urls.txt

  2. Download extracted JS files:
      python3 extractJs.py --download ./js_downloads -o js_urls.txt

  3. Extract REAL sourcemaps from JS URLs:
      python3 extractJs.py -o js_urls.txt --findmaps

  4. Full chain (extract + download + sourcemap extraction):
      python3 extractJs.py -d ./responses -o js_urls.txt --findmaps
"""

import argparse
import base64
import html
import os
import re
import sys
import hashlib
import requests
from urllib.parse import urljoin, urlparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

MAX_WORKERS = 8
SKIP_SCHEMES = ("javascript:", "data:", "mailto:", "tel:", "#")

# --- Regex patterns for JS URL extraction
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

# ---------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------

def infer_domain_from_path(p: Path) -> str:
    """Try to infer a domain from a file path or name."""
    m = DOMAIN_TOKEN_RE.search(str(p))
    if m:
        return m.group(0)
    base = p.stem.replace("_", ".")
    m2 = DOMAIN_TOKEN_RE.search(base)
    if m2:
        return m2.group(0)
    return "localhost"


def normalize_url(base: str, candidate: str) -> str:
    """Normalize relative → absolute URLs and clean artifacts."""
    c = html.unescape(candidate.strip())
    if not c or any(c.lower().startswith(s) for s in SKIP_SCHEMES):
        return ""
    c = c.strip(",;<> ")
    c = c.replace("\\/", "/")
    c = re.sub(r"[<>\s]*$", "", c)
    try:
        if c.startswith("//"):
            return "https:" + c
        return urljoin(base, c)
    except Exception:
        return ""


def extract_candidates(text: str):
    """Extract candidate JS URLs using regex patterns."""
    for rx in PATTERNS:
        for m in rx.findall(text):
            yield m.strip()


def read_text_safe(path: Path, max_size=5 * 1024 * 1024) -> str:
    """Safely read file as text; skip binary or too-large files."""
    try:
        if path.stat().st_size > max_size:
            return ""
        with open(path, "rb") as f:
            chunk = f.read(2048)
            if b"\x00" in chunk:
                return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def process_file(path: Path):
    """Process a file to extract JS URLs."""
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


def gather_files(single: Path = None, directory: Path = None):
    """Collect all readable files recursively."""
    files = []
    if single and single.is_file():
        files.append(single)
    if directory:
        for p in directory.rglob("*"):
            if p.is_file() and os.access(p, os.R_OK):
                files.append(p)
    return files

# ---------------------------------------------------------------------
#  Main Extraction
# ---------------------------------------------------------------------

def extract_main(args):
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

# ---------------------------------------------------------------------
#  Downloading JS Files
# ---------------------------------------------------------------------

def download_js_files(url_file: Path, out_dir: Path, jobs=8):
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Downloading JS files from {url_file} ...")

    urls = [u.strip() for u in url_file.read_text().splitlines() if u.strip()]
    downloaded = set()

    def fetch(u):
        try:
            r = requests.get(u, timeout=10, verify=False)
            if r.status_code == 200 and r.content:
                parsed = urlparse(u)
                domain_dir = out_dir / parsed.netloc
                domain_dir.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha1(u.encode()).hexdigest()[:12]
                filename = Path(parsed.path).name or "index.js"
                file_path = domain_dir / f"{filename}_{h}.js"
                file_path.write_bytes(r.content)
                return str(file_path)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(fetch, u): u for u in urls}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                downloaded.add(res)

    print(f"[+] Downloaded {len(downloaded)} JS files → {out_dir}")
    return downloaded

# ---------------------------------------------------------------------
#  Extract REAL Source Maps from JS URLs
# ---------------------------------------------------------------------

def extract_real_sourcemaps(js_url_file: Path, out_file: Path, jobs=8):
    """Fetch JS URLs and extract real sourceMappingURL entries."""
    urls = [u.strip() for u in js_url_file.read_text().splitlines() if u.strip()]
    maps = set()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    pattern = re.compile(r'(?://#|//@)\s*sourceMappingURL\s*=\s*(\S+)', re.I)

    def fetch_and_extract(u):
        try:
            r = requests.get(u, timeout=10, verify=False)
            if r.status_code != 200 or not r.text:
                return None
            matches = pattern.findall(r.text)
            if not matches:
                return None
            found_maps = []
            for m in matches:
                m = m.strip().rstrip(";")
                # Handle inline Base64 maps
                if m.startswith("data:") and "base64," in m:
                    b64 = m.split("base64,", 1)[1]
                    try:
                        decoded = base64.b64decode(b64)
                        map_name = hashlib.sha1(u.encode()).hexdigest()[:10] + ".map"
                        map_path = out_file.parent / map_name
                        map_path.write_bytes(decoded)
                        found_maps.append(f"[inline] {map_name}")
                    except Exception:
                        continue
                else:
                    abs_url = urljoin(u, m)
                    found_maps.append(abs_url)
            return found_maps
        except Exception:
            return None

    print(f"[*] Extracting REAL sourcemaps from {len(urls)} JS URLs...")

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(fetch_and_extract, u): u for u in urls}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                for m in res:
                    maps.add(m)

    with out_file.open("w", encoding="utf-8") as fh:
        for m in sorted(maps):
            fh.write(m + "\n")

    print(f"[+] Extracted {len(maps)} sourcemap references → {out_file}")
    return maps

# ---------------------------------------------------------------------
#  CLI Entrypoint
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Extract JavaScript URLs, download them, and find real sourcemaps.")
    parser.add_argument("-f", "--file", type=Path, help="Single input file")
    parser.add_argument("-d", "--dir", type=Path, help="Directory to scan recursively")
    parser.add_argument("-o", "--output", type=Path, default=Path("js_urls.txt"), help="Output file")
    parser.add_argument("--download", type=Path, help="Directory to save downloaded JS files")
    parser.add_argument("--findmaps", action="store_true", help="Extract real sourcemap URLs from JS URLs")
    parser.add_argument("-j", "--jobs", type=int, default=MAX_WORKERS, help="Parallel threads (default: 8)")
    args = parser.parse_args()

    if args.file or args.dir:
        extract_main(args)

    if args.download:
        download_js_files(args.output, args.download, args.jobs)

    if args.findmaps:
        extract_real_sourcemaps(args.output, args.output.with_suffix(".sourcemaps.txt"), args.jobs)


if __name__ == "__main__":
    sys.exit(main())
