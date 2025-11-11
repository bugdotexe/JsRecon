#!/usr/bin/env bash
# extractJs.sh
# Usage: ./extractJs.sh [-f file.txt] [-d dir] [-o output.txt]
# -d will search recursively for .txt files
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 [-f file.txt] [-d dir] [-o output.txt]

 -f <file.txt>    single input file (e.g. 87f4bca6c47a13af5a36c84e94bddc67888e8898.txt)
 -d <dir>         directory containing .txt files (searches recursively)
 -o <output.txt>  output file (default: js_urls.txt)
EOF
  exit 1
}

out_file="js_urls.txt"
single_file=""
dir=""

while getopts ":f:d:o:h" opt; do
  case "${opt}" in
    f) single_file="${OPTARG}" ;;
    d) dir="${OPTARG}" ;;
    o) out_file="${OPTARG}" ;;
    h) usage ;;
    *) usage ;;
  esac
done

if [[ -z "${single_file}" && -z "${dir}" ]]; then
  echo "[!] Provide -f or -d"
  usage
fi

tmp_all="$(mktemp)"
trap 'rm -f "$tmp_all"' EXIT

# Infer domain: look for a hostname-like token in the path (best-effort)
# Looks for tokens like: sub.example.com or example.com
infer_domain() {
  local path="$1"
  # search path for domain-like token (a.b or a.b.c) - pick the first longest match
  # uses perl-compatible regex with grep -oP if available, otherwise fallback to simple sed
  if grep -oP '.' >/dev/null 2>&1; then
    # grep -oP may exist; use a conservative domain regex
    domain="$(echo "$path" | grep -oP '([a-z0-9\-]+\.)+[a-z]{2,}' | head -n1 || true)"
  else
    domain="$(echo "$path" | sed -nE 's/.*(([a-z0-9-]+\.)+[a-z]{2,}).*/\1/p' | head -n1 || true)"
  fi

  # If domain still empty, try basename replacing underscores with dots
  if [[ -z "$domain" ]]; then
    local base="$(basename "$path")"
    base="${base%.*}"
    domain="${base//_/.}"
  fi

  # If still empty, fallback to "localhost"
  if [[ -z "$domain" ]]; then
    domain="localhost"
  fi

  echo "$domain"
}

# Extract candidate JS references from file using Python (regexes)
extract_candidates() {
  local file="$1"
  python3 - <<PY "$file"
import re, sys
fn = sys.argv[1]
text = ""
try:
    with open(fn, 'r', encoding='utf-8', errors='ignore') as fh:
        text = fh.read()
except Exception as e:
    sys.exit(0)

patterns = [
    r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']',    # <script src="">
    r'\bimport\s*\(\s*["\']([^"\']+)["\']\s*\)',      # import('...')
    r'\bimport\s+["\']([^"\']+)["\']',                # import "..."
    r'\bfetch\s*\(\s*["\']([^"\']+)["\']',            # fetch("...")
    r'\baxios\.\w+\s*\(\s*["\']([^"\']+)["\']',       # axios.get("...")
    r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']', # $.get("...")
    r'xhr\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']', # xhr.open
    r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']'          # any ".js" in quotes
]

seen = set()
for p in patterns:
    for m in re.findall(p, text, flags=re.IGNORECASE):
        s = m.strip()
        if not s:
            continue
        # skip unwanted schemes
        if s.lower().startswith(("javascript:", "data:", "mailto:", "tel:", "#")):
            continue
        if s not in seen:
            seen.add(s)
            print(s)
PY
}

# Use Python's urljoin to canonicalize relative -> absolute using base
urljoin() {
  local base="$1"
  local rel="$2"
  python3 - <<PY
from urllib.parse import urljoin
b = "$base"
r = "$rel"
if not r or r.strip().lower().startswith(("javascript:","data:","#","mailto:","tel:")):
    print("")
else:
    # handle protocol-relative
    if r.startswith("//"):
        print("https:" + r)
    else:
        print(urljoin(b, r))
PY
}

process_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "[!] File not found: $file" >&2
    return 1
  fi

  local domain
  domain="$(infer_domain "$file")"
  # If directory name like 930697.classdojo.com_443 exists in path, infer_domain will match it.
  # Use https by default
  local base="https://${domain}/"

  # Extract and normalize
  while IFS= read -r cand; do
    [[ -z "${cand// }" ]] && continue
    # trim
    cand="$(echo "$cand" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
    # skip unwanted
    if [[ "$cand" =~ ^(data:|javascript:|mailto:|tel:) ]]; then
      continue
    fi

    if [[ "$cand" =~ ^// ]]; then
      full="https:${cand}"
    else
      full="$(urljoin "$base" "$cand" | tr -d '\r')"
    fi

    [[ -z "$full" ]] && continue
    echo "$full"
  done < <(extract_candidates "$file")
}

# gather files (recursive if dir)
files=()
if [[ -n "$single_file" ]]; then
  files+=("$single_file")
fi
if [[ -n "$dir" ]]; then
  while IFS= read -r -d $'\0' f; do
    files+=("$f")
  done < <(find "$dir" -type f -name "*.txt" -print0)
fi

if [[ ${#files[@]} -eq 0 ]]; then
  echo "[!] No files to process" >&2
  exit 1
fi

echo "[*] Processing ${#files[@]} file(s)..."

for f in "${files[@]}"; do
  echo "[*] -> $f"
  process_file "$f" >> "$tmp_all" || true
done

# Dedup and sort
sort -u "$tmp_all" > "${out_file}"
echo "[+] Wrote $(wc -l < "${out_file}") unique JS URLs to ${out_file}"
