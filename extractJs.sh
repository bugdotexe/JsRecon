#!/usr/bin/env bash
# extract_js_urls.sh
# Usage: ./extract_js_urls.sh [-f file.txt] [-d dir_with_txt_files] [-o output.txt]
# Default output: js_urls.txt

set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 [-f file.txt] [-d dir] [-o output.txt]

 -f <file.txt>    single input file (e.g. evil_com.txt)
 -d <dir>         directory containing .txt files (e.g. ./html_downloads/)
 -o <output.txt>  output file (default: js_urls.txt)

Files are expected to be plain text HTML sources saved with names like:
  evil_com.txt  -> domain inferred as evil.com
EOF
  exit 1
}

# defaults
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

# Utility: infer domain from filename
# e.g. evil_com.txt  -> evil.com
infer_domain() {
  local filename="$1"
  # strip path
  local base="$(basename "$filename")"
  # remove extension
  base="${base%.*}"
  # replace underscores with dots (e.g. evil_com -> evil.com)
  # also replace double-underscore -> dash (in case used), keep simple
  echo "${base//_/.}"
}

# For robust URL joining we call python's urljoin on each candidate.
# This lets us safely handle ../ ./ /path //host and absolute urls.
urljoin() {
  local base="$1"
  local rel="$2"
  python3 - <<PY
from urllib.parse import urljoin, urlparse
b = "$base"
r = "$rel"
# handle empty or javascript: etc.
if not r or r.strip().lower().startswith(("javascript:","data:","#")):
    print("")
else:
    # if scheme-less like //host/foo -> ensure scheme on base
    print(urljoin(b, r))
PY
}

# Regex extraction function: prints candidate URLs (raw)
extract_candidates() {
  local file="$1"

  # Use GNU grep -P if available, fallback to perl if not
  # Patterns to capture common JS references:
  #  - <script src="...">
  #  - import "..."
  #  - import('...')
  #  - fetch("...")
  #  - axios.get("...") / axios.post("...")
  #  - $.get("...") / $.ajax("...")
  #  - xhr.open("GET", "...")
  #  - any "something.js" in quotes
  #
  # We'll use perl to run multiple regexes and print matches
  perl -0777 -ne '
    my $s = $_;
    while ($s =~ /<script[^>]*\bsrc\s*=\s*["'\'']([^"'\'']+)["'\'']/ig) { print "$1\n"; }
    while ($s =~ /\bimport\s*\(\s*["'\'']([^"'\'']+)["'\'']\s*\)/ig) { print "$1\n"; }
    while ($s =~ /\bimport\s+["'\'']([^"'\'']+)["'\'']/ig) { print "$1\n"; }
    while ($s =~ /\bfetch\s*\(\s*["'\'']([^"'\'']+)["'\'']/ig) { print "$1\n"; }
    while ($s =~ /\baxios\.\w+\s*\(\s*["'\'']([^"'\'']+)["'\'']/ig) { print "$1\n"; }
    while ($s =~ /\$\.(get|post|ajax)\s*\(\s*["'\'']([^"'\'']+)["'\'']/ig) { print \"$2\n\"; }
    while ($s =~ /xhr\.open\s*\(\s*["'\''](?:GET|POST|PUT|DELETE)["'\'']\s*,\s*["'\'']([^"'\'']+)["'\'']/ig) { print \"$1\n\"; }
    while ($s =~ /["'\'']([^"'\'']+\.js(?:\?[^"'\'']*)?)["'\'']/ig) { print \"$1\n\"; }
  ' "$file" || true
}

process_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "[!] File not found: $file" >&2
    return 1
  fi

  local domain
  domain="$(infer_domain "$file")"
  # If the filename contains things like example.com -> domain becomes example.com
  # build base URL with https
  local base="https://${domain}/"

  # Extract candidates and canonicalize
  while IFS= read -r cand; do
    [[ -z "${cand// }" ]] && continue
    # trim
    cand="$(echo "$cand" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
    # Skip data:, javascript:, mailto:, tel:
    if [[ "$cand" =~ ^(data:|javascript:|mailto:|tel:) ]]; then
      continue
    fi

    # If candidate looks like protocol-relative (//example.com/..)
    if [[ "$cand" =~ ^// ]]; then
      # Prepend https:
      full="https:${cand}"
    else
      # Use python urljoin to handle absolute vs relative correctly
      full="$(urljoin "$base" "$cand" | tr -d '\r')"
    fi

    # Skip empty results
    if [[ -z "$full" ]]; then
      continue
    fi

    echo "$full"
  done < <(extract_candidates "$file")
}

# Main: gather files to process
files=()
if [[ -n "$single_file" ]]; then
  files+=("$single_file")
fi
if [[ -n "$dir" ]]; then
  # add all .txt files in dir
  while IFS= read -r -d $'\0' f; do
    files+=("$f")
  done < <(find "$dir" -maxdepth 1 -type f -name "*.txt" -print0)
fi

if [[ ${#files[@]} -eq 0 ]]; then
  echo "[!] No files to process" >&2
  exit 1
fi

echo "[*] Processing ${#files[@]} file(s)..."

# process each and append to tmp_all
for f in "${files[@]}"; do
  echo "[*] -> $f"
  process_file "$f" >> "$tmp_all" || true
done

# Deduplicate and sort
sort -u "$tmp_all" > "${out_file}"
echo "[+] Wrote $(wc -l < "${out_file}") unique JS URLs to ${out_file}"
