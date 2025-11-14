#!/usr/bin/env bash
set -uo pipefail

SECRETS_FILE="regex.json"
TARGET=""
IGNORE_CASE=0
FOLLOW_SYMLINKS=0

usage() {
cat <<EOF
Usage: $0 -t <target> [options]
  -t <target>     File or directory to scan
  -s <regex.json> Regex rules (default: regex.json)
  -i              Case-insensitive search
  --follow        Follow symlinks
  -h              Show help

Example:
  ./secret.sh -t ./src
  curl -s https://example.com/file.js | ./secret.sh
EOF
exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) TARGET="$2"; shift 2;;
        -s) SECRETS_FILE="$2"; shift 2;;
        -i) IGNORE_CASE=1; shift;;
        --follow) FOLLOW_SYMLINKS=1; shift;;
        -h|--help) usage;;
        *) echo "Unknown arg: $1"; usage;;
    esac
done

TMP_STDIN=""
if [ -z "$TARGET" ] && [ ! -t 0 ]; then
    TMP_STDIN=$(mktemp)
    cat - > "$TMP_STDIN"
    TARGET="$TMP_STDIN"
fi

if [ -z "$TARGET" ]; then echo "❌ No target given."; usage; fi
if [ ! -f "$SECRETS_FILE" ]; then echo "❌ Regex file not found: $SECRETS_FILE"; exit 1; fi
if [ ! -e "$TARGET" ]; then echo "❌ Target not found: $TARGET"; exit 1; fi


if command -v rg &>/dev/null; then
    SEARCH_TOOL="rg"
    RG_OPTS=(--no-heading --line-number --color=never --no-messages -o)
    [ "$IGNORE_CASE" -eq 1 ] && RG_OPTS+=(-i)
    [ "$FOLLOW_SYMLINKS" -eq 1 ] && RG_OPTS+=(--follow)
else
    SEARCH_TOOL="grep"
    GREP_OPTS=(-nHoE)
    [ "$IGNORE_CASE" -eq 1 ] && GREP_OPTS+=(-i)
fi

IGNORE_DIRS=(node_modules .git dist build coverage __pycache__)
EXCLUDE_ARGS=()
for d in "${IGNORE_DIRS[@]}"; do
    if [ "$SEARCH_TOOL" = "rg" ]; then
        EXCLUDE_ARGS+=(--glob "!$d/**")
    else
        EXCLUDE_ARGS+=(--exclude-dir="$d")
    fi
done

cleanup() { rm -f "$TMP_STDIN" 2>/dev/null || true; }
trap cleanup EXIT

echo "🔎 Using $SEARCH_TOOL"
echo "📘 Regex source: $SECRETS_FILE"
echo "📂 Target: $TARGET"
echo "------------------------------------------------------------"

jq -r 'to_entries[] | "\(.key)|\(.value)"' "$SECRETS_FILE" | \
while IFS='|' read -r rule regex; do
    [ -z "$regex" ] && continue
    echo "🔍 Scanning for: $rule"

    if [ "$SEARCH_TOOL" = "rg" ]; then
        rg "${RG_OPTS[@]}" "${EXCLUDE_ARGS[@]}" -e "$regex" "$TARGET" 2>/dev/null | \
        while IFS=: read -r file line match; do
            [ -z "$file" ] && continue
            echo "🟡 [$rule] $file:$line"
            echo "    🔑 $match"
        done
    else
        grep -R "${GREP_OPTS[@]}" "${EXCLUDE_ARGS[@]}" -e "$regex" "$TARGET" 2>/dev/null | \
        while IFS=: read -r file line match; do
            [ -z "$file" ] && continue
            echo "🟡 [$rule] $file:$line"
            echo "    🔑 $match"
        done
    fi
done
