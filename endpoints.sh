#!/bin/bash
# Version: 0.1
# Author: gonn4cry
echo -e "                                 _____
   ____   ____   ____   ____    /  |  |   ___________ ___.__.
  / ___\ /  _ \ /    \ /    \  /   |  |__/ ___\_  __ <   |  |
 / /_/  >  <_> )   |  \   |  \/    ^   /\  \___|  | \/\___  |
 \___  / \____/|___|  /___|  /\____   |  \___  >__|   / ____|
/_____/             \/     \/      |__|      \/       \/


"
echo -e "Javascript endpoints extractor"
set -eo pipefail
shopt -s nocasematch
GREP="grep"

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'
BOLD='\033[1m'
UL='\033[4m'

analyze_routes() {
    local content="$1"
    local routes=$(
        echo "$content" | grep -oP 'route:"\K[^"]+'
        echo "$content" | grep -oP 'url:"\K[^"]+'
        echo "$content" | grep -oP 'path:"\K[^"]+'
        echo "$content" | grep -oP 'href:"\K[^"]+'
        echo "$content" | grep -oP '\.(?:get|post|put|delete|patch)\(\s*"\K[^"]+'
        echo "$content" | grep -oP '\.concat\(t,"\K[^"]+'
        echo "$content" | grep -oP '"\K/[^"]+(?="\s*:\s*(\{|$))'
        echo "$content" | grep -oP '"components/\K[^"]+'
        echo "$content" | grep -oP '["'\''](/api[^"'\'']*)["'\'']'
    )


printf " • %s\n" "${routes}" |  awk 'length($0) > 3' |
        $GREP -P '^/' |
        awk '{print $1}' |
        awk '!x[$0]++' |
        sort -u

}

main() {
    local content=""
    if [[ $# -eq 0 ]]; then
        echo
        content=$(cat)
    elif [[ -f "$1" ]]; then
        echo -e "${GREEN}Analyzing:${NC} $1"
        content=$(<"$1")
    else
        echo -e "${RED}Error:${NC} File not found or no input provided" >&2
        exit 1
    fi

    [[ -z "$content" ]] && echo -e "${YELLOW}Warning:${NC} Input is empty" >&2

    analyze_routes "$content"
}

main "$@"
