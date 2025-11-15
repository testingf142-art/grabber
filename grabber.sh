#!/bin/bash

# Enhanced URL Enumeration Script with Parallel Processing and HTTP Probing
# Optimized for speed and efficiency

set -o pipefail

# Color codes
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

# Temporary directory
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Configuration
PROBE_URLS=false
THREADS=50

#############################################
### SUBFINDER ADDED ###
#############################################
fetch_subfinder() {
  local domain=$1
  echo -e "${BLUE}[*] Fetching subdomains with subfinder -all: $domain${NC}" >&2

  if ! command -v subfinder &>/dev/null; then
    echo -e "${YELLOW}[!] subfinder not found, skipping${NC}" >&2
    return
  fi

  # Run subfinder, convert hostnames to URLs
  subfinder -d "$domain" -all -silent \
    | sed 's/^/http:\/\//' \
    | sed 's/$/\//'   # append slash so filtering catches ?params later

  echo -e "${GREEN}[✓] Subfinder completed${NC}" >&2
}
#############################################


fetch_alienvault_urls() {
  local domain=$1
  echo -e "${BLUE}[*] Fetching from AlienVault: $domain${NC}" >&2

  for page in {1..5}; do
    (
      local api="https://otx.alienvault.com/api/v1/indicators/hostname/$domain/url_list?limit=500&page=$page"
      response=$(curl -s --connect-timeout 10 --max-time 30 "$api" 2>/dev/null)

      if [[ $? -eq 0 && -n "$response" ]]; then
        echo "$response" | jq -r '.url_list[]?.url // empty'
      fi
    ) &
  done
  wait

  echo -e "${GREEN}[✓] AlienVault completed${NC}" >&2
}

fetch_virustotal_urls() {
  local domain=$1
  local api_keys=(
    "9943ec760252da4f4578c490d70a6846ad8e877736aa74df644f7dffd0c67f8c"
    "82e177d74de2bc84363cbe945448b3926fed09d6e9d1932a4b6d431c45ed9789"
  )

  echo -e "${BLUE}[*] Fetching from VirusTotal: $domain${NC}" >&2

  for key in "${api_keys[@]}"; do
    local api="https://virustotal.com/vtapi/v2/domain/report?apikey=$key&domain=$domain"
    response=$(curl -s --connect-timeout 10 --max-time 30 "$api" 2>/dev/null)

    if [[ $? -eq 0 && -n "$response" ]]; then
      if ! echo "$response" | jq -e '.error' &>/dev/null; then
        echo "$response" | jq -r '(.detected_urls[]?[0] // empty), (.undetected_urls[]?[0] // empty)'
        echo -e "${GREEN}[✓] VirusTotal completed${NC}" >&2
        return
      else
        echo -e "${YELLOW}[!] Rate limited, trying next key...${NC}" >&2
      fi
    fi
  done

  echo -e "${YELLOW}[!] All VirusTotal keys exhausted${NC}" >&2
}

fetch_wayback_urls() {
  local domain=$1

  echo -e "${BLUE}[*] Fetching from Wayback Machine: $domain${NC}" >&2

  local filter="filter=!mimetype:image/.*|video/.*|audio/.*|font/.*|application/font.*|application/.*pdf|application/octet-stream&filter=!statuscode:404|301|302"

  (
    local api="https://web.archive.org/cdx/search/cdx?url=$domain/*&fl=original&collapse=urlkey&$filter"
    curl -s --connect-timeout 15 --max-time 60 "$api"
  ) &

  (
    local api="https://web.archive.org/cdx/search/cdx?url=*.$domain/*&fl=original&collapse=urlkey&$filter"
    curl -s --connect-timeout 15 --max-time 60 "$api"
  ) &

  wait
  echo -e "${GREEN}[✓] Wayback completed${NC}" >&2
}

fetch_commoncrawl_urls() {
  local domain=$1

  echo -e "${BLUE}[*] Fetching from CommonCrawl: $domain${NC}" >&2

  local api="https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.$domain&output=json"
  response=$(curl -s --connect-timeout 15 --max-time 45 "$api")

  if [[ $? -eq 0 && -n "$response" ]]; then
    echo "$response" | jq -r '.url // empty' | head -n 1000
  fi

  echo -e "${GREEN}[✓] CommonCrawl completed${NC}" >&2
}

probe_urls() {
  local input_file=$1
  local output_file=$2

  echo -e "${CYAN}[*] Probing URLs with httpx-toolkit...${NC}" >&2

  httpx-toolkit -l "$input_file" \
    -silent \
    -threads $THREADS \
    -timeout 10 \
    -status-code \
    -title \
    -tech-detect \
    -follow-redirects \
    -o "$output_file"

  local live_count=$(wc -l < "$output_file")
  echo -e "${GREEN}[✓] Found $live_count live URLs${NC}" >&2
}

show_usage() {
  echo -e "${GREEN}Enhanced URL Enumeration Script${NC}"
  echo ""
  echo -e "Usage: $0 -d <domain> -o <output_file> [OPTIONS]"
  echo ""
}

while getopts ":d:o:pt:h" opt; do
  case $opt in
    d) domain=$OPTARG ;;
    o) output_file=$OPTARG ;;
    p) PROBE_URLS=true ;;
    t) THREADS=$OPTARG ;;
    h) show_usage; exit ;;
  esac
done

if [[ -z "$domain" || -z "$output_file" ]]; then
  echo -e "${RED}Error: Both domain and output file required${NC}"
  show_usage
  exit 1
fi

for cmd in jq curl; do
  if ! command -v $cmd &>/dev/null; then
    echo -e "${RED}Error: $cmd missing${NC}"
    exit 1
  fi
done

echo -e "${BLUE}[*] Target: $domain${NC}"

RAW_URLS="$TEMP_DIR/raw_urls.txt"

### RUN ALL FETCHERS IN PARALLEL — INCLUDING SUBFINDER ###
{
  fetch_subfinder "$domain" &
  fetch_alienvault_urls "$domain" &
  fetch_virustotal_urls "$domain" &
  fetch_wayback_urls "$domain" &
  fetch_commoncrawl_urls "$domain" &
  wait
} | grep -E '\?.*=' | sort -u > "$RAW_URLS"

raw_count=$(wc -l < "$RAW_URLS")
echo -e "${GREEN}[✓] Collected $raw_count unique parameterized URLs${NC}"

if [[ "$PROBE_URLS" == true ]]; then
  probe_urls "$RAW_URLS" "$output_file"
else
  cp "$RAW_URLS" "$output_file"
fi

final_count=$(wc -l < "$output_file")
echo -e "${GREEN}[✓] Final URLs: $final_count${NC}"
