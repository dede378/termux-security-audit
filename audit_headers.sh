#!/usr/bin/env bash
set -u

VERSION="1.0.0"
MAX_TIME=15

usage() {
  printf '%s\n' "Usage: $0 <URL>"
  printf '%s\n' "Example: $0 https://example.com"
}

if [ "$#" -ne 1 ]; then
  usage
  exit 2
fi

URL="$1"

case "$URL" in
  http://*|https://*) ;;
  *)
    printf '[FAIL] Invalid URL. Use http:// or https://\n'
    exit 2
    ;;
esac

TMP_HEADERS="$(mktemp)"
TMP_BODY="$(mktemp)"
cleanup() {
  rm -f "$TMP_HEADERS" "$TMP_BODY"
}
trap cleanup EXIT INT TERM

printf '\n'
printf '%s\n' '╔══════════════════════════════════════════════╗'
printf '%s\n' '║        TERMUX SECURITY AUDIT v1.0.0        ║'
printf '%s\n' '╚══════════════════════════════════════════════╝'
printf '\nTarget : %s\n' "$URL"

CURL_META="$(curl -sS -L --max-time "$MAX_TIME" -D "$TMP_HEADERS" -o "$TMP_BODY" -w '%{http_code}\n%{url_effective}' "$URL" 2>/dev/null)"
CURL_STATUS=$?

if [ "$CURL_STATUS" -ne 0 ]; then
  printf '[FAIL] Unable to connect to target (curl exit %s)\n' "$CURL_STATUS"
  exit 1
fi

HTTP_CODE="$(printf '%s\n' "$CURL_META" | sed -n '1p')"
EFFECTIVE_URL="$(printf '%s\n' "$CURL_META" | sed -n '2p')"

printf 'Status : %s\n' "$HTTP_CODE"
printf 'Final  : %s\n' "$EFFECTIVE_URL"

if printf '%s' "$EFFECTIVE_URL" | grep -qi '^https://'; then
  HTTPS="yes"
else
  HTTPS="no"
fi
printf 'HTTPS  : %s\n' "$HTTPS"

header_value() {
  awk -v name="$1" '
    BEGIN { IGNORECASE=1 }
    tolower($0) ~ "^" tolower(name) "[[:space:]]*:" {
      sub(/^[^:]*:[[:space:]]*/, "", $0)
      print
      exit
    }
  ' "$TMP_HEADERS"
}

has_header() {
  [ -n "$(header_value "$1")" ]
}

check_header() {
  local name="$1"
  local label="$2"
  local value
  value="$(header_value "$name")"
  if [ -n "$value" ]; then
    printf '[PASS] %-28s %s\n' "$label" "$value"
    PASS=$((PASS + 1))
  else
    printf '[FAIL] %-28s missing\n' "$label"
    FAIL=$((FAIL + 1))
  fi
}

PASS=0
WARN=0
FAIL=0
INFO=0

printf '\n%s\n' 'SECURITY HEADERS'
printf '%s\n' '──────────────────────────────────────────────'

if [ "$HTTPS" = "yes" ]; then
  HSTS="$(header_value "Strict-Transport-Security")"
  if [ -n "$HSTS" ]; then
    printf '[PASS] %-28s %s\n' 'HSTS' "$HSTS"
    PASS=$((PASS + 1))
  else
    printf '[FAIL] %-28s missing on HTTPS\n' 'HSTS'
    FAIL=$((FAIL + 1))
  fi
else
  printf '[WARN] %-28s target is not HTTPS\n' 'HSTS'
  WARN=$((WARN + 1))
fi

CSP="$(header_value "Content-Security-Policy")"
if [ -n "$CSP" ]; then
  printf '[PASS] %-28s configured\n' 'Content-Security-Policy'
  PASS=$((PASS + 1))
else
  printf '[WARN] %-28s missing\n' 'Content-Security-Policy'
  WARN=$((WARN + 1))
fi

XFO="$(header_value "X-Frame-Options")"
if [ -n "$XFO" ]; then
  printf '[PASS] %-28s %s\n' 'X-Frame-Options' "$XFO"
  PASS=$((PASS + 1))
elif printf '%s' "$CSP" | grep -qi 'frame-ancestors'; then
  printf '[PASS] %-28s CSP frame-ancestors\n' 'Clickjacking protection'
  PASS=$((PASS + 1))
else
  printf '[FAIL] %-28s missing\n' 'Clickjacking protection'
  FAIL=$((FAIL + 1))
fi

XCTO="$(header_value "X-Content-Type-Options")"
if printf '%s' "$XCTO" | grep -qi '^nosniff[[:space:]]*$'; then
  printf '[PASS] %-28s nosniff\n' 'X-Content-Type-Options'
  PASS=$((PASS + 1))
elif [ -n "$XCTO" ]; then
  printf '[WARN] %-28s %s\n' 'X-Content-Type-Options' "$XCTO"
  WARN=$((WARN + 1))
else
  printf '[FAIL] %-28s missing\n' 'X-Content-Type-Options'
  FAIL=$((FAIL + 1))
fi

check_header "Referrer-Policy" "Referrer-Policy"
check_header "Permissions-Policy" "Permissions-Policy"

for pair in \
  "Cross-Origin-Opener-Policy|COOP" \
  "Cross-Origin-Resource-Policy|CORP"
do
  NAME="${pair%%|*}"
  LABEL="${pair#*|}"
  check_header "$NAME" "$LABEL"
done

printf '\n%s\n' 'CORS'
printf '%s\n' '──────────────────────────────────────────────'
CORS="$(header_value "Access-Control-Allow-Origin")"
if [ -z "$CORS" ]; then
  printf '[INFO] %-28s not present\n' 'Access-Control-Allow-Origin'
  INFO=$((INFO + 1))
elif [ "$CORS" = "*" ]; then
  printf '[WARN] %-28s wildcard (*)\n' 'CORS'
  WARN=$((WARN + 1))
else
  printf '[PASS] %-28s %s\n' 'CORS' "$CORS"
  PASS=$((PASS + 1))
fi

printf '\n%s\n' 'COOKIES'
printf '%s\n' '──────────────────────────────────────────────'
COOKIE_LINES="$(grep -i '^Set-Cookie:' "$TMP_HEADERS" || true)"
if [ -z "$COOKIE_LINES" ]; then
  printf '[INFO] No Set-Cookie header observed\n'
  INFO=$((INFO + 1))
else
  COOKIE_INDEX=0
  while IFS= read -r cookie; do
    [ -z "$cookie" ] && continue
    COOKIE_INDEX=$((COOKIE_INDEX + 1))
    COOKIE_NAME="$(printf '%s' "$cookie" | sed -E 's/^[^:]+:[[:space:]]*([^=;]+).*/\1/')"
    printf '[INFO] Cookie %-22s ' "$COOKIE_NAME"
    FLAGS=""
    printf '%s' "$cookie" | grep -qi ';[[:space:]]*Secure\b' && FLAGS="${FLAGS} Secure"
    printf '%s' "$cookie" | grep -qi ';[[:space:]]*HttpOnly\b' && FLAGS="${FLAGS} HttpOnly"
    printf '%s' "$cookie" | grep -qi ';[[:space:]]*SameSite=' && FLAGS="${FLAGS} SameSite"
    if [ -n "$FLAGS" ]; then
      printf '%s\n' "$FLAGS"
    else
      printf '%s\n' 'no common security flags detected'
      WARN=$((WARN + 1))
    fi
  done <<< "$COOKIE_LINES"
fi

printf '\n%s\n' 'INFORMATION DISCLOSURE'
printf '%s\n' '──────────────────────────────────────────────'
SERVER="$(header_value "Server")"
POWERED="$(header_value "X-Powered-By")"

if [ -n "$SERVER" ]; then
  printf '[INFO] Server                     %s\n' "$SERVER"
  INFO=$((INFO + 1))
fi
if [ -n "$POWERED" ]; then
  printf '[WARN] X-Powered-By              %s\n' "$POWERED"
  WARN=$((WARN + 1))
fi
if [ -z "$SERVER" ] && [ -z "$POWERED" ]; then
  printf '[PASS] Server fingerprint headers not exposed\n'
  PASS=$((PASS + 1))
fi

TOTAL=$((PASS + WARN + FAIL))
if [ "$TOTAL" -gt 0 ]; then
  SCORE=$(( (PASS * 100) / TOTAL ))
else
  SCORE=0
fi

if [ "$SCORE" -ge 90 ]; then
  RATING="EXCELLENT"
elif [ "$SCORE" -ge 75 ]; then
  RATING="GOOD"
elif [ "$SCORE" -ge 50 ]; then
  RATING="NEEDS IMPROVEMENT"
else
  RATING="WEAK"
fi

printf '\n%s\n' 'SUMMARY'
printf '%s\n' '══════════════════════════════════════════════'
printf 'PASS : %s\n' "$PASS"
printf 'WARN : %s\n' "$WARN"
printf 'FAIL : %s\n' "$FAIL"
printf 'INFO : %s\n' "$INFO"
printf '\nScore  : %s/100\n' "$SCORE"
printf 'Rating : %s\n' "$RATING"

printf '\n%s\n' 'IMPORTANT'
printf '%s\n' 'This tool reports configuration findings and indicators.'
printf '%s\n' 'A missing header is not, by itself, proof of an exploitable'
printf '%s\n' 'vulnerability. Confirm application-level issues separately.'
printf '\n'
