#!/usr/bin/env bash
# netfilter_test.sh — tests for netfilter.sh (CORP_EXCLUDE_SUBNETS filtering).
# Plain bash, no external tools; prints NETFILTER_OK and exits 0 on success.
set -u

dir="${BASH_SOURCE[0]%/*}"
[[ $dir == "${BASH_SOURCE[0]}" ]] && dir=.
LIB="$dir/netfilter.sh"

FAILED=0

assert_eq() { # DESC EXPECTED ACTUAL
  if [[ "$3" == "$2" ]]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1: want [$2] got [$3]" >&2
    FAILED=1
  fi
}

assert_contains() { # DESC SUBSTRING HAYSTACK
  if [[ "$3" == *"$2"* ]]; then
    echo "ok   - $1"
  else
    echo "FAIL - $1: [$2] missing in [$3]" >&2
    FAILED=1
  fi
}

[[ -f $LIB ]] || { echo "FAIL - library not found: $LIB" >&2; exit 1; }
# shellcheck source=netfilter.sh
source "$LIB"

# exact match excluded
assert_eq "exact match excluded" "" \
  "$(filter_excluded "10.52.0.0/16" "10.52.0.0/16")"

# contained candidate removed
assert_eq "contained candidate removed" "" \
  "$(filter_excluded "10.52.0.0/16" "10.52.3.0/24")"

# non-overlapping kept
assert_eq "non-overlapping kept" "10.53.0.0/24" \
  "$(filter_excluded "10.52.0.0/16" "10.53.0.0/24")"

# broader candidate kept (documented semantics: no prefix splitting)
assert_eq "broader candidate kept" "10.0.0.0/8" \
  "$(filter_excluded "10.52.0.0/16" "10.0.0.0/8")"

# empty exclude list keeps everything
assert_eq "empty exclude list keeps everything" $'10.52.0.0/16\n10.53.0.0/24' \
  "$(filter_excluded "" "10.52.0.0/16" "10.53.0.0/24")"

# CORP_EXCLUDE_SUBNETS is a whitespace-separated list: every prefix applies
assert_eq "multiple excludes from one list" "10.53.0.0/24" \
  "$(filter_excluded "10.52.0.0/16 172.16.0.0/12" "10.52.3.0/24" "10.53.0.0/24" "172.16.5.0/24")"

# malformed exclude entry (missing /len): warning on stderr, entry skipped
err="$(filter_excluded "10.52.0.0" "10.53.0.0/24" 2>&1 >/dev/null)"
assert_contains "malformed entry warns" "invalid CORP_EXCLUDE_SUBNETS entry:" "$err"
assert_eq "malformed entry skipped" "10.53.0.0/24" \
  "$(filter_excluded "10.52.0.0" "10.53.0.0/24")"

if (( FAILED )); then
  echo "netfilter_test: FAILURES" >&2
  exit 1
fi
echo "NETFILTER_OK"
