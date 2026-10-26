#!/usr/bin/env bash
# netfilter.sh — CIDR containment helpers for CORP_EXCLUDE_SUBNETS.
# Pure bash, no external tools; safe to source from route-up.sh and tests.

# ip_to_int "a.b.c.d" -> prints decimal int, returns non-zero on garbage
ip_to_int() {
  local IFS=. a b c d
  read -r a b c d <<<"$1" || return 1
  for v in "$a" "$b" "$c" "$d"; do [[ $v =~ ^[0-9]+$ ]] && (( v <= 255 )) || return 1; done
  echo $(( a << 24 | b << 16 | c << 8 | d ))
}

# net_in_prefix NET PREFIX: 0 (true) if NET (CIDR a.b.c.d/n) lies inside PREFIX (CIDR)
net_in_prefix() {
  local net=$1 pre=$2 na pa nb pb mask
  [[ $net == */* && $pre == */* ]] || return 1
  na=$(ip_to_int "${net%/*}") || return 1
  pa=$(ip_to_int "${pre%/*}") || return 1
  nb=${net#*/}; pb=${pre#*/}
  [[ $nb =~ ^[0-9]+$ && $pb =~ ^[0-9]+$ ]] && (( nb <= 32 && pb <= 32 )) || return 1
  if (( pb == 0 )); then mask=0; else mask=$(( (0xFFFFFFFF << (32 - pb)) & 0xFFFFFFFF )); fi
  (( (na & mask) == (pa & mask) ))
}

# filter_excluded EXCLUDE_LIST NET... : prints NETs not inside any exclude prefix;
# malformed exclude entries are skipped with a warning on stderr
filter_excluded() {
  local excl=$1; shift
  local e net bad
  local -a exs=()
  for e in $excl; do
    if net_in_prefix "$e" "$e" 2>/dev/null; then exs+=("$e"); else
      echo "invalid CORP_EXCLUDE_SUBNETS entry: $e" >&2; fi
  done
  for net in "$@"; do
    bad=0
    for e in ${exs[@]+"${exs[@]}"}; do
      if net_in_prefix "$net" "$e"; then bad=1; break; fi
    done
    (( bad )) || printf '%s\n' "$net"
  done
}
