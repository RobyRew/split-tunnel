#!/usr/bin/env bash
# SplitTunnel egress allowlist.
#
# Restricts what the TUNNEL USER may reach, by UID, without touching any other
# traffic on the host. Both IPv4 and IPv6 are enforced: a dual-stack host will
# happily reach a CDN over IPv6, so an IPv4-only allowlist enforces nothing.
#
# Idempotent. Safe to run on a timer. ENABLED=no removes the rules cleanly.
set -uo pipefail

# Serialise: the timer and a manual run overlapping produced duplicated rules
# and two OUTPUT hooks. flock makes concurrent invocations wait instead.
LOCK=/run/split-tunnel-egress.lock
if [ "${_ST_LOCKED:-}" != "1" ]; then
  export _ST_LOCKED=1
  exec flock -w 60 "$LOCK" "$0" "$@"
fi

CONF="${CONF:-/etc/split-tunnel/egress.conf}"
[ -r "$CONF" ] || { echo "[egress] no config at $CONF"; exit 0; }
# shellcheck disable=SC1090
. "$CONF"

CHAIN=SPLITTUNNEL
SET4=splittunnel-allow4
SET6=splittunnel-allow6

unhook() {
  local ipt="$1"
  # Delete EVERY copy, not just one: a previous racing run may have inserted
  # the hook more than once, and -D removes a single instance per call.
  while $ipt -C OUTPUT -m owner --uid-owner "$UID_OWNER" -j "$CHAIN" 2>/dev/null; do
    $ipt -D OUTPUT -m owner --uid-owner "$UID_OWNER" -j "$CHAIN" 2>/dev/null || break
  done
}

teardown() {
  for ipt in iptables ip6tables; do
    unhook "$ipt"
    $ipt -F "$CHAIN" 2>/dev/null
    $ipt -X "$CHAIN" 2>/dev/null
  done
  echo "[egress] disabled — tunnel traffic unrestricted"
}

if [ "${ENABLED:-no}" != "yes" ]; then
  teardown
  exit 0
fi

command -v ipset >/dev/null 2>&1 || { echo "[egress] ipset not installed" >&2; exit 1; }

ipset create "$SET4" hash:ip  family inet  timeout 86400 -exist
ipset create "$SET6" hash:ip  family inet6 timeout 86400 -exist

# Resolve the allowlist. Entries carry a TTL, so addresses a CDN stops using
# age out on their own rather than accumulating for ever.
n4=0; n6=0
for d in $DOMAINS; do
  [ -z "$d" ] && continue
  while read -r ip; do
    [ -n "$ip" ] && ipset add "$SET4" "$ip" timeout 86400 -exist && n4=$((n4+1))
  done < <(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u)
  while read -r ip; do
    [ -n "$ip" ] && ipset add "$SET6" "$ip" timeout 86400 -exist && n6=$((n6+1))
  done < <(getent ahostsv6 "$d" 2>/dev/null | awk '{print $1}' | sort -u)
done

build_chain() {
  local ipt="$1" set="$2"
  $ipt -N "$CHAIN" 2>/dev/null || $ipt -F "$CHAIN"
  # Established first, or we cut the tunnel's own SSH session to the client.
  $ipt -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $ipt -A "$CHAIN" -o lo -j ACCEPT
  $ipt -A "$CHAIN" -p udp --dport 53 -j ACCEPT
  $ipt -A "$CHAIN" -p tcp --dport 53 -j ACCEPT
  $ipt -A "$CHAIN" -m set --match-set "$set" dst -j ACCEPT
  # Rate-limited log makes "what did I forget to allow" answerable.
  $ipt -A "$CHAIN" -m limit --limit 6/min -j LOG --log-prefix "SPLITTUNNEL-DROP " --log-level 4
  $ipt -A "$CHAIN" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
    || $ipt -A "$CHAIN" -j REJECT
  # Hook it to the tunnel UID only. Nothing else on the host is affected.
  # Drop any existing copies first so repeat runs cannot stack them up.
  unhook "$ipt"
  $ipt -I OUTPUT -m owner --uid-owner "$UID_OWNER" -j "$CHAIN"
}

build_chain iptables  "$SET4"
build_chain ip6tables "$SET6"

echo "[egress] enforcing for uid $UID_OWNER — $(ipset list "$SET4" | grep -c '^[0-9]') v4 / $(ipset list "$SET6" | grep -c ':') v6 addresses"
