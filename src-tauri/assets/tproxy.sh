#!/usr/bin/env bash
# TPROXY transparent proxy rules for clash-verge-rev (Linux only).
#
# Installed and removed through the app's elevation helper (pkexec, falling back
# to sudo). The app embeds this file and writes it to the app data dir before
# running it, so this copy in src-tauri/assets is the single source of truth.
#
# Usage:
#   tproxy.sh enable  <mark> <table> <pref> <tproxy-port> <dns-port>
#   tproxy.sh disable <mark> <table> <pref> <tproxy-port> <dns-port>
#
# Design notes:
# - PREROUTING-only: LAN clients' traffic is diverted with TPROXY (TCP+UDP) and
#   their DNS is redirected to Mihomo's `dns.listen`. Nothing touches OUTPUT, so
#   the Core's own upstream connections and this machine's traffic stay direct
#   (no TPROXY loop) - this machine should use TUN mode instead.
# - Every rule belongs to chains named CLASH_VERGE_* so `disable` can remove
#   exactly what `enable` added, and `enable` is idempotent for re-applies
#   (port changes, startup restore after a reboot).
# - Policy routing sends marked packets to a `local` route so the kernel
#   delivers them to the TPROXY socket with the original destination intact.

set -euo pipefail

ACTION="${1:?action required}"
MARK="${2:?mark required}"
TABLE="${3:?table required}"
PREF="${4:?pref required}"
TPROXY_PORT="${5:?tproxy port required}"
DNS_PORT="${6:?dns port required}"

CHAIN=CLASH_VERGE_TPROXY
DNS_CHAIN=CLASH_VERGE_DNS
FORWARD_STATE=/run/clash-verge-tproxy.ip_forward

# Resolve a netfilter/ip tool, preferring the user PATH then the usual root PATHs.
find_cmd() {
  local name=$1
  local path
  path=$(command -v "$name" 2>/dev/null || true)
  if [ -z "$path" ]; then
    for candidate in "/usr/sbin/$name" "/sbin/$name"; do
      if [ -x "$candidate" ]; then
        path=$candidate
        break
      fi
    done
  fi
  printf '%s' "$path"
}

IPTABLES=$(find_cmd iptables)
IP6TABLES=$(find_cmd ip6tables)
IP=$(find_cmd ip)

fail() {
  echo "tproxy: $*" >&2
  exit 1
}

require_iptables() {
  [ -n "$IPTABLES" ] || fail "iptables is required (install iptables or iptables-nft)"
  [ -n "$IP" ] || fail "iproute2 'ip' command is required"
}

# Create (or flush) a chain so enable() is safe to run repeatedly.
create_or_flush() {
  local tool=$1
  local table=$2
  local chain=$3
  if ! "$tool" -t "$table" -N "$chain" 2>/dev/null; then
    "$tool" -t "$table" -F "$chain"
  fi
}

hook_chain() {
  local tool=$1
  local table=$2
  local hook=$3
  local chain=$4
  if ! "$tool" -t "$table" -C "$hook" -j "$chain" 2>/dev/null; then
    "$tool" -t "$table" -A "$hook" -j "$chain"
  fi
}

enable_v4() {
  require_iptables

  # --- divert LAN TCP/UDP to the TPROXY port ---
  create_or_flush "$IPTABLES" mangle "$CHAIN"
  # Never re-divert packets this setup already marked.
  "$IPTABLES" -t mangle -A "$CHAIN" -m mark --mark "$MARK" -j RETURN
  # Keep local and LAN traffic direct.
  "$IPTABLES" -t mangle -A "$CHAIN" -m addrtype --dst-type LOCAL -j RETURN
  for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
    172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    "$IPTABLES" -t mangle -A "$CHAIN" -d "$net" -j RETURN
  done
  "$IPTABLES" -t mangle -A "$CHAIN" -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK/$MARK"
  "$IPTABLES" -t mangle -A "$CHAIN" -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK/$MARK"
  hook_chain "$IPTABLES" mangle PREROUTING "$CHAIN"

  # --- redirect LAN DNS to Mihomo's DNS listener ---
  create_or_flush "$IPTABLES" nat "$DNS_CHAIN"
  "$IPTABLES" -t nat -A "$DNS_CHAIN" -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
  "$IPTABLES" -t nat -A "$DNS_CHAIN" -p tcp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
  hook_chain "$IPTABLES" nat PREROUTING "$DNS_CHAIN"

  # --- deliver marked packets locally ---
  "$IP" rule add fwmark "$MARK" table "$TABLE" pref "$PREF" 2>/dev/null || true
  "$IP" route replace local 0.0.0.0/0 dev lo table "$TABLE"

  # --- forwarding for LAN clients that route through this host ---
  if [ -r /proc/sys/net/ipv4/ip_forward ]; then
    if [ ! -f "$FORWARD_STATE" ]; then
      printf '%s' "$(cat /proc/sys/net/ipv4/ip_forward)" >"$FORWARD_STATE" 2>/dev/null || true
    fi
    printf '%s' 1 >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  fi
}

disable_v4() {
  require_iptables

  "$IPTABLES" -t mangle -D PREROUTING -j "$CHAIN" 2>/dev/null || true
  "$IPTABLES" -t mangle -F "$CHAIN" 2>/dev/null || true
  "$IPTABLES" -t mangle -X "$CHAIN" 2>/dev/null || true

  "$IPTABLES" -t nat -D PREROUTING -j "$DNS_CHAIN" 2>/dev/null || true
  "$IPTABLES" -t nat -F "$DNS_CHAIN" 2>/dev/null || true
  "$IPTABLES" -t nat -X "$DNS_CHAIN" 2>/dev/null || true

  "$IP" rule del fwmark "$MARK" table "$TABLE" pref "$PREF" 2>/dev/null || true
  "$IP" route del local 0.0.0.0/0 dev lo table "$TABLE" 2>/dev/null || true

  if [ -f "$FORWARD_STATE" ]; then
    printf '%s' "$(cat "$FORWARD_STATE")" >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    rm -f "$FORWARD_STATE"
  fi
}

enable_v6() {
  [ -n "$IP6TABLES" ] || return 0

  create_or_flush "$IP6TABLES" mangle "$CHAIN"
  "$IP6TABLES" -t mangle -A "$CHAIN" -m mark --mark "$MARK" -j RETURN
  "$IP6TABLES" -t mangle -A "$CHAIN" -m addrtype --dst-type LOCAL -j RETURN
  for net in ::/128 ::1/128 ::ffff:0:0/96 100::/64 2001:db8::/32 2002::/16 \
    fc00::/7 fe80::/10 ff00::/8; do
    "$IP6TABLES" -t mangle -A "$CHAIN" -d "$net" -j RETURN
  done
  "$IP6TABLES" -t mangle -A "$CHAIN" -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK/$MARK"
  "$IP6TABLES" -t mangle -A "$CHAIN" -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$MARK/$MARK"
  hook_chain "$IP6TABLES" mangle PREROUTING "$CHAIN"

  create_or_flush "$IP6TABLES" nat "$DNS_CHAIN"
  "$IP6TABLES" -t nat -A "$DNS_CHAIN" -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
  "$IP6TABLES" -t nat -A "$DNS_CHAIN" -p tcp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
  hook_chain "$IP6TABLES" nat PREROUTING "$DNS_CHAIN"

  "$IP" -6 rule add fwmark "$MARK" table "$TABLE" pref "$PREF" 2>/dev/null || true
  "$IP" -6 route replace local ::/0 dev lo table "$TABLE"
}

disable_v6() {
  [ -n "$IP6TABLES" ] || return 0

  "$IP6TABLES" -t mangle -D PREROUTING -j "$CHAIN" 2>/dev/null || true
  "$IP6TABLES" -t mangle -F "$CHAIN" 2>/dev/null || true
  "$IP6TABLES" -t mangle -X "$CHAIN" 2>/dev/null || true

  "$IP6TABLES" -t nat -D PREROUTING -j "$DNS_CHAIN" 2>/dev/null || true
  "$IP6TABLES" -t nat -F "$DNS_CHAIN" 2>/dev/null || true
  "$IP6TABLES" -t nat -X "$DNS_CHAIN" 2>/dev/null || true

  "$IP" -6 rule del fwmark "$MARK" table "$TABLE" pref "$PREF" 2>/dev/null || true
  "$IP" -6 route del local ::/0 dev lo table "$TABLE" 2>/dev/null || true
}

case "$ACTION" in
enable)
  enable_v4
  enable_v6
  echo "TPROXY enabled: tproxy-port=$TPROXY_PORT dns-port=$DNS_PORT mark=$MARK table=$TABLE"
  ;;
disable)
  disable_v4
  disable_v6
  echo "TPROXY disabled"
  ;;
*)
  fail "unknown action '$ACTION' (expected enable|disable)"
  ;;
esac
