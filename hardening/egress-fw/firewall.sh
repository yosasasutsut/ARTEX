#!/bin/sh
# Network-level egress firewall for the ARTEX container (hardening pass; not upstream).
#
# This container OWNS the network namespace. The artex service joins it with
# `network_mode: service:egress-fw` and has no NET_ADMIN capability, so nothing
# inside artex (the server, an agent shell, a tool such as curl or nmap) can
# change these rules.
#
# Outbound traffic is rejected unless it goes to:
#   - loopback
#   - an established connection (replies to the published UI port)
#   - FW_INTERNAL_HOSTS   services of this compose project (postgres)   SERVER ONLY
#   - FW_ALLOW_HOSTS      control-plane hosts (LLM, search ...), TCP 80/443   SERVER ONLY
#   - FW_TARGETS          pentest targets: IPs, CIDRs or host names, any protocol, any user
#
# "SERVER ONLY" means the rule matches only sockets owned by FW_SERVER_UID (the
# artex server, root). Agent shells and tools run as another user, so a hijacked
# agent can reach neither the database port nor the LLM provider (which it could
# otherwise use as an exfiltration channel with its own API key).
#
# DNS (FW_DNS=filter, the default): every DNS query in the namespace is redirected
# to a local dnsmasq that answers only for the names listed above (and their
# subdomains) plus FW_DNS_ALLOW, and refuses the rest. This closes DNS tunnelling
# through Docker's resolver. FW_DNS=open leaves Docker's resolver untouched.
#
# Host names are resolved now and again every FW_REFRESH seconds; addresses seen
# earlier stay allowed, so a CDN that rotates addresses does not flap.
#
# Limit: an allowed host name admits every site served from the same IP address.
set -eu

FW_ALLOW_HOSTS="${FW_ALLOW_HOSTS:-}"
FW_TARGETS="${FW_TARGETS:-}"
FW_INTERNAL_HOSTS="${FW_INTERNAL_HOSTS:-postgres}"
FW_DNS_ALLOW="${FW_DNS_ALLOW:-}"
FW_DNS="${FW_DNS:-filter}"
FW_SERVER_UID="${FW_SERVER_UID:-0}"
FW_REFRESH="${FW_REFRESH:-60}"
STATE=/run/artex-fw
READY=/run/fw-ready
CHAIN=ARTEX_OUT
DNS_PORT=5353
DOCKER_DNS=127.0.0.11

log() { echo "[egress-fw] $*"; }

# Pick the iptables backend the kernel accepts.
IPT=""
for c in iptables iptables-legacy; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -w -L OUTPUT -n >/dev/null 2>&1; then IPT="$c"; break; fi
done
[ -n "$IPT" ] || { log "no usable iptables (is NET_ADMIN granted?)"; exit 1; }
RESTORE="${IPT}-restore"
log "using $IPT"

words() { printf '%s' "$1" | tr ',;' '  ' | tr -s ' \t\n' '\n' | sed '/^$/d'; }
is_name() { case "$1" in *[!0-9./]*) return 0 ;; *) return 1 ;; esac; }

# resolve prints the IPv4 addresses (or the CIDR itself) for one entry.
resolve() {
  if is_name "$1"; then getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u; else echo "$1"; fi
}

# collect resolves every entry of a list and unions the result into a state file.
collect() { # $1 = list, $2 = state file name
  f="$STATE/$2"
  touch "$f"
  for e in $(words "$1"); do
    r="$(resolve "$e" || true)"
    if [ -z "$r" ]; then log "cannot resolve $e yet"; continue; fi
    echo "$r" >> "$f"
  done
  sort -u "$f" -o "$f"
}

apply() {
  {
    echo "*filter"
    echo ":$CHAIN - [0:0]"
    echo "-A $CHAIN -o lo -j ACCEPT"
    echo "-A $CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    while read -r ip; do [ -n "$ip" ] && echo "-A $CHAIN -d $ip -m owner --uid-owner $FW_SERVER_UID -j ACCEPT"; done < "$STATE/internal"
    while read -r ip; do [ -n "$ip" ] && echo "-A $CHAIN -d $ip -p tcp -m multiport --dports 80,443 -m owner --uid-owner $FW_SERVER_UID -j ACCEPT"; done < "$STATE/allow"
    while read -r ip; do [ -n "$ip" ] && echo "-A $CHAIN -d $ip -j ACCEPT"; done < "$STATE/targets"
    echo "-A $CHAIN -p tcp -j REJECT --reject-with tcp-reset"
    echo "-A $CHAIN -j REJECT --reject-with icmp-port-unreachable"
    echo "COMMIT"
  } | "$RESTORE" -w --noflush
}

mkdir -p "$STATE"
: > "$STATE/internal"; : > "$STATE/allow"; : > "$STATE/targets"

# Lock down first: only loopback and established traffic, before any name is resolved.
"$IPT" -w -N "$CHAIN" 2>/dev/null || true
apply
"$IPT" -w -C OUTPUT -j "$CHAIN" 2>/dev/null || "$IPT" -w -A OUTPUT -j "$CHAIN"

# IPv6 is not used by this deployment: drop it outright except loopback.
for c in ip6tables ip6tables-legacy; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -w -L OUTPUT -n >/dev/null 2>&1; then
    "$c" -w -P OUTPUT DROP
    "$c" -w -C OUTPUT -o lo -j ACCEPT 2>/dev/null || "$c" -w -A OUTPUT -o lo -j ACCEPT
    log "IPv6 egress dropped ($c)"
    break
  fi
done

# ---- DNS filter -------------------------------------------------------------
DNS_UID=""
start_dns_filter() {
  DNS_UID="$(id -u dnsmasq)"
  # The redirect must sit in the same nat table Docker used for its embedded
  # resolver, ahead of Docker's own rule.
  NAT=""
  for c in iptables iptables-legacy; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -w -t nat -S 2>/dev/null | grep -q "$DOCKER_DNS"; then NAT="$c"; break; fi
  done
  [ -n "$NAT" ] || NAT="$IPT"
  set -- --keep-in-foreground --no-resolv --no-hosts --no-poll --port="$DNS_PORT" \
    --listen-address=127.0.0.1 --bind-interfaces --cache-size=500 --log-facility=- --user=dnsmasq --group=dnsmasq
  n=0
  for e in $(words "$FW_INTERNAL_HOSTS $FW_ALLOW_HOSTS $FW_TARGETS $FW_DNS_ALLOW"); do
    is_name "$e" || continue
    set -- "$@" "--server=/${e#.}/$DOCKER_DNS"
    n=$((n + 1))
  done
  dnsmasq "$@" &
  # Everyone except dnsmasq itself is redirected to the filter, for UDP and TCP.
  for p in udp tcp; do
    "$NAT" -w -t nat -C OUTPUT -p "$p" --dport 53 -m owner ! --uid-owner "$DNS_UID" -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null \
      || "$NAT" -w -t nat -I OUTPUT 1 -p "$p" --dport 53 -m owner ! --uid-owner "$DNS_UID" -j REDIRECT --to-ports "$DNS_PORT"
  done
  log "DNS filter on ($NAT): $n name(s) resolvable, everything else refused"
}

case "$FW_DNS" in
  filter) start_dns_filter ;;
  open) log "DNS filter off (FW_DNS=open): any name resolves through Docker's resolver" ;;
  *) log "unknown FW_DNS=$FW_DNS; using filter"; start_dns_filter ;;
esac

refresh() {
  collect "$FW_INTERNAL_HOSTS" internal
  collect "$FW_ALLOW_HOSTS" allow
  collect "$FW_TARGETS" targets
  apply
}

# dnsmasq needs a moment before the first lookups go through it.
sleep 1
refresh
log "rules applied: internal=$(wc -l < "$STATE/internal") control-plane=$(wc -l < "$STATE/allow") targets=$(wc -l < "$STATE/targets")"
log "control-plane hosts (server uid $FW_SERVER_UID only, TCP 80/443): ${FW_ALLOW_HOSTS:-<none>}"
log "targets (any user, any port): ${FW_TARGETS:-<none>}"
touch "$READY"

trap 'exit 0' TERM INT
while :; do
  sleep "$FW_REFRESH" &
  wait $!
  refresh || log "refresh failed; previous rules stay in force"
done
