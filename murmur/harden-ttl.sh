#!/usr/bin/env bash
# Normalise the Pi's outgoing IPv4 TTL so its flows don't cluster apart from
# the household's (mostly Windows = 128) devices. Run as root (via sudo).
#   harden-ttl.sh on    -> apply rule, persist flag
#   harden-ttl.sh off   -> remove rule, clear flag
set -e
TTL=128
FLAG=/var/lib/murmur/ttl.on
mkdir -p /var/lib/murmur

apply_nft() {
  nft list table ip murmur >/dev/null 2>&1 || nft add table ip murmur
  nft 'add chain ip murmur postrouting { type filter hook postrouting priority mangle ; }' 2>/dev/null || true
  nft flush chain ip murmur postrouting
  nft add rule ip murmur postrouting ip ttl set $TTL
}
remove_nft() { nft delete table ip murmur 2>/dev/null || true; }

apply_ipt() { iptables -t mangle -C POSTROUTING -j TTL --set-ttl $TTL 2>/dev/null \
  || iptables -t mangle -A POSTROUTING -j TTL --set-ttl $TTL; }
remove_ipt() { iptables -t mangle -D POSTROUTING -j TTL --set-ttl $TTL 2>/dev/null || true; }

case "$1" in
  on)
    if command -v nft >/dev/null 2>&1 && apply_nft 2>/dev/null; then
      echo "TTL set to $TTL via nftables"
    elif command -v iptables >/dev/null 2>&1 && apply_ipt 2>/dev/null; then
      echo "TTL set to $TTL via iptables"
    else
      echo "ERROR: no working TTL target (need nftables or iptables xt_HL)"; exit 1
    fi
    touch "$FLAG" ;;
  off)
    remove_nft; remove_ipt; rm -f "$FLAG"; echo "TTL rule removed" ;;
  *) echo "usage: $0 on|off"; exit 2 ;;
esac
