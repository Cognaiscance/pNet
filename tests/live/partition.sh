#!/usr/bin/env bash
# Real network partition via nftables, applied on a root-capable host. Drops UDP
# (both directions) between that host and a given peer IP, isolating the SG↔SG
# link while both SGs keep running — the live analogue of stage-c's relay pause.
#
# Heal = remove the rule; convergence then flows through the 60s periodic merge
# tick (PARTITION_RECONCILE_INTERVAL) — for WAN/NAT peers, once the isolated SG
# re-initiates to the anchor.
#
# Usage:
#   bash partition.sh cut  <ssh_host> <peer_ip> [udp_port]   # default port 7777
#   bash partition.sh heal <ssh_host>
#   bash partition.sh show <ssh_host>
#
# Examples (current topology uses public path; tealface has no house-LAN route):
#   House LAN peer:  bash partition.sh cut  zeus 192.168.1.40 7777
#   Office "WAN down" is usually: drop UDP to the public IP on tealface, e.g.
#     bash partition.sh cut tealface $(getent ahostsv4 pnet.thehomegarage.com | awk '{print $1; exit}') 7777
#   heal: bash partition.sh heal tealface

cd "$(dirname "$0")"
source hosts.env 2>/dev/null || true
source lib.sh    2>/dev/null || { SSH_OPTS=(-o ConnectTimeout=8 -o BatchMode=yes); }

TABLE="pnet_live_partition"
action="${1:?cut|heal|show}"; host="${2:?ssh_host}"

case "$action" in
  cut)
    peer="${3:?peer_ip}"; port="${4:-7777}"
    echo "[partition] cutting UDP/$port between $host and $peer (nft table $TABLE)"
    ssh "${SSH_OPTS[@]}" "$host" "
      nft list table inet $TABLE >/dev/null 2>&1 && nft delete table inet $TABLE
      nft add table inet $TABLE
      nft add chain inet $TABLE out '{ type filter hook output priority 0; }'
      nft add chain inet $TABLE in  '{ type filter hook input  priority 0; }'
      nft add rule  inet $TABLE out ip daddr $peer udp dport $port drop
      nft add rule  inet $TABLE out ip daddr $peer udp sport $port drop
      nft add rule  inet $TABLE in  ip saddr $peer udp sport $port drop
      nft add rule  inet $TABLE in  ip saddr $peer udp dport $port drop
      echo applied; nft list table inet $TABLE
    " || die "nft cut failed on $host (root + nft required)"
    ;;
  heal)
    echo "[partition] healing $host (removing nft table $TABLE)"
    ssh "${SSH_OPTS[@]}" "$host" "nft delete table inet $TABLE 2>/dev/null && echo healed || echo 'no table (already healed)'"
    ;;
  show)
    ssh "${SSH_OPTS[@]}" "$host" "nft list table inet $TABLE 2>/dev/null || echo 'no partition table present'"
    ;;
  *) die "unknown action: $action (cut|heal|show)";;
esac
