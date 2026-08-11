#!/bin/bash
#
# Cron-based auto-unblock for the direct-block architecture.
#
# Runs every minute (via crontab). Tracks the LATEST block timestamp
# per unique IP (not every historical line - see lessons-learned.md
# for the bug this fixes) and removes any iptables DROP rule once its
# most recent block has exceeded TIMEOUT_SECONDS.
#
# Built as a reliable replacement for Wazuh's native stateful Active
# Response timeout mechanism, which was found to be unreliable in
# this deployment (see docs/lessons-learned.md for the full
# troubleshooting story).

LOG="/var/ossec/logs/active-responses.log"
TIMEOUT_SECONDS=600

declare -A latest_block_time

while read -r line; do
    if [[ "$line" == *"BLOCKED"* ]] && [[ "$line" != *"UNBLOCKED"* ]]; then
        ts=$(echo "$line" | awk '{print $1" "$2}')
        ip=$(echo "$line" | awk '{print $NF}')
        epoch=$(date -d "${ts//\//-}" +%s 2>/dev/null)
        latest_block_time["$ip"]="$epoch"
    fi
done < "$LOG"

now_epoch=$(date +%s)

for ip in "${!latest_block_time[@]}"; do
    block_epoch="${latest_block_time[$ip]}"
    age=$((now_epoch - block_epoch))

    if [ "$age" -ge "$TIMEOUT_SECONDS" ]; then
        if iptables -L INPUT -n | grep -q "$ip"; then
            iptables -D INPUT -s "$ip" -j DROP
            echo "$(date '+%Y/%m/%d %H:%M:%S') threat-intel-cleanup: UNBLOCKED $ip (age ${age}s, timeout reached)" >> "$LOG"
        fi
    fi
done
