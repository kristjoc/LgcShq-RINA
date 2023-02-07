#!/usr/bin/env bash

IPCP_ID=$1

STATS_PATH="/sys/rina/ipcps/${IPCP_ID}/connections/*/dtcp/rcvr_credit"
INTERVAL='0.001'

while true; do
    BEFORE=$(date +%s.%N)
    path=$(echo $STATS_PATH)
    if [ "$path" != "$STATS_PATH" ]; then
        grep "" $path | sed -e "s@/sys/rina/ipcps/${IPCP_ID}/connections/@@" \
-e "s@/dtcp/rcvr_credit@@" | awk 'BEGIN { FS=":"; } { print "'$BEFORE',"$1","$2 }'
    fi
    AFTER=`date +%s.%N`
    SLEEP_TIME=`echo $BEFORE $AFTER $INTERVAL | awk '{ st = $3 - ($2 - $1) ; \
if ( st < 0 ) st = 0 ; print st }'`
    sleep $SLEEP_TIME
done
