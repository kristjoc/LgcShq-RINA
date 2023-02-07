#!/bin/bash

export RINAPERF_LOG_FILE

. param.sh

# RINAPERF
run_rinaperf() {
    RINAPERF_LOG_FILE="rinaperf_${MODE}_${RATE}_run_${RUN}.dat"
    CWND_LOG_FILE="${MODE}_${CCC}_BITS_${BIT}_RATE_${RATE}_RUN_${RUN}.dat"

    # Launch rinaperf server
    CMD="sudo nohup ${irati_root}/bin/rinaperf -l > /dev/null 2>&1 &"
    ssh $server_host $CMD
    sleep 1

    # Start congestion window logger at the sender
    CMD_CWND="nohup timeout 9s bash /home/ocarina/michal/cwnd_logger.sh 2 > ${CWND_LOG_FILE} 2>&1 &"
    parallel-ssh -i -H "hylia" -p 1 $CMD_CWND

    # Launch rinaperf client
    CMD="sudo /home/ocarina/michal/irati/bin/rinaperf -t perf -D 5 >> ${RINAPERF_LOG_FILE} 2>&1 &"
    ssh $client_host $CMD
    sleep 3
    ssh $client_host $CMD
    sleep 9
}
