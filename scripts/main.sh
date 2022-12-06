#!/bin/bash

export MODE
export CCC
export BIT
export RUN

. param.sh
. setup.sh
. run.sh
. stats.sh

main_over_nbits() {
    for i in ${!CCS[@]}; do
        CCC=${CCS[$i]}
        for j in ${!BITS[@]}; do
            BIT=${BITS[$j]}

            teardown
            prepare_hosts
            setup_aqm

            sleep 1

	    load_rina_stuff

            echo "Starting iperf instances"
            for run in $(seq 1 $COUNT); do
                RUN=$run
                run_rinaperf
                sleep 5
            done
        done
    done
    # collect_stats
    # python plot_qdisc.py $LOG_FILE
    # extract_stats
    # plot_stats
}

main() {
    MODE="over_nbits"
    main_over_nbits

    echo "It is finished!"
}

main
