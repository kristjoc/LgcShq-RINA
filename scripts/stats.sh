#!/bin/bash

. param.sh

collect_stats() {
    # collect rinaperf stats from client hosts (epona for now)
    for host in epona
    do
        ssh ${host} " rename -v 's/.dat/.dat.${host}/' rinaperf_${MODE}_*"
        ssh ${host} "tar -cvf rinaperf_${MODE}_${host}.tar.gz rinaperf_${MODE}_* --remove-files"
        scp ${host}://home/ocarina/rinaperf_${MODE}_${host}.tar.gz .
        tar -xvf rinaperf_${MODE}_${host}.tar.gz
        rm -f rinaperf_${MODE}_${host}.tar.gz
        ssh ${host} "rm -f rinaperf_${MODE}_${host}.tar.gz"
    done

    # collect cwnd stats from client hosts
    for host in hylia
    do
        ssh ${host} " rename -v 's/.dat/.dat.${host}/' ${MODE}_*"
        ssh ${host} "tar -cvf ${MODE}_${host}.tar.gz ${MODE}_* --remove-files"
        scp ${host}://home/ocarina/${MODE}_${host}.tar.gz .
        tar -xvf ${MODE}_${host}.tar.gz
        rm -f ${MODE}_${host}.tar.gz
        ssh ${host} "rm -f ${MODE}_${host}.tar.gz"
    done

    # Try to kill rinaperf server
    CMD_KILL_RINAPERF="sudo pkill -2 rinaperf"
    ssh hylia $CMD_KILL_RINAPERF
}

extract_stats() {
    if [[ "${MODE}" == "cwnd_over_nbits" ]]; then
        extract_cwnd_over_nbits
    fi
}

extract_cwnd_over_nbits() {
    # original file
    # ts,cep-id,cwnd ts,cep-id,cwnd
    filename=("${MODE}_")
    for b in ${!BITS[@]}; do
	nbits=${BITS[$b]}
	for run in $(seq 1 $COUNT); do
            for f in ${!filename[@]}; do
                myfilenames=`ls | grep ${filename[$f]}${CCC}_BITS_${nbits}_RATE_${RATE}_RUN`
                for eachfile in $myfilenames; do
		    awk '{print $2}' $eachfile > tmp.dat && mv tmp.dat $eachfile
                done
            done
        done
    done
}


plot_stats() {
    if [ $MODE = 'cwnd_over_nbits' ]; then
        echo -n "Plotting cwnd over nbits"
        python3 plot_all.py 'cwnd_over_nbits' "${BIT}" "${RATE}" "${RUN}"
    fi
}
