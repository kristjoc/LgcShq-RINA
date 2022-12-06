#!/bin/bash

. param.sh
. utils.sh

teardown() {

    unload_modules
    teardown_router
    set_cpufreq_scaling "reset" 10

    sleep 3
}

prepare_hosts() {
    hosts=($server_host $client_host)

    CMD='sudo sysctl -w net.ipv4.tcp_ecn=1;
         sudo sysctl -w net.ipv4.tcp_ecn_fallback=0;
         sudo ethtool -K 10Ge tso off;
         sudo ethtool -K 10Ge gso off;
         sudo ethtool -K 10Ge lro off;
         sudo ethtool -K 10Ge gro off;
         sudo ethtool -K 10Ge ufo off;
         sudo sysctl -w net.ipv4.tcp_window_scaling=1;
         sudo tc qdisc del dev 10Ge root;
         sudo tc qdisc del dev 10Ge root fq;
         sudo ip link set dev 10Ge gso_max_size 1514;
         sudo tc qdisc add dev 10Ge root fq maxrate '${RATE}'mbit;

         sudo sysctl -w net.ipv4.tcp_no_metrics_save=1;
         sudo sysctl -w net.ipv4.tcp_low_latency=1;
         sudo sysctl -w net.ipv4.tcp_autocorking=0;
         sudo sysctl -w net.ipv4.tcp_fastopen=0;

         sudo sysctl -w net.core.rmem_max=8388608;
         sudo sysctl -w net.core.wmem_max=8388608;
         sudo sysctl -w net.core.rmem_default=8388608;
         sudo sysctl -w net.core.wmem_default=8388608;
         sudo sysctl -w net.ipv4.tcp_rmem="8388608 8388608 8388608";
         sudo sysctl -w net.ipv4.tcp_wmem="8388608 8388608 8388608";
         sudo sysctl -w net.ipv4.tcp_mem="8388608 8388608 8388608";
         sudo sysctl -w net.ipv4.ip_local_port_range="20000 61000";
         sudo sysctl -w net.ipv4.tcp_fin_timeout=20;
         sudo sysctl -w net.ipv4.tcp_tw_reuse=1;
         sudo sysctl -w net.core.somaxconn=2048;
         sudo sysctl -w net.core.netdev_max_backlog=2000;
         sudo sysctl -w net.ipv4.tcp_max_syn_backlog=2048;'

    for i in ${!hosts[@]}; do
        ssh ${hosts[$i]} $CMD
    done

    sleep 1

    set_cpufreq_scaling "set" 10
}

setup_aqm() {
    aqm_iface=$router_right_iface

    CMD="sudo tc qdisc add dev ${aqm_iface} root handle 2: netem delay ${RTT}ms;
	 sudo tc qdisc add dev ${aqm_iface} parent 2: handle 3: htb default 10;
	 sudo tc class add dev ${aqm_iface} parent 3: classid 10 htb rate ${RATE}mbit \
ceil ${RATE}mbit burst 1514b cburst 1514b"

    ssh $router_host $CMD

    sleep 3
}
