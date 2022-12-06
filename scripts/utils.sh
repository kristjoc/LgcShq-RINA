# -*- bash -*-

#
# Written by: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
#

. param.sh

#-----------------------------------------------------
# Load RINA modules
#-----------------------------------------------------
load_modules() {
    hosts=($server_host $router_host $client_host)
    CMDS="sudo modprobe rina-irati-core irati_verbosity=7;
          sudo modprobe rina-default-plugin;
          sudo modprobe normal-ipcp;
          sudo modprobe shim-eth;
          sudo modprobe lgcshq-plugin;
          sudo ${irati_root}/bin/ipcm -c ${irati_root}/etc/ipcmanager.conf > /dev/null 2>&1 &"

    for i in ${!hosts[@]}; do
        ssh ${hosts[$i]} $CMDS
    done

    sleep 3
}

#------------------------
# Generate IRATI configs
#------------------------
generate_irati_configs() {
    # subshell so we don't pollute the global env
    (
        export server_host server_right_iface \
               router_host router_left_iface router_right_iface \
               client_host client_left_iface \
               irati_root \
               dtcp_policy \
               lgc_max_rate lgc_min_rtt lgc_ecn_bits \
               rmt_policy \
               rmt_limit rmt_bandwidth rmt_interval

        shim_iface="$server_right_iface" envsubst < configs/shim-eth.dif | ssh ${server_host} "cat > ${irati_root}/etc/${server_host}-${router_host}.dif"

        shim_iface="$router_left_iface" envsubst < configs/shim-eth.dif | ssh ${router_host} "cat > ${irati_root}/etc/${server_host}-${router_host}.dif"
        shim_iface="$router_right_iface" envsubst < configs/shim-eth.dif | ssh ${router_host} "cat > ${irati_root}/etc/${router_host}-${client_host}.dif"

        shim_iface="$client_left_iface" envsubst < configs/shim-eth.dif | ssh ${client_host} "cat > ${irati_root}/etc/${router_host}-${client_host}.dif"

        envsubst < configs/ipcm-server.conf | ssh ${server_host} "cat > ${irati_root}/etc/ipcmanager.conf"
        envsubst < configs/ipcm-router.conf | ssh ${router_host} "cat > ${irati_root}/etc/ipcmanager.conf"
        envsubst < configs/ipcm-client.conf | ssh ${client_host} "cat > ${irati_root}/etc/ipcmanager.conf"

        envsubst < configs/default.dif | ssh ${router_host} "cat > ${irati_root}/etc/default.dif"
        export rmt_policy="default"
        envsubst < configs/default.dif | ssh ${server_host} "cat > ${irati_root}/etc/default.dif"
        envsubst < configs/default.dif | ssh ${client_host} "cat > ${irati_root}/etc/default.dif"

    )
}

#---------------------------------------------------------
# Enroll to DIF (applied only on the 'middle/router' node)
#---------------------------------------------------------
enroll_to_dif() {
    CMD="sudo ${irati_root}/bin/irati-ctl --unix-socket ${irati_root}/var/run/ipcm-console.sock enroll-to-dif 3 normal.DIF ${server_host}-${router_host} > /dev/null 2>&1;
         sudo ${irati_root}/bin/irati-ctl --unix-socket ${irati_root}/var/run/ipcm-console.sock enroll-to-dif 3 normal.DIF ${router_host}-${client_host} > /dev/null 2>&1"

    ssh $router_host $CMD

    sleep 3
}

#----------------------------
# Unload modules and teardown
#----------------------------
unload_modules() {
    hosts=($server_host $router_host $client_host)

    for i in ${!hosts[@]}; do
        CMD="sudo killall -2 rinaperf;
             sudo killall -9 rinaperf;
             sudo killall -9 ipcm;
	     sudo killall -9 ${irati_root}/bin/ipcp;
             sudo pkill -9 ${irati_root}/bin/ipcp;
             sudo rmmod lgcshq-plugin;
             sudo rmmod shim-eth;
             sudo rmmod normal-ipcp;
             sudo rmmod rina-default-plugin;
             sudo rmmod rina-irati-core;
             sync; echo 3 | sudo tee /proc/sys/vm/drop_caches;"

	ssh ${hosts[$i]} $CMD > /dev/null 2>&1
        done

        sleep 3
}

#-----------------
# Prepare host
#-----------------
prepare_host() {
        local rate=$1

        set_out_delay $global_delay
        set_eth_speed $rate
        set_cpufreq_scaling "set" 10

        sleep 3
}

#-------------------
# Load RINA stuff
#-------------------
load_rina_stuff() {
    generate_irati_configs
    load_modules
    enroll_to_dif
}

#-------------------
# Reset host config
#-------------------
reset_config() {
        set_out_delay "0"
        set_eth_speed "10000"
        set_cpufreq_scaling "reset" 10

        sleep 3
}

teardown_router() {
    CMD="sudo tc qdisc del dev ifb2 root;
         sudo tc qdisc del dev ifb1 root;
         sudo tc qdisc del dev ifb0 root;
         sudo tc qdisc del dev ifb3 root;
         sudo tc qdisc del dev 10Ga root;
         sudo tc qdisc del dev 10Gb root;
         sudo tc qdisc del dev 10Gc root;
         sudo tc qdisc del dev 10Gd root;
         sudo tc qdisc del dev 10Ge root;
         sudo tc qdisc del dev 10Gf root;
         sudo modprobe -r ifb;
         sudo sysctl -w net.ipv4.tcp_ecn=1;
         sudo sysctl -w net.ipv4.tcp_ecn_fallback=0"

    ssh $router_host $CMD

    sleep 3
}

#--------------------------------------------
# Set cpufrew settings for up to 'proc' CPUs
#--------------------------------------------
set_cpufreq_scaling() {
    local onoff=$1
    local proc=$2

    hosts=($client_host $router_host $server_host)

    for i in ${!hosts[@]}; do
	if [ $onoff == "set" ]; then
	    CMD='for i in $(seq 1 '${proc}'); do
		    sudo cpufreq-set -c$i -r -g performance;
		done'
	else
	    CMD='for i in $(seq 1 '${proc}'); do
		    sudo cpufreq-set -c$i -r -g powersave;
		done'
	fi
	ssh ${hosts[$i]} $CMD > /dev/null 2>&1
    done

    sleep 1
}
