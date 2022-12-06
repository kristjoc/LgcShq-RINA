# -*- bash -*-

#
# Written by: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
#             Michal Koutenský <koutenmi@fit.vutbr.cz>
#


# sudo rm -rf exp_* *.pyc *.txt

# run the experiments 'COUNT' times
readonly COUNT='1'
# CC algorithms: ( "dctcp" "lgc")
readonly CCS=( "lgc" )
# readonly nbits=( "1" "2" "3" "4" "5" "6" "7" )
readonly BITS=( "1" )
# RTT ~10ms
readonly RTT="10"
# Bw ~100Mbps
readonly RATE="100"

testbed_variables() {
    # Topology: hylia (10Ge) --- (10Gc) midna (10Ge) --- (10Ge) epona (C)
    #             ------------------------------------------------>
    readonly server_host="hylia"
    readonly server_right_ip="10.100.36.3"
    readonly server_right_iface="10Ge"

    readonly router_host="midna"
    readonly router_left_ip="10.100.36.6"
    readonly router_left_iface="10Gc"
    readonly router_right_ip="10.100.56.6"
    readonly router_right_iface="10Ge"

    readonly client_host="epona"
    readonly client_left_ip="10.100.56.5"
    readonly client_left_iface="10Ge"

    readonly global_path="/home/ocarina/michal/"
    readonly irati_root="/home/ocarina/michal/irati"

    # variables for default.dif, probably calculated from global params?
    dtcp_policy="lgcshq-ps"
    lgc_max_rate="100"
    lgc_min_rtt="10"
    lgc_ecn_bits="1" # change value between experiments
    rmt_policy="lgcshq-ps" # should be different between hosts
    rmt_limit="1000"
    rmt_bandwidth="100"
    rmt_interval="10"
}

testbed_variables
