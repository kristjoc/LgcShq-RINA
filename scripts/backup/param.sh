# -*- bash -*-

#
# Written by: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
#

readonly localhost="127.0.0.1"
# change global_count to 'n' to run the experiments 'n' times
readonly global_count="100"
readonly global_perf_rate_vec=("50" "100" "250" "500" "1000" "2500" "5000")
readonly global_perf_concon_vec=("100" "200" "500" "1000" "2000" "5000" "10000")
readonly global_mss="1451"
# global_lport is the TCP listening port of the server application
readonly global_lport="8080"
# PEP-DNA listens for incoming connections on port 9999
readonly global_proxy_port="9999"
# Sock Mark needed to achieve transparency when PEP-DNA is running at the same host
# as the server
readonly global_mark="333"
# For the FlowCompletionTime experiment to work, a 4GB file needs to be generated at
# /var/www/web/ at server side; Generate using dd
readonly global_filename="4g.bin"
# No delay emulated
readonly global_def_delay="0"
# Default ethernet speed 10000Mbps
readonly global_def_speed="10000"
readonly global_speed_vec=("10000")
# If you want to run the experiments for different ethernet speeds, uncomment the line below
# readonly global_speed_vec=("1000" "10000")
global_delay="1"
global_bufsize=0

testbed_variables() {
    # Supported topology: zelda --- midna --- epona
    readonly server_host="zelda"
    readonly server_right_ip="10.100.26.2"
    readonly server_right_iface="10Ge"

    readonly router_host="midna"
    readonly router_left_ip="10.100.26.6"
    readonly router_left_iface="10Gb"
    readonly router_right_ip="10.100.56.6"
    readonly router_right_iface="10Ge"

    readonly client_host="epona"
    readonly client_left_ip="10.100.56.5"
    readonly client_left_iface="10Ge"

    readonly global_path="/home/ocarina/michal/"
    readonly irati_root="/home/ocarina/michal/irati"

    # variables for default.dif, probably calculated from global params?
    dtcp_policy="lgcshq-ps"
    lgc_max_rate="1000"
    lgc_min_rtt="1"
    lgc_ecn_bits="1" # change value between experiments
    rmt_policy="lgcshq-ps" # should be different between hosts
    rmt_limit="1000"
    rmt_bandwidth="1000"
    rmt_interval="1"
}

testbed_variables
