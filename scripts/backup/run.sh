# -*- bash -*-

#
# Written by: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
#

. utils.sh
. apps.sh

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

#---------------------#
clean_up() {
    unload_modules
    reset_config
    exit
}

#-----------------------------------------------------------------------------#
run_rinaperf() {
    unload_modules

    # $1 - speed
    prepare_host 100

    load_rina_stuff
    rinaperf
    unload_modules
    reset_config

    sleep 1
}

# Signal handling
trap clean_up SIGHUP SIGINT SIGTERM

#-----------------------------------------------------------------------------#
# Functions below are called at 'main.sh'
#-----------------------------------------------------------------------------#
run_ping_app() {
    for i in ${!global_speed_vec[@]}; do
	speed=${global_speed_vec[$i]}
	run_pure_tcp "ping" "off"
	sleep 3
    done

    # collect results
    if [ $nnodes -eq '2' ]; then
	ssh $client_gw_host "sudo gzip -f ${global_path}ping.dat"
	scp $client_gw_host:${global_path}ping.dat.gz $SCRIPTPATH/results/ping/
    elif [ $nnodes -gt '2' ]; then
	ssh $client_host "sudo gzip -f ${global_path}ping.dat"
	scp $client_host:${global_path}ping.dat.gz $SCRIPTPATH/results/ping/
    fi

    gunzip -d $SCRIPTPATH/results/rinaperf/rinaperf.dat.gz
    echo "RINAPERF app done"
}
