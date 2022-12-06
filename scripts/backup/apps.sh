# -*- bash -*-

#
# Written by: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
#

. param.sh

#--------------
# RINAPERF APP
#--------------
rinaperf() {
    CMD="sudo nohup /home/ocarina/michal/irati/bin/rinaperf -l > /dev/null 2>&1 &"
    ssh $server_host $CMD
    sleep 1

    CMD="sudo /home/ocarina/michal/irati/bin/rinaperf -t perf -D 12 >> rinaperf 2>&1 &"
    ssh $client_host $CMD
    sleep 3
    ssh $client_host $CMD
    sleep 3
    ssh $client_host $CMD
    sleep 15
}
