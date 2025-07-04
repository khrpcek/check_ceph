#!/usr/bin/python3

# Examples:
# osd status, warn at 2 missing, crit at 3: ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --osd -w 2 -c 3
# general health statis: /check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --health
# pg status, does not take warning or critical arguments yet. Only warns on PGs not in an active+clean state which means some PGs are not in an optimal state. ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --pg
# extra performance metrics (iops, read/write bytes/sec): ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --perf
# disk space, if run with --pool you only alert on that pool. when run without --pool the thresholds are for every pool. warning and ciritcal are the max avail fields from `ceph df`: ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --df -w 100 -c 50
#
#
import sys
import argparse
import json
import subprocess
import traceback
from types import TracebackType

#ceph osd stat
#ceph mon stat
#ceph pg stat
#ceph health status
#ceph mon_status
#ceph quorum status

# If an error occurs try to exit with exitcode 3 (UNKNOWN state in the monitoring server)
def handle_exception(
    type_: type[BaseException], value: BaseException, tb: TracebackType | None
) -> None:

    traceback.print_tb(tb)
    sys.exit(3)
sys.excepthook = handle_exception

def checkHealth(args):

    try:
        ceph_health_json=subprocess.check_output([f"ceph -n {args.id} -c {args.conf} -k {args.keyring} --format json health"],shell=True)
    except subprocess.CalledProcessError:
        sys.exit(3)

    ceph_health_dict = json.loads(ceph_health_json)

    if ceph_health_dict['status'] == 'HEALTH_WARN':
        overall_status = 'HEALTH_WARN: '
        check_messages = []
        for check in ceph_health_dict['checks'].keys():
            overall_status = f"{overall_status}{check}({ceph_health_dict['checks'][check]['summary']['count']}), "
            check_messages.append(f"{check}: {ceph_health_dict['checks'][check]['summary']['message']}")
        print(overall_status.rstrip(" ,"))
        print
        for msg in check_messages:
            print(msg)
        sys.exit(1)
    elif ceph_health_dict['status'] == 'HEALTH_OK':
        print(ceph_health_dict['status'])
        sys.exit(0)

def checkOSD(args):
    if args.warning:
        WARN = float(args.warning)
    if args.critical:
        CRIT = float(args.critical)
    try:
        osd_stat_json=subprocess.check_output([f"ceph -n {args.id} -c {args.conf} -k {args.keyring} --format json osd stat"], shell=True)
    except subprocess.CalledProcessError:
        sys.exit(3)
    osd_stat_dict = json.loads(osd_stat_json)
    osd_not_up = osd_stat_dict['num_osds'] - osd_stat_dict['num_up_osds']
    osd_not_in = osd_stat_dict['num_osds'] - osd_stat_dict['num_in_osds']
    perf_string=f"num_osds={osd_stat_dict['num_osds']} num_up_osds={osd_stat_dict['num_up_osds']} num_in_osds={osd_stat_dict['num_in_osds']}"

#Build in logic to handle the full and near full keys that are returned in the json
    if (osd_not_up >= WARN and osd_not_up < CRIT) or (osd_not_in >= WARN and osd_not_in < CRIT):
        print(f"WARNING: ALL OSDs are not up and in. {osd_stat_dict['num_osds']} OSDS. {osd_stat_dict['num_up_osds']} up, {osd_stat_dict['num_in_osds']} in|{perf_string}")
        sys.exit(1)
    elif (osd_not_up >= CRIT) or (osd_not_in >= CRIT):
        print(f"CRITICAL: ALL OSDs are not up and in. {osd_stat_dict['num_osds']} OSDS. {osd_stat_dict['num_up_osds']} up, {osd_stat_dict['num_in_osds']} in|{perf_string}")
        sys.exit(2)
    elif (osd_stat_dict['num_osds'] == osd_stat_dict['num_in_osds']) and (osd_stat_dict['num_osds'] == osd_stat_dict['num_up_osds']):
        print(f"ALL OSDs are up and in. {osd_stat_dict['num_osds']} OSDS. {osd_stat_dict['num_up_osds']} up, {osd_stat_dict['num_in_osds']} in|{perf_string}")
        sys.exit(0)
    else:
        print("Script shouldn't reach this point. There may be bugs!")
        sys.exit(3)

def checkMON(args):
    if args.warning:
        WARN = float(args.warning)
    if args.critical:
        CRIT = float(args.critical)
    #not written yet, more important things

def checkPG(args):
    try:
        pg_stat_json=subprocess.check_output([f"ceph -n {args.id} -c {args.conf} -k {args.keyring} --format json pg stat"], shell=True)
    except subprocess.CalledProcessError:
        sys.exit(3)
    pg_stat_dict=json.loads(pg_stat_json)
    #cheap fix for nautilus change in json output
    if 'num_pgs' in pg_stat_dict.keys():
        #pre nautilus json format
        pg_summary=pg_stat_dict
    elif 'pg_summary' in pg_stat_dict.keys():
        #nautilus json format
        pg_summary = pg_stat_dict['pg_summary']
    num_pgs = pg_summary['num_pgs']
    active_pgs=0
    perf_string=""
    for x in pg_summary['num_pg_by_state']:
        if "active+clean" in x['name']:
            active_pgs += x['num']
        perf_string += f"{x['name']}={x['num']} "
#Maybe build in a percentage based threshold for users who want to have thresholds like that
    if active_pgs < num_pgs:
        print(f"WARNING: Not all PGs are active+clean: {num_pgs} PGs total, {perf_string}|{perf_string}")
        sys.exit(1)
    elif active_pgs == num_pgs:
        print(f"All PGs are active+clean: {num_pgs} PGs Total, {perf_string}|{perf_string}")
        sys.exit(0)
    else:
        print("Script shouldn't reach this point. There may be bugs!")
        sys.exit(3)

def checkPerf(args):
    try:
        pg_stat_json=subprocess.check_output([f"ceph -n {args.id} -c {args.conf} -k {args.keyring} --format json pg stat"], shell=True)
    except subprocess.CalledProcessError:
        sys.exit(3)
    pg_stat_dict=json.loads(pg_stat_json)
    if 'read_bytes_sec' not in  pg_stat_dict:
        pg_stat_dict['read_bytes_sec'] = 0
    if 'write_bytes_sec' not in  pg_stat_dict:
        pg_stat_dict['write_bytes_sec'] = 0
    if 'io_sec' not in  pg_stat_dict:
        pg_stat_dict['io_sec'] = 0
    perf_string=f"read_bytes_sec={pg_stat_dict['read_bytes_sec']} write_bytes_sec={pg_stat_dict['write_bytes_sec']} io_sec={pg_stat_dict['io_sec']}"
    print(f"Healthy: Additional perf stats for cluster {perf_string}|{perf_string}")
    sys.exit(0)

def checkDF(args):
    if args.warning:
        WARN = float(args.warning)
    if args.critical:
        CRIT = float(args.critical)
    if args.byte:
        if args.byte == "T":
            byte_divisor=1024**4
            perf_metric="TB"
        elif args.byte == "G":
            byte_divisor=1024**3
            perf_metric="GB"
        elif args.byte == "P":
            byte_divisor=1024**5
            perf_metric="PB"
    else:
        byte_divisor=1024**4
        perf_metric="TB"

    try:
        ceph_df_json=subprocess.check_output([f"ceph -n {args.id} -c {args.conf} -k {args.keyring} --format json df"], shell=True)
    except subprocess.CalledProcessError:
        sys.exit(3)
    ceph_df_dict=json.loads(ceph_df_json)
    #get global stats
    global_bytes, global_used_bytes, global_avail_bytes = ceph_df_dict['stats']['total_bytes'], ceph_df_dict['stats']['total_used_bytes'], ceph_df_dict['stats']['total_avail_bytes']
    global_total=global_bytes / byte_divisor
    global_used=global_used_bytes / byte_divisor
    global_avail=global_avail_bytes / byte_divisor
    
    #get all pool stats
    pool_stats = {}
    for pool in ceph_df_dict['pools']:
        pool_stats[pool['name']] = {'bytes_used': pool['stats']['bytes_used'] / byte_divisor, 'max_avail': pool['stats']['max_avail'] / byte_divisor, 'objects': pool['stats']['objects']}

    perf_string=f"global_total_bytes={global_bytes / byte_divisor}{perf_metric} global_used_bytes={global_used_bytes / byte_divisor}{perf_metric} global_avail_bytes={global_avail_bytes / byte_divisor}{perf_metric} "
    for item in pool_stats.keys():
        perf_string += f"{item}_bytes_used={pool_stats[item]['bytes_used']}{perf_metric,pool_stats[item]['max_avail']} {item}_max_avail={pool_stats[item]['objects']}{perf_metric,pool_stats[item]['max_avail']} {item}_objects={4} "

#if pool is defined alert on that. if pool is not defined alert on the max_avail of all pools if any cross threshold
    if args.pool in pool_stats.keys():
#        print pool_stats[args.pool]
#add in percentage later
        if (pool_stats[args.pool]['max_avail'] < WARN) and (pool_stats[args.pool]['max_avail'] > CRIT):
            print(f"WARNING: Ceph pool {args.pool} has {pool_stats[args.pool]['max_avail']}{perf_metric} availbale|{perf_string}")
            sys.exit(1)
        elif pool_stats[args.pool]['max_avail'] < CRIT:
            print(f"CRITICAL: Ceph pool {args.pool} has {pool_stats[args.pool]['max_avail']}{perf_metric} availbale|{perf_string}")
            sys.exit(2)
        elif pool_stats[args.pool]['max_avail'] > WARN:
            prin(f"Healthy: Ceph pool {args.pool} has {pool_stats[args.pool]['max_avail']}{perf_metric} availbale|{perf_string}")
            sys.exit(0)
        else:
            print("Script shouldn't reach this point. There may be bugs!")
            sys.exit(3)

    else:
        #Alerts based on all pools. If any pool is crossing the threshold we alert on it
        warn_list = []
        crit_list = []

        for key in pool_stats.keys():
            if (pool_stats[key]['max_avail'] < WARN) and (pool_stats[key]['max_avail'] > CRIT):
                warn_list.append(f"{key}:{pool_stats[key]['max_avail']}{perf_metric}")
            elif pool_stats[key]['max_avail'] < CRIT:
                crit_list.append(f"{key}:{pool_stats[key]['max_avail']}{perf_metric}")

        if (len(warn_list) > 0) and (len(crit_list) == 0):
            print(f"WARNING: Ceph pool(s) low on free space. {warn_list}|{perf_string}")
            sys.exit(1)
        elif len(crit_list) > 0:
            print(f"CRITICAL: Ceph pool(s) critically low on free space. Critial:{crit_list} Warning:{warn_list}|{perf_string}")
            sys.exit(2)
        elif (len(warn_list) == 0) and (len(crit_list) == 0):
            print(f"Healthy: All ceph pools are within free space thresholds|{perf_string}")
        else:
            print("Script shouldn't reach this point. There may be bugs!")
            sys.exit(3)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Runs health checks against a ceph cluster. This is designed to run on the monitoring server using the ceph client software. Supply a ceph.conf, keyring, and user to access the cluster.')
    parser.add_argument('-C','--conf', help='ceph.conf file, defaults to /etc/ceph/ceph.conf.')
    parser.add_argument('-id','--id', help='Ceph authx user',required=True)
    parser.add_argument('-k','--keyring', help='Path to ceph keyring if not in /etc/ceph/client.\$id.keyring')
    parser.add_argument('--health', help='Get general health status. ex. HEALTH_OK, HEALTH_WARN',action="store_true")
    parser.add_argument('-o','--osd', help='OSD status. Thresholds are in number of OSDs missing',action="store_true")
    parser.add_argument('-m','--mon', help='MON status. Thesholds are in number of mons missing')
    parser.add_argument('-p','--pg', help='PG status. No thresholds due to the large number of pg states.',action="store_true")
    parser.add_argument('--perf', help='collects additional ceph performance statistics',action='store_true')
    parser.add_argument('--df', help='Disk/cluster usage. Reports global and all pools unless --pool is used. Warning and critical are number of -b free to the pools. This is not Raw Free, but Max Avail to the pools based on rep or k,m settings. If you do not define a pool the threshold is run agains all the pools in the cluster.',action="store_true")
    parser.add_argument('-b','--byte', help="Format to use for displaying DF data. G=Gigabyte, T=Terabyte. Use with the --df option. Defults to TB")
    parser.add_argument('--pool',help='Pool. Use with df')
    parser.add_argument('--objects', help='Object counts based on pool')
    parser.add_argument('-w','--warning',help='Warning threshold. See specific checks for value types')
    parser.add_argument('-c','--critical',help='Critical threshold. See specific checks for value types')

    args = parser.parse_args()

    if args.health:
        checkHealth(args)
    elif args.osd:
        checkOSD(args)
    elif args.pg:
        checkPG(args)
    elif args.df:
        checkDF(args)
    elif args.perf:
        checkPerf(args)
