#!/bin/bash

# Random read FIO performance test example
# Creates I/O queue pairs for nr_cpus, formats the namespace to unmap
# full LBA ranges, then runs a random read workload with queue depth 64

set -e

RUNTIME=60
BDF=""
NR_QUEUES=$(nproc)
DEBUG=0
CMD_TIMEOUT=""

usage() {
	echo "Usage: $0 -b <bdf> [-t <runtime>] [-q <nr_queues>] [-T <timeout>] [-d]"
	echo "  -b <bdf>        : PCI BDF of the NVMe device (e.g., 0000:01:00.0)"
	echo "  -t <runtime>    : Test duration in seconds (default: 60)"
	echo "  -q <nr_queues>  : Number of I/O queues to use (default: $(nproc))"
	echo "  -T <timeout>    : Command timeout in seconds (optional)"
	echo "  -d              : Enable debug log level"
	echo ""
	echo "This test performs the following:"
	echo "  1. Creates I/O queue pairs for specified number of queues"
	echo "  2. Formats namespace 1 to unmap full LBA ranges"
	echo "  3. Runs random read workload with QD=64 and group reporting"
	exit 1
}

while getopts "b:t:q:T:d" opt; do
	case ${opt} in
		b)
			BDF=$OPTARG
			;;
		t)
			RUNTIME=$OPTARG
			;;
		q)
			NR_QUEUES=$OPTARG
			;;
		T)
			CMD_TIMEOUT=$OPTARG
			;;
		d)
			DEBUG=1
			;;
		\?)
			usage
			;;
	esac
done

if [ -z "$BDF" ]; then
	usage
fi

if pgrep -x "unvmed" > /dev/null; then
	unvme stop -a
fi

FIO_BDF=${BDF//:/.}
FIO_BDF=${FIO_BDF//./.}

trap "unvme stop -a" EXIT

(
	set -x
	unvme start
	if [ $DEBUG -eq 1 ]; then
		unvme log-level 2
	fi
	unvme add $BDF --nr-ioqs=$NR_QUEUES
	unvme create-adminq $BDF
	if [ -z "$CMD_TIMEOUT" ]; then
		unvme enable $BDF
	else
		unvme enable $BDF -t $CMD_TIMEOUT
	fi
	unvme id-ns $BDF -n 1 > /dev/null
)

for ((qid=1; qid <= $NR_QUEUES; qid++));
do
	(
		set -x
		unvme create-iocq $BDF -q $qid -z 256 -v $qid
		unvme create-iosq $BDF -q $qid -z 256 -c $qid
	) &
done
wait

unvme status $BDF

(
	set -x
	unvme format $BDF -n 1
)

(
set -x
unvme fio \
	--ioengine=libunvmed \
	--filename=$FIO_BDF \
	--nsid=1 \
	--direct=1 \
	--thread=1 \
	--numjobs=$NR_QUEUES \
	--group_reporting \
	--time_based \
	--runtime=${RUNTIME}s \
	--name=randread_perf \
	--bs=4k \
	--iodepth=64 \
	--rw=randread
)
