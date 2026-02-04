#!/bin/bash

# This script runs a fio workload with libunvmed ioengine in the background
# and repeatedly deletes and re-creates I/O Submission Queues for the same
# duration to test the stability of queue deletion/creation during I/O.

set -e

RUNTIME=10
BDF=""
NR_IOQS=2
DEBUG=0
CMD_TIMEOUT=""
TARGET_QID=1
INTERVAL=1

usage() {
	echo "Usage: $0 -b <bdf> [-t <runtime>] [-q <nr_ioqs>] [-T <timeout>] [-Q <target_qid>] [-i <interval>] [-d]"
	echo "  -b <bdf>        : PCI BDF of the NVMe device (e.g., 0000:01:00.0)"
	echo "  -t <runtime>    : Test duration in seconds (default: 10)"
	echo "  -q <nr_ioqs>    : Number of I/O queues to create (default: 2)"
	echo "  -T <timeout>    : Command timeout in seconds (optional)"
	echo "  -Q <target_qid> : Target queue ID to delete/create (default: 1)"
	echo "  -i <interval>   : Interval between delete/create cycles in seconds (default: 1)"
	echo "  -d              : Enable debug log level"
	echo ""
	echo "This test performs the following:"
	echo "  1. Creates I/O queue pairs for specified number of queues"
	echo "  2. Runs fio random read/write workload in the background"
	echo "  3. Repeatedly deletes and re-creates the target I/O SQ"
	exit 1
}

while getopts "b:t:q:T:Q:i:d" opt; do
	case ${opt} in
		b)
			BDF=$OPTARG
			;;
		t)
			RUNTIME=$OPTARG
			;;
		q)
			NR_IOQS=$OPTARG
			;;
		T)
			CMD_TIMEOUT=$OPTARG
			;;
		Q)
			TARGET_QID=$OPTARG
			;;
		i)
			INTERVAL=$OPTARG
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

if [ $TARGET_QID -gt $NR_IOQS ]; then
	echo "Error: target_qid ($TARGET_QID) must be <= nr_ioqs ($NR_IOQS)"
	exit 1
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
	unvme add $BDF --nr-ioqs=$NR_IOQS
	unvme create-adminq $BDF -s 32 -c 32
	if [ -z "$CMD_TIMEOUT" ]; then
		unvme enable $BDF
	else
		unvme enable $BDF -t $CMD_TIMEOUT
	fi
	unvme id-ns $BDF -n 1 > /dev/null
)

for ((qid=1; qid <= $NR_IOQS; qid++));
do
	(
		set -x
		unvme create-iocq $BDF -q $qid -z 256 -v $qid
		unvme create-iosq $BDF -q $qid -z 256 -c $qid
	) &
done
wait

unvme status $BDF

# Start fio in the background
echo "Starting fio workload for ${RUNTIME} seconds..."
unvme fio --ioengine=libunvmed \
	--filename=$FIO_BDF \
	--nsid=1 \
	--direct=1 \
	--thread=1 \
	--numjobs=$NR_IOQS \
	--group_reporting \
	--time_based \
	--runtime=${RUNTIME}s \
	--name=randrw \
	--bsrange=4k-128k \
	--iodepth=64 \
	--ignore_error=0x371,0x371 \
	--rw=randrw &
FIO_PID=$!

# Wait a moment for fio to start up
sleep 1

# Repeatedly delete and re-create the target I/O SQ
echo "Starting delete/create I/O SQ loop for ${RUNTIME} seconds (target qid=$TARGET_QID, interval=${INTERVAL}s)..."
end_time=$((SECONDS + RUNTIME))
cycle_count=0
while [ $SECONDS -lt $end_time ]; do
	echo -n "."

	# Delete I/O SQ
	unvme delete-iosq $BDF -q $TARGET_QID 2>/dev/null || true

	sleep $INTERVAL

	# Re-create I/O SQ (with same CQ)
	unvme create-iosq $BDF -q $TARGET_QID -z 256 -c $TARGET_QID 2>/dev/null || true

	cycle_count=$((cycle_count + 1))
done

echo ""
echo "Finished delete/create loop after $cycle_count cycles."

# Wait for fio to complete
echo "Waiting for fio to complete..."
wait $FIO_PID
FIO_EXIT_CODE=$?

if [ $FIO_EXIT_CODE -eq 0 ]; then
	echo "Fio completed successfully."
else
	echo "Fio failed with exit code $FIO_EXIT_CODE."
fi

exit $FIO_EXIT_CODE
