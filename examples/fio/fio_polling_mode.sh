#!/bin/bash

# Polling Mode (No Interrupts) Example
# This example demonstrates using polling mode by disabling interrupt vectors
# for all completion queues (vector=-1). Each submission queue has its own
# completion queue (1:1 relationship).

set -e

RUNTIME=30
BDF=""
NR_QUEUES=4
DEBUG=0
CMD_TIMEOUT=""

usage() {
	echo "Usage: $0 -b <bdf> [-t <runtime>] [-n <nr_queues>] [-T <timeout>] [-d]"
	echo "  -b <bdf>        : PCI BDF of the NVMe device (e.g., 0000:01:00.0)"
	echo "  -t <runtime>    : Test duration in seconds (default: 30)"
	echo "  -n <nr_queues>  : Number of I/O queue pairs to create (default: 4)"
	echo "  -T <timeout>    : Command timeout in seconds (optional)"
	echo "  -d              : Enable debug log level"
	echo ""
	echo "This test performs the following:"
	echo "  1. Creates I/O queue pairs (1:1 SQ:CQ relationship)"
	echo "  2. Disables interrupts for all CQs (vector=-1, polling mode)"
	echo "  3. Runs fio workload with polling-based completion checking"
	echo ""
	echo "Example: $0 -b 0000:01:00.0 -n 4 -t 30"
	exit 1
}

while getopts "b:t:n:T:d" opt; do
	case ${opt} in
		b)
			BDF=$OPTARG
			;;
		t)
			RUNTIME=$OPTARG
			;;
		n)
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
	echo "Error: BDF is required"
	usage
fi

if pgrep -x "unvmed" > /dev/null; then
	unvme stop -a
fi

# Convert BDF format for fio (replace ':' and '.' with '.')
FIO_BDF=${BDF//:/.}
FIO_BDF=${FIO_BDF//./.}

trap "unvme stop -a" EXIT

echo "=========================================="
echo "Polling Mode (No Interrupts) Test"
echo "=========================================="
echo "Device        : $BDF"
echo "Runtime       : ${RUNTIME}s"
echo "Num Queues    : $NR_QUEUES (1:1 SQ:CQ)"
echo "Interrupt Mode: Disabled (polling)"
echo "Configuration : Each SQ has its own CQ with vector=-1"
echo "=========================================="
echo ""

# Start daemon and initialize controller
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

echo ""
echo "Creating 1:1 queue pairs with polling mode (vector=-1)..."
echo ""

# Create I/O queue pairs with polling mode (vector=-1)
for ((qid=1; qid <= $NR_QUEUES; qid++));
do
	(
		set -x
		# Create CQ with vector=-1 to disable interrupts (polling mode)
		unvme create-iocq $BDF -q $qid -z 256 -v -1
		# Create SQ paired with the corresponding CQ
		unvme create-iosq $BDF -q $qid -z 256 -c $qid
	) &
done
wait

echo ""
echo "Queue configuration complete. Current device status:"
unvme status $BDF
echo ""

# Run fio benchmark
echo "Running fio benchmark (polling mode, $NR_QUEUES queues)..."
echo ""

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
	--name=polling_mode_test \
	--bs=4k \
	--iodepth=32 \
	--rw=randread
)

echo ""
echo "=========================================="
echo "Test completed successfully"
echo "=========================================="
