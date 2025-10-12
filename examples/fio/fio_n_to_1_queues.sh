#!/bin/bash

# N:1 Queue Configuration Example
# This example demonstrates creating multiple submission queues (SQs) that
# share a single completion queue (CQ), and runs a single-job fio benchmark.
# This configuration is useful for testing shared completion queue scenarios.

set -e

RUNTIME=30
BDF=""
NR_SQS=4
CQ_SIZE=1024
SQ_SIZE=256
DEBUG=0
CMD_TIMEOUT=""

usage() {
	echo "Usage: $0 -b <bdf> [-t <runtime>] [-n <nr_sqs>] [-T <timeout>] [-d]"
	echo "  -b <bdf>        : PCI BDF of the NVMe device (e.g., 0000:01:00.0)"
	echo "  -t <runtime>    : Test duration in seconds (default: 30)"
	echo "  -n <nr_sqs>     : Number of submission queues to create (default: 4)"
	echo "  -T <timeout>    : Command timeout in seconds (optional)"
	echo "  -d              : Enable debug log level"
	echo ""
	echo "This test performs the following:"
	echo "  1. Creates a single completion queue (CQ) of size 1024"
	echo "  2. Creates multiple submission queues (SQs) of size 256 that share the same CQ"
	echo "  3. Runs a single-job fio workload across all queues"
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
			NR_SQS=$OPTARG
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

# Validate that CQ size is sufficient for all SQs
MIN_CQ_SIZE=$((NR_SQS * SQ_SIZE))
if [ $CQ_SIZE -lt $MIN_CQ_SIZE ]; then
	echo "Warning: CQ size ($CQ_SIZE) may be too small for $NR_SQS SQs of size $SQ_SIZE"
	echo "         Recommended minimum: $MIN_CQ_SIZE"
fi

if pgrep -x "unvmed" > /dev/null; then
	unvme stop -a
fi

# Convert BDF format for fio (replace ':' and '.' with '.')
FIO_BDF=${BDF//:/.}
FIO_BDF=${FIO_BDF//./.}

trap "unvme stop -a" EXIT

echo "=========================================="
echo "N:1 Queue Configuration Test"
echo "=========================================="
echo "Device        : $BDF"
echo "Runtime       : ${RUNTIME}s"
echo "Num SQs       : $NR_SQS"
echo "CQ Size       : $CQ_SIZE"
echo "SQ Size       : $SQ_SIZE (per queue)"
echo "Configuration : $NR_SQS SQs -> 1 CQ"
echo "=========================================="
echo ""

# Start daemon and initialize controller
(
	set -x
	unvme start
	if [ $DEBUG -eq 1 ]; then
		unvme log-level 2
	fi
	unvme add $BDF --nr-ioqs=$NR_SQS
	unvme create-adminq $BDF
	if [ -z "$CMD_TIMEOUT" ]; then
		unvme enable $BDF
	else
		unvme enable $BDF -t $CMD_TIMEOUT
	fi
	unvme id-ns $BDF -n 1 > /dev/null
)

echo ""
echo "Creating N:1 queue configuration..."
echo "  - 1 Completion Queue (CQ ID: 1, size: $CQ_SIZE)"
echo "  - $NR_SQS Submission Queues (SQ IDs: 1-$NR_SQS, size: $SQ_SIZE each)"
echo ""

# Create a single completion queue
(
	set -x
	unvme create-iocq $BDF -q 1 -z $CQ_SIZE -v 1
)

# Create multiple submission queues that all use the same completion queue (cqid=1)
for ((qid=1; qid <= $NR_SQS; qid++));
do
	(
		set -x
		unvme create-iosq $BDF -q $qid -z $SQ_SIZE -c 1
	) &
done
wait

echo ""
echo "Queue configuration complete. Current device status:"
unvme status $BDF
echo ""

# Run single-job fio benchmark
# Note: Using numjobs=$NR_SQS to utilize all submission queues
echo "Running fio benchmark (single job, utilizing all $NR_SQS queues)..."
echo ""

(
set -x
unvme fio \
	--ioengine=libunvmed \
	--filename=$FIO_BDF \
	--nsid=1 \
	--direct=1 \
	--thread=1 \
	--numjobs=$NR_SQS \
	--group_reporting \
	--time_based \
	--runtime=${RUNTIME}s \
	--name=n_to_1_test \
	--bs=4k \
	--iodepth=32 \
	--rw=randread \
	--rwmixread=70
)

echo ""
echo "=========================================="
echo "Test completed successfully"
echo "=========================================="
