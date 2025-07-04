#!/bin/bash

# This script runs a 128k sequential read/write fio workload with libunvmed
# ioengine in the background and repeatedly resets the controller for the
# same duration to test the stability of the re-initialization process.

set -e

RUNTIME=10
BDF=""
NR_IOQS=1
DEBUG=0
RESET_TYPE="ctrl"

usage() {
    echo "Usage: $0 -b <bdf> [-t <runtime>] [-q <nr_ioqs>] [-d] [-r <reset_type>]"
    echo "  -b <bdf>       : PCI BDF of the NVMe device (e.g., 0000:01:00.0)"
    echo "  -t <runtime>   : Test duration in seconds (default: 10)"
    echo "  -q <nr_ioqs>   : Number of I/O queues to create (default: 1)"
    echo "  -d             : Enable debug log level"
    echo "  -r <reset_type>: Reset type: ctrl, nssr, flr, link-disable, hot-reset (default: ctrl)"
    exit 1
}

while getopts "b:t:q:dr:" opt; do
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
        d)
            DEBUG=1
            ;;
        r)
            RESET_TYPE=$OPTARG
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
    unvme add $BDF --nr-ioqs=$NR_IOQS
    unvme create-adminq $BDF
    unvme enable $BDF
    unvme id-ns $BDF -n 1
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

# Start fio in the background
echo "Starting fio workload for ${RUNTIME} seconds..."
unvme fio --ioengine=libunvmed \
    --filename=$FIO_BDF \
    --nsid=1 \
    --direct=1 \
    --thread=1 \
    --group_reporting \
    --time_based \
    --runtime=${RUNTIME}s \
    --name=readwrite \
    --bs=128k \
    --iodepth=64 \
    --ignore_error=0x371,0x371 \
    --rw=rw &
FIO_PID=$!

# Wait a moment for fio to start up
sleep 1

# Repeatedly reset the controller
echo "Starting unvme reset loop for ${RUNTIME} seconds with reset type '${RESET_TYPE}'..."
end_time=$((SECONDS + RUNTIME))
reset_count=0
while [ $SECONDS -lt $end_time ]; do
    case ${RESET_TYPE} in
        ctrl)
            COMMAND="unvme reset $BDF --reinit --graceful"
            ;;
        nssr)
            COMMAND="unvme subsystem-reset $BDF --reinit"
            ;;
        flr)
            COMMAND="unvme flr $BDF --reinit"
            ;;
        "link-disable")
            COMMAND="unvme link-disable $BDF --reinit"
            ;;
        "hot-reset")
            COMMAND="unvme hot-reset $BDF --reinit"
            ;;
        *)
            echo "Invalid reset type: ${RESET_TYPE}"
            exit 1
            ;;
    esac

    echo -n "."
    $COMMAND
    if [ $? -ne 0 ]; then
        echo "${RESET_TYPE} reset failed!"
        exit 1 # trap will handle cleanup
    fi
    reset_count=$((reset_count + 1))
done

echo "Finished reset loop after $reset_count resets."

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
