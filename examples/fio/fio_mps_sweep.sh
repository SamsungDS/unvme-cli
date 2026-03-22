#!/bin/bash

# MPS sweep fio test
# Iterates MPS from system page size up to cap.mpsmax, running a 128K
# sequential read workload (iodepth=128, runtime=1s) at each MPS value.
# Uses disable + enable transitions between MPS iterations (no unvme del).

set -e

BDF=""
NR_IOQS=1
DEBUG=0

usage() {
	echo "Usage: $0 -b <bdf> [-q <nr_ioqs>] [-d]"
	echo "  -b <bdf>     : PCI BDF of the NVMe device (e.g., 0000:01:00.0)"
	echo "  -q <nr_ioqs> : Number of I/O queues per iteration (default: 1)"
	echo "  -d           : Enable debug log level"
	echo ""
	echo "This test performs the following:"
	echo "  1. Determines system MPS (from getconf PAGESIZE)"
	echo "  2. Reads cap.mpsmax from the controller CAP register"
	echo "  3. For each MPS in [system_mps .. mpsmax]:"
	echo "       create-adminq (with matching --pagesize)"
	echo "       enable (with --mps=<n>)"
	echo "       create I/O queues"
	echo "       fio: 128K seqread, iodepth=128, runtime=1s"
	echo "       disable (except after the last MPS iteration)"
	exit 1
}

while getopts "b:q:d" opt; do
	case ${opt} in
		b) BDF=$OPTARG ;;
		q) NR_IOQS=$OPTARG ;;
		d) DEBUG=1 ;;
		\?) usage ;;
	esac
done

if [ -z "$BDF" ]; then
	usage
fi

FIO_BDF=${BDF//:/.}
FIO_BDF=${FIO_BDF//./.}

# Stop any running unvmed instance at the start
if pgrep -x "unvmed" > /dev/null; then
	(set -x; unvme stop -a)
fi

trap "unvme stop -a" EXIT

# Compute system MPS value: MPS = log2(PAGESIZE) - 12
PAGESIZE=$(getconf PAGESIZE)
MPS_MIN=$(python3 -c "import math; print(int(math.log2(${PAGESIZE})) - 12)")

(
	set -x
	unvme start
)

if [ $DEBUG -eq 1 ]; then
	(set -x; unvme log-level 2)
fi

(
	set -x
	unvme add $BDF --nr-ioqs=$NR_IOQS
)

# Read CAP register to extract cap.mpsmax (bits [55:52])
CAP=$(unvme show-regs $BDF --output-format=json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d['cap'])
")
MPS_MAX=$(python3 -c "print((${CAP} >> 52) & 0xf)")

echo ""
echo "System pagesize : ${PAGESIZE} bytes"
echo "MPS_MIN         : ${MPS_MIN}  (2^(12+${MPS_MIN}) = $((1 << (12 + MPS_MIN))) bytes)"
echo "MPS_MAX (cap)   : ${MPS_MAX}  (2^(12+${MPS_MAX}) = $((1 << (12 + MPS_MAX))) bytes)"
echo ""

create_ioqs() {
	local bdf=$1
	local nr=$2

	for ((qid=1; qid <= nr; qid++)); do
		(
			set -x
			unvme create-iocq $bdf -q $qid -z 256 -v $qid
			unvme create-iosq $bdf -q $qid -z 256 -c $qid
		)
	done
}

for ((mps=MPS_MIN; mps<=MPS_MAX; mps++)); do
	MPS_PAGESIZE=$((1 << (12 + mps)))

	echo "=========================================="
	echo " MPS=${mps}  pagesize=${MPS_PAGESIZE} bytes"
	echo "=========================================="

	(
		set -x
		unvme create-adminq $BDF --pagesize=$MPS_PAGESIZE -s 32 -c 32
		unvme enable $BDF --mps=$mps
		unvme id-ctrl $BDF > /dev/null
		unvme id-ns $BDF -n 1 > /dev/null
	)

	create_ioqs $BDF $NR_IOQS

	(
		set -x
		unvme fio \
			--ioengine=libunvmed \
			--filename=$FIO_BDF \
			--nsid=1 \
			--direct=1 \
			--thread=1 \
			--numjobs=$NR_IOQS \
			--group_reporting \
			--time_based \
			--runtime=1s \
			--name=seqread_mps${mps} \
			--bs=128k \
			--iodepth=128 \
			--rw=read
	)

	if [ $mps -lt $MPS_MAX ]; then
		(set -x; unvme disable $BDF)
	fi
done

echo ""
echo "All MPS iterations passed (MPS ${MPS_MIN}..${MPS_MAX})."
