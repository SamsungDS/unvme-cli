#!/bin/bash

set -e

BDF=""
CMD_TIMEOUT=""

usage() {
	echo "Usage: $0 -b <bdf> [-T <timeout>]"
	echo "  -b <bdf>      : PCI device address (e.g., '0000:01:00.0')"
	echo "  -T <timeout>  : Command timeout in seconds (optional)"
	echo ""
	echo "Run a fio job write down 10% of the namespace (nsid=1) and verify it with "
	echo "NVMe COMPARE command rather than READ command."
	echo ""
	echo "Note that it assumes fio.so is installed in somewhere in the current system."
	exit 1
}

while getopts "b:T:" opt; do
	case ${opt} in
		b)
			BDF=$OPTARG
			;;
		T)
			CMD_TIMEOUT=$OPTARG
			;;
		\?)
			usage
			;;
	esac
done

if [ -z "$BDF" ]; then
	usage
fi

bdf="$BDF"
bdf_dot=$(echo $bdf | sed 's/:/./g')  # Convert ':' to '.' for fio

if pgrep -x "unvmed" > /dev/null; then (
	set -x
	unvme stop
) fi

(
set -x
unvme start
unvme add $bdf --nr-ioqs=$(nproc)

unvme create-adminq $bdf -s 32 -c 32
if [ -z "$CMD_TIMEOUT" ]; then
	unvme enable $bdf
else
	unvme enable $bdf -t $CMD_TIMEOUT
fi
unvme id-ns $bdf -n 1 > /dev/null
unvme set-features-noq $bdf -s 0xfffe -c 0xfffe > /dev/null
unvme create-iocq $bdf -q 1 -z 512 -v 1
unvme create-iosq $bdf -q 1 -z 512 -c 1
unvme status $bdf

unvme fio \
	--rw=write \
	--bs=128k \
	--size=10% \
	--ioengine=libunvmed \
	--filename=$bdf_dot \
	--nsid=1 \
	--name=write-and-verify \
	--verify=pattern \
	--verify_pattern=%o \
	--verify_mode=compare \
	--do_verify=1
)
