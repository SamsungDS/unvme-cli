#!/bin/bash

set -e

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <bdf>"
	echo ""
	echo "    @bdf: PCI device address (e.g., '0000:01:00.0')"
	echo ""
	echo "Run a fio job write down 10% of the namespace (nsid=1) and verify it with "
	echo "NVMe COMPARE command rather than READ command."
	echo ""
	echo "Note that it assumes fio.so is installed in somewhere in the current system."
	exit 1
fi
bdf="$1"
bdf_dot=$(echo $bdf | sed 's/:/./g')  # Convert ':' to '.' for fio

if pgrep -x "unvmed" > /dev/null; then (
	set -x
	unvme stop
) fi

(
set -x
unvme start
unvme add $bdf --nr-ioqs=$(nproc)

unvme create-adminq $bdf
unvme enable $bdf
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
