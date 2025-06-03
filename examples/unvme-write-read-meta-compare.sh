#!/bin/bash
#
# Example (write and read metadata)
#  - ./unvme-meta-read-write-compare.sh $bdf 1
#
# Scenario
#  - Configure admin sq/cq with enabling controller
#  - Create I/O CQ and SQ with qid 1
#  - Issue READ and WRITE commands with metadata
#  - Check the difference between WRITE and READ data with metadata

set -x
set -e

if [[ $# -ne 4 ]]; then
	echo "Usage: $0 <bdf> <nsid> <lbasize> <metasize>"
	exit 1
fi

bdf="$1"
nsid="$2"
ds="$3"
ms="$4"

unvme start
unvme add $bdf
unvme create-adminq $bdf
unvme enable $bdf

unvme id-ns $bdf -n $nsid
unvme nvm-id-ns $bdf -n $nsid

unvme create-iocq $bdf -q 1 -z 32 -v 1
unvme create-iosq $bdf -q 1 -z 32 -c 1

dd if=/dev/urandom of=data.in bs=$ds count=1 2> /dev/null
dd if=/dev/urandom of=meta.in bs=$ms count=1 2> /dev/null
unvme write $bdf -q 1 -n $nsid -s 0 -c 0 -z $ds -d data.in -y $ms -M meta.in
unvme read $bdf -q 1 -n $nsid -s 0 -c 0 -z $ds -d data.out -y $ms -M meta.out

diff data.in data.out
diff meta.in meta.out

rm -f data.in
rm -f data.out
rm -f meta.in
rm -f meta.out

unvme stop
