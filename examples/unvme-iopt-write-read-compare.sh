#!/bin/bash
#
# Scenario
#  - Configure admin sq/cq with enabling controller
#  - Create I/O CQ and SQ with qid 1 for 32 qsize
#  - Write random data to slba 0 with nlb 0
#  - Read it back and compare

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <bdf>"
	exit 1
fi
bdf="$1"

unvme start
unvme add $bdf
unvme enable $bdf
unvme create-iocq $bdf -q 1 -z 32 -v 0
unvme create-iosq $bdf -q 1 -z 32 -c 1

dd if=/dev/urandom of=/tmp/wdata.bin bs=4096 count=1 2> /dev/null

unvme passthru $bdf -q 1 -n 1 -o 0x1 -l 4096 -i /tmp/wdata.bin -w
unvme passthru $bdf -q 1 -o 0x2 -n 1 -l 4096 -r > /tmp/rdata.bin

unvme stop

diff /tmp/wdata.bin /tmp/rdata.bin
if [[ $? -ne 0 ]]; then
	echo "Data mismatch!"
	exit 1
fi
