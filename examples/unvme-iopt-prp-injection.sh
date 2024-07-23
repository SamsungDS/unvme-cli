#!/bin/bash
#
# Scenario
#  - Configure admin sq/cq with enabling controller
#  - Create I/O CQ and SQ with qid 1 for 32 qsize
#  - Issue a WRITE command with a specific invalid values in prp1/prp2

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

unvme io-passthru $bdf -q 1 -n 1 -o 0x1 -w -i /dev/urandom -l 4k --prp1=0x12340000 --prp2=0xdead0000

unvme stop
