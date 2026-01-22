#!/bin/bash
#
# Scenario
#  - Configure admin sq/cq with enabling controller
#  - Create I/O CQ and SQ with qid 1 for 32 qsize
#  - Issue READ commands without updating SQ tail doorbell
#  - Update tail doorbell at once

if [[ $# -ne 2 ]]; then
	echo "Usage: $0 <bdf> <qd>"
	exit 1
fi
bdf="$1"
qd="$2"

unvme start
unvme add $bdf
unvme create-adminq $bdf -s 32 -c 32
unvme enable $bdf
unvme create-iocq $bdf -q 1 -z 32 -v 1
unvme create-iosq $bdf -q 1 -z 32 -c 1

for ((i=0; i<$qd; i++))
do
	unvme read $bdf -q 1 -n 1 -s $i -c 0 -z 4096 -d /dev/null -N
done
unvme update-sqdb $bdf -q 1

unvme stop
