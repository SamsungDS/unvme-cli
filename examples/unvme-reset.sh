#!/bin/bash
#
# Scenario
#  - Configure admin sq/cq with enabling controller
#  - Reset the controller by setting CC.EN=0 and wait for CSTS.RDY=0

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <bdf>"
	exit 1
fi
bdf="$1"

unvme start
unvme add $bdf
unvme create-adminq $bdf -s 32 -c 32
unvme enable $bdf
unvme reset $bdf
unvme stop
