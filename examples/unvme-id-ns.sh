#!/bin/bash
#
# Scenario
#  - Configure admin sq/cq with enabling controller
#  - Issue Identify Namespace (CNS 0h) with nsid 1

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <bdf>"
	exit 1
fi
bdf="$1"

unvme start
unvme add $bdf
unvme create-adminq $bdf
unvme enable $bdf
unvme id-ns $bdf -n 0x1
unvme stop
