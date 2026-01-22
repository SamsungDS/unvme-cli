#!/bin/bash

set -e

if [[ $# -ne 2 ]]; then
	echo "Usage: $0 <bdf> <nr_ioqs>"
	echo ""
	echo "This driver enables the given NVMe controller <bdf> and issues the following commands."
	echo "  - Identify Namespace (CNS 0h) to nsid=1"
	echo "  - Set Features for Number of Queues (FID 7h) for maximum number of queues"
	echo "  - Create 256-sized I/O CQ and SQ pair for <nr_ioqs> with interrupt enabled"
	exit 1
fi
bdf="$1"
nr_ioqs="$2"

function create_ioq() {
	bdf="$1"
	qid="$2"

	set -x
	unvme create-iocq $bdf -q $qid -z 256 -v $qid
	unvme create-iosq $bdf -q $qid -z 256 -c $qid
}

function init_hmb() {
	hmpre=$(unvme id-ctrl $bdf --output-format=json | jq -r '.hmpre')

	if (( $hmpre > 0 )); then
		(
		set -x
		unvme hmb $bdf --allocate --size=$hmpre
		)

		status=$(unvme status $bdf --output-format=json)
		desc=$(echo $status | jq -r '.hmb.descs_addr')
		nr_descs=$(echo $status | jq -r '.hmb.nr_descs')

		(
		set -x
		unvme set-features-hmb $bdf --enable --hsize=$hmpre --desc=$desc --nr-descs=$nr_descs 2> /dev/null
		)
	fi
}

if pgrep -x "unvmed" > /dev/null; then (
	set -x
	unvme stop
) fi

(
set -x
unvme start
unvme add $bdf --nr-ioqs=$nr_ioqs

unvme create-adminq $bdf --sqsize=32 --cqsize=32
unvme enable $bdf
unvme id-ns $bdf -n 1 > /dev/null
unvme set-features-noq $bdf -s 0xfffe -c 0xfffe > /dev/null
)

init_hmb &

for ((qid=1; qid <= $nr_ioqs; qid++));
do
	create_ioq $bdf $qid &
done

wait

(
set -x
unvme status $bdf
)
