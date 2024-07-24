#!/bin/bash
#
# Example (4KB random for 1MB)
#  - ./unvme-rand-rw.sh 1:0 read 4096 $((4*1024)) $((1*1024*1024))
#  - ./unvme-rand-rw.sh 1:0 write 4096 $((4*1024)) $((1*1024*1024))
#
# Scenario
#  - Configure admin sq/cq with enabling controller
#  - Create I/O CQ and SQ with qid 1
#  - Issue READ ro WRITE commands without updating SQ tail doorbell
#  - Update tail doorbell at once

if [[ $# -ne 5 ]]; then
	echo "Usage: $0 <bdf> <rw> <lbasize> <blocksize> <totalsize>"
	exit 1
fi
bdf="$1"
rw="$2"
lbasize="$3"
blocksize="$4"
totalsize="$5"

slba=$((0))
nlb=$(expr $blocksize / $lbasize)
nr=$(expr $totalsize / $blocksize)
last_lba=$(expr $totalsize / $lbasize)

unvme start
unvme add $bdf
unvme enable $bdf
unvme create-iocq $bdf -q 1 -z $(($nr * 2)) -v 0
unvme create-iosq $bdf -q 1 -z $(($nr * 2)) -c 1

for ((i=0; i<$nr; i++))
do
	unvme $rw $bdf --sqid=1 --namespace-id=1 \
		--start-block=$(( RANDOM % $last_lba )) \
		--block-count=$((nlb - 1)) \
		--data-size=$((blocksize)) \
		--data=/dev/null \
		--nodb
done
unvme update-sqdb $bdf -q 1

unvme stop
