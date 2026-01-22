#!/bin/bash
#
# Example (128KB sequential for 1MB)
#  - ./unvme-seq-rw.sh 1:0 read 4096 $((128*1024)) $((1*1024*1024))
#  - ./unvme-seq-rw.sh 1:0 write 4096 $((128*1024)) $((1*1024*1024))
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

unvme start
unvme add $bdf
unvme create-adminq $bdf -s 32 -c 32
unvme enable $bdf
unvme create-iocq $bdf -q 1 -z $(($nr * 2)) -v 1
unvme create-iosq $bdf -q 1 -z $(($nr * 2)) -c 1

for ((i=0; i<$nr; i++))
do
	unvme $rw $bdf --sqid=1 --namespace-id=1 \
		--start-block=$(($slba + ($i * $nlb))) \
		--block-count=$((nlb - 1)) \
		--data-size=$((blocksize)) \
		--data=/dev/null \
		--nodb
done
unvme update-sqdb $bdf -q 1

unvme stop
