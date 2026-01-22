#!/bin/bash
#
# Scenario
#  - Configure admin sq/cq with enabling primary controller
#  - Assign VI/VQ resources to secondary controller
#  - enable secondary controller(e.g., vf)
#  - make secondary controller to online state
#  - function level reset to VFs to init

set -e

bdf=$1
nr_vfs=$2

if [ $# -ne 2 ]; then
    echo "Usage: $0 <bdf> <nr_vfs>"
    echo ""
    echo "Example: $0 0000:01:00.0 4"
    exit 1
fi

(
set -x

bash -c "echo 0 > /sys/bus/pci/devices/$bdf/sriov_numvfs"
unvme start
unvme add $bdf
unvme create-adminq $bdf -s 32 -c 32
unvme enable $bdf
)

for (( i=1; i<=nr_vfs; i++ ))
do
    (
    set -x

    unvme virt-mgmt $bdf -c $i -r 0 -a 8 -n 2
    unvme virt-mgmt $bdf -c $i -r 1 -a 8 -n 2
    )
    echo "assign resources to VF$i"
done

(
set -x

bash -c "echo 1 > /sys/module/vfio_pci/parameters/enable_sriov"
bash -c "echo $nr_vfs > /sys/bus/pci/devices/$bdf/sriov_numvfs"
)
echo "enable VFs"

for (( i=1; i<=nr_vfs; i++ ))
do

    (
    set -x

    unvme virt-mgmt $bdf -c $i -a 9
    )
    echo "VF$i online"

    fnid=$(($i-1))

    # FLR here
    (
    set -x

    bash -c "echo 1 > /sys/bus/pci/devices/$bdf/virtfn$fnid/reset"
    )
    echo "FLR to VF$i"
done
(
set -x

unvme list
)
