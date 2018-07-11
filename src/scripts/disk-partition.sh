#!/bin/sh
#
# This file is part of the IPCop Firewall.
# (c) Gilles Espinasse
#
# something too easy to run would not be good on installed machine
# to be simplier, we do not count partitions size before '/ partition' that are present on some arch
# /var/log partition size is what remain from disk size after '/ partition'
# parameters list
#
# $Id: disk-partition.sh 7797 2015-01-08 08:45:27Z owes $
#

if [ $# -ne 5 ]; then
    echo "bad parameters number"
    echo "#1 arch (alpha, powerpc, sparc, x86)"
    echo "#2 device name (without /dev/)"
    echo "#3 size of root partition (in MiB)"
    echo "#4 disk size (in MiB) as seen by parted <device> unit MiB print"
    echo "#5 install type (onedisk, raid, flash, flashraid)"
    exit 1
fi

arch=$1
dev="/dev/$2"
root_size=$3
disk_size=$4
install_type=$5

erase_partition()
{
    local device

    # Try to remove old raid(s).
    # Stop raid on all /dev/md[0..9]? devices
    for device in $(ls /dev/md?*); do
        echo "Stopping raid on $device"
        /sbin/mdadm --stop $device
    done
    # Remove raid superblocks on $dev, no problem as we will overwrite the disk anyway
    for device in $(ls ${dev}*); do
        echo "Erasing raid superblock on $device"
        /sbin/mdadm --zero-superblock $device
    done

    # OWES: ped_device_get fails after this on some CF card/adapter.
    # Using nodma install parameter helps. */
    if ( ! /bin/dd if=/dev/zero of=$dev bs=512 count=2048 ); then
        echo "Fail: erase partition table, maybe dma issue"
        exit 1
    else
        echo "Done: partition table erased"
    fi
}

parted_call()
{
    if ( ! /usr/sbin/parted -s $1 ); then
        echo "Fail: parted -s $1"
        exit 1
    else
        echo "Done: parted -s $1"
    fi

    sleep 1
}

case "$install_type" in
    onedisk | raid )
        varlog_name="varlog"
        ;;
    flash | flashraid)
        varlog_name="varlog_comp"
        ;;
    *)
        echo "Unsupported install_type:$install_type"
        exit 1
        ;;
esac

case "$install_type" in
    raid | flashraid)
        raid="yes"
        ;;
    onedisk | flash)
        raid="no"
        ;;
    *)
        echo "Unsupported install_type:$install_type"
        exit 1
        ;;
esac

# erase before checking, some partitions may fool partprobe
erase_partition

# check for device
if ( ! /usr/sbin/partprobe $dev 2>&1 1>/dev/null ); then
    echo "device:$dev not found"
    exit 1
fi

# Create partitions
# generally sector 0 contain the partition table, so first partition start after
case "$arch" in
    x86)
        size=$((${disk_size}-1-${root_size}-1))
        echo ${root_size} ${size} ${disk_size} 
        if [ $raid = "yes" ]; then
            /sbin/sfdisk -fuM $dev << EOF
1,${root_size},fd,*
,${size},fd
EOF
        else
            /sbin/sfdisk -fuM $dev << EOF
1,${root_size},83,*
,${size},83
EOF
        fi
        ;;
    x86_parted)
        parted_call "$dev mklabel msdos"
        parted_call "$dev mkpart primary 1MiB ${root_size}MiB"
        parted_call "$dev mkpart primary $((${root_size}+1))MiB ${disk_size}MiB"
        parted_call "$dev set 1 boot on"
        if [ $raid = "yes" ]; then
            parted_call "$dev set 1 raid on"
            parted_call "$dev set 2 raid on"
        fi
        ;;
    alpha)
        parted_call "$dev mklabel bsd"
        # aboot need 70k or 150sectors * 512B at disk start
        parted_call "$dev mkpart primary 150s ${root_size}MiB"
        parted_call "$dev mkpart primary ${root_size}MiB ${disk_size}MiB"
        parted_call "$dev set 1 boot on"
        if [ $raid = "yes" ]; then
            parted_call "$dev set 1 raid on"
            parted_call "$dev set 2 raid on"
        fi
        ;;
    powerpc)
        # mac label create a first partition from sector 1 to 63
        parted_call "$dev mklabel mac"
        # so second partition start at sector 64 and contain boot code
        # (don't know if it could be smaller than 1MiB)
        parted_call "$dev mkpart primary 64s 1MiB"
        parted_call "$dev name 2 bootstrap"
        parted_call "$dev set 2 boot on"
        parted_call "$dev mkpart primary 1MiB ${root_size}MiB"
        parted_call "$dev name 3 root"
        parted_call "$dev mkpart primary ${root_size}MiB ${disk_size}MiB"
        parted_call "$dev name 4 $varlog_name"
        if [ $raid = "yes" ]; then
            parted_call "$dev set 3 raid on"
            parted_call "$dev set 4 raid on"
        fi
        ;;
    sparc)
        parted_call "$dev mklabel sun"
        # 'Whole disk' partition3 is not displayed by parted print but fdisk show that
        # boot flag is not needed on sun label
        # root partition should be limited to 1GB from start of disk (see silo docs/README)
        # sun partitions have to be aligned on cylinder boundaries (that's why we round root_size)
        if [ $raid = "yes" ]; then
            # first cylinder can't be used in raid case as swap or md use the first blocks
            # disk block 0 and 1 are used by silo to write partition and second.b
            parted_call "$dev mkpart 1cyl ${root_size}MiB"
        else
            # ext2 does not use the first blocks contrary to swap and md partitions
            parted_call "$dev mkpart 0 ${root_size}MiB"
        fi
        parted_call "$dev mkpart ${root_size}MiB ${disk_size}MiB"
        if [ $raid = "yes" ]; then
            parted_call "$dev set 1 raid on"
            parted_call "$dev set 2 raid on"
        fi
        ;;
    *)
        echo "Unsupported arch:$arch"
        exit 1
        ;;
esac

/bin/sync
/usr/sbin/partprobe $dev
# still look needed
# or I curiously had an error during second file system creation (/var/log)
sleep 1
