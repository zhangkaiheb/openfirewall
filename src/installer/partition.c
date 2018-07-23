/*
 * partition.c: Create partitions
 *
 * This file is part of the IPCop Firewall.
 *
 * IPCop is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * IPCop is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
 *
 * (c) 2007-2014, the IPCop team
 *
 *
 *
 *  Partition scheme is:
 *  i386      partition1 /
 *            partition2 /var/log
 *
 *  alpha     partition1 /          need to let space at disk start for aboot installation
 *            partition2 /var/log
 *            partition3 -- reserved, absolutely can't be used
 *
 *  powerpc   partition1 -- reserved, absolutely can't be used
 *            partition2 -- reserved, absolutely can't be used
 *            partition3 /
 *            partition4 /var/log
 *
 *  sparc     partition1 /
 *            partition2 /var/log
 *            partition3 -- reserved, absolutely can't be used
 *
 *  In case of flash installation, /var/log will be /var/log_compressed with fixed size.
 *  This to store the (regularly) compressed /var/log contents.
 *
 * $Id: partition.c 7846 2015-02-01 18:35:46Z owes $
 *
 */

#include <dirent.h>
#include <fcntl.h>
#include <newt.h>
#ifdef USE_UUID
#include <libvolume_id.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <parted/parted.h>

#include "common.h"
#include "common_newt.h"
#include "arch_defs.h"


// tweak for errorbox
#define  gettext  ipcop_gettext

#define BLKGETSIZE64 _IOR(0x12,114,size_t)

/*  Make these module globals.
    Since we are not multi-tasking, multi-threaded, multi-anything that is OK
    and avoids passing pointers to pointers, addresses of pointers, etc. between functions.
*/
static int raid;
static char arch[STRING_SIZE];                                  // alpha, powerpc, sparc, x86
static char install_type[STRING_SIZE];                          // onedisk, raid, flash
static char partition_label[NR_PARTITIONS][STRING_SIZE];        // add 1 string for terminator mark
static char partition_mount[NR_PARTITIONS][STRING_SIZE];        // mountpoints for partitions
static char partition_uuidenc[NR_PARTITIONS][STRING_SIZE];      // UUIDs

#define PART_INDEX_ROOT     0
#define PART_INDEX_VARLOG   1
static int partition_index[NR_PARTITIONS];  // [0] is / partition number, 0 translates to hda1
                                            // [1] is /var/log partition number, 0 translates to hda1
                                            // this may seem complicated but helps for differences in architectures

/*  Calculate for the user a useable disk schema partition
    and make it so.
*/
int make_partitions(char *dev, char *dev2, long int disk_size, int part_options, long int *swap_file)
{
    int i;
    int retcode = FAILURE;
    long int root_partition, log_partition;
    long int current_free;
    char command[STRING_SIZE];
    char device[STRING_SIZE];
    char device2[STRING_SIZE];
    newtComponent *f;
    newtComponent scale;

    snprintf(device, STRING_SIZE, "/dev/%s", dev);
    snprintf(device2, STRING_SIZE, "/dev/%s", dev2);

    /*
        Reduce disk size by 5MiB to reduce risk of partition errors caused by
        wrong disk size informations from /sys/block/DEVICE/size.
        Also alignment 'modifications' might lead to difficulty.
    */
    if (!(part_options & PART_OPTIONS_USER_SIZE)) {
        disk_size -= 5;
    }

    /*
       someday offer semi-manual partition here
       keep /, /var/log but allow user to set different sizes (> MINIMUM) or leave free space
     */

    if (medium_target == flash) {
        /* flash install is easy */
        *swap_file = 0;
        log_partition = LOGCOMPRESSED;
        root_partition = disk_size - log_partition;
        if (raid) {
            strcpy(install_type,"flashraid");
        } else {
            strcpy(install_type,"flash");
        }
    }
    else {
        if (raid) {
            strcpy(install_type,"raid");
        } else {
            strcpy(install_type,"onedisk");
        }
        /* set the minimum size(s) */
        root_partition = ROOT_MINIMUM;

        if ((*swap_file != -1) && (ROOT_MINIMUM + *swap_file >= disk_size)) {
            /* The wanted swapfilesize does not fit */
            fprintf(flog, "Not enough space for %ld MiB swapfile\n", *swap_file);
            *swap_file = -1;
        }

        if (*swap_file == -1) {
            *swap_file = SWAP_MINIMUM;
            log_partition = DISK_MINIMUM - ROOT_MINIMUM - SWAP_MINIMUM;
            current_free = disk_size - root_partition - log_partition - *swap_file;

            /* 25% of remaining space goes to swap and maximize swap */
            *swap_file += current_free / 4;
            if (*swap_file > SWAP_MAXIMUM) {
                *swap_file = SWAP_MAXIMUM;
            }
        }
        else {
            log_partition = DISK_MINIMUM - ROOT_MINIMUM - *swap_file;
            current_free = disk_size - root_partition - log_partition - *swap_file;
        }

        /* 25% of remaining space goes to root partition */
        root_partition += current_free / 4;
        /* and maximize root */
        if (root_partition > ROOT_MAXIMUM) {
            root_partition = ROOT_MAXIMUM;
        }
        /* swap is just a file in root partition */
        root_partition = root_partition + *swap_file;
    }

#if defined(__sparc__) || defined(__sparc64__)
    /* Trunk to 16 MB block and maximize to 65520 MByte which should be enough */
    root_partition &= 0xFFF0;
#endif
    /* recalc log */
    log_partition = disk_size - root_partition;

    /*
       We now have auto-partition data (in MiB)
       start:                    end:
       start_p                   root_p
       root_p                    disk_size
     */

    for (i = 0; i < NR_PARTITIONS; i++) {
        /* zap label and mountpoint strings */
        partition_label[i][0] = 0;
        partition_mount[i][0] = 0;
        partition_index[i] = -1;
    }

    /* define all label and mountpoints for the architectures we support */
#if defined(__i386__) || defined(__x86_64__)
    if (part_options & PART_OPTIONS_PARTED) {
        strcpy(arch, "x86_parted");
    }
    else {
        strcpy(arch, "x86");
    }
    partition_index[PART_INDEX_ROOT] = 0;
    partition_index[PART_INDEX_VARLOG] = 1;
#endif
#if defined(__powerpc__) || defined(__powerpc64__)
    strcpy(arch, "powerpc");
    partition_index[PART_INDEX_ROOT] = 2;
    partition_index[PART_INDEX_VARLOG] = 3;
#endif
#if defined(__sparc__) || defined(__sparc64__)
    strcpy(arch, "sparc");
    partition_index[PART_INDEX_ROOT] = 0;
    partition_index[PART_INDEX_VARLOG] = 1;
#endif
#if defined(__alpha__)
    strcpy(arch, "alpha");
    partition_index[PART_INDEX_ROOT] = 0;
    partition_index[PART_INDEX_VARLOG] = 1;
#endif

    strcpy(partition_label[partition_index[PART_INDEX_ROOT]], "root");
    strcpy(partition_mount[partition_index[PART_INDEX_ROOT]], "/");

    if (partition_index[PART_INDEX_ROOT] == -1) {
        /* Can't be, probably because of non-supported arch. */
        fprintf(flog, "Partition# for / is not set, non-supported arch?\n");
        return FAILURE;         /* exit immediately */
    }
    if (partition_index[PART_INDEX_VARLOG] == -1) {
        /* Can't be, probably because of non-supported arch. */
        fprintf(flog, "Partition# for /var/log is 0, non-supported arch?\n");
        return FAILURE;         /* exit immediately */
    }

    if (medium_target == flash) {
        strcpy(partition_label[partition_index[PART_INDEX_VARLOG]], "varlog_comp");
        strcpy(partition_mount[partition_index[PART_INDEX_VARLOG]], "/var/log_compressed");
    }
    else {
        strcpy(partition_label[partition_index[PART_INDEX_VARLOG]], "varlog");
        strcpy(partition_mount[partition_index[PART_INDEX_VARLOG]], "/var/log");
    }


    if (part_options & PART_OPTIONS_MANUAL) {
        /* OK, user thinks he's smart enough to do by himself */

        newtWinMessage(ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_OK"), "Do your thing with parted now!");

        /* TODO: some verification? */
        return SUCCESS;
    }

    statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_MAKING_PARTITIONS"));
        /* disk-partition parameters
         #1 arch (alpha, powerpc, sparc, x86)
         #2 dev name (without /dev)
         #3 size of root partition (in MiB)
         #4 disk size (in MiB) as seen by parted <device> unit MiB print
         #5 install type (onedisk , raid , flash) */
    snprintf(command, STRING_SIZE, "/usr/bin/disk-partition.sh %s %s %ld %ld %s",
             arch, dev, root_partition*1024*2, disk_size*1024*2, install_type);
    if (mysystem(command)) {
        fprintf(flog, "error partitioning %s\n", device);
        goto PARTITION_EXIT;
    }

    if (raid) {
        /* Repeat partitioning for 2nd disk */
        snprintf(command, STRING_SIZE, "/usr/bin/disk-partition.sh %s %s %ld %ld %s",
                 arch, dev2, root_partition*1024*2, disk_size*1024*2, install_type);
        if (mysystem(command)) {
            fprintf(flog, "error partitioning %s\n", device2);
            goto PARTITION_EXIT;
        }
    }

    retcode = SUCCESS;

PARTITION_EXIT:
    /* Remove status window */
    newtPopWindow();

    if (retcode == FAILURE) {
        fprintf(flog, "Make partitions failed ...\n");
        return FAILURE;
    }

    fprintf(flog, "Make partitions done ...\n");

    if (!raid) {
        return SUCCESS;
    }

    /* Create RAID and wait for the drives to be synchronised */

    f = (newtComponent *) statuswindow_progress(72, 5, ipcop_gettext("TR_TITLE_DISK"),
                                                ipcop_gettext("TR_CREATING_RAID"));
    scale = newtScale(1, 3, 70, 100);
    newtFormAddComponent(*f, scale);
    newtDrawForm(*f);
    newtScaleSet(scale, 0);
    newtRefresh();

    mysystem("/sbin/modprobe md-mod");
    mysystem("/sbin/modprobe raid1");
    if (system("echo y > /tmp/yes")) {
        /* We are in serious trouble if something simple like this fails */
        newtPopWindow();
        fprintf(flog, "ERROR: echo /tmp/yes failed\n");
        fprintf(flog, "Make RAID failed ...\n");
        return FAILURE;
    }

    for (i = 0; i < IPCOP_PARTITIONS; i++) {
        FILE *pipe;
        char string[STRING_SIZE];
        char *ptr;
        int percentage;

        snprintf(command, STRING_SIZE,
            "/sbin/mdadm --create /dev/md%d --homehost=ipcop --metadata=0.9 --level=1 --raid-devices=2 %s%d %s%d < /tmp/yes",
            i, device, partition_index[i]+1, device2, partition_index[i]+1);
        if (mysystem(command)) {
            newtPopWindow();
            fprintf(flog, "Make RAID failed ...\n");
            return FAILURE;
        }

        newtScaleSet(scale, (i * 100) / IPCOP_PARTITIONS);
        newtRefresh();
        sleep(1);

        while(system("cat /proc/mdstat | grep resync > /dev/null") == 0) {
            if ((pipe = popen("cat /proc/mdstat | grep resync", "r")) != NULL) {
                if(fgets(string, STRING_SIZE, pipe) == NULL) {
                    pclose(pipe);
                    continue;
                }

                /* Something like this:
                 *      [====>.....]  resync = 35.5% (x/y) etc... */

                ptr = strstr(string, "resync = ");
                if (ptr == NULL) {
                    pclose(pipe);
                    continue;
                }

                ptr += strlen("resync = ");
                percentage = atoi(ptr);
                newtScaleSet(scale, percentage/IPCOP_PARTITIONS + (i*100)/IPCOP_PARTITIONS);
                newtRefresh();

                pclose(pipe);
                sleep(1);
            }
        }
    }

    fprintf(flog, "Make RAID done ...\n");
    newtPopWindow();

    return SUCCESS;
}   /* End of int autopart() */


/*
    Format and copy ipcop files.
    We assume the disk is partitioned.
    No manual labelling.
*/
static int make_disk(char *dev, char *dev2, long int swap_file)
{
    char command[STRING_SIZE];
    char string[STRING_SIZE];
    char devname[STRING_SIZE];
    FILE *handlelocal;          // /etc/fstab containing only /, /boot and /var/log
    FILE *handletarget;         // full /harddisk/etc/fstab
    int i;
    int retcode;
    char tarball_location[STRING_SIZE] = "/tmp";
    newtComponent *f;

    if ((handlelocal = fopen("/etc/fstab", "w")) == NULL) {
        errorbox(ipcop_gettext("TR_UNABLE_TO_WRITE_ETC_FSTAB"));
        return FAILURE;
    }
    /* Need to create a temp. first, since /harddisk is not yet populated */
    if ((handletarget = fopen("/tmp/tmpfstab", "w")) == NULL) {
        errorbox(ipcop_gettext("TR_UNABLE_TO_WRITE_ETC_FSTAB"));
        return FAILURE;
    }
#define FORMAT_FSTAB  "%-14s %-14s %-10s %-20s %-5s %-5s\n"
    fprintf(handletarget, FORMAT_FSTAB, "# device", "mount-point", "type", "options", "dump", "fsck");
    fprintf(handletarget, FORMAT_FSTAB, "#", "", "", "", "", "order");

    /*  No special need to read and test for partitions.
        They are created by make_partitions() or by the user in case of manual partitioning.
        If a partition is missing, mke2fs will throw an error and we can abort.
    */

    statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_MAKING_FILESYSTEMS"));

    for (i = 0; i < IPCOP_PARTITIONS; i++) {
        int pindex = partition_index[i];
#ifdef USE_UUID
        int fd;
        struct volume_id *vid;
        uint64_t size;
        const char *uuid;
#endif

        if (raid) {
            snprintf(devname, STRING_SIZE, "/dev/md%d", i);
        }
        else {
            snprintf(devname, STRING_SIZE, "/dev/%s%d", dev, pindex+1);
        }
        partition_uuidenc[pindex][0] = 0;
        snprintf(command, STRING_SIZE, "/usr/bin/mke2fs -F -F -L %s -q -j %s", partition_label[pindex], devname);
        if (mysystem(command)) {
            newtPopWindow();
            switch (i) {
            case PART_INDEX_ROOT:
                errorbox(ipcop_gettext("TR_UNABLE_TO_MAKE_ROOT_FILESYSTEM"));
                break;
            case PART_INDEX_VARLOG:
                errorbox(ipcop_gettext("TR_UNABLE_TO_MAKE_LOG_FILESYSTEM"));
                break;
            default:
                /* FIXME: cannot be, can it? */
                break;
            }
            return FAILURE;
        }

#ifdef USE_UUID
        /* Following sequence from udev/vol_id.c to retrieve the UUID */
        fd = open(string, O_RDONLY);
        if (fd < 0) {
            fprintf(flog, " %s: error opening volume\n", devname);
        }
        else {
            if ((vid = volume_id_open_fd(fd)) == NULL) {
                fprintf(flog, " %s: error opening VID\n", devname);
            }
            else {
                /* OWES: could do with some error checking here. */
                ioctl(fd, BLKGETSIZE64, &size);
                volume_id_probe_filesystem(vid, 0, size);
                volume_id_get_uuid(vid, &uuid);
                volume_id_encode_string(uuid, partition_uuidenc[pindex], STRING_SIZE);
                fprintf(flog, "  %s UUID %s\n", devname, partition_uuidenc[pindex]);
            }
            close(fd);
        }
#endif

        fprintf(handlelocal, "%s\t/harddisk%s\text3\n", devname, partition_mount[pindex]);

        /* either use UUID,LABEL (when available) or device for /etc/fstab */
        if (partition_uuidenc[pindex][0]) {
            snprintf(devname, STRING_SIZE, "UUID=%s", partition_uuidenc[pindex]);
        }
        else if (partition_label[pindex][0]) {
            snprintf(devname, STRING_SIZE, "LABEL=%s", partition_label[pindex]);
        }
        fprintf(handletarget, FORMAT_FSTAB, devname, partition_mount[pindex], "ext3", "noatime", "1", "1");
    }

    /* Finalize target /etc/fstab */
    fprintf(handletarget, FORMAT_FSTAB, "tmpfs", "/tmp", "tmpfs", "defaults", "0", "0");
    fprintf(handletarget, FORMAT_FSTAB, "proc", "/proc", "proc", "defaults", "0", "0");
    fprintf(handletarget, FORMAT_FSTAB, "sysfs", "/sys", "sysfs", "defaults", "0", "0");
    fprintf(handletarget, FORMAT_FSTAB, "devpts", "/dev/pts", "devpts", "gid=5,mode=620", "0", "0");
    /* /dev/shm is required for POSIX shared memory. */
    fprintf(handletarget, FORMAT_FSTAB, "shm", "/dev/shm", "tmpfs", "defaults,nosuid,nodev,noexec", "0", "0");

#if defined(__sparc__) || defined(__sparc64__)
    fprintf(handletarget, FORMAT_FSTAB, "openpromfs", "/proc/openprom", "openpromfs", "defaults", "0", "0");
#endif

    fclose(handlelocal);
    fclose(handletarget);
    newtPopWindow();

    statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_MOUNTING_ROOT_FILESYSTEM"));
    /* load ext3 now */
    if (mysystem("/sbin/modprobe ext4") || mysystem("/bin/mount /harddisk/")) {
        newtPopWindow();
        errorbox(ipcop_gettext("TR_UNABLE_TO_MOUNT_ROOT_FILESYSTEM"));
        return FAILURE;
    }
    newtPopWindow();

    /* create mountpoint for /var/log and mount */
    statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_MOUNTING_LOG_FILESYSTEM"));
    snprintf(command, STRING_SIZE, "/bin/mkdir -p /harddisk%s", partition_mount[partition_index[PART_INDEX_VARLOG]]);
    mysystem(command);
    snprintf(command, STRING_SIZE, "/bin/mount /harddisk%s", partition_mount[partition_index[PART_INDEX_VARLOG]]);
    if (mysystem(command)) {
        newtPopWindow();
        errorbox(ipcop_gettext("TR_UNABLE_TO_MOUNT_LOG_FILESYSTEM"));
        return FAILURE;
    }
    newtPopWindow();

    /* populate files on the partitions */
    switch (medium_sources) {
    case cdrom:
        strcpy(tarball_location, "/cdrom");
        break;
    case network:
        /* download needed files */
        statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_DOWNLOADING_IMAGE"));
        mysystem("mkdir -p /harddisk/tmp");

        strcpy(string, TARBALL_IPCOP);
        snprintf(command, STRING_SIZE, "wget -O /harddisk/tmp/%s %s/%s", string, network_source, string);
        if ((retcode = mysystem(command)) == 0) {
            strcpy(tarball_location, "/harddisk/tmp");
        }
        newtPopWindow();

        if (retcode) {
            /* Houston we have a problem, wget failed */
            snprintf(command, STRING_SIZE, ipcop_gettext("TR_TAR_GZ_NOT_FOUND"), string, network_source);
            errorbox(command);
            return FAILURE;
        }
        break;

    default:
        /* ouch how did we get here ? */
        return FAILURE;
    }

    f = (newtComponent *) statuswindow_progress(72, 5, ipcop_gettext("TR_TITLE_DISK"),
                                                ipcop_gettext("TR_INSTALLING_FILES"));
    snprintf(command, STRING_SIZE, "/bin/tar -C /harddisk -vxpzf %s/" TARBALL_IPCOP, tarball_location);
    retcode = mysystem_progress(command, f, 1, 3, 70, 5250, 0);
    if (medium_sources == network) {
        mysystem("rm -f /harddisk/tmp/" TARBALL_IPCOP);
    }

    newtFormDestroy(*f);
    newtPopWindow();

    /* abort if tar failed (source missing or archive broken) */
    if (retcode) {
        newtWinMessage(get_title(), ipcop_gettext("TR_OK"), "tar error");
        return FAILURE;
    }

    /* Create swapfile (if any) */
    if (swap_file != 0) {
        statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_MAKING_SWAPSPACE"));
        snprintf(command, STRING_SIZE, "/bin/dd if=/dev/zero of=/harddisk/swapfile bs=1024k count=%ld", swap_file);
        if (mysystem(command)) {
            newtPopWindow();
            errorbox(ipcop_gettext("TR_UNABLE_TO_MAKE_SWAPSPACE"));
            return FAILURE;
        }

        retcode = mysystem("mkswap /harddisk/swapfile");
        newtPopWindow();
        if (retcode) {
            errorbox(ipcop_gettext("TR_UNABLE_TO_MAKE_SWAPSPACE"));
            return FAILURE;
        }

        /*  We need to activate swap here
         *  depmod requires a lot of memory (~50-60 MB) which will fail on a 64 MB machine without swap */
        statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_MOUNTING_SWAP_PARTITION"));
        retcode = mysystem("swapon /harddisk/swapfile");
        newtPopWindow();
        if (retcode) {
            errorbox(ipcop_gettext("TR_UNABLE_TO_MOUNT_SWAP_PARTITION"));
            return FAILURE;
        }
    }

    /* Now is a good time to move temp. fstab to final location */
    mysystem("mv /tmp/tmpfstab /harddisk/etc/fstab");

    if (raid) {
        /* Create mdadm.conf, also for inclusion in initramfs */
        mysystem("mkdir -p /harddisk/etc/mdadm");
        if (system("echo DEVICE partitions > /harddisk/etc/mdadm/mdadm.conf")) {
            errorbox(ipcop_gettext("TR_UNABLE_TO_INSTALL_FILES"));
            return FAILURE;
        }
        if (system("/sbin/mdadm --examine --scan >> /harddisk/etc/mdadm/mdadm.conf")) {
            errorbox(ipcop_gettext("TR_UNABLE_TO_INSTALL_FILES"));
            return FAILURE;
        }
    }

    return SUCCESS;
}


static int create_initramfs(void)
{
    char bigstring[STRING_SIZE_LARGE];  // many modules maybe!
    int i;
    int retcode;
    FILE *handle;

    statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_BUILDING_INITRD"));

    // run depmod to have complete modules.* files on target system
    snprintf(bigstring, STRING_SIZE, "chroot /harddisk /sbin/depmod -a %s", helper_kernel_release());
    if (mysystem(bigstring)) {
        errorbox(ipcop_gettext("TR_UNABLE_TO_BUILD_INITRD"));
        newtPopWindow();
        return FAILURE;
    }

    //pivot_root for initrd
    mkdir("/harddisk/initrd", S_IRWXU | S_IRWXG | S_IRWXO);

    strcpy(bigstring,
           "chroot /harddisk /sbin/mkinitramfs --with-firmware --many-modules --with-list=/etc/modules.initramfs");

    if ((handle = fopen("/harddisk/etc/modules.initramfs", "w")) == NULL) {
        errorbox(ipcop_gettext("TR_UNABLE_TO_BUILD_INITRD"));
        newtPopWindow();
        return FAILURE;
    }

    /* TODO be more specific which modules to include */
    fprintf(handle, "ext4\njbd2\n");
    fprintf(handle, "ehci-hcd\nohci-hcd\nuhci-hcd\nhid\nusbhid\n");

    //add each module to module-list
    for (i = 0; i < numhardwares; i++) {
        if ((hardwares[i].type == specialmodule) && hardwares[i].module[0]) {
            fprintf(handle, "%s\n", hardwares[i].module);
        }
    }

#if defined(__sparc__) || defined(__sparc64__)
    fprintf(handle, "sparcspkr\n");
#else
    fprintf(handle, "pcspkr\n");
#endif

    if (raid) {
        fprintf(handle, "md-mod\nraid1\n");
    }
    fclose(handle);

    strcat(bigstring, " --with-kernel=");
    strcat(bigstring, helper_kernel_release());

    retcode = mysystem(bigstring);
    newtPopWindow();
    if (retcode) {
        errorbox(ipcop_gettext("TR_UNABLE_TO_BUILD_INITRD"));
        return FAILURE;
    }

    return SUCCESS;
}


/*  Make the new installation bootable, add ramdisksize.
    Note that there are few similarities between the architectures here.
*/
static int make_bootable(char *dev, char *dev2, int part_options)
{
    char command[STRING_SIZE];
    char bigstring[STRING_SIZE_LARGE];
    char device[STRING_SIZE];
    char device2[STRING_SIZE];

    statuswindow(72, 5, ipcop_gettext("TR_TITLE_DISK"), ipcop_gettext("TR_MAKING_BOOTABLE"));

    snprintf(device, STRING_SIZE, "/dev/%s", dev);
    snprintf(device2, STRING_SIZE, "/dev/%s", dev2);

#if defined(__i386__) || defined(__x86_64__)
    snprintf(bigstring, STRING_SIZE, "/bin/sed -i -e 's+KVER+%s+g' ", helper_kernel_release());

    if (raid) {
        /* replace the ROOT_DEV with md0 */
        strcat(bigstring, "-i -e 's+ROOT_DEV+/dev/md0+g' ");
    }
    else if (partition_uuidenc[PART_INDEX_ROOT][0]) {
        /* replace the ROOT_DEV with UUID partition */
        snprintf(command, STRING_SIZE, "-i -e 's+ROOT_DEV+/dev/disk/by-uuid/%s+g' ",
                 partition_uuidenc[PART_INDEX_ROOT]);
        strcat(bigstring, command);
    }
    else if (partition_label[PART_INDEX_ROOT][0]) {
        /* replace the ROOT_DEV with LABEL partition */
        snprintf(command, STRING_SIZE, "-i -e 's+ROOT_DEV+/dev/disk/by-label/%s+g' ", "root");
        strcat(bigstring, command);
    }
    else {
        /* fallback: replace the ROOT_DEV with the real device, partition 1 */
        snprintf(command, STRING_SIZE, "-i -e 's+ROOT_DEV+%s1+g' ", device);
        strcat(bigstring, command);
    }

    if (medium_console == serial) {
        snprintf(command, STRING_SIZE, "-i -e 's+SERIAL_CONSOLE+SERIAL %u %u\\nCONSOLE 0+' ",
                serial_console, serial_bitrate);
        strcat(bigstring, command);
        snprintf(command, STRING_SIZE, "-i -e 's+serial_settings+console=%s+' ",
                serial_commandline);
        strcat(bigstring, command);
    }
    else {
        strcat(bigstring, "-i -e 's+SERIAL_CONSOLE++' ");
        strcat(bigstring, "-i -e 's+serial_settings++' ");
    }
    if (part_options & PART_OPTIONS_NO_DMA) {
        /* Add nodma */
        fprintf(flog, "Adding nodma\n");
        strcat(bigstring, "-i -e 's+flashdisk_settings+nodma+' ");
    }
    else {
        strcat(bigstring, "-i -e 's+flashdisk_settings++' ");
    }

    strcat(bigstring, "/harddisk/boot/extlinux.conf");
    if (mysystem(bigstring)) {
        return(FAILURE);
    }
    mysystem("/bin/sync");

    /* Install extlinux and MBR */
    if (mysystem("chroot /harddisk /sbin/extlinux --install /boot")) {
         return FAILURE;
    }
    if (part_options & PART_OPTIONS_NO_MBR) {
        fprintf(flog, "Skipping MBR\n");
    }
    else {
        fprintf(flog, "Writing MBR\n");
        snprintf(command, STRING_SIZE, "/bin/cat /harddisk/boot/mbr.bin > %s", device);
        if (system(command)) {
            return FAILURE;
        }

        if (raid) {
            snprintf(command, STRING_SIZE, "/bin/cat /harddisk/boot/mbr.bin > %s", device2);
            if (system(command)) {
                return FAILURE;
            }
        }
    }
#endif

#if defined (__powerpc__) || defined (__powerpc64__)
    int newworld = 1;           /* 1 = NewWorld powerpc; 0 = OldWorld.  Partitions are the same, bootloaders are not */
    FILE *cpufile = NULL;
    char line[STRING_SIZE];
    char string[STRING_SIZE];

    /* Let's first detect if this is a newworld or an oldworld mac */
    if (!(cpufile = fopen("/proc/cpuinfo", "r"))) {
        fprintf(flog, "Couldn't open cpufile: /proc/cpuinfo\n");
    }
    else {
        while (fgets(line, STRING_SIZE, cpufile)) {
            if (sscanf(line, "pmac-generation : %s", string)) {
                if (strcmp(string, "NewWorld") == 0) {
                    newworld = 1;
                }
                else if (strcmp(string, "OldWorld") == 0) {
                    newworld = 0;
                }
            }
        }

        fprintf(flog, "Found %s mac.\n", string);
        fclose(cpufile);
    }

    fprintf(flog, "Making this machine bootable\n");

    if (newworld) {
        fprintf(flog, "Configuring Open Firmware (NewWorld)\n");
        snprintf(command, STRING_SIZE, "chroot /harddisk /usr/sbin/mkofboot --force -b %s2", device);
        mysystem(command);

        snprintf(command, STRING_SIZE, "/bin/sed -i -e 's+KVER+%s+g' /harddisk/etc/yaboot.conf", helper_kernel_release());
        mysystem(command);

        /* replace the ROOT_DEV with the real device, partition 2 */
        if (raid) {
            /* replace the ROOT_DEV with md0 */
            mysystem("/bin/sed -i -e 's+BOOTSTRAP_DEV+/dev/md0+g' /harddisk/etc/yaboot.conf");
        }
        else {
            snprintf(command, STRING_SIZE, "/bin/sed -i -e 's+BOOTSTRAP_DEV+%s2+g' /harddisk/etc/yaboot.conf", device);
            mysystem(command);
        }
        snprintf(command, STRING_SIZE, "/bin/sed -i -e 's+ROOT_DEV+%s4+g' /harddisk/etc/yaboot.conf", device);
        mysystem(command);

        fprintf(flog, "Running ybin\n");
        snprintf(command, STRING_SIZE, "chroot /harddisk /usr/sbin/ybin");
        if (mysystem(command)) {
             return FAILURE;
        }
    }
    else {
        fprintf(flog, "Configuring Open Firmware (OldWorld)\n");
        snprintf(command, STRING_SIZE, "chroot /harddisk /usr/local/bin/install-quik.sh %s3 %s4", device, device);
        if (mysystem(command)) {
             return FAILURE;
        }
    }
#endif

#if defined (__sparc__) || defined (__sparc64__)
    fprintf(flog, "Installing silo\n");

    snprintf(command, STRING_SIZE, "/bin/sed -i -e 's+KVER+%s+g' /harddisk/etc/silo.conf", helper_kernel_release());
    mysystem(command);

    if (raid) {
        /* replace the ROOT_DEV with md0 */
        mysystem("/bin/sed -i -e 's+ROOT_DEV+/dev/md0+g' /harddisk/etc/silo.conf");
    }
    else if (partition_uuidenc[PART_INDEX_ROOT][0]) {
        /* replace the ROOT_DEV with UUID partition */
        snprintf(command, STRING_SIZE, "/bin/sed -i -e 's+ROOT_DEV+/dev/disk/by-uuid/%s+g' /harddisk/etc/silo.conf",
                 partition_uuidenc[PART_INDEX_ROOT]);
        mysystem(command);
    }
    else if (partition_label[PART_INDEX_ROOT][0]) {
        /* replace the ROOT_DEV with LABEL partition */
        snprintf(command, STRING_SIZE, "/bin/sed -i -e 's+ROOT_DEV+/dev/disk/by-label/%s+g' /harddisk/etc/silo.conf", "root");
        mysystem(command);
    }
    else {
        /* replace the ROOT_DEV with the real device, partition 1 */
        snprintf(command, STRING_SIZE, "/bin/sed -i -e 's+ROOT_DEV+%s1+g' /harddisk/etc/silo.conf", device);
        mysystem(command);
    }

    /* We need to mount /proc/openprom so we can rewrite the boot-device prom variable */
    snprintf(command, STRING_SIZE, "chroot /harddisk /bin/mount /proc/openprom");
    mysystem(command);

    /* raid need -t flag to work, does not hurt in non raid case */
    snprintf(command, STRING_SIZE, "chroot /harddisk /sbin/silo -t");
    if (mysystem(command)) {
         return FAILURE;
    }

    /* set boot-device once calculated the number from the letter hda=>disk0 hdc=>disk2 */
    /* TODO make that work too with device name lenght different of 3 (hardware raid cciss and )? */
    if (strlen(device) != 7 ) {
        fprintf(flog, "with mmcblk and cciss, you need to set boot-device manually with setenv boot-device disk<your number>\n");
    } else {
        int devnum = device[7] - 'a';   /* 0/ 1d 2e 3v 4/ 5h 6d 7a */
        if (!raid) {
            snprintf(command, STRING_SIZE,
                "chroot /harddisk /usr/sbin/eeprom boot-device=disk%d", devnum);
        } else {
            int devnum2 = device2[7] - 'a';
            snprintf(command, STRING_SIZE,
                "chroot /harddisk /usr/sbin/eeprom boot-device=\"disk%d disk%d\"", devnum, devnum2);
        }
        mysystem(command);
    }

    /* We can unmount /proc/openprom now */
    snprintf(command, STRING_SIZE, "chroot /harddisk /bin/umount /proc/openprom");
    mysystem(command);
#endif

#if defined(__alpha__)

/* Surely alpha must have something marked bootable as well ..... */

#endif

    newtPopWindow();
    return SUCCESS;
}


/*  The big one. Cleaning, cooking, laundring, the whole enchilada.
*/
int make_ipcop_disk(char *dev, char *dev2, long int disk_size, long int swap_file, int part_options)
{
    raid = (*dev2 != 0);
    /* Make partition table and partitions */
    if (make_partitions(dev, dev2, disk_size, part_options, &swap_file) != SUCCESS) {
        errorbox(ipcop_gettext("TR_UNABLE_TO_PARTITION"));
        return FAILURE;
    }

    /* Format the fresh partitions and fill them with files */
    if (make_disk(dev, dev2, swap_file) != SUCCESS)
        return FAILURE;

    /* Mount some filesystems for later use (chroot'd setup) */
    mysystem("/bin/mount -n -t sysfs none /harddisk/sys");
    mysystem("/bin/mount -n -t tmpfs none /harddisk/tmp");
    mysystem("/bin/mount -n -t proc  none /harddisk/proc");

    /* We've already discovered all the devices on the host, so use that information */
    mysystem("/bin/mount -n -o bind /dev /harddisk/dev");

    /* InitRD */
    if (create_initramfs() != SUCCESS)
        return FAILURE;

    /* Make the new installation bootable */
    if (make_bootable(dev, dev2, part_options)) {
         errorbox(ipcop_gettext("TR_BOOTLOADER_INSTALLATION_ERROR"));
         return FAILURE;
    }

    return SUCCESS;
}
