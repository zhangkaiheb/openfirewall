/*
 * arch_defs.h: Global defines, function definitions etc. concerning portabilty
 *              Probably only necessary for installer. 
 *
 * This file is part of the Openfirewall.
 *
 * Openfirewall is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Openfirewall is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Openfirewall.  If not, see <http://www.gnu.org/licenses/>.
 *
 * (c) 2007-2014, the Openfirewall Team
 *
 * $Id: arch_defs.h 7846 2015-02-01 18:35:46Z owes $
 * 
 */


/*  
    Test which arch is used for building.
    We currently support i386, alpha, powerpc and sparc.

    If you want to compile on a different architecture look in this file for modifications.
*/
#if defined (__i386__)
#elif defined (__x86_64__)
#elif defined (__alpha__)
#elif defined (__powerpc__) || defined (__powerpc64__)
#elif defined (__sparc__) || defined (__sparc64__)
#else
#error "We currently do not support your hardware architecture"
#endif


#include <stdint.h>
#include <sys/utsname.h>


/*
    Number of partitions
*/
#define OFW_PARTITIONS    2
#if defined (__i386__)
#define NR_PARTITIONS       2
#elif defined (__x86_64__)
#define NR_PARTITIONS       2
#elif defined (__alpha__)
#define NR_PARTITIONS       2
#elif defined (__powerpc__) || defined (__powerpc64__)
#define NR_PARTITIONS       4
#elif defined (__sparc__) || defined (__sparc64__)
#define NR_PARTITIONS       3
#endif

/*
    Partioning settings (all in MByte)
*/
#define DISK_MINIMUM    480     /* 512 MB minus several MB 'marketing-margin' */
#define ROOT_MINIMUM    256
#define ROOT_MAXIMUM    512
#define SWAP_MINIMUM     32
#define SWAP_MAXIMUM     64
#define LOGCOMPRESSED    64


#define TARBALL_OFW    "ipcop-" VERSION ".tar.gz"


typedef enum
{
    none = 0,
    floppy,                     /* bootable, restore */
    cdrom,                      /* bootable and sources available */
    usb,                        /* bootable, sources available and restore */
    harddisk,                   /* possible installation target */
    flash,                      /* target */
    network,                    /* bootable (PXE), sources available (http/ftp server) and restore (http/ftp server) */
    console,                    /* console: standard */
    serial,                     /* console: serial */
    specialmodule = 100,        /* for module list only */
    unknown,
} supported_media_t;


extern supported_media_t medium_boot;
extern supported_media_t medium_sources;
extern supported_media_t medium_target;
extern supported_media_t medium_console;

struct hardware_s
{
    char *module;               /* kernel module */
    char *device;               /* hda, sda, eth0 etc. */
    char *description;
    supported_media_t type;     /* network */
    char *vendorid;             /* vendor and device ID for better NIC matching */
    char *modelid;
};

extern unsigned int numhardwares;
extern unsigned int numharddisk;
extern unsigned int numcdrom;
extern unsigned int numnetwork;
extern struct hardware_s *hardwares;

extern char network_source[STRING_SIZE];        /* something like http://ip/path */
extern unsigned int memtotal;                   /* Total memory in MB */

extern unsigned int serial_console;             /* 0 = ttyS0, 1 = ttyS1, etc. */
extern unsigned int serial_bitrate;             /* 9600, 38400, etc. */
extern char *serial_commandline;                /* ttyS0,38400n81 */

/*
    Functions implemented in hardware.c and partition.c    
*/
void scan_hardware(int installer_setup, int nopcmcia, int nousb, int manualmodule);
int make_ofw_disk(char *device, char *device2, long int disk_size, long int swapfilesize, int part_options);

#define PART_OPTIONS_MANUAL     0x0001
#define PART_OPTIONS_NO_MBR     0x0002
#define PART_OPTIONS_NO_DMA     0x0004
#define PART_OPTIONS_PARTED     0x0008

#define PART_OPTIONS_USER_SIZE  0x8000


/* init uts & friends */
int helper_kernel_init(void);
/* retrieve kernel release, i.e. 3.4-3 */
char *helper_kernel_release(void);

/* find a kernel module for pci/usb bus depending on vendor and device id */
char *find_modulename(char *bus, uint16_t vendor_id, uint16_t device_id);

/* 
 * Get kernel module, vendor and device ID for device using 
 *     /sys/class/net/interface/device/driver/module
 * and /sys/class/net/interface/device/{vendor,device}
 */
char *getkernelmodule(char *device);
extern char module_buffer[STRING_SIZE];    /* to return the value out of the function */

extern char vendorid_buffer[STRING_SIZE];  /* global variable */
extern char deviceid_buffer[STRING_SIZE];  /* global variable */

