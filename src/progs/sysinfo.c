/* IPCop helper program - sysinfo
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
 * Copyright (C) 2006-05-27 weizen_42 at ipcop-forum dot de
 * (c) 2007-2011, the IPCop team
 *
 * $Id: sysinfo.c 5760 2011-07-31 15:11:53Z owes $
 *
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "common.h"
#include "setuid.h"


static char command[STRING_SIZE];


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  -b, --bios            run biosdecode\n"); 
    printf("  -d, --disk=DRIVE      get hdparm for dev DRIVE\n"); 
    printf("  -l, --link=ETH        get link status from ethtool for ETH\n"); 
    printf("  -m, --mii=ETH         get link status from mii-tool for ETH\n"); 
    printf("  -p, --pci=SLOT        get (very verbose) lspci info for SLOT\n"); 
    printf("  -r, --raid=DRIVE      get details for raid DRIVE\n"); 
    printf("  -u, --usb             get details for usb\n"); 
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char *argv[])
{
    int flag_disk = 0;
    int flag_link = 0;
    int flag_mii = 0;
    int flag_pci = 0;
    int flag_raid = 0;
    int flag_usb = 0;
    char *opt_eth = NULL;
    char *opt_mii = NULL;
    char *opt_drive = NULL;
    char *opt_raid = NULL;
    char *opt_slot = NULL;

    static struct option long_options[] =
    {
        { "disk", required_argument, 0, 'd' },
        { "link", required_argument, 0, 'l' },
        { "mii", required_argument, 0, 'm' },
        { "pci", required_argument, 0, 'p' },
        { "raid", required_argument, 0, 'r' },
        { "usb", no_argument, 0, 'u' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "d:l:m:p:r:uv", long_options, &option_index)) != -1) {
        switch (c) {
        case 'd':              /* hdparm drive */
            flag_disk = 1;
            opt_drive = strdup(optarg);
            break;
        case 'l':              /* ethtool link */
            flag_link = 1;
            opt_eth = strdup(optarg);
            break;
        case 'm':              /* mii-tool link */
            flag_mii = 1;
            opt_mii = strdup(optarg);
            break;
        case 'p':              /* pci slot */
            flag_pci = 1;
            opt_slot = strdup(optarg);
            break;
        case 'r':              /* raid drive */
            flag_raid = 1;
            opt_raid = strdup(optarg);
            break;
        case 'u':              /* lsusb */
            flag_usb = 1;
            break;
        case 'v':              /* verbose */
            flag_verbose++;
            break;
        case 'h':
            usage(argv[0], 0);
        default:
            fprintf(stderr, "unknown option\n");
            usage(argv[0], 1);
        }
    }

    if (!flag_disk && !flag_link && !flag_mii && !flag_pci && !flag_raid && !flag_usb) {
        fprintf(stderr, "option missing\n");
        usage(argv[0], 2);
    }

    if (flag_disk) {
        snprintf(command, STRING_SIZE - 1, "/usr/sbin/hdparm -I /dev/%s", opt_drive);
        safe_system(command);
    }
    if (flag_pci) {
        snprintf(command, STRING_SIZE - 1, "/usr/sbin/lspci -nvvvs %s", opt_slot);
        safe_system(command);
    }
    if (flag_raid) {
        snprintf(command, STRING_SIZE - 1, "/sbin/mdadm --detail /dev/%s", opt_raid);
        safe_system(command);
    }
    if (flag_usb) {
        safe_system("/usr/bin/lsusb");
    }
    if (flag_link) {
        snprintf(command, STRING_SIZE - 1, "/usr/sbin/ethtool %s", opt_eth);
        safe_system(command);
    }
    if (flag_mii) {
        snprintf(command, STRING_SIZE - 1, "/sbin/mii-tool %s", opt_mii);
        safe_system(command);
    }
    return (0);
}
