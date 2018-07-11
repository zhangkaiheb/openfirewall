/*
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
 * along with IPCop; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) 2005-10-25 Franck Bourdonnec
 * (c) 2009, the IPCop team
 *
 * $Id: ipcopreboot.c 6491 2012-03-18 12:35:39Z gespinasse $
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "common.h"
#include "setuid.h"


static int flag_boot = 0;
static int flag_bootfs = 0;
static int flag_down = 0;
static char command[STRING_SIZE_LARGE];
static char message[STRING_SIZE];


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION] [warning message]\n\n", prg);
    printf("Options:\n");
    printf("  --boot                reboot after shutdown\n");
    printf("  --bootfs              reboot after shutdown and force fsck\n");
    printf("  --down                halt or power off after shutdown\n");
    printf("  -v, --verbose         be verbose\n");
    printf("  --help                display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char**argv)
{
    static struct option long_options[] =
    {
        { "boot", no_argument, &flag_boot, 1},
        { "bootfs", no_argument, &flag_bootfs, 1},
        { "down", no_argument, &flag_down, 1 },
        { "verbose", no_argument, 0, 'v'},
        { "help", no_argument, 0, 'h'},
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;
    extern int optind;

    while ((c = getopt_long(argc, argv, "vh", long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
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

    if (!flag_boot && !flag_bootfs && !flag_down) {
        /* need at least one of boot, bootfs, down */
        usage(argv[0], 1);
    }

    if (!(initsetuid())) {
        exit(1);
    }

    /* Read remaining words. */
    message[0] = 0;
    for(c = optind; c < argc; c++) {
        if (strlen(message) + strlen(argv[c]) + 4 > STRING_SIZE)
            break;
        strcat(message, argv[c]);
        strcat(message, " ");
    }

    openlog("ipcopreboot", LOG_PID, LOG_USER);
    if (message[0]) {
        syslog(LOG_NOTICE, "%s", message);
    }
    if (flag_down) {
        syslog(LOG_NOTICE, "IPCop will shutdown and halt/power off");
        verbose_printf(1, "IPCop will shutdown and halt/power off ... \n");
        snprintf(command, STRING_SIZE_LARGE, "/sbin/shutdown -t 10 -h now %s", message);
        safe_system(command);
        return 0;
    }
    if (flag_boot) {
        syslog(LOG_NOTICE, "IPCop will shutdown and reboot");
        verbose_printf(1, "IPCop will shutdown and reboot ... \n");
        snprintf(command, STRING_SIZE_LARGE, "/sbin/shutdown -t 10 -r now %s", message);
        safe_system(command);
        return 0;
    }
    if (flag_bootfs) {
        syslog(LOG_NOTICE, "IPCop will shutdown and reboot with fsck forced");
        verbose_printf(1, "IPCop will shutdown and reboot with fsck forced ... \n");
        snprintf(command, STRING_SIZE_LARGE, "/sbin/shutdown -t 10 -F -r now %s", message);
        safe_system(command);
        return 0;
    }
    closelog();

    return 0;
}
