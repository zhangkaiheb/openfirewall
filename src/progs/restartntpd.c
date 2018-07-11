/*
 * Ipcop helper program - restartntpd
 *
 * Starts or stops the ntpd daemon.
 *
 *
 * This file is part of the IPCop Firewall.
 *
 * IPCop is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * IPCop is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
 *
 * (c) Darren Critchley 2003
 * (c) 2006-2010, the IPCop team
 * 
 * $Id: restartntpd.c 4075 2010-01-05 16:13:18Z owes $
 * 
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "common.h"
#include "setuid.h"


#define MAX_SERVER 3


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  -r, --red             after update red\n");
    printf("  -f, --force           force a quick NTP sync\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char *argv[])
{
    NODEKV *kv = NULL;
    int flag_red = 0;
    int flag_quick = 0;
    int enabled = 0;
    int enabled_redirect = 0;
    int rc = 0;
    char ntp_server[MAX_SERVER+1][STRING_SIZE];
    int i;
    char command[STRING_SIZE_LARGE];

    static struct option long_options[] =
    {
        { "red", no_argument, 0, 'r' },
        { "force", no_argument, 0, 'f' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "frv", long_options, &option_index)) != -1) {
        switch (c) {
        case 'r':              /* red update */
            flag_red = 1;
            break;
        case 'f':              /* force quick sync */
            flag_quick = 1;
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

    /* Get configuration settings */
    verbose_printf(1, "Reading NTP settings ... \n");
    if (read_kv_from_file(&kv, "/var/ipcop/time/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read time settings\n");
        return 1;
    }
    if (test_kv(kv, "ENABLED_NTP", "on") == SUCCESS) {
        verbose_printf(1, "NTPd enabled\n");
        enabled = 1;
        if (test_kv(kv, "ENABLED_NTP_REDIRECT", "on") == SUCCESS) {
            verbose_printf(2, "NTP redirect enabled\n");
            enabled_redirect = 1;
        }
        else {
            verbose_printf(2, "NTP redirect not enabled\n");
        }
    }
    else {
        verbose_printf(1, "NTPd not enabled\n");
    }

    if (flag_red) {
        if (access("/var/run/ntpdate-red", 0) == -1) {
            verbose_printf(2, "Flagfile ntpdate RED not there\n");
            exit(0);
        }
        else {
            unlink("/var/run/ntpdate-red");
        }
    }

    /* Fetch ethernet/settings, exit on error */
    read_ethernet_settings(1);
    
    /* Stop ntpd if running */
    if (access("/var/run/ntpd.pid", 0) != -1) {
        verbose_printf(1, "Flush ntp iptables chain ... \n");
        safe_system("/sbin/iptables -t nat -F NTP");
        verbose_printf(1, "Stopping NTPd ... \n");
        if (mysignalpidfile("/var/run/ntpd.pid", SIGTERM) != SUCCESS ) {
            exit(0);
        }
        /* PID exists after stopping */
        unlink("/var/run/ntpd.pid");

        if (enabled) {
            /* small delay between stop and start */
            sleep(1);
        }
    }

    /* Synchronise clock now! */
    if (enabled && (flag_red || flag_quick)) {

        if (flag_verbose) {
            strcpy(command, "/usr/bin/ntpdate -U ntp -u");
        }
        else {
            strcpy(command, "/usr/bin/ntpdate -U ntp -su");
        }

        /* Initialize and retrieve NTP servers */
        for (i = 1; i <= MAX_SERVER; i++) {
            char key[STRING_SIZE];

            strcpy(ntp_server[i], "");
            snprintf(key, STRING_SIZE, "NTP_ADDR_%i", i);
            find_kv_default(kv, key, ntp_server[i]);
            strcat(command, " ");
            strcat(command, ntp_server[i]);
        }

        if (!flag_verbose) {
            /* Silence ntpdate, even with -s it can still produce messages in case RED down */
            strcat(command, " >/dev/null 2>/dev/null");
        }
        verbose_printf(1, "Starting NTP quick sync ... \n");
        rc = safe_system(command);
        if (flag_red && rc) {
            /* Add some output to indicate ntpdate failed and we possibly have wrong time */
            verbose_printf(0, "ntpdate failed");
        }
    }

    /* Start ntpd if enabled */
    if (enabled) {
        verbose_printf(1, "Starting NTPd ... \n");
        rc = safe_system("/usr/bin/ntpd -p /var/run/ntpd.pid -u ntp:ntp");
    }

    if (enabled && enabled_redirect) {
        /* redirect for GREEN */
        for (i = 1; i <= ipcop_ethernet.count[GREEN]; i++) {
            verbose_printf(2, "Setting redirect iptables rule for GREEN %i ... \n", i);
            snprintf(command, STRING_SIZE - 1,
                        "/sbin/iptables -t nat -A NTP -i %s -p udp --dport 123 ! -d %s -j DNAT --to %s",
                        ipcop_ethernet.device[GREEN][i], ipcop_ethernet.address[GREEN][i], ipcop_ethernet.address[GREEN][i]);
            safe_system(command);
        }
        /* redirect for BLUE */
        for (i = 1; i <= ipcop_ethernet.count[BLUE]; i++) {
            verbose_printf(2, "Setting redirect iptables rule for BLUE %i ... \n", i);
            snprintf(command, STRING_SIZE - 1,
                        "/sbin/iptables -t nat -A NTP -i %s -p udp --dport 123 ! -d %s -j DNAT --to %s",
                        ipcop_ethernet.device[BLUE][i], ipcop_ethernet.address[BLUE][i], ipcop_ethernet.address[BLUE][i]);
            safe_system(command);
        }
    }

    free_kv(&kv);

    return rc;
}
