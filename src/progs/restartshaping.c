/* IPCop helper program - restartshaping
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
 * along with IPCop; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) 2002-04-09 Mark Wormgoor <mark@wormgoor.com>
 *
 * $Id: restartshaping.c 5146 2010-11-19 09:26:12Z owes $
 *
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"
#include "setuid.h"


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char *argv[])
{
    FILE *file = NULL;
    NODEKV *shp_kv = NULL;
    int uplink, downlink, count = 0, r2q = 10;
    char command[STRING_SIZE];
    char *iface;
    char s[STRING_SIZE];
    char *result;
    char proto[STRING_SIZE];
    char *protocol;
    char *port;
    char *prio;
    char *enabled;

    static struct option long_options[] =
    {
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid())) {
        fprintf(stderr, "Cannot run setuid\n");
        exit(1);
    }

    while ((c = getopt_long(argc, argv, "v", long_options, &option_index)) != -1) {
        switch (c) {
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

    verbose_printf(1, "Reading shaping settings ... \n");
    if (read_kv_from_file(&shp_kv, "/var/ipcop/shaping/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read shaping settings\n");
        goto EXIT;
    }

    /* Find the VALID value */
    if (test_kv(shp_kv, "VALID", "yes") != SUCCESS) {
        fprintf(stderr, "Configuration is not VALID\n");
        goto EXIT;
    }

    /* Fetch ethernet/settings, exit on error */
    read_ethernet_settings(1);

    /* See what interface there is */
    if (ipcop_ethernet.red_device[1][0] == 0) {
        fprintf(stderr, "Couldn't open iface file\n");
        return (1);
    }

    iface = ipcop_ethernet.red_device[1];

    /* Remove old shaping, silence error since shaping may have been inactive */
    verbose_printf(1, "Remove qdiscs ... \n");
    snprintf(command, STRING_SIZE - 1, "/sbin/tc qdisc del dev %s root %s", iface, flag_verbose ? "" : "2>/dev/null");
    safe_system(command);
    snprintf(command, STRING_SIZE - 1, "/sbin/tc qdisc del dev %s ingress %s", iface, flag_verbose ? "" : "2>/dev/null");
    safe_system(command);

    /* Find the ENABLE value */
    if (test_kv(shp_kv, "ENABLE", "on") != SUCCESS) {
        verbose_printf(1, "Shaping is not ENABLED\n");
        goto EXIT;
    }

    /* Find the UPLINK value */
    if (find_kv_default(shp_kv, "UPLINK", s) != SUCCESS) {
        fprintf(stderr, "Cannot read UPLINK\n");
        goto EXIT;
    }
    uplink = atoi(s);
    if (uplink <= 0) {
        fprintf(stderr, "Invalid value for UPLINK\n");
        goto EXIT;
    }
    /* In some limited testing, it was shown that
       r2q = ( uplink * 1024 / 1500 );
       * produced error messages from the kernel saying r2q needed to be
       * changed. 1500 is taken as the MTU, but it seems that 16384 works
       * better. -Alan.
     */
    r2q = (uplink * 1024 / 16384);
    uplink = (uplink * 100) / 101;

    /* Find the DOWNLINK value, 0 is allowed to skip downlink shaping */
    if (find_kv_default(shp_kv, "DOWNLINK", s) != SUCCESS) {
        fprintf(stderr, "Cannot read DOWNLINK\n");
        goto EXIT;
    }
    downlink = atoi(s);
    if (downlink < 0) {
        fprintf(stderr, "Invalid value for DOWNLINK\n");
        goto EXIT;
    }
    downlink = (downlink * 200) / 201;

    verbose_printf(1, "Add qdiscs ... \n");
    /* Uplink classes */
    snprintf(command, STRING_SIZE - 1,
            "/sbin/tc qdisc add dev %s root handle 1: htb default 20 r2q %d",
            iface, r2q);
    safe_system(command);
    snprintf(command, STRING_SIZE - 1,
            "/sbin/tc class add dev %s parent 1: classid 1:1 htb rate %dkbit",
            iface, uplink);
    safe_system(command);
    snprintf(command, STRING_SIZE - 1,
             "/sbin/tc class add dev %s parent 1:1 classid 1:10 htb rate %dkbit ceil %dkbit prio 1", iface,
             (8 * uplink) / 10, uplink);
    safe_system(command);
    snprintf(command, STRING_SIZE - 1,
             "/sbin/tc class add dev %s parent 1:1 classid 1:20 htb rate %dkbit ceil %dkbit prio 2", iface,
             (6 * uplink) / 10, uplink);
    safe_system(command);
    snprintf(command, STRING_SIZE - 1,
             "/sbin/tc class add dev %s parent 1:1 classid 1:30 htb rate %dkbit ceil %dkbit prio 3", iface,
             (4 * uplink) / 10, uplink);
    safe_system(command);

    /* Uplink Stochastic fairness queue */
    snprintf(command, STRING_SIZE - 1, "/sbin/tc qdisc add dev %s parent 1:10 handle 10: sfq perturb 10", iface);
    safe_system(command);
    snprintf(command, STRING_SIZE - 1, "/sbin/tc qdisc add dev %s parent 1:20 handle 20: sfq perturb 10", iface);
    safe_system(command);
    snprintf(command, STRING_SIZE - 1, "/sbin/tc qdisc add dev %s parent 1:30 handle 30: sfq perturb 10", iface);
    safe_system(command);

    /* TOS Minimum Delay and ICMP traffic for high priority queue */
    snprintf(command, STRING_SIZE - 1,
             "/sbin/tc filter add dev %s parent 1:0 protocol ip prio 10 u32 match ip tos 0x10 0xff flowid 1:10", iface);
    safe_system(command);
    snprintf(command, STRING_SIZE - 1,
             "/sbin/tc filter add dev %s parent 1:0 protocol ip prio 10 u32 match ip protocol 1 0xff flowid 1:10", iface);
    safe_system(command);

    /* ACK packets for high priority queue (to speed up downloads) */
    snprintf(command, STRING_SIZE - 1,
             "/sbin/tc filter add dev %s parent 1: protocol ip prio 10 u32 match ip protocol 6 0xff match u8 0x05 0x0f at 0 match u16 0x0000 0xffc0 at 2 match u8 0x10 0xff at 33 flowid 1:10",
             iface);
    safe_system(command);

    verbose_printf(1, "Add shaping rules ... \n");
    file = fopen("/var/ipcop/shaping/config", "r");
    if (file) {
        while (fgets(s, STRING_SIZE, file) != NULL) {
            if (s[strlen(s) - 1] == '\n')
                s[strlen(s) - 1] = '\0';
            result = strtok(s, ",");

            count = 0;
            protocol = NULL;
            port = NULL;
            prio = NULL;
            enabled = NULL;
            while (result) {
                if (count == 0)
                    protocol = result;
                else if (count == 1)
                    port = result;
                else if (count == 2)
                    prio = result;
                else if (count == 3)
                    enabled = result;
                count++;
                result = strtok(NULL, ",");
            }
            if (!(protocol && port && prio && enabled)) {
                break;
            }

            if (strcmp(protocol, "tcp") == 0) {
                strcpy(proto, "6");
            }
            else if (strcmp(protocol, "udp") == 0) {
                strcpy(proto, "17");
            }
            else {
                fprintf(stderr, "Bad protocol: %s\n", protocol);
                goto EXIT;
            }

            if (strspn(port, PORT_NUMBERS) != strlen(port)) {
                fprintf(stderr, "Bad port: %s\n", port);
                goto EXIT;
            }
            if (strspn(prio, NUMBERS) != strlen(prio)) {
                fprintf(stderr, "Bad priority: %s\n", prio);
                goto EXIT;
            }

            if (strcmp(enabled, "on") == 0) {
                snprintf(command, STRING_SIZE - 1,
                         "/sbin/tc filter add dev %s parent 1: protocol ip prio 14 u32 match ip protocol %s 0xff match ip dport %s 0xffff flowid 1:%s",
                         iface, proto, port, prio);

                safe_system(command);

                snprintf(command, STRING_SIZE - 1,
                         "/sbin/tc filter add dev %s parent 1: protocol ip prio 15 u32 match ip protocol %s 0xff match ip sport %s 0xffff flowid 1:%s",
                         iface, proto, port, prio);

                safe_system(command);
            }
        }
    }

    /* Setting everything else to the default queue */
    snprintf(command, STRING_SIZE - 1,
             "/sbin/tc filter add dev %s parent 1: protocol ip prio 18 u32 match ip dst 0.0.0.0/0 flowid 1:20", iface);
    safe_system(command);

    /* Downlink Section */
    if (downlink > 0) {
        snprintf(command, STRING_SIZE - 1, "/sbin/tc qdisc add dev %s handle ffff: ingress", iface);
        safe_system(command);
        snprintf(command, STRING_SIZE - 1,
                "/sbin/tc filter add dev %s parent ffff: protocol ip prio 50 u32 match ip src 0.0.0.0/0 police rate %dkbit burst 10k drop flowid :1",
                iface, downlink);
        safe_system(command);
    }

  EXIT:
    if (shp_kv)
        free_kv(&shp_kv);
    if (file)
        fclose(file);
    return 0;
}
