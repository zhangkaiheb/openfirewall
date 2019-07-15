/*
 * restartdhcp.c: suid helper to restart DHCP service
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
 * along with Openfirewall; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * (c) 2017-2020, the Openfirewall Team
 *
 */


#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
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
    printf("  -b, --boot            after booting create rules only\n");
    printf("                            no need to restart DHCPd\n");
    printf("  -s, --sighup          send sighup signal to DHCPd\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char **argv)
{
    int i, j;
    int flag_boot = 0;
    int flag_sighup = 0;
    char buffer[STRING_SIZE];
    NODEKV *dhcp_kv = NULL;
    int enabled[CFG_COLOURS_COUNT][MAX_NETWORK_COLOUR + 1];
    int enabled_count;

    static struct option long_options[] =
    {
        { "boot", no_argument, 0, 'b' },
        { "sighup", no_argument, 0, 's' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "bsv", long_options, &option_index)) != -1) {
        switch (c) {
        case 'b':              /* booting */
            flag_boot = 1;
            break;
        case 's':              /* sighup */
            flag_sighup = 1;
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

    /* Fetch ethernet/settings, exit on error */
    helper_read_ethernet_settings(1);

    /* Read DHCP settings */
    verbose_printf(1, "Reading DHCP settings ... \n");
    if (read_kv_from_file(&dhcp_kv, "/var/ofw/dhcp/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read DHCP settings\n");
        exit(1);
    }

    enabled_count = 0;
    memset(enabled, 0, sizeof(enabled));
    for (i = 0; i < CFG_COLOURS_COUNT; i++) {
        /* filter all but GREEN and BLUE */
        if ((i != GREEN) && (i != BLUE)) {
            continue;
        }

        for (j = 1; j <= MAX_NETWORK_COLOUR; j++) {
            snprintf(buffer, STRING_SIZE, "ENABLED_%s_%d", openfw_colours_text[i], j);

            if (test_kv(dhcp_kv, buffer, "on") == SUCCESS) {
                /* this card is enabled in dhcp/settings */
                if (j > openfw_ethernet.count[i]) {
                    /* card is missing in ethernet/settings */
                    fprintf(stderr, "%s_%d enabled but no device defined\n",
							openfw_colours_text[i], j);
                    exit(1);
                }

                enabled[i][j] = 1;
                enabled_count++;
            }
        }
    }
    verbose_printf(2, "  %d enabled interface(s)\n", enabled_count);

    /* restart dnsmasq, dhcp.cgi will have made appropriate dhcp config */
    if (flag_sighup) {
        verbose_printf(1, "Send SIGHUP to dnsmasq ... \n");
        safe_system("/etc/rc.d/rc.dnsmasq --sighup");
    }
    else if (!flag_boot) {
        verbose_printf(1, "Restarting dnsmasq ... \n");
        safe_system("/etc/rc.d/rc.dnsmasq --restart");
    }

    /* start dnsmasq not necessary */

    return 0;
}
