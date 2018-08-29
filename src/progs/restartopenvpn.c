/*
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
 * (c) 2009-2015 The Openfirewall Team
 *
 * $Id: restartopenvpn.c 7890 2015-02-15 17:01:39Z owes $
 *
 */


#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "common.h"
#include "setuid.h"


static int flag_start = 0;
static int flag_stop = 0;
static int flag_restart = 0;
static int flag_status = 0;
static int enabled_count;


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  --start               .\n"); 
    printf("  --stop                .\n"); 
    printf("  --restart             .\n"); 
//    printf("      --config          re-generate server.conf\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


/*
    Write server.conf
*/
void config()
{
    char command[STRING_SIZE];

    snprintf(command, STRING_SIZE,
        "/usr/bin/perl -e \"use NetAddr::IP; require '/usr/lib/ofw/vpn-functions.pl'; &VPN::writeovpnserverconf();\"");
    safe_system(command);

    exit(0);
}


/*
    Fetch server status from /var/log/openvpnserver.log
*/
void status()
{
    if (access("/var/log/openvpnserver.log", F_OK) == -1) {
        /* Does not exist? Server not yet started or something else */
        verbose_printf(1, "openvpnserver.log does not exist\n");
    }
    else {
        safe_system("cat /var/log/openvpnserver.log");
    }
    exit(0);
}


int main(int argc, char *argv[])
{
    int i, j;
    char buffer[STRING_SIZE];
    NODEKV *openvpn_kv = NULL;

    static struct option long_options[] =
    {
        { "start",   no_argument, &flag_start, 1 },
        { "stop",    no_argument, &flag_stop, 1 },
        { "restart", no_argument, &flag_restart, 1 },
        { "config", no_argument, 0, 'c' },
        { "status", no_argument, &flag_status, 1 },
        { "verbose", no_argument, 0, 'v' },
        { "help",    no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    while ((c = getopt_long(argc, argv, "v", long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            break;
        case 'v':              /* verbose */
            flag_verbose++;
            break;
        case 'c':
            config();
        case 'h':
            usage(argv[0], 0);
        default:
            fprintf(stderr, "unknown option\n");
            usage(argv[0], 1);
        }
    }
    
    if (!flag_start && !flag_stop && !flag_restart && !flag_status) {
        /* need at least one of start, stop, restart */
        usage(argv[0], 1);
    }

    if ( !(initsetuid()) )
        exit(1);

    if (flag_status) {
        status();
        /* no return */
    }

    /* Terminate running OpenVPN server */
    if (access("/var/run/openvpn.pid", 0) != -1) {
        verbose_printf(2, "Stopping OpenVPN server ... \n");
        if (mysignalpidfile("/var/run/openvpn.pid", SIGTERM) != SUCCESS ) {
            exit(0);
        }
        safe_system("/bin/rm -f /var/run/openvpn.pid");

        if (flag_start || flag_restart) {
            sleep(1);
        }
    }

    /* Fetch ethernet/settings, exit on error */
    read_ethernet_settings(1);

    /* Fetch openvpn/settings */
    verbose_printf(1, "Reading OpenVPN settings ... \n");
    if (read_kv_from_file(&openvpn_kv, "/var/ofw/openvpn/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read OpenVPN settings\n");
        exit(1);
    }

    enabled_count = 0;
    for (i = 0; i < CFG_COLOURS_COUNT; i++) {
        /* filter GREEN, no OpenVPN daemon there */
        if (i == GREEN) {
            continue;
        }

        for (j = 1; j <= MAX_NETWORK_COLOUR; j++) {
            snprintf(buffer, STRING_SIZE, "ENABLED_%s_%d", ofw_colours_text[i], j);

            if (test_kv(openvpn_kv, buffer, "on") == SUCCESS) {
                /* this card is enabled in openvpn/settings */
                if (j > ofw_ethernet.count[i]) {
                    /* card is missing in ethernet/settings */
                    if (i == RED) {
                        /* RED could be Modem/ISDN */
                        verbose_printf(2, "RED is enabled and is not in ethernet/settings ... \n");
                    }
                    else {
                        fprintf(stderr, "%s_%d enabled but no device defined\n", ofw_colours_text[i], j);
                        exit(1);
                    }
                }

                enabled_count++;
            }
        }
    }
    verbose_printf(2, "  %d enabled interface(s)\n", enabled_count);

    if (enabled_count == 0) {
        verbose_printf(1, "OpenVPN not enabled ... \n");
    }

    if (enabled_count && (flag_start || flag_restart)) {
        safe_system("/sbin/modprobe tun");
        verbose_printf(1, "Starting OpenVPN server ... \n");
        safe_system("/usr/sbin/openvpn --config /var/ofw/openvpn/server.conf");
    }

    /* rebuild rules, maybe server is now disabled, or some other change */
    verbose_printf(1, "Rebuild firewall rules ... \n");
    safe_system("/usr/local/bin/setfwrules --ofw");

    return(0);
}
