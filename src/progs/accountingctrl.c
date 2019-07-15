/*
 * accountingctrl.c: Simple program to setup iptables rules for traffic accounting.
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
 * (c) 2018-2020, the Openfirewall Team
 *
 */


#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "common.h"
#include "setuid.h"


static int flag_empty_all = 0;
static int flag_empty_ulogd = 0;
static int flag_init  = 0;
static char command[STRING_SIZE_LARGE];
static char message[STRING_SIZE];


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  --emptyall            Empty all traffic accounting data\n");
    printf("  --emptyulogd          Empty the ulogd accounting DB\n");
    printf("  --init                Init, starts ulogd\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


static void add_device_rules(char *dev_id, char *iface)
{
    char options[STRING_SIZE];

    snprintf(options, STRING_SIZE, "-j NFLOG --nflog-group 1 --nflog-threshold 50 --nflog-range 48");

    verbose_printf(2, "  For %s:\n", dev_id);

    snprintf(command, STRING_SIZE_LARGE, 
            "/sbin/iptables -A ACCOUNT_INPUT -i %s %s --nflog-prefix %s_INPUT", iface, options, dev_id);
    verbose_printf(2, "    %s\n", command);
    safe_system(command);

    snprintf(command, STRING_SIZE_LARGE,
             "/sbin/iptables -A ACCOUNT_FORWARD_IN -i %s %s --nflog-prefix %s_FORWARD_IN", iface, options, dev_id);
    verbose_printf(2, "    %s\n", command);
    safe_system(command);

    snprintf(command, STRING_SIZE_LARGE,
             "/sbin/iptables -A ACCOUNT_FORWARD_OUT -o %s %s --nflog-prefix %s_FORWARD_OUT", iface, options, dev_id);
    verbose_printf(2, "    %s\n", command);
    safe_system(command);

    snprintf(command, STRING_SIZE_LARGE,
             "/sbin/iptables -A ACCOUNT_OUTPUT -o %s %s --nflog-prefix %s_OUTPUT", iface, options, dev_id);
    verbose_printf(2, "    %s\n", command);
    safe_system(command);
}


static void add_vnstat_db(char *dev_id, char *iface)
{
    snprintf(command, STRING_SIZE, "/var/log/traffic/vnstat/%s", iface);
    if (access(command, F_OK) == -1) {
        snprintf(message, STRING_SIZE, "Create vnstat DB for %s nick %s", iface, dev_id);
        verbose_printf(1, "%s\n", message);
        syslog(LOG_NOTICE, "%s", message);
        /* Silence error messages, error messages will appear when a DB is created */
        snprintf(command, STRING_SIZE_LARGE, 
                "/usr/bin/vnstat --update --iface %s --nick %s > /dev/null", iface, dev_id);
        safe_system(command);

        /* Stop vnstatd, later code will notice that PID file is gone and restart vnstatd */
        verbose_printf(1, "Stop vnstatd ... \n");
        mysignalpidfile("/var/run/vnstat.pid", SIGTERM);
    }
}


int main(int argc, char **argv)
{
    int enabled = 0;
    int detail_high = 0;
    int i, j;
    char dev_id[STRING_SIZE];
    char *iface;
    NODEKV *kv = NULL;


    static struct option long_options[] = {
        { "emptyall", no_argument, &flag_empty_all, 1 },
        { "emptyulogd", no_argument, &flag_empty_ulogd, 1 },
        { "init", no_argument, &flag_init, 1 },
        { "verbose", no_argument, 0, 'v'},
        { "help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "chv", long_options, &option_index)) != -1) {
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

    verbose_printf(1, "Reading traffic accounting settings ... \n");
    if (read_kv_from_file(&kv, "/var/ofw/traffic/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read traffic accounting settings\n");
        return 1;
    }
    if (test_kv(kv, "ENABLED", "on") == SUCCESS) {
        verbose_printf(2, "Traffic accounting enabled\n");
        enabled = 1;
        if (test_kv(kv, "DETAIL_LEVEL", "High") == SUCCESS) {
            verbose_printf(2, "High detail level\n");
            detail_high = 1;
        }
        else {
            verbose_printf(2, "Low detail level\n");
        }
    }
    else {
        verbose_printf(2, "Traffic accounting not enabled\n");
    }
    free_kv(&kv);

    openlog("accountingctrl", 0, LOG_USER);

    if (flag_empty_ulogd || flag_empty_all) {
        // TODO: recreate vnstat databases

        if (flag_empty_all) {
            verbose_printf(1, "Empty traffic accounting DB ... \n");
            safe_system("cp /var/ofw/traffic/empty-aggregate.db /var/log/traffic/aggregate.db");
            syslog(LOG_NOTICE, "Traffic accounting DB emptied");
        }

        if (flag_empty_ulogd || flag_empty_all) {
            verbose_printf(1, "Stop ulogd ... \n");
            safe_system("/usr/bin/killall ulogd");
            verbose_printf(1, "Empty ulogd DB ... \n");
            safe_system("cp /var/ofw/traffic/empty-ulogd.db /var/log/traffic/ulogd.db");
            if (enabled && detail_high) {
                verbose_printf(1, "Start ulogd ... \n");
                safe_system("/usr/sbin/ulogd -d");
            }
            syslog(LOG_NOTICE, "ulogd DB emptied");
        }
        return 0;
    }

    verbose_printf(1, "Flush traffic accounting iptables rules... \n");
    safe_system("/sbin/iptables -F ACCOUNT_INPUT\n");
    safe_system("/sbin/iptables -F ACCOUNT_FORWARD_IN\n");
    safe_system("/sbin/iptables -F ACCOUNT_FORWARD_OUT\n");
    safe_system("/sbin/iptables -F ACCOUNT_OUTPUT");

    if (enabled) {
        /* Fetch ethernet/settings, exit on error */
        helper_read_ethernet_settings(1);

        verbose_printf(1, "Create traffic accounting iptables rules... \n");

        /* for all colours */
        for (i = 0; i < NONE; i++) {

            for (j = 1; j <= openfw_ethernet.count[i]; j++) {
                if (i == RED) {
                    if (! openfw_ethernet.red_active[j]) {
                        continue;
                    }

                    iface = openfw_ethernet.red_device[j];
                }
                else {
                    iface = openfw_ethernet.device[i][j];
                }
                
                snprintf(dev_id, STRING_SIZE, "%s_%d", openfw_colours_text[i], j);
                if (detail_high) {
                    add_device_rules(dev_id, iface);
                }
                else {
                    add_vnstat_db(dev_id, iface);
                }
            }
        }
        
        if ((openfw_ethernet.count[RED] == 0) && (strlen(openfw_ethernet.red_device[1]))) {
            // Special case for Modem/ISDN
            if (detail_high) {
                add_device_rules("RED_1", openfw_ethernet.red_device[1]);
            }
            else {
                add_vnstat_db("RED_1", openfw_ethernet.red_device[1]);
            }
        }
        
        if (detail_high && safe_system("/bin/ps -C ulogd > /dev/null")) {
            verbose_printf(1, "Start ulogd ... \n");
            safe_system("/usr/sbin/ulogd -d");
        }
        if (!detail_high && (access("/var/run/vnstat.pid", F_OK) == -1)) {
            verbose_printf(1, "Start vnstatd ... \n");
            safe_system("/usr/sbin/vnstatd -d");
        }
    }

    /* Stop ulogd if traffic accounting is not enabled and high detail */
    if (!safe_system("/bin/ps -C ulogd > /dev/null") && !(enabled && detail_high)) {
        verbose_printf(1, "Stop ulogd ... \n");
        safe_system("/usr/bin/killall ulogd");
    }
    /* Stop vnstat if traffic accounting is not enabled and low detail */
    if ((access("/var/run/vnstat.pid", F_OK) != -1) && !(enabled && !detail_high)) {
        verbose_printf(1, "Stop vnstatd ... \n");
        mysignalpidfile("/var/run/vnstat.pid", SIGTERM);
    }
    return 0;
}
