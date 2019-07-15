/*
 * setaliases - configure red aliased interfaces
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
 * (c) 2017-2020 the Openfirewall Team
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "common.h"
#include "setuid.h"

FILE *file = NULL;

void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}

void exithandler(void)
{
    if (file)
        fclose(file);
}

int main(int argc, char *argv[])
{
    char s[STRING_SIZE];
    char command[STRING_SIZE];
    char aliasip[STRING_SIZE];
    char netmask[STRING_SIZE];
    char enabled[STRING_SIZE];
    char comment[STRING_SIZE];

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

    while ((c = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1) {
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

    
    atexit(exithandler);


    /* Fetch ethernet/settings, exit on error */
    helper_read_ethernet_settings(1);

    /* delete all aliases, readd the active ones below */
    memset(command, 0, STRING_SIZE);
    verbose_printf(1, "Flushing aliases\n");
    snprintf(command, STRING_SIZE - 1, "/sbin/ip addr flush label %s:alias", openfw_ethernet.device[RED][1]);
    safe_system(command);

    /* Check for RED_COUNT=1 (or higher) i.e. RED ethernet present. If not,
     * exit gracefully.  This is not an error... */
    if ((openfw_ethernet.count[RED] == 0) || (openfw_ethernet.red_active[1] == 0)) {
        verbose_printf(1, "No RED ethernet present. Exit.\n");
        exit(0);
    }
#if 0
    /* Now check the RED_TYPE - aliases currently only set when RED is STATIC. */
    if (strcmp(openfw_ethernet.red_type[1], "STATIC")) {
        verbose_printf(1, "RED is not STATIC. Exit.\n");
        exit(0);
    }
#endif

    /* Now set up the new aliases from the config file */
    if (!(file = fopen("/var/ofw/ethernet/aliases", "r"))) {
        fprintf(stderr, "Unable to open aliases configuration file\n");
        exit(1);
    }

    int linecounter = 0;
    while (fgets(s, STRING_SIZE, file) != NULL) {
        char *running;
        char *result;
        int count = 0;

        linecounter++;
        if (s[strlen(s) - 1] == '\n')
            s[strlen(s) - 1] = '\0';

        running = strdupa(s);
        result = strsep(&running, ",");
        while (result) {
            if (count == 0)
                strcpy(aliasip, result);
            if (count == 1)
                strcpy(enabled, result);
            if (count == 2)
                strcpy(comment, result);
            if (count == 3)
                strcpy(netmask, result);
            count++;
            result = strsep(&running, ",");
        }

        if ((aliasip == NULL) || (enabled == NULL) || (count < 4)) {
            fprintf(stderr, "Incomplete data line: in %s(%d)\n", "/var/ofw/ethernet/aliases", linecounter);
            exit(1);
        }
        if (!strcmp(enabled, "on") == 0)        /* disabled rule? */
            continue;

        if (!VALID_IP(aliasip)) {
            fprintf(stderr, "Bad alias : %s in %s(%d)\n", aliasip, "/var/ofw/ethernet/aliases", linecounter);
            exit(1);
        }

        memset(command, 0, STRING_SIZE);
        if (netmask == NULL || ( (!VALID_IP(netmask)) && (!VALID_SHORT_MASK(netmask)))) {
            /* ip addr will set proper mask. /32 if alias outside RED ip address range */
            snprintf(command, STRING_SIZE - 1,
                     "/sbin/ip addr add %s dev %s label %s:alias",
                     aliasip, openfw_ethernet.red_device[1], openfw_ethernet.red_device[1]);
            verbose_printf(1, "Add alias %s\n", aliasip);
        }
        else {
            snprintf(command, STRING_SIZE - 1,
                     "/sbin/ip addr add %s/%s dev %s label %s:alias",
                     aliasip, netmask, openfw_ethernet.red_device[1], openfw_ethernet.red_device[1]);
            verbose_printf(1, "Add alias %s/%s\n", aliasip, netmask);
        }
        safe_system(command);
        /* Send gratuitous ARP (request) to update neighbours */
        memset(command, 0, STRING_SIZE);
        snprintf(command, STRING_SIZE - 1,
                "/usr/bin/arping -q -c 1 -U -I %s -s %s %s",
                openfw_ethernet.device[RED][1], aliasip, aliasip);
        safe_system(command);
    }
    return 0;
}
