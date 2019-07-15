/* Openfirewall helper program - rebuildhosts
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
 * (c) 2017-2020 the Openfirewall team
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "setuid.h"

FILE *fd = NULL;
FILE *hosts = NULL;
NODEKV *main_kv = NULL;


static int flag_nosighup = 0;


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  --nosighup            Do not SIGHUP dnsmasq but use restart instead\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


void exithandler(void)
{
    if (main_kv)
        free_kv(&main_kv);
    if (fd)
        fclose(fd);
    if (hosts)
        fclose(hosts);
}


int main(int argc, char *argv[])
{
    char hostname[STRING_SIZE] = "";
    char domainname[STRING_SIZE] = "";
    char buffer[STRING_SIZE];
    char string[STRING_SIZE];
    char *active, *ip, *host, *domain;

    static struct option long_options[] = {
        { "nosighup", no_argument, &flag_nosighup, 1 },
        { "verbose", no_argument, 0, 'v'},
        { "help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1) {
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

    atexit(exithandler);

    memset(buffer, 0, STRING_SIZE);

    /* Fetch ethernet/settings, exit on error */
    helper_read_ethernet_settings(1);

    if (read_kv_from_file(&main_kv, "/var/ofw/main/settings") != SUCCESS) {
        fprintf(stderr, "Couldn't read main settings\n");
        exit(1);
    }
    strcpy(hostname, SNAME);
    find_kv_default(main_kv, "HOSTNAME", hostname);
    find_kv_default(main_kv, "DOMAINNAME", domainname);
    free_kv(&main_kv);
    main_kv = NULL;

    if (!(fd = fopen("/var/ofw/main/hosts", "r"))) {
        fprintf(stderr, "Couldn't open main hosts file\n");
        exit(1);
    }
    snprintf(string, STRING_SIZE, "/etc/hosts");
    if (!(hosts = fopen(string, "w"))) {
        fprintf(stderr, "Couldn't open /etc/hosts file\n");
        fclose(fd);
        fd = NULL;
        exit(1);
    }
    fprintf(hosts, "127.0.0.1\tlocalhost\n");

    if (strlen(domainname))
        fprintf(hosts, "%s\t%s.%s\t%s\n", openfw_ethernet.address[GREEN][1], hostname, domainname, hostname);
    else
        fprintf(hosts, "%s\t%s\n", openfw_ethernet.address[GREEN][1], hostname);

    while (fgets(buffer, STRING_SIZE, fd)) {
        buffer[strlen(buffer) - 1] = 0;
        if (buffer[0] == ',')
            continue;           /* disabled if empty field      */
        active = strtok(buffer, ",");
        if (strcmp(active, "off") == 0)
            continue;           /* or 'off'                     */

        ip = strtok(NULL, ",");
        host = strtok(NULL, ",");
        domain = strtok(NULL, ",");

        if (!(ip && host))
            continue;           /* bad line ? skip              */

        if (!VALID_IP(ip)) {
            fprintf(stderr, "Bad IP: %s\n", ip);
            continue;           /* bad ip, continue             */
        }

        if (strspn(host, LETTERS_NUMBERS "-") != strlen(host)) {
            fprintf(stderr, "Bad Host: %s\n", host);
            continue;           /* bad name, continue           */
        }

        if (domain)
            fprintf(hosts, "%s\t%s.%s\t%s\n", ip, host, domain, host);
        else
            fprintf(hosts, "%s\t%s\n", ip, host);
    }
    fclose(fd);
    fd = NULL;
    fclose(hosts);
    hosts = NULL;

    if (flag_nosighup) {
        verbose_printf(1, "Restart dnsmasq... \n");
        safe_system("/etc/rc.d/rc.dnsmasq --restart");
    }
    else {
        verbose_printf(1, "Send SIGHUP to dnsmasq... \n");
        safe_system("/etc/rc.d/rc.dnsmasq --sighup");
    }
    
    return 0;
}
