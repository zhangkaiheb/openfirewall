/* openfirewall helper program - restartsquid
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
 * restartsquid originally from the Smoothwall project
 * (c) Lawrence Manning, 2001
 *
 * 05/02/2004 - Roy Walker <rwalker@miracomnetwork.com>
 * Exclude red network from transparent proxy to allow browsing to alias IPs
 * Read in VPN settings and exclude each VPN network from transparent proxy
 *
 * (c) 2004-2012 The Openfirewall Team
 *
 * $Id: restartsquid.c 7262 2014-02-28 21:50:59Z owes $
 *
 */


#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"
#include "setuid.h"

#define PORT_PROXY_INTERCEPT    82

void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  -f, --flush           flush proxy cache\n");
    printf("  -r, --repair          repair proxy cache\n");
    printf("  -t, --test            test first, do not start if not running\n");
//    printf("      --config          re-generate squid.conf from proxy settings\n");
    printf("  -w, --waitpid         wait for squid started\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


/*
    Call helper script to generate squid.conf
*/
void config()
{
    char command[STRING_SIZE];

    snprintf(command, STRING_SIZE, "/usr/local/bin/makesquidconf.pl");
    safe_system(command);

    exit(0);
}


/* read the IPsec config file and adds a rule for every net-to-net definition
    that skip the transparent rules REDIRECT
*/
void setdirectipsec(int setdirectipsec_green, int setdirectipsec_blue)
{
    int count;
    char *result;
    char *name;
    char *type;
    char *running;
    char *ipsec_network_mask;
    char *ipsec_netaddress;
    char *ipsec_netmask;
    FILE *file = NULL;
    char *conn_enabled;
    char buffer[STRING_SIZE];
    char s[STRING_SIZE_LARGE];

    if (!setdirectipsec_green && !setdirectipsec_blue)
        return;                 /* nothing to do */

    if (!(file = fopen("/var/ofw/ipsec/config", "r"))) {
        fprintf(stderr, "Couldn't open IPsec config file");
        return;                 /* error! exit or return? */
    }

    while (fgets(s, STRING_SIZE_LARGE, file) != NULL) {
        /* Line should contain 25+ comma seperated fields */
        if (strlen(s) < 25) {
            verbose_printf(2, "Bad (empty?) configline\n");
            continue;
        }
        if (s[strlen(s) - 1] == '\n') {
            s[strlen(s) - 1] = '\0';
        }

        running = strdup(s);
        result = strsep(&running, ",");
        count = 0;
        name = NULL;
        type = NULL;
        ipsec_network_mask = NULL;
        conn_enabled = NULL;
        while (result) {
            if (count == 1)
                conn_enabled = result;
            if (count == 2)
                name = result;
            if (count == 4)
                type = result;
            if (count == 12)
                ipsec_network_mask = result;
            count++;
            result = strsep(&running, ",");
        }

        if (name == NULL) {
            verbose_printf(2, "Bad (empty?) configline\n");
            continue;
        }
        if (strspn(name, LETTERS_NUMBERS) != strlen(name)) {
            verbose_printf(1, "Bad connection name: %s\n", name);
            continue;
        }
        if (count < 25) {
            verbose_printf(2, "Bad configline, name %s count %d, %s\n", name, count, s);
            continue;
        }

        if (!(strcmp(type, "net") == 0)) {
            verbose_printf(2, "Skip (no net-net) connection name: %s\n", name);
            continue;
        }

        /* Darren Critchley - new check to see if connection is enabled */
        if (!(strcmp(conn_enabled, "on") == 0)) {
            verbose_printf(2, "Skip disabled connection name: %s\n", name);
            continue;
        }

        result = strsep(&ipsec_network_mask, "/");
        count = 0;
        ipsec_netaddress = NULL;
        ipsec_netmask = NULL;
        while (result) {
            if (count == 0)
                ipsec_netaddress = result;
            if (count == 1)
                ipsec_netmask = result;
            count++;
            result = strsep(&ipsec_network_mask, "/");
        }

        if (!VALID_IP(ipsec_netaddress)) {
            verbose_printf(1, "Bad network for IPsec connection %s: %s\n", name, ipsec_netaddress);
            continue;
        }

        if ((!VALID_IP(ipsec_netmask)) && (!VALID_SHORT_MASK(ipsec_netmask))) {
            verbose_printf(1, "Bad mask for IPsec connection %s: %s\n", name, ipsec_netmask);
            continue;
        }

        memset(buffer, 0, STRING_SIZE);
        if (setdirectipsec_green) {
            if (snprintf(buffer, STRING_SIZE - 1,
                         "/sbin/iptables -t nat -A SQUID -i %s -p tcp -d %s/%s --dport 80 -j RETURN",
                         ofw_ethernet.device[GREEN][1], ipsec_netaddress, ipsec_netmask) >= STRING_SIZE) {
                fprintf(stderr, "Command too long\n");
                fclose(file);
                exit(1);
            }
            verbose_printf(1, "Bypass proxy redirect for GREEN to remote IPsec network %s/%s\n", ipsec_netaddress, ipsec_netmask);
            safe_system(buffer);
        }
        if (setdirectipsec_blue) {
            if (snprintf(buffer,
                         STRING_SIZE - 1,
                         "/sbin/iptables -t nat -A SQUID -i %s -p tcp -d %s/%s --dport 80 -j RETURN",
                         ofw_ethernet.device[BLUE][1], ipsec_netaddress, ipsec_netmask) >= STRING_SIZE) {
                fprintf(stderr, "Command too long\n");
                fclose(file);
                exit(1);
            }
            verbose_printf(1, "Bypass proxy redirect for BLUE to remote IPsec network %s/%s\n", ipsec_netaddress, ipsec_netmask);
            safe_system(buffer);
        }
    }
    fclose(file);
}


int main(int argc, char **argv)
{
    int flag_test = 0;
    int flag_flush = 0;
    int flag_repair = 0;
    int flag_waitpid = 0;
    int enabled_green = 0;
    int transparent_green = 0;
    int enabled_blue = 0;
    int transparent_blue = 0;
    int enabled_ovpn = 0;
    int transparent_ovpn = 0;
    int enabled = 0;
    struct stat st;
    NODEKV *squid_kv = NULL;
    char buffer[STRING_SIZE];
    char proxy_port[STRING_SIZE];
    NODEKV *ipsec_kv = NULL;
    char enabled_IPsec[STRING_SIZE] = "";

    static struct option long_options[] =
    {
        { "flush", no_argument, 0, 'f' },
        { "repair", no_argument, 0, 'r' },
        { "test", no_argument, 0, 't' },
        { "config", no_argument, 0, 'c' },
        { "waitpid", no_argument, 0, 'w' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "frtvw", long_options, &option_index)) != -1) {
        switch (c) {
        case 't':              /* test first */
            flag_test = 1;
            break;
        case 'f':              /* flush cache */
            flag_flush = 1;
            break;
        case 'r':              /* repair cache */
            flag_repair = 1;
            break;
        case 'v':              /* verbose */
            flag_verbose++;
            break;
        case 'w':              /* wait for PID file */
            flag_waitpid = 1;
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


    /* Retrieve the Squid pid file */
    if ((access("/var/run/squid.pid", F_OK) == -1) && flag_test) {
        verbose_printf(1, "Squid not running, no need to start\n");
        exit(0);                /* Not running, no need to start with -t */
    }

    if (access("/var/run/squid.pid", F_OK) != -1) {
        /* Kill running squid */
        verbose_printf(1, "Flush squid iptables chain ... \n");
        safe_system("/sbin/iptables -t nat -F SQUID");
        verbose_printf(1, "Shutdown squid ");
        safe_system("/usr/sbin/squid -k shutdown >/dev/null 2>/dev/null");
        c = 0;
        while ((c++ < 15) && (access("/var/run/squid.pid", F_OK) != -1)) {
            verbose_printf(1, ".");
            _flushlbf();
            sleep(1);
        }
        verbose_printf(1, "\n");

        if (access("/var/run/squid.pid", F_OK) != -1) {
            verbose_printf(1, "Really shutdown squid ... \n");
            safe_system("/usr/bin/killall -9 squid >/dev/null 2>/dev/null");
        }
    }
    if (access("/var/run/squid.pid", F_OK) != -1) {
        verbose_printf(2, "Remove leftover PID file ... \n");
        unlink("/var/run/squid.pid");
    }

    /* See if we need to flush/repair the cache */
    if (flag_flush) {
        struct passwd *pw;
        if ((pw = getpwnam("squid"))) {
            endpwent();         /* probably paranoia, but just in case.. */
            verbose_printf(1, "Flushing proxy cache ... \n");
            unpriv_system("/bin/rm -rf /var/log/cache/*", pw->pw_uid, pw->pw_gid);
        }
        else {
            fprintf(stderr, "User squid not found, cache not flushed\n");
            endpwent();
        }
    }

    int saferestart = 0;
    if (flag_repair) {
        struct passwd *pw;
        if ((pw = getpwnam("squid"))) {
            endpwent();         /* probably paranoia, but just in case.. */
            verbose_printf(1, "Repairing proxy cache ... \n");
            if (stat("/var/log/cache/swap.state", &st) == 0) {
                unpriv_system("/bin/rm -f /var/log/cache/swap.state", pw->pw_uid, pw->pw_gid);
            }
            saferestart = 1;
        }
        else {
            fprintf(stderr, "User squid not found, cache not repaired\n");
            endpwent();
        }
    }

    verbose_printf(1, "Reading Proxy settings ... \n");
    if (read_kv_from_file(&squid_kv, "/var/ofw/proxy/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read proxy settings\n");
        exit(1);
    }

    /* See if proxy is enabled and / or transparent */
    if (test_kv(squid_kv, "ENABLED_GREEN_1", "on") == SUCCESS) {
        enabled_green = 1;
    }
    if (test_kv(squid_kv, "TRANSPARENT_GREEN_1", "on") == SUCCESS) {
        transparent_green = 1;
    }
    if (test_kv(squid_kv, "ENABLED_BLUE_1", "on") == SUCCESS) {
        enabled_blue = 1;
    }
    if (test_kv(squid_kv, "TRANSPARENT_BLUE_1", "on") == SUCCESS) {
        transparent_blue = 1;
    }
    if (test_kv(squid_kv, "ENABLED_OVPN", "on") == SUCCESS) {
        enabled_ovpn = 1;
    }
    if (test_kv(squid_kv, "TRANSPARENT_OVPN", "on") == SUCCESS) {
        transparent_ovpn = 1;
    }

    /* Retrieve the proxy port */
    if (transparent_green || transparent_blue || transparent_ovpn) {
        if (find_kv_default(squid_kv, "PROXY_PORT", proxy_port) != SUCCESS) {
            strcpy(proxy_port, "8080");
        }
        else {
            if (strspn(proxy_port, NUMBERS) != strlen(proxy_port)) {
                fprintf(stderr, "Invalid proxy port: %s, defaulting to 8080\n", proxy_port);
                strcpy(proxy_port, "8080");
            }
        }
    }
    free_kv(&squid_kv);

    if (!enabled_green && !enabled_blue && !enabled_ovpn) {
        verbose_printf(1, "Proxy not enabled ... exit ... \n");
        return 0;
    }

    /* We can't start squid if .conf is missing */
    if (access("/var/ofw/proxy/squid.conf", F_OK) == -1) {
        fprintf(stderr, "Configuration file squid.conf not found\n");
        exit(1);
    }

    /* Fetch ethernet/settings, exit on error */
    read_ethernet_settings(1);


    if (enabled_green || enabled_blue || enabled_ovpn) {
        enabled = 1;
        /* rebuild firewall rules, proxy port may be different now */
        verbose_printf(1, "Rebuild firewall rules ... \n");
        safe_system("/usr/local/bin/setfwrules --ofw");

        verbose_printf(1, "Create swap directories ... \n");
        if (safe_system("/usr/sbin/squid -s -z 2>/dev/null")) {
            verbose_printf(1, "Error creating swap directories ... \n");
        }
        verbose_printf(1, "Starting squid ... \n");
        if (saferestart)
            safe_system("/usr/sbin/squid -s -S");
        else
            safe_system("/usr/sbin/squid -s");
    }

    /* static (green/blue) interfaces must exist if transparence is requested */
    if (transparent_green && enabled_green && !ofw_ethernet.count[GREEN]) {
        fprintf(stderr, "No GREEN device, not running transparent\n");
        exit(1);
    }

    if (transparent_blue && enabled_blue && !ofw_ethernet.count[BLUE]) {
        fprintf(stderr, "No BLUE device, not running transparent\n");
        exit(1);
    }

    /* TODO: test for OpenVPN device if ovpn transparent is selected? */
    /* For now we use fixed tun0 and expect it to be present. */

    /* disable transparence for known IPsec networks */
    verbose_printf(1, "Reading IPsec settings ... \n");
    if (read_kv_from_file(&ipsec_kv, "/var/ofw/ipsec/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read IPsec settings\n");
        exit(1);
    }
    find_kv_default(ipsec_kv, "ENABLED_RED_1", enabled_IPsec);
    if (strcmp(enabled_IPsec, "on")) {
        find_kv_default(ipsec_kv, "ENABLED_BLUE_1", enabled_IPsec);
    }
    free_kv(&ipsec_kv);

    if (!strcmp(enabled_IPsec, "on")) {
        setdirectipsec (enabled_green && transparent_green,
                    enabled_blue && transparent_blue);
    }

    /*  TODO: disable transparence for OpenVPN networks, but only for
        OpenVPN net-2-net which we currently have not implemented */

    /* choose RED destination: 'localip' or 'red_netaddress/red_netmask' */
    char destination[STRING_SIZE] = "";
    if (strcmp(ofw_ethernet.red_type[1], "STATIC") == 0) {
        snprintf(destination, STRING_SIZE, "%s/%s", ofw_ethernet.address[RED][1], ofw_ethernet.netmask[RED][1]);
    }
    else {
        if (ofw_ethernet.red_address[1][0] && VALID_IP(ofw_ethernet.red_address[1])) {
            snprintf(destination, STRING_SIZE, "%s", ofw_ethernet.red_address[1]);
        }
    }

    /* RED may be down */
    if (!strlen(destination)) {
        verbose_printf(1, "Cannot determine RED network.\n");
    }
    else {
        verbose_printf(2, "Dest IP is set to: %s\n", destination);
    }

    /* install the transparency rules */
    /* green transparent ? */
    if (transparent_green && enabled_green) {
        /* direct http GREEN-->RED network */
        verbose_printf(1, "Setting transparent iptables rule for GREEN ... \n");
        if (snprintf(buffer, STRING_SIZE - 1,
                     "/sbin/iptables -t nat -A SQUID -i %s -p tcp -d %s --dport 80 -j RETURN",
                     ofw_ethernet.device[GREEN][1], destination) >= STRING_SIZE) {
            fprintf(stderr, "Command too long\n");
            exit(1);
        }
        if (strlen(destination))
            safe_system(buffer);        /* only id known RED */

        /* install the redirect for other port http destinations from green */
        if (snprintf(buffer, STRING_SIZE - 1,
                     "/sbin/iptables -t nat -A SQUID -i %s -p tcp --dport 80 -j REDIRECT --to-port %d",
                     ofw_ethernet.device[GREEN][1], PORT_PROXY_INTERCEPT) >= STRING_SIZE) {
            fprintf(stderr, "Command too long\n");
            exit(1);
        }
        safe_system(buffer);
    }
    /* blue transparent ? */
    if (transparent_blue && enabled_blue) {
        /* direct http BLUE-->RED network */
        verbose_printf(1, "Setting transparent iptables rule for BLUE ... \n");
        if (snprintf(buffer, STRING_SIZE - 1,
                     "/sbin/iptables -t nat -A SQUID -i %s -p tcp -d %s --dport 80 -j RETURN",
                     ofw_ethernet.device[BLUE][1], destination) >= STRING_SIZE) {
            fprintf(stderr, "Command too long\n");
            exit(1);
        }
        if (strlen(destination))
            safe_system(buffer);        /* only id known RED */

        /* install the redirect for other port http destinations from blue */
        if (snprintf(buffer, STRING_SIZE - 1,
                     "/sbin/iptables -t nat -A SQUID -i %s -p tcp --dport 80 -j REDIRECT --to-port %d",
                     ofw_ethernet.device[BLUE][1], PORT_PROXY_INTERCEPT) >= STRING_SIZE) {
            fprintf(stderr, "Command too long\n");
            exit(1);
        }
        safe_system(buffer);
    }
    /* OpenVPN roadwarriors transparent ? */
    if (transparent_ovpn && enabled_ovpn) {
        /* direct http OpenVPN-->RED network */
        verbose_printf(1, "Setting transparent iptables rule for OpenVPN RW ... \n");
        if (snprintf(buffer, STRING_SIZE - 1,
                     "/sbin/iptables -t nat -A SQUID -i %s -p tcp -d %s --dport 80 -j RETURN",
                     "tun0", destination) >= STRING_SIZE) {
            fprintf(stderr, "Command too long\n");
            exit(1);
        }
        if (strlen(destination))
            safe_system(buffer);        /* only id known RED */

        /* install the redirect for other port http destinations from OpenVPN */
        if (snprintf(buffer, STRING_SIZE - 1,
                     "/sbin/iptables -t nat -A SQUID -i %s -p tcp --dport 80 -j REDIRECT --to-port %d",
                     "tun0", PORT_PROXY_INTERCEPT) >= STRING_SIZE) {
            fprintf(stderr, "Command too long\n");
            exit(1);
        }
        safe_system(buffer);
    }
    
    if (enabled && flag_waitpid) {
        c = 0;

        while ((access("/var/run/squid.pid", F_OK) == -1) && (c < 15)) {
            if (!c) {
                verbose_printf(1, "Waiting for squid to start ");
            }
            verbose_printf(1, ".");
            _flushlbf();
            c++;
            sleep(1);
        }
        
        if (c == 15) {
            verbose_printf(1, " [TIMEOUT]\n");
        }
        else if (c) {
            verbose_printf(1, "\n");
        }
    }

    return 0;
}
