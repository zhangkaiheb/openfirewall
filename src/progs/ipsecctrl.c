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
 * (c) 2018-2019, the Openfirewall Team
 *
 */


#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.h"
#include "setuid.h"


/*
    TODO: 
     - revisit the possibility to start IPsec if RED down
     - can 1 interface (RED) be activated/deactivated without affecting tunnels on other interfaces?
     - start/stop single interface
*/


static int flag_start = 0;
static int flag_stop = 0;
static int flag_status = 0;
static int flag_reload = 0;
static int flag_wait = 0;
static int enabled_count;


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  --start               start/restart\n");
    printf("  --stop                stop\n");
    printf("  --status              retrieve pluto status\n");
    printf("  --reload              reload certificates and secrets\n");
    printf("  --start=key#          start/restart key number\n");
    printf("  --stop=key#           stop key number\n");
    printf("  --wait                wait before start\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int ipsec_running()
{
    return (access("/var/run/pluto/pluto.pid", 0) != -1) ? SUCCESS : FAILURE;
}

/*
    reserve room for ipsec0=red, ipsec1=blue
*/
void add_alias_interfaces(int offset)
{
    FILE *file = NULL;
    char s[STRING_SIZE];
    int alias = 0;

    /* Check for RED present. If not, exit gracefully.  This is not an error... */
    if (!VALID_DEVICE(ofw_ethernet.red_device[1]))
        return;

    /* Now check the RED_TYPE - aliases only work with STATIC. */
    if (!(strcmp(ofw_ethernet.red_type[1], "STATIC") == 0))
        return;

    /* Now set up the new aliases from the config file */
    if (!(file = fopen("/var/ofw/ethernet/aliases", "r"))) {
        fprintf(stderr, "Unable to open aliases configuration file\n");
        return;
    }
    while (fgets(s, STRING_SIZE, file) != NULL && (offset + alias) < 16) {
        if (s[strlen(s) - 1] == '\n')
            s[strlen(s) - 1] = '\0';
        int count = 0;
        char *aliasip = NULL;
        char *enabled = NULL;
        char *comment = NULL;
        char *sptr = strtok(s, ",");
        while (sptr) {
            if (count == 0)
                aliasip = sptr;
            if (count == 1)
                enabled = sptr;
            else
                comment = sptr;
            count++;
            sptr = strtok(NULL, ",");
        }

        if (!(aliasip && enabled))
            continue;

        if (!VALID_IP(aliasip)) {
            fprintf(stderr, "Bad alias : %s\n", aliasip);
            return;
        }

        if (strcmp(enabled, "on") == 0) {
            memset(s, 0, STRING_SIZE);
            snprintf(s, STRING_SIZE - 1, "/usr/sbin/ipsec tncfg --attach --virtual ipsec%d --physical %s:%d %s",
                     offset + alias, ofw_ethernet.red_device[1], alias, flag_verbose ? "" : ">/dev/null");
            safe_system(s);
            alias++;
        }
    }

    fclose(file);
}

/*
 return values from the vpn config file or false if not 'on'
*/
int decode_line(char *s, char **key, char **name, char **type, char **interface)
{
    int count = 0;
    *key = NULL;
    *name = NULL;
    *type = NULL;
    *interface = NULL;

    if (s[strlen(s) - 1] == '\n')
        s[strlen(s) - 1] = '\0';

    char *result = strsep(&s, ",");
    while (result) {
        if (count == 0)
            *key = result;
        if ((count == 1) && strcmp(result, "on") != 0)
            return 0;           // a disabled line
        if (count == 2)
            *name = result;
        if (count == 4)
            *type = result;
        if (count == 27)
            *interface = result;
        count++;
        result = strsep(&s, ",");
    }

    // check other syntax
    if (!*name)
        return 0;
    if (count != 30) {
        // name was found, so we know that keynumber and name (may) make some sense
        fprintf(stderr, "Bad configline, key %s, name %s\n", *key, *name);
        return 0;
    }

    if (strspn(*name, LETTERS_NUMBERS) != strlen(*name)) {
        fprintf(stderr, "Bad connection name: %s\n", *name);
        return 0;
    }

    if (!(strcmp(*type, "host") == 0 || strcmp(*type, "net") == 0)) {
        fprintf(stderr, "Bad connection type: %s\n", *type);
        return 0;
    }

    if (!((strcmp(*interface, "RED") == 0) || (strcmp(*interface, "BLUE") == 0))) {
        fprintf(stderr, "Bad interface name: %s\n", *interface);
        return 0;
    }
    //it's a valid & active line
    return 1;
}

/*
    issue ipsec commmands to turn on connection 'name'
*/
void turn_connection_on(char *name, char *type)
{
    char command[STRING_SIZE];

    if (flag_verbose) {
        safe_system("/usr/sbin/ipsec auto --rereadsecrets");
    }
    else {
        safe_system("/usr/sbin/ipsec auto --rereadsecrets >/dev/null");
    }
    memset(command, 0, STRING_SIZE);
    snprintf(command, STRING_SIZE - 1, "/usr/sbin/ipsec auto --replace %s %s", name, flag_verbose ? "" : ">/dev/null");
    safe_system(command);
    if (strcmp(type, "net") == 0) {
        memset(command, 0, STRING_SIZE);
        snprintf(command, STRING_SIZE - 1, "/usr/sbin/ipsec auto --asynchronous --up %s %s", name, flag_verbose ? "" : ">/dev/null");
        safe_system(command);
    }
}

/*
    issue ipsec commmands to turn off connection 'name'
*/
void turn_connection_off(char *name)
{
    char command[STRING_SIZE];

    memset(command, 0, STRING_SIZE);
    snprintf(command, STRING_SIZE - 1, "/usr/sbin/ipsec auto --down %s %s", name, flag_verbose ? "" : ">/dev/null");
    safe_system(command);
    memset(command, 0, STRING_SIZE);
    snprintf(command, STRING_SIZE - 1, "/usr/sbin/ipsec auto --delete %s %s", name, flag_verbose ? "" : ">/dev/null");
    safe_system(command);
    safe_system("/usr/sbin/ipsec auto --rereadsecrets >/dev/null");
}


int main(int argc, char *argv[])
{
    int i, j;
    char buffer[STRING_SIZE];
    char *connection = NULL;
    NODEKV *ipsec_kv = NULL;

    static struct option long_options[] =
    {
        { "start",   optional_argument, 0, 's' },
        { "stop",    optional_argument, 0, 'd' },
        { "status",  no_argument, &flag_status, 1 },
        { "reload",  no_argument, &flag_reload, 1 },
        { "verbose", no_argument, 0, 'v' },
        { "wait",    no_argument, &flag_wait, 1 },
        { "help",    no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    while ((c = getopt_long(argc, argv, "s:d:v", long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            break;
        case 's':               /* start/restart */
            flag_start = 1;
            if (optarg)
                connection = strdup(optarg);
            break;
        case 'd':               /* stop */
            flag_stop = 1;
            if (optarg)
                connection = strdup(optarg);
            break;
        case 'v':               /* verbose */
            flag_verbose++;
            break;
        case 'h':
            usage(argv[0], 0);
        default:
            fprintf(stderr, "unknown option\n");
            usage(argv[0], 1);
        }
    }

    if (!flag_start && !flag_stop && !flag_status && !flag_reload) {
        /* need at least one of start, stop, status, reload */
        usage(argv[0], 1);
    }

    if (connection != NULL) {
        if (strspn(connection, NUMBERS) != strlen(connection)) {
            fprintf(stderr, "Bad key number (%s)\n", connection);
            usage(argv[0], 1);
            exit(1);
        }
        verbose_printf(2, "Start/Stop key: %s \n", connection);
    }

    if (!(initsetuid()))
        exit(1);

    /* FIXME: workaround for pclose() issue - still no real idea why
     * this is happening */
    signal(SIGCHLD, SIG_DFL);

    /* handle operations that do not need to start the IPsec system */
    if (connection == NULL) {
        if (flag_stop) {
            safe_system("/usr/local/bin/vpn-watch --stop");

            /* Only shutdown pluto if it really is running */
            if (ipsec_running() == SUCCESS) {
                verbose_printf(2, "Stopping IPsec ... \n");
                safe_system("/etc/rc.d/ipsec stop 2> /dev/null >/dev/null");
            }

            /* reset firewall rules */
            safe_system("/usr/local/bin/setfwrules --ofw");

            exit(0);
        }

        if (flag_reload) {
            safe_system("/usr/sbin/ipsec auto --rereadall");
            exit(0);
        }

        if (flag_status) {
            if (ipsec_running() == SUCCESS) {
                safe_system("/usr/sbin/ipsec auto --status");
            }
            else {
                /* Output something so we can see that when called from GUI */
                printf("Pluto is not running\n");
            }
            exit(0);
        }
    }

    /* stop the watch script as soon as possible */
    safe_system("/usr/local/bin/vpn-watch --stop");

    /* Fetch ethernet/settings, exit on error */
    read_ethernet_settings(1);

    /* read IPsec config */
    verbose_printf(1, "Reading IPsec settings ... \n");
    if (read_kv_from_file(&ipsec_kv, "/var/ofw/ipsec/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read IPsec settings\n");
        exit(1);
    }

    enabled_count = 0;
    for (i = 0; i < CFG_COLOURS_COUNT; i++) {
        /* filter GREEN and ORANGE, no IPsec there */
        if ((i == GREEN) || (i == ORANGE)) {
            continue;
        }

        for (j = 1; j <= MAX_NETWORK_COLOUR; j++) {
            snprintf(buffer, STRING_SIZE, "ENABLED_%s_%d", ofw_colours_text[i], j);

            if (test_kv(ipsec_kv, buffer, "on") == SUCCESS) {
                /* this card is enabled in vpn/settings */
                if (j > ofw_ethernet.count[i]) {
                    /* card is missing in ethernet/settings */
                    fprintf(stderr, "%s_%d enabled but no device defined\n", ofw_colours_text[i], j);
                    exit(1);
                }

                enabled_count++;
            }
        }
    }
    verbose_printf(2, "  %d enabled interface(s)\n", enabled_count);

    if (enabled_count == 0) {
        verbose_printf(1, "IPsec not enabled ... \n");

        safe_system("/usr/local/bin/vpn-watch --stop");
        /* Shutdown pluto if it is running */
        if (ipsec_running() == SUCCESS) {
            verbose_printf(2, "Stopping IPsec ... \n");
            safe_system("/etc/rc.d/ipsec stop 2> /dev/null >/dev/null");
        }

        /* reset firewall rules */
        safe_system("/usr/local/bin/setfwrules --ofw");

        exit(0);
    }


    /* Loop through the config file to find physical interface that will accept IPSEC */
    int enable_red = 0;         // states 0: not used
    int enable_blue = 0;        //        1: error condition
                                //        2: good
    size_t s_size = STRING_SIZE;
    char *ptr;
    FILE *file = NULL;

    ptr = malloc(s_size);
    if (ptr == NULL) {
        fprintf(stderr, "Couldn't allocate memory");
        exit(1);
    }

    if (!(file = fopen("/var/ofw/ipsec/config", "r"))) {
        fprintf(stderr, "Couldn't open vpn settings file");
        exit(1);
    }
    while (getline(&ptr, &s_size, file) != -1) {
        char *key;
        char *name;
        char *type;
        char *interface;

        verbose_printf(2, "Decoding line: %s\n", ptr);
        if (!decode_line(ptr, &key, &name, &type, &interface))
            continue;

        verbose_printf(2, "  decoded\n");
        /* search interface and verify interfaces */

        /*  TODO:   check if interface is ENABLED 
                    do we really want/need to block *all* tunnels if only one is using a no longer valid interface?
        */
        if (!enable_red && (strcmp(interface, "RED") == 0) && VALID_DEVICE(ofw_ethernet.red_device[1])) {
            enable_red += 2;
        }

        if (!enable_blue && strcmp(interface, "BLUE") == 0) {
            enable_blue++;

            if (ofw_ethernet.count[BLUE])
                enable_blue++;
            else
                fprintf(stderr, "IPsec enabled on blue but blue interface is invalid or not found\n");

        }
    }
    fclose(file);

    // do nothing if something is in error condition
    if ((enable_red == 1) || (enable_blue == 1)) {
        verbose_printf(1, "Interface with error\n");
        exit(1);
    }

    // reset firewall rules
    safe_system("/usr/local/bin/setfwrules --ofw");

    // exit if nothing to do
    if ((enable_red + enable_blue) == 0) {
        verbose_printf(1, "Nothing to do\n");
        exit(0);
    }

    // start the system
    if (flag_start && ((connection == NULL) || (ipsec_running() == FAILURE))) {
        if (flag_wait) {
            char ipsec_delay[STRING_SIZE] = "0";
            find_kv_default(ipsec_kv, "VPN_DELAYED_START", ipsec_delay);
            verbose_printf(1, "IPsec delayed start (%s) ", ipsec_delay);
            _flushlbf();
            snprintf(buffer, STRING_SIZE-1, "sleep %s", ipsec_delay);
            safe_system(buffer);
            verbose_printf(1, "...\n");
        }
        if (flag_verbose) {
            verbose_printf(1, "Starting IPsec ... \n");

            if (safe_system("/sbin/modinfo ipsec 2>/dev/null") == 0) {
                /* KLIPS only */
                safe_system("/sbin/modprobe ipsec");
                safe_system("/usr/sbin/ipsec tncfg --clear");
            }
            safe_system("/etc/rc.d/ipsec restart");
        }
        else {
            if (safe_system("/sbin/modinfo ipsec 2>/dev/null") == 0) {
                /* KLIPS only */
                safe_system("/sbin/modprobe ipsec");
                safe_system("/usr/sbin/ipsec tncfg --clear >/dev/null");
            }
            safe_system("/etc/rc.d/ipsec restart >/dev/null");
        }
        add_alias_interfaces((enable_red + enable_blue) >> 1);
        if (connection == NULL) {
            safe_system("/usr/local/bin/vpn-watch --start");
            exit(0);
        }
    }

    // search the connection pointed by 'key'
    if (!(file = fopen("/var/ofw/ipsec/config", "r"))) {
        fprintf(stderr, "Couldn't open IPsec settings file");
        exit(1);
    }
    while (getline(&ptr, &s_size, file) != -1) {
        char *key;
        char *name;
        char *type;
        char *interface;
        if (!decode_line(ptr, &key, &name, &type, &interface))
            continue;

        /* TODO: yet another use case, was never covered by usage() ... sigh */
#if 0
        // start/stop a vpn if belonging to specified interface
        if (strcmp(argv[1], interface) == 0) {
            if (strcmp(argv[2], "0") == 0)
                turn_connection_off(name);
            else
                turn_connection_on(name, type);
            continue;
        }
#endif
        // is it the 'key' requested ?
        if (strcmp(connection, key) != 0)
            continue;

        // Start or Delete this Connection
        if (flag_start)
            turn_connection_on(name, type);
        if (flag_stop)
            turn_connection_off(name);
    }
    fclose(file);

    safe_system("/usr/local/bin/vpn-watch --start");
    return 0;
}
