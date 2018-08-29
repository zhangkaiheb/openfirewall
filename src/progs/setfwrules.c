/* Openfirewall helper program - setfwrules
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 * Copyright (c) Achim Weber - Completly rewritten, see comment below
 *
 * 12/16/04 Achim Weber:	This Helper programm only does SUID stuff and
 *							calls new Perl script "puzzleFwRules.pl".
 *							Puzzle of firewall rules is moved from this file to
 *							the new Perl script because it is much easier to
 *							manage all the structures in Perl(Hashes) as it is in C.
 *
 * 04/23/2005 Achim Weber:	Add -c option for check if the timeframe rules need an update
 *
 * $Id: setfwrules.c 5269 2010-12-23 07:35:04Z owes $
 *
 */


#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "setuid.h"


static int flag_emergency = 0;


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  -a, --all             force update for all user and Openfirewall services rules\n");
    printf("  -c, --cron            check for timeframe rule changes\n");
    printf("  -f, --force=CHAIN     force update for CHAIN\n");
    printf("  -o, --ofw             force update for Openfirewall services rules\n");
    printf("  -u, --user            force update for user rules\n");
    printf("  -w, --wireless        force update of Addressfilter rules\n");
    printf("      --emergency       enable admin access for GREEN\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char *argv[])
{
    char command[STRING_SIZE];
    int flag_all = 0;
    int flag_cron = 0;
    int flag_force = 0;
    int flag_ofw = 0;
    int flag_user = 0;
    int flag_wireless = 0;
    char *opt_chain = NULL;
    char *opt_debug = NULL;

    static struct option long_options[] =
    {
        { "all", no_argument, 0, 'a' },
        { "emergency", no_argument, &flag_emergency, 1 },
        { "cron", no_argument, 0, 'c' },
        { "force", required_argument, 0, 'f' },
        { "ofw", no_argument, 0, 'o' },
        { "user", no_argument, 0, 'u' },
        { "wireless", no_argument, 0, 'w' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "acf:houvw", long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            break;
        case 'a':
            flag_all = 1;
            break;
        case 'c':
            flag_cron = 1;
            break;
        case 'f':
            flag_force = 1;
            if (strcmp(optarg,"INPUT") && strcmp(optarg,"OUTGOING") &&
                strcmp(optarg,"EXTERNAL") && strcmp(optarg,"PINHOLES") &&
                strcmp(optarg,"PORTFW")) {

                fprintf(stderr, "invalid chain (%s)\n", optarg);
                exit(2);
            }
            opt_chain = strdup(optarg);
            break;
        case 'o':
            flag_ofw = 1;
            break;
        case 'u':
            flag_user = 1;
            break;
        case 'w':
            flag_wireless = 1;
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

    if(flag_verbose > 0) {
        // Only pass debuglevel==1 to puzzleFwRules. If an user calls setfwrules
        // with higher verbose level and we would pass the high level to
        // puzzleFwRules.pl the iptables wouldn't be created and user may have
        // a problem ;-)
        // If you really want to have a higher debuglevel, call puzzleFwRules.pl
        // directly
        opt_debug = strdup("-d");
    }
    else {
         opt_debug = strdup("");
    }

    // Enable access from GREEN network and disable MAC filter, in case admin has locked himself out
    // FW_ADMIN chain comes before user firewall rules, so this is sufficient
    if (flag_emergency) {
        safe_system("/bin/sed -i -e s+ADMIN_GREEN_1.*+ADMIN_GREEN_1=on+ -e s+USE_ADMIN_MAC.*+USE_ADMIN_MAC=off+ /var/ofw/firewall/settings");
        flag_ofw = 1;
    }

    // should we check for (timeframe) rule changes only?
    if (flag_cron) {
        snprintf(command, STRING_SIZE, "/usr/local/bin/puzzleFwRules.pl %s -c", opt_debug);
        safe_system(command);
    }

    if (flag_all) {
        snprintf(command, STRING_SIZE, "/usr/local/bin/puzzleFwRules.pl %s -a", opt_debug);
        safe_system(command);
    }

    if (flag_force) {
        snprintf(command, STRING_SIZE, "/usr/local/bin/puzzleFwRules.pl %s -f %s", opt_debug, opt_chain);
        safe_system(command);
    }

    if (flag_ofw) {
        snprintf(command, STRING_SIZE, "/usr/local/bin/puzzleFwRules.pl %s -i", opt_debug);
        safe_system(command);
    }

    if (flag_user) {
        snprintf(command, STRING_SIZE, "/usr/local/bin/puzzleFwRules.pl %s -u", opt_debug);
        safe_system(command);
    }

    if (flag_wireless) {
        snprintf(command, STRING_SIZE, "/usr/local/bin/puzzleFwRules.pl %s -w", opt_debug);
        safe_system(command);
    }

    return 0;
}
