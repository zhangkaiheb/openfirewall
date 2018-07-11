/*
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
 * $Id: conntrack_helper.c 3839 2009-11-20 12:01:09Z owes $
 *
 */


#include <getopt.h>
#include <stdio.h>
#include "common.h"
#include "setuid.h"


static int flag_eroute = 0;


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  --eroute              output ipsec_eroute\n"); 
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char *argv[])
{
    static struct option long_options[] =
    {
        { "eroute",  no_argument, &flag_eroute, 1 },
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
        case 'h':
            usage(argv[0], 0);
        default:
            fprintf(stderr, "unknown option\n");
            usage(argv[0], 1);
        }
    }

    if ( !(initsetuid()) )
        exit(1);

    if (flag_eroute) {
        safe_system("/bin/cat /proc/net/ipsec_eroute 2>/dev/null");
    }
    else {
        safe_system("/usr/sbin/conntrack -L -o xml 2>/dev/null");
    }

    return(0);
}
