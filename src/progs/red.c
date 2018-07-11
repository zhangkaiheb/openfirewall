/*
 * red.c: suid helper to (re)start RED
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
 * (c) 2009, the IPCop team
 *
 * $Id: red.c 4022 2009-12-18 09:15:58Z owes $
 *
 */


#include <getopt.h>
#include <stdio.h>
#include "common.h"
#include "setuid.h"


static int flag_start = 0;
static int flag_stop = 0;
static int flag_clear = 0;


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  --start               Connect RED\n"); 
    printf("  --stop                Disconnect RED\n"); 
    printf("  --clear               Clear files and remove drivers\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char *argv[])
{
    static struct option long_options[] =
    {
        { "start",   no_argument, &flag_start, 1 },
        { "stop",    no_argument, &flag_stop, 1 },
        { "clear",   no_argument, &flag_clear, 1 },
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

    if (!flag_start && !flag_stop && !flag_clear) {
        /* need at least one of start, stop, clear */
        usage(argv[0], 1);
    }

    if ( !(initsetuid()) )
        exit(1);

    if (flag_stop) {
        safe_system("/etc/rc.d/rc.red stop");
    }
    if (flag_clear) {
        safe_system("/etc/rc.d/rc.red clear");
    }
    if (flag_start) {
        safe_system("/etc/rc.d/rc.red start");
    }

    return(0);
}
