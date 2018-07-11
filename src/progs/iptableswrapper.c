/* 
 * Q&D wrapper for iptables
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 * Copyright (C) 2007-2008 weizen_42 at ipcop-forum dot de
 *
 * $Id: iptableswrapper.c 2404 2009-01-31 19:33:51Z owes $
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include "setuid.h"


#define BUFFER_SIZE 1024

char command[BUFFER_SIZE];

int main(int argc, char *argv[])
{
    if ( argc < 2 ) {
        printf("invalid parameter(s)\n");
        return(1);
    }

    if (!(initsetuid()))
		exit(1);

    if ( (argc == 2) && (!strcmp("filter", argv[1]) || !strcmp("mangle", argv[1]) || !strcmp("nat", argv[1]) || !strcmp("raw", argv[1])) ) {
        snprintf(command, BUFFER_SIZE-1, "/sbin/iptables -t %s --line-numbers -nvL", argv[1]);
    }
    else if ( (argc == 4) && !strcmp("chain", argv[1]) ) {
        snprintf(command, BUFFER_SIZE-1, "/sbin/iptables -t %s --line-numbers -nvL %s", argv[2], argv[3]);
    }

    safe_system(command);

    return(0);
}
