/* Ipcop helper program - setdate.c
 *
 * Sets the date and time
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
 * (c) Darren Critchley 2003
 * 
 * $Id: setdate.c 3442 2009-08-15 07:51:34Z owes $
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "common.h"
#include "setuid.h"


int main(int argc, char *argv[])
{
    char command[STRING_SIZE];
    int a, b, c;

    if (!(initsetuid()))
        exit(1);

    if (argc < 3) {
        fprintf(stderr, "Missing arg\n");
        exit(1);
    }

    if (!(strlen(argv[1]) < 11 && sscanf(argv[1], "%d-%d-%d", &a, &b, &c) == 3)
        || (strspn(argv[1], NUMBERS "-") != strlen(argv[1]))) {
        fprintf(stderr, "Bad arg\n");
        exit(1);
    }

    if (!(strlen(argv[2]) < 6 && sscanf(argv[2], "%d:%d", &a, &b) == 2)
        || (strspn(argv[2], NUMBERS ":") != strlen(argv[2]))) {
        fprintf(stderr, "Bad arg\n");
        exit(1);
    }

    memset(command, 0, STRING_SIZE);
    snprintf(command, STRING_SIZE - 1, "/bin/date -s '%s %s' >/dev/null", argv[1], argv[2]);
    fprintf(stderr, "Setting Date: %s %s\n", argv[1], argv[2]);
    safe_system(command);

    /* Also store system time in hw clock */
    safe_system("/sbin/hwclock --systohc --utc");

    return 0;
}
