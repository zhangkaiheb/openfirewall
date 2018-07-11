/* 
 * helper_kernel.c: kernel related helper functions
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
 * along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
 *
 * (c) 2015, the IPCop team
 *
 * $Id: helper_kernel.c 7909 2015-03-01 11:25:39Z owes $
 * 
 */

 
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include "common.h"
#include "arch_defs.h"


/* Used globally */
char module_buffer[STRING_SIZE];    /* to return the value out of the function */
char vendorid_buffer[STRING_SIZE];  /* global variable */
char deviceid_buffer[STRING_SIZE];  /* global variable */


static int kernel_inited = -1;
static struct utsname uts;
static char module_find[STRING_SIZE];   /* to return the value out of the function */


int helper_kernel_init(void)
{
    if (kernel_inited >= 0)
        return kernel_inited;

    memset(&uts, 0, sizeof(struct utsname));
    if (uname(&uts) < 0) {
        fprintf(fstderr, "FATAL ERROR: uname\n");
        exit(1);
    }

    char *name = alloca(64 + strlen(uts.release));
    if (name == NULL) {
        fprintf(fstderr, "FATAL ERROR: alloca uts release\n");
        exit(1);
    }
    sprintf(name, "/lib/modules/%s", uts.release);
    fprintf(flog, "Kernelpath %s\n", name);

    kernel_inited = 1;
    return 1;
}


char *helper_kernel_release(void)
{
    if (kernel_inited != 1) {
        return NULL;
    }
    return(uts.release);
}


/* find a kernel module for pci/usb bus depending on vendor and device id */
char *find_modulename(char *bus, uint16_t vendor_id, uint16_t device_id)
{
    FILE *p;
    char command[STRING_SIZE];
    char modulemap[STRING_SIZE];

    if (kernel_inited != 1) {
        return NULL;
    }

    if (!strcmp(bus, "usb")) {
        /* USB syntax slightly differs */
        snprintf(command, STRING_SIZE,
                 "/bin/grep \"%s:v%04Xp%04X\" /lib/modules/%s/modules.alias",
                 bus, vendor_id, device_id, uts.release);
    }
    else {
        snprintf(command, STRING_SIZE,
                 "/bin/grep \"%s:v0000%04Xd0000%04X\" /lib/modules/%s/modules.alias",
                 bus, vendor_id, device_id, uts.release);
    }

    p = popen(command, "r");
    if (fgets(modulemap, STRING_SIZE, p)) {
        char *module;
        if ((module = strrchr(modulemap, ' ')) != NULL) {
            strcpy(module_find, module+1);
            stripnl(module_find);
            pclose(p);
            return module_find;
        }
    }
    pclose(p);
    return NULL;
}


/* 
 * Get kernel module, vendor and device ID for device using 
 *     /sys/class/net/interface/device/driver/module
 * and /sys/class/net/interface/device/{vendor,device}
 *
 * Return module_buffer.
 * vendorid_buffer and deviceid_buffer are global variables.
 */
char *getkernelmodule(char *device)
{
    char command[STRING_SIZE];
    char line[STRING_SIZE];
    FILE *f;
    char *ptr;

    strcpy(module_buffer, "");

    snprintf(command, STRING_SIZE, "ls -l /sys/class/net/%s/device/driver/module", device);

    f = popen(command, "r");
    if (fgets(line, STRING_SIZE, f) != NULL) {
        stripnl(line);
        if ((ptr = strrchr(line, '/')) != NULL) {
            /* ptr now points to /e100 */
            ptr++;
            if (*ptr) {
                /* temporarily store driver */ 
                strcpy(module_buffer, ptr);
            }
        }
    }

    pclose(f);

    strcpy(vendorid_buffer, "");
    snprintf(command, STRING_SIZE, "/sys/class/net/%s/device/vendor", device);
    if ((f = fopen(command, "r")) != NULL) {
        if (fgets(line, STRING_SIZE, f) != NULL) {
            stripnl(line);
            strcpy(vendorid_buffer, line+2);
        }
        fclose(f);
    }

    strcpy(deviceid_buffer, "");
    snprintf(command, STRING_SIZE, "/sys/class/net/%s/device/device", device);
    if ((f = fopen(command, "r")) != NULL) {
        if (fgets(line, STRING_SIZE, f) != NULL) {
            stripnl(line);
            strcpy(deviceid_buffer, line+2);
        }
        fclose(f);
    }
    return module_buffer;
}
