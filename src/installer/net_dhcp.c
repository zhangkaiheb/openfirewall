/*
 * net_dhcp.c: DHCP server configuration
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
 * (c) 2007-2010, the IPCop team
 *
 * $Id: net_dhcp.c 5182 2010-11-28 15:56:41Z owes $
 * 
 */


#include <libintl.h>
#include <newt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "common.h"
#include "common_newt.h"
#include "arch_defs.h"


/*  Configure (optional) DHCP server for GREEN.
    This is only a minimal setup, to help get an admin PC working.
    Full DHCP server config is done through web GUI.
*/
int changedhcpserver(void)
{
    newtComponent netdhcpform;
    newtComponent text;
    newtComponent enabledcheckbox;
    char enabledresult;
    char enabledinitvalue;
    newtComponent labelstart;
    newtComponent entrystart;
    const char *resultstart;
    newtComponent labelend;
    newtComponent entryend;
    const char *resultend;
    newtComponent labellease;
    newtComponent entrylease;
    const char *resultlease;
    newtComponent ok, cancel;
    struct newtExitStruct exitstruct;
    char keyvalue[STRING_SIZE];
    char message[STRING_SIZE_LARGE];
    int error;
    int numLines;
    NODEKV *dhcpkv = NULL;
    int changed;
    struct in_addr green_address;
    struct in_addr green_netmask;
    struct in_addr green_netaddress;
    NODEKV *mainkv = NULL;
    char domainname[STRING_SIZE];

    changed = FALSE;

    /* we will need GREEN IP and mask */
    if (read_ethernet_settings(0)) {
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }
    if (inet_aton(ipcop_ethernet.address[GREEN][1], &green_address) == 0) {
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }
    if (inet_aton(ipcop_ethernet.netmask[GREEN][1], &green_netmask) == 0) {
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }
    if (inet_aton(ipcop_ethernet.netaddress[GREEN][1], &green_netaddress) == 0) {
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }

    if (read_kv_from_file(&dhcpkv, "/var/ipcop/dhcp/settings") != SUCCESS) {
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }

    /* Fetch domainname */
    domainname[0] = 0;
    if (read_kv_from_file(&mainkv, "/var/ipcop/main/settings") == SUCCESS) {
        find_kv_default(mainkv, "DOMAINNAME", domainname);
        free_kv(&mainkv);
    }

    /* set some default values if not defined */
    if (find_kv(dhcpkv, "ENABLED_GREEN_1") == NULL) {
        update_kv(&dhcpkv, "ENABLED_GREEN_1", "off");
    }
    if (find_kv(dhcpkv, "START_ADDR_GREEN_1") == NULL) {
        uint32_t addr = htonl(green_address.s_addr);
        uint32_t broadcast;
        struct in_addr iaddr;
        
        broadcast = addr | ~htonl(green_netmask.s_addr);

        if (addr+2 < broadcast) {
            addr++;
        }
        else {
            addr = htonl(green_netaddress.s_addr) + 1;
        }

        iaddr.s_addr = htonl(addr);
        strcpy(keyvalue, inet_ntoa(iaddr));
        update_kv(&dhcpkv, "START_ADDR_GREEN_1", keyvalue);
        changed = TRUE;
    }
    if (find_kv(dhcpkv, "END_ADDR_GREEN_1") == NULL) {
        uint32_t addr = htonl(green_address.s_addr);
        uint32_t broadcast;
        struct in_addr iaddr;

        broadcast = addr | ~htonl(green_netmask.s_addr);

        if (addr+2 < broadcast) {
            addr = broadcast - 1;
        }
        else {
            addr--;
        }

        iaddr.s_addr = htonl(addr);
        strcpy(keyvalue, inet_ntoa(iaddr));
        update_kv(&dhcpkv, "END_ADDR_GREEN_1", keyvalue);
        changed = TRUE;
    }
    if (find_kv(dhcpkv, "DNS1_GREEN_1") == NULL) {
        update_kv(&dhcpkv, "DNS1_GREEN_1", ipcop_ethernet.address[GREEN][1]);
        changed = TRUE;
    }
    if (find_kv(dhcpkv, "DEFAULT_LEASE_TIME_GREEN_1") == NULL) {
        update_kv(&dhcpkv, "DEFAULT_LEASE_TIME_GREEN_1", "60");
        changed = TRUE;
    }

    snprintf(message, STRING_SIZE, gettext("TR_CONFIGURE_DHCP"));
    text = newtTextboxReflowed(1, 1, message, 68, 0, 0, 0);
    numLines = newtTextboxGetNumLines(text);

    newtCenteredWindow(72, 13 + numLines, gettext("TR_DHCP_SERVER_CONFIGURATION"));
    netdhcpform = newtForm(NULL, NULL, 0);
    newtFormAddComponent(netdhcpform, text);

    enabledinitvalue = (test_kv(dhcpkv, "ENABLED_GREEN_1", "on") == SUCCESS) ? '*' : ' ';
    enabledcheckbox = newtCheckbox(2, 2 + numLines, gettext("TR_ENABLED"), enabledinitvalue, " *", &enabledresult);
    newtFormAddComponent(netdhcpform, enabledcheckbox);

    labelstart = newtTextbox(2, 4 + numLines, 33, 1, 0);
    strcpy(message, gettext("TR_START_ADDRESS"));
    strcat(message, ":");
    newtTextboxSetText(labelstart, message);
    entrystart = newtEntry(35, 4 + numLines, find_kv(dhcpkv, "START_ADDR_GREEN_1"), 20, &resultstart, 0);
    newtEntrySetFilter(entrystart, filterip, NULL);
    newtFormAddComponents(netdhcpform, labelstart, entrystart, NULL);

    labelend = newtTextbox(2, 5 + numLines, 33, 1, 0);
    strcpy(message, gettext("TR_END_ADDRESS"));
    strcat(message, ":");
    newtTextboxSetText(labelend, message);
    entryend = newtEntry(35, 5 + numLines, find_kv(dhcpkv, "END_ADDR_GREEN_1"), 20, &resultend, 0);
    newtEntrySetFilter(entryend, filterip, NULL);
    newtFormAddComponents(netdhcpform, labelend, entryend, NULL);

    labellease = newtTextbox(2, 6 + numLines, 33, 1, 0);
    strcpy(message, gettext("TR_DEFAULT_LEASE"));
    strcat(message, ":");
    newtTextboxSetText(labellease, message);
    entrylease = newtEntry(35, 6 + numLines, find_kv(dhcpkv, "DEFAULT_LEASE_TIME_GREEN_1"), 20, &resultlease, 0);
    newtFormAddComponents(netdhcpform, labellease, entrylease, NULL);

    ok = newtButton(6, 8 + numLines, gettext("TR_OK"));
    cancel = newtButton(26, 8 + numLines, gettext("TR_SKIP"));
    newtFormAddComponents(netdhcpform, ok, cancel, NULL);

    newtRefresh();
    newtDrawForm(netdhcpform);

    do {
        error = FALSE;
        newtFormRun(netdhcpform, &exitstruct);

        if (exitstruct.u.co == ok) {
            if (enabledresult == '*') {
                strcpy(message, gettext("TR_INVALID_FIELDS"));
                strcat(message, ":\n\n");

                if (!strlen(resultstart) || (inet_addr(resultstart) == INADDR_NONE)) {
                    strcat(message, gettext("TR_START_ADDRESS_CR"));
                    error = TRUE;
                }
                if (!strlen(resultend) || (inet_addr(resultend) == INADDR_NONE)) {
                    strcat(message, gettext("TR_END_ADDRESS_CR"));
                    error = TRUE;
                }
                if (!atol(resultlease)) {
                    strcat(message, gettext("TR_DEFAULT_LEASE_CR"));
                    error = TRUE;
                }

                if (error == FALSE) {
                    update_kv(&dhcpkv, "ENABLED_GREEN_1", "on");
                    update_kv(&dhcpkv, "START_ADDR_GREEN_1", (char *)resultstart);
                    update_kv(&dhcpkv, "END_ADDR_GREEN_1", (char *)resultend);
                    update_kv(&dhcpkv, "DEFAULT_LEASE_TIME_GREEN_1", (char *)resultlease);
                    changed = TRUE;
                }
                else {
                    errorbox(message);
                }
            }
            else {
                update_kv(&dhcpkv, "ENABLED_GREEN_1", "off");
                changed = TRUE;
            }
        }
    } while (error == TRUE);

    newtFormDestroy(netdhcpform);
    newtPopWindow();

    /* In case of changes, rewrite dhcpd.conf (basics only!) and restart DHCP server */
    if (changed == TRUE) {
        if (test_kv(dhcpkv, "ENABLED_GREEN_1", "on") == SUCCESS) {
            FILE *f;
            int leasetime;

            if ((f = fopen("/var/ipcop/dhcp/dnsmasq.conf", "w")) == NULL) {
                errorbox(gettext("TR_ERROR_WRITING_CONFIG"));
                return FAILURE;
            }

            fprintf(f, "# Do not modify '/var/ipcop/dhcp/dnsmasq.conf' directly since any changes\n");
            fprintf(f, "# you make will be overwritten whenever you resave dhcp settings using the\n");
            fprintf(f, "# web interface! \n");
            fprintf(f, "# Instead modify the file '/var/ipcop/dhcp/dnsmasq.local' and then restart \n");
            fprintf(f, "# the DHCP server using the web interface or restartdhcp.\n");
            fprintf(f, "# Changes made to the 'local' file will then propagate to the DHCP server.\n");
            fprintf(f, "\n");

            fprintf(f, "pid-file=/var/run/dnsmasq/dnsmasq.pid\n");
            fprintf(f, "bind-interfaces\n");
            fprintf(f, "except-interface=wan-1\n");
            fprintf(f, "except-interface=ppp0\n");
            fprintf(f, "except-interface=dmz-1\n");
            fprintf(f, "no-poll\n");
            fprintf(f, "domain-needed\n");
            fprintf(f, "dhcp-authoritative\n");
            fprintf(f, "dhcp-leasefile=/var/run/dnsmasq/dnsmasq.leases\n");
            fprintf(f, "dhcp-hostsfile=/var/ipcop/dhcp/dnsmasq.statichosts\n");
            fprintf(f, "dhcp-optsfile=/var/ipcop/dhcp/dnsmasq.staticopts\n");
            fprintf(f, "conf-file=/var/ipcop/dhcp/dnsmasq.local\n");
            fprintf(f, "\n");

            leasetime = atol(find_kv(dhcpkv, "DEFAULT_LEASE_TIME_GREEN_1")) * 60;
            fprintf(f, "dhcp-range=GREEN_1,%s,%s,%d\n", 
                        find_kv(dhcpkv, "START_ADDR_GREEN_1"),
                        find_kv(dhcpkv, "END_ADDR_GREEN_1"),
                        leasetime);
            if (domainname[0]) {
                update_kv(&dhcpkv, "DOMAIN_NAME_GREEN_1", domainname);
                fprintf(f, "dhcp-option=GREEN_1,option:domain-name,%s\n", domainname);
            }
            fprintf(f, "dhcp-option=GREEN_1,option:dns-server,%s\n", find_kv(dhcpkv, "DNS1_GREEN_1"));

            fclose(f);
        }

        write_kv_to_file(&dhcpkv, "/var/ipcop/dhcp/settings");

        if (flag_is_state == setup) {
            mysystem("/usr/local/bin/restartdhcp");
        }
    }

    free_kv(&dhcpkv);

    return SUCCESS;
}
