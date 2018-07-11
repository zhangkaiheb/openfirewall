/* 
 * host_domain.c: entry of hostname and domainname
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
 * $Id: host_domain.c 5041 2010-10-19 20:45:10Z owes $
 *
 */


#include <libintl.h>
#include <malloc.h>
#include <newt.h>
#include <string.h>
#include "common.h"
#include "common_newt.h"


static char default_hostname[STRING_SIZE] = SNAME;
static char default_domainname[STRING_SIZE] = "localdomain";

static char hostname[STRING_SIZE] = "";
static char domainname[STRING_SIZE] = "";


/* rewrite /etc/hosts, the Apache ServerName file and update the hostname */
static int writehostsfiles(char *hostname, char *domainname)
{
    FILE *file;
    char commandstring[STRING_SIZE];

    /* set defaults if not defined yet */
    if (hostname == NULL) {
        hostname = default_hostname;
    }
    if (domainname == NULL) {
        domainname = default_domainname;
    }

    /* rebuildhosts will take main/settings and main/hosts to rebuild /etc/hosts */
    if (flag_is_state == setupchroot) {
        /* rebuildhosts will send SIGHUP to dnsmasq, not a problem as dnsmasq is not there (yet) */
        mysystem("/usr/local/bin/rebuildhosts");
    }
    else {
        /* restart dnsmasq so it knows about new host/domain */
        mysystem("/usr/local/bin/rebuildhosts --nosighup");
    }

    /* Tell our indian about host & domain */
    if (!(file = fopen("/var/ipcop/main/hostname.conf", "w"))) {
        errorbox(gettext("UNABLE_TO_WRITE_APACHE_HOSTNAME"));
        return FAILURE;
    }
    fprintf(file, "ServerName %s.%s\n", hostname, domainname);
    fclose(file);

    /* Launch hostname */
    snprintf(commandstring, STRING_SIZE, "/bin/hostname %s.%s", hostname, domainname);
    if (mysystem(commandstring)) {
        errorbox(gettext("TR_UNABLE_TO_SET_HOSTNAME"));
        return FAILURE;
    }

    return SUCCESS;
}


/*
 * We can be called from 2 different places:
 *  - setup called during installation (chroot'd)
 *  - 'normal' setup
*/
int handlehostname(void)
{
    NODEKV *kv = NULL;
    char *values[] = { hostname, NULL };
    struct newtWinEntry entries[] = { {"", &values[0], 0,}, {NULL, NULL, 0} };
    int rc;
    int result;

    if (read_kv_from_file(&kv, "/var/ipcop/main/settings") != SUCCESS) {
        free_kv(&kv);
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }

    strcpy(hostname, default_hostname);
    strcpy(domainname, default_domainname);
    find_kv_default(kv, "HOSTNAME", hostname);
    find_kv_default(kv, "DOMAINNAME", domainname);

    if (flag_is_state == setupchroot) {
        NODEKV *kv_dhcp_params = NULL;

        read_kv_from_file(&kv_dhcp_params, "/tmp/dhcp.params");
        find_kv_default(kv_dhcp_params, "HOSTNAME", hostname);
        find_kv_default(kv_dhcp_params, "DOMAIN", domainname);
        free_kv(&kv_dhcp_params);
    }

    for (;;) {
        rc = newtWinEntries(gettext("TR_HOSTNAME"), gettext("TR_ENTER_HOSTNAME"), 65, 5, 5, 40, entries, 
                            gettext("TR_OK"), (flag_is_state == setupchroot) ? gettext("TR_SKIP") : gettext("TR_GO_BACK"), NULL);

        if (rc == 1) {
            strcpy(hostname, values[0]);
            if (!(strlen(hostname)))
                errorbox(gettext("TR_HOSTNAME_CANNOT_BE_EMPTY"));
            else if (strchr(hostname, ' '))
                errorbox(gettext("TR_HOSTNAME_CANNOT_CONTAIN_SPACES"));
            else if (strlen(hostname) !=
                     strspn(hostname, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"))
                errorbox(gettext("TR_HOSTNAME_NOT_VALID_CHARS"));
            else {
                update_kv(&kv, "HOSTNAME", hostname);
                write_kv_to_file(&kv, "/var/ipcop/main/settings");
                if (flag_is_state == setup) {
                    /* In case of installation we will simply rewrite the files after setting the domainname */
                    writehostsfiles(hostname, domainname);
                }
                result = SUCCESS;
                break;
            }
        }
        else {
            result = FAILURE;
            break;
        }
    }
    free(values[0]);
    free_kv(&kv);

    return result;
}


/*
 * We can be called from 2 different places:
 *  - setup called during installation (chroot'd)
 *  - 'normal' setup
*/
int handledomainname(void)
{
    NODEKV *kv = NULL;
    char *values[] = { domainname, NULL };
    struct newtWinEntry entries[] = { {"", &values[0], 0,}, {NULL, NULL, 0} };
    int rc;
    int result;

    if (read_kv_from_file(&kv, "/var/ipcop/main/settings") != SUCCESS) {
        free_kv(&kv);
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }

    strcpy(hostname, default_hostname);
    strcpy(domainname, default_domainname);
    find_kv_default(kv, "HOSTNAME", hostname);
    find_kv_default(kv, "DOMAINNAME", domainname);

    if (flag_is_state == setupchroot) {
        NODEKV *kv_dhcp_params = NULL;

        read_kv_from_file(&kv_dhcp_params, "/tmp/dhcp.params");
        find_kv_default(kv_dhcp_params, "HOSTNAME", hostname);
        find_kv_default(kv_dhcp_params, "DOMAIN", domainname);
        free_kv(&kv_dhcp_params);
    }

    for (;;) {
        rc = newtWinEntries(gettext("TR_DOMAINNAME"), gettext("TR_ENTER_DOMAINNAME"), 65, 5, 5, 40, entries, 
                            gettext("TR_OK"), (flag_is_state == setupchroot) ? gettext("TR_SKIP") : gettext("TR_GO_BACK"), NULL);

        if (rc == 1) {
            strcpy(domainname, values[0]);
            if (!(strlen(domainname)))
                errorbox(gettext("TR_DOMAINNAME_CANNOT_BE_EMPTY"));
            else if (strchr(domainname, ' '))
                errorbox(gettext("TR_DOMAINNAME_CANNOT_CONTAIN_SPACES"));
            else if (strlen(domainname) != strspn(domainname, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-."))
                errorbox(gettext("TR_DOMAINNAME_NOT_VALID_CHARS"));
            else {
                char *dot = strrchr(domainname, '.');
                if (dot == NULL) {
                    dot = domainname;
                }
                else {
                    dot++;
                }
                if (strlen(dot) != strspn(dot, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")) {
                    errorbox(gettext("TR_DOMAINNAME_TLD_NOT_VALID_CHARS"));
                }
                else {
                    update_kv(&kv, "DOMAINNAME", domainname);
                    write_kv_to_file(&kv, "/var/ipcop/main/settings");
                    writehostsfiles(hostname, domainname);
                    result = SUCCESS;
                    break;
                }
            }
        }
        else {
            result = FAILURE;
            if (flag_is_state == setupchroot) {
                /* In case of installation always write the files, so they exist afterwards */
                writehostsfiles(hostname, domainname);
            }
            break;
        }
    }
    free(values[0]);
    free_kv(&kv);

    return result;
}
