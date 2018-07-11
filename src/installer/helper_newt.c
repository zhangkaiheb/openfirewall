/* 
 * helper_newt.c: window helper functions
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
 * (c) 2007-2008, the IPCop team
 *
 * $Id: helper_newt.c 5079 2010-10-30 22:33:15Z owes $
 * 
 */


#include <libintl.h>
#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include "common_newt.h"


newtComponent f_progress;

void statuswindow(int width, int height, char *title, char *text, ...)
{
    newtComponent t, f;
    char *buf = NULL;
    int size = 0;
    int i = 0;
    va_list args;

    va_start(args, text);

    do {
        size += 1000;
        if (buf)
            free(buf);
        buf = malloc(size);
        i = vsnprintf(buf, size, text, args);
    } while (i == size);

    va_end(args);

    newtCenteredWindow(width, height, title);

    t = newtTextbox(1, 1, width - 2, height - 2, NEWT_TEXTBOX_WRAP);
    newtTextboxSetText(t, buf);
    f = newtForm(NULL, NULL, 0);

    free(buf);

    newtFormAddComponent(f, t);

    newtDrawForm(f);
    newtRefresh();
    newtFormDestroy(f);
}


/*
  Create and show newt Window, but return form component instead of destroying,
  makes easy to add for example scale component.
*/
void *statuswindow_progress(int width, int height, char *title, char *text, ...)
{
    newtComponent t;
    char *buf = NULL;
    int size = 0;
    int i = 0;
    va_list args;

    va_start(args, text);

    do {
        size += 1000;
        if (buf)
            free(buf);
        buf = malloc(size);
        i = vsnprintf(buf, size, text, args);
    } while (i == size);

    va_end(args);

    newtCenteredWindow(width, height, title);

    t = newtTextbox(1, 1, width - 2, height - 2, NEWT_TEXTBOX_WRAP);
    newtTextboxSetText(t, buf);
    f_progress = newtForm(NULL, NULL, 0);

    free(buf);

    newtFormAddComponent(f_progress, t);

    newtDrawForm(f_progress);
    newtRefresh();

    return &f_progress;
}


/* newtScale mechanism borrowed from redhat installer */
int mysystem_progress(char *command, void *form, int left, int top, int width, int lines, int offset)
{
    int progress = offset;
    newtComponent *f = (newtComponent *) form;
    newtComponent s;
    FILE *p;
    char buffer[STRING_SIZE];

    s = newtScale(left, top, width, lines);
    newtScaleSet(s, progress);

    newtFormAddComponent(*f, s);

    newtDrawForm(*f);
    newtRefresh();

    if (flog != NULL) {
        fprintf(flog, "Running command: %s\n", command);
    }

    if (!(p = popen(command, "r"))) {
        return 1;
    }

    setvbuf(p, NULL, _IOLBF, 255);

    while (fgets(buffer, STRING_SIZE, p)) {
        newtScaleSet(s, ++progress);
        newtRefresh();
    }

    return pclose(p);
}


/*  Verify IP address and netmask for newt entry fields.
    Return 0 if the character is invalid.
*/
int filterip(newtComponent entry, void *data, int ch, int cursor)
{
    if (((ch >= '0') && (ch <= '9')) || (ch == '.') || (ch == '\r') || (ch >= NEWT_KEY_EXTRA_BASE))
        return ch;
    return 0;
}

/* Small window to change IP and Netmask of some colour */
void changeaddress(char *colour, int *changed_flag)
{
    newtComponent networkform;
    newtComponent text;
    newtComponent ok, cancel;
    struct newtExitStruct exitstruct;
    char keyvalue[STRING_SIZE];
    char addresskey[STRING_SIZE];
    char netmaskkey[STRING_SIZE];
    char netaddresskey[STRING_SIZE];
    newtComponent addresslabel;
    newtComponent netmasklabel;
    newtComponent addressentry;
    newtComponent netmaskentry;
    const char *addressresult;
    const char *netmaskresult;
    char message[STRING_SIZE_LARGE];
    int error;
    int numLines;
    char *tmpstring;

    /* Build some key strings. */
    sprintf(addresskey, "%s_1_ADDRESS", colour);
    sprintf(netmaskkey, "%s_1_NETMASK", colour);
    sprintf(netaddresskey, "%s_1_NETADDRESS", colour);

    /* workaround gcc warning, there is really 1 %s there */
    tmpstring=strdup(gettext("TR_ENTER_THE_IP_ADDRESS_INFORMATION"));
    snprintf(message, STRING_SIZE, tmpstring, colour);
    free(tmpstring);
    text = newtTextboxReflowed(1, 1, message, 68, 0, 0, 0);
    numLines = newtTextboxGetNumLines(text);

    /* workaround gcc warning, there is really 1 %s there */
    tmpstring=strdup(gettext("TR_INTERFACE"));
    snprintf(message, STRING_SIZE, tmpstring, colour);
    free(tmpstring);
    newtCenteredWindow(72, 10 + numLines, message);
    networkform = newtForm(NULL, NULL, 0);
    newtFormAddComponent(networkform, text);

    /* Address */
    addresslabel = newtTextbox(2, 2 + numLines, 18, 1, 0);
    newtTextboxSetText(addresslabel, gettext("TR_IP_ADDRESS_PROMPT"));
    if (!strcmp(colour, "GREEN")) {
        /* green only for now */
        strcpy(keyvalue, DEFAULT_IP);
    }
    else {
        strcpy(keyvalue, "");
    }
    find_kv_default(eth_kv, addresskey, keyvalue);
    addressentry = newtEntry(20, 2 + numLines, keyvalue, 20, &addressresult, 0);
    newtEntrySetFilter(addressentry, filterip, NULL);
    newtFormAddComponent(networkform, addresslabel);
    newtFormAddComponent(networkform, addressentry);

    /* Netmask */
    netmasklabel = newtTextbox(2, 3 + numLines, 18, 1, 0);
    newtTextboxSetText(netmasklabel, gettext("TR_NETMASK_PROMPT"));
    strcpy(keyvalue, DEFAULT_NETMASK);
    find_kv_default(eth_kv, netmaskkey, keyvalue);
    netmaskentry = newtEntry(20, 3 + numLines, keyvalue, 20, &netmaskresult, 0);
    newtEntrySetFilter(netmaskentry, filterip, NULL);
    newtFormAddComponent(networkform, netmasklabel);
    newtFormAddComponent(networkform, netmaskentry);

    ok = newtButton(6, 5 + numLines, gettext("TR_OK"));
    /* In case of installer we need a valid address, no turning back */
    if (flag_is_state == setupchroot) {
        newtFormAddComponent(networkform, ok);
    }
    else {
        cancel = newtButton(26, 5 + numLines, gettext("TR_GO_BACK"));
        newtFormAddComponents(networkform, ok, cancel, NULL);
    }
    newtRefresh();
    newtDrawForm(networkform);

    do {
        error = 0;
        newtFormRun(networkform, &exitstruct);

        if (exitstruct.u.co == ok) {

            strcpy(message, gettext("TR_INVALID_FIELDS"));
            if (VALID_IP(addressresult) == FALSE) {
                strcat(message, gettext("TR_IP_ADDRESS_CR"));
                error = 1;
                newtFormSetCurrent(networkform, addressentry);
            }
            if (VALID_IP(netmaskresult) == FALSE) {
                strcat(message, gettext("TR_NETWORK_MASK_CR"));
                error = 1;
                newtFormSetCurrent(networkform, netmaskentry);
            }

            // TODO: additional network mask validation

            if (error) {
                errorbox(message);
            }
            else {
                /* all is well, calc netaddress and store everything */
                unsigned long int intaddress;
                unsigned long int intnetaddress;
                unsigned long int intnetmask;
                struct in_addr i_addr;
                char *netaddress;

                update_kv(&eth_kv, addresskey, (char *) addressresult);
                update_kv(&eth_kv, netmaskkey, (char *) netmaskresult);
                /* calculate netaddress */
                intaddress = inet_addr(addressresult);
                intnetmask = inet_addr(netmaskresult);
                intnetaddress = intaddress & intnetmask;
                i_addr.s_addr = intnetaddress;
                netaddress = inet_ntoa(i_addr);
                update_kv(&eth_kv, netaddresskey, (char *) netaddress);

                changed_config = 1;
                *changed_flag = 1;
            }
        }
    }
    while (error);

    newtFormDestroy(networkform);
    newtPopWindow();
}
