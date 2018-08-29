/*
 * passwords.c: Set root, backup and admin passwords
 *
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
 * along with Openfirewall; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * (c) 2007-2010, the Openfirewall Team
 *
 * $Id: passwords.c 4545 2010-04-30 21:33:00Z owes $
 * 
 */


#include <libintl.h>
#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "common_newt.h"


/* Get a password
   Return SUCCESS if OK
   Return FAILURE if CANCEL
*/
static int getpassword(char *password, char *text)
{
    char *values[] = { NULL, NULL, NULL };      /* pointers for the values. */
    struct newtWinEntry entries[] = {
        {gettext("TR_PASSWORD_PROMPT"), &values[0], NEWT_FLAG_PASSWORD},
        {gettext("TR_AGAIN_PROMPT"), &values[1], NEWT_FLAG_PASSWORD},
        {NULL, NULL, 0}
    };
    int rc;
    int done;

    do {
        done = 1;
        rc = newtWinEntries(gettext("TR_TITLE_PASSWORD"), text,
                            68, 5, 5, 40, entries, gettext("TR_OK"), (flag_is_state == setup) ? gettext("TR_GO_BACK") : NULL, NULL);

        if (rc == 2) {
            return FAILURE;
        }

        if (strlen(values[0]) == 0 || strlen(values[1]) == 0) {
            errorbox(gettext("TR_PASSWORD_CANNOT_BE_BLANK"));
            done = 0;
        }
        else if (strcmp(values[0], values[1]) != 0) {
            errorbox(gettext("TR_PASSWORDS_DO_NOT_MATCH"));
            done = 0;
        }
        else if (strchr(values[0], ' ')) {
            errorbox(gettext("TR_PASSWORD_CANNOT_CONTAIN_SPACES"));
            done = 0;
        }
        else if (strlen(values[0]) < 6) {
            errorbox(gettext("TR_PASSWORD_MINIMAL_LENGTH_IS_6"));
            done = 0;
        }
        else if (strchr(values[0], '"') || strstr(values[0], "'")) {
            errorbox(gettext("TR_PASSWORD_CANNOT_CONTAIN_SIMPLE_OR_DOUBLE_QUOTE"));
            done = 0;
        }
        if (done == 0) {
            strcpy(values[0], "");
            strcpy(values[1], "");
        }
    }
    while (!done);

    strncpy(password, values[0], STRING_SIZE);

    if (values[0])
        free(values[0]);
    if (values[1])
        free(values[1]);

    return SUCCESS;
}


int password(char *user)
{
    char message[STRING_SIZE];
    char password[STRING_SIZE];
    char commandstring[STRING_SIZE];
    char *tmpstring;

    if (!strcmp(user, "root")) {
        strcpy(message, gettext("TR_ENTER_ROOT_PASSWORD"));
    }
    else if (!strcmp(user, "admin")) {
        /* workaround gcc warning, there is really 2 %s there */
        tmpstring = strdup(gettext("TR_ENTER_ADMIN_PASSWORD"));
        snprintf(message, STRING_SIZE, tmpstring, NAME, NAME);
        free(tmpstring);
    }
    else if (!strcmp(user, "backup")) {
        strcpy(message, gettext("TR_ENTER_BACKUP_PASSWORD"));
    }
    else if (!strcmp(user, "dial")) {
        strcpy(message, gettext("TR_ENTER_DIAL_PASSWORD"));
    }
    else {
        return FAILURE;
    }

    if (getpassword(password, message) == SUCCESS) {
        if (!strcmp(user, "admin") || !strcmp(user, "dial")) {
            snprintf(commandstring, STRING_SIZE, "/usr/sbin/htpasswd -m -b /var/ipcop/auth/users %s '%s'",
                     user, password);
        }
        else {
            snprintf(commandstring, STRING_SIZE, "/bin/echo '%s:%s' | /usr/sbin/chpasswd", user, password);
        }

        if (mysystemhidden(commandstring)) {
            snprintf(message, STRING_SIZE, "%s %s", gettext("TR_PROBLEM_SETTING_PASSWORD_FOR"), user);
            newtWinMessage(get_title(), gettext("TR_OK"), message);
            return FAILURE;
        }
    }

    return SUCCESS;
}


/* Open a window with selection of which password to modify */
int handlepasswords(void)
{
    int rc;
    int choice;
    char *menuchoices[5];

    menuchoices[0] = gettext("TR_ROOT_PASSWORD");
    menuchoices[1] = gettext("TR_ADMIN_PASSWORD");
    menuchoices[2] = gettext("TR_BACKUP_PASSWORD");
    menuchoices[3] = gettext("TR_DIAL_PASSWORD");

    menuchoices[4] = NULL;

    for (;;) {

        rc = newtWinMenu(gettext("TR_PASSWORDS"),
                         gettext("TR_SELECT_THE_ITEM"), 50, 5, 5, 11,
                         menuchoices, &choice, gettext("TR_OK"), gettext("TR_GO_BACK"), NULL);

        if (rc == 2)
            break;

        switch (choice) {
        case 0:
            password("root");
            break;
        case 1:
            password("admin");
            break;
        case 2:
            password("backup");
            break;
        case 3:
            password("dial");
            break;
        default:
            break;
        }
    }

    return SUCCESS;
}
