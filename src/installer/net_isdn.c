/*
 * net_isdn.c: ISDN configuration
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
 * (c) 2009-2010, the IPCop team
 *
 * $Id $
 * 
 */

 
#include <libintl.h>
#include <malloc.h>
#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "common_newt.h"
#include "arch_defs.h"


/* list of ISDN cards */
#define ISDN_MAX     128        // arbitrary value, should be more than sufficient
char *isdn_cards_description[ISDN_MAX];
int isdn_cards_type[ISDN_MAX];

static NODEKV *isdn_kv = NULL;


/* Read list of ISDN cards */
static void readisdncards(void)
{
    int i;
    FILE *f;
    char buffer[STRING_SIZE];

    /* clean the list */
    for (i = 0; i < ISDN_MAX; i++) {
        if (isdn_cards_description[i] != NULL) {
            free(isdn_cards_description[i]);
            isdn_cards_description[i] = NULL;
        }
        isdn_cards_type[i] = 0;
    }

    if (!(f = fopen("/etc/isdn-card-list", "r")))
        return;

    i = 0;

    while ((fgets(buffer, STRING_SIZE, f) != NULL) && (i < ISDN_MAX)) {
        char *ptr = strchr(buffer, ',');

        stripnl(buffer);
        /* We expect at least 3 characters.
           Simply skip lines containing comment character.
           Also skip lines not containing comma.
         */
        if ((strlen(buffer) < 3) || strchr(buffer, '#') || (ptr == NULL)) {
            continue;
        }

        isdn_cards_type[i] = (int) strtol(ptr + 1, (char **) NULL, 10);
        *ptr = 0;
        isdn_cards_description[i] = strdup(buffer);
        i++;
    }
    fclose(f);

#if 0
    /* Output the found list for testing purposes */
    fprintf(flog, "ISDN list\n");
    for (i = 0; isdn_cards_type[i] != 0; i++) {
        fprintf(flog, "%s, %d\n", isdn_cards_description[i], isdn_cards_type[i]);
    }
#endif
}


static void changeprotocol(char **protocolnames)
{
    int rc;
    int choice;
    char keyvalue[STRING_SIZE] = "0";

    find_kv_default(isdn_kv, "PROTOCOL", keyvalue);
    choice = (int) strtol(keyvalue, (char **) NULL, 10);
    choice = choice - 1;

    rc = newtWinMenu(gettext("TR_ISDN_PROTOCOL_SELECTION"), gettext("TR_CHOOSE_THE_ISDN_PROTOCOL"), 65, 5, 5, 11, 
                        protocolnames, &choice, gettext("TR_ASSIGN"), gettext("TR_GO_BACK"), NULL);

    if (rc == 2)
        return;

    sprintf(keyvalue, "%d", choice + 1);
    update_kv(&isdn_kv, "PROTOCOL", keyvalue);
}


static void changeparameters(void)
{
    int rc;
    char parameters[STRING_SIZE] = "";
    char *values[] = { parameters, NULL };
    struct newtWinEntry entries[] = { {"", &values[0], 0,}, {NULL, NULL, 0} };

    find_kv_default(isdn_kv, "MODULE_PARAMS", parameters);

    rc = newtWinEntries(get_title(), gettext("TR_ENTER_ADDITIONAL_MODULE_PARAMS"), 65, 5, 5, 40, 
                        entries, gettext("TR_OK"), gettext("TR_GO_BACK"), NULL);

    if (rc == 1) {
        update_kv(&isdn_kv, "MODULE_PARAMS", values[0]);
    }
}


static void changecard(void)
{
    int rc;
    int choice;
    int type;
    int c;
    char parameters[STRING_SIZE] = "";
    char keyvalue[STRING_SIZE] = "0";

    find_kv_default(isdn_kv, "TYPE", keyvalue);
    type = (int) strtol(keyvalue, (char **) NULL, 10);
    find_kv_default(isdn_kv, "MODULE_PARAMS", parameters);

    /* Determine inital value for choice. */
    c = 0;
    choice = 0;
    while (isdn_cards_type[c]) {
        if (isdn_cards_type[c] == type) {
            choice = c;
            break;
        }
        c++;
    }

    for (;;) {
        rc = newtWinMenu(gettext("TR_ISDN_CARD_SELECTION"), gettext("TR_CHOOSE_THE_ISDN_CARD_INSTALLED"),
                            65, 5, 5, 10, isdn_cards_description, &choice, gettext("TR_SELECT"), gettext("TR_GO_BACK"), NULL);

        if (rc == 2) {
            break;
        }
        else {
            /* TODO: verify that card is present. Modprobing does not seem to work as it does not always return an error. */

            sprintf(keyvalue, "%d", isdn_cards_type[choice]);
            update_kv(&isdn_kv, "TYPE", keyvalue);

            /* TODO: find places where this is used and try to get rid of it */
            update_kv(&isdn_kv, "ENABLED", "on");
            break;
        }
    }
}


static void changemsn(void)
{
    int rc;
    char msn[STRING_SIZE] = "";
    char *values[] = { msn, NULL };
    struct newtWinEntry entries[] = { {"", &values[0], 0,}, {NULL, NULL, 0} };

    find_kv_default(isdn_kv, "MSN", msn);

    for (;;)
    {
        rc = newtWinEntries(get_title(), gettext("TR_ENTER_THE_LOCAL_MSN"), 65, 5, 5, 40,
                            entries, gettext("TR_OK"), gettext("TR_GO_BACK"), NULL);

        if (rc == 1) {
            if (!(strlen(values[0]))) {
                errorbox(gettext("TR_PHONENUMBER_CANNOT_BE_EMPTY"));
            }
            else {
                update_kv(&isdn_kv, "MSN", values[0]);
                break;
            }
        }
        else {
            break;
        }
    }
}


int handleisdn(void)
{
    int rc;
    int choice;
    int c;
    int i;
    char *menuchoices[10];
    char message[STRING_SIZE_LARGE];
    char *tmpstring;
    char *protocolnames[] = {   gettext("TR_GERMAN_1TR6"),
                                gettext("TR_EURO_EDSS1"),
                                gettext("TR_LEASED_LINE"),
                                gettext("TR_US_NI1"),
                                NULL };

    menuchoices[0] = gettext("TR_PROTOCOL_COUNTRY");
    menuchoices[1] = gettext("TR_SET_ADDITIONAL_MODULE_PARAMETERS");
    menuchoices[2] = gettext("TR_ISDN_CARD");
    menuchoices[3] = gettext("TR_MSN_CONFIGURATION");

    menuchoices[4] = NULL;

    if (read_kv_from_file(&isdn_kv, "/var/ipcop/ethernet/isdn") != SUCCESS) {
        free_kv(&isdn_kv);
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }

    readisdncards();

    choice = 0;
    for (;;) {
        char protocolname[STRING_SIZE];
        char cardname[STRING_SIZE] = "";
        char msn[STRING_SIZE];
        char keyvalue[STRING_SIZE];

        strcpy(protocolname, gettext("TR_UNSET"));
        strcpy(keyvalue, "-1");
        if (find_kv_default(isdn_kv, "PROTOCOL", keyvalue) == SUCCESS) {
            i = (int) strtol(keyvalue, (char **) NULL, 10);
            if ((i >= 1) && (i <= 4)) {
                strcpy(protocolname, protocolnames[i-1]);
            }
        }

        strcpy(cardname, gettext("TR_UNSET"));
        strcpy(keyvalue, "-1");
        if (find_kv_default(isdn_kv, "TYPE", keyvalue) == SUCCESS) {
            i = (int) strtol(keyvalue, (char **) NULL, 10);
            if (i >= 1) {
                c = 0;
                while (isdn_cards_type[c]) {
                    if (isdn_cards_type[c] == i) {
                        strcpy(cardname, isdn_cards_description[c]);
                        break;
                    }
                    c++;
                }
            }
        }

        strcpy(msn, gettext("TR_UNSET"));
        find_kv_default(isdn_kv, "MSN", msn);

        /* workaround gcc warning */
        tmpstring = strdup(gettext("TR_ISDN_STATUS"));
        snprintf(message, STRING_SIZE_LARGE, tmpstring, "XX", protocolname, cardname, msn);
        free(tmpstring);

        rc = newtWinMenu(gettext("TR_ISDN_CONFIGURATION_MENU"), message, 65, 5, 5, 11,
                         menuchoices, &choice, gettext("TR_SELECT"), gettext("TR_OK"), gettext("TR_GO_BACK"), NULL);

        if (rc == 2) {
            /* Exit, with modifications */
            write_kv_to_file(&isdn_kv, "/var/ipcop/ethernet/isdn");
            break;
        }
        if (rc == 3) {
            /* Exit, no modifications */
            break;
        }

        switch(choice) {
        case 0:
            changeprotocol(protocolnames);
            break;
        case 1:
            changeparameters();
            break;
        case 2:
            changecard();
            break;
        case 3:
            changemsn();
            break;
        default:
            break;
        }
        choice++;
        if (menuchoices[choice] == NULL) {
            choice = 0;
        }
    }

    free_kv(&isdn_kv);

    return SUCCESS;
}
