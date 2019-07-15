/* 
 * setup.c: setup main loop
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
 * along with Openfirewall.  If not, see <http://www.gnu.org/licenses/>.
 *
 * (c) 2017-2020, the Openfirewall Team
 *
 */


#include <errno.h>
#include <libintl.h>
#include <newt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <locale.h>

#include "common.h"
#include "common_newt.h"
#include "arch_defs.h"


NODEKV *kv = NULL;              // contains a list key=value pairs
installer_setup_t flag_is_state = INST_SETUP;
int medium_console = MT_CONSOLE;
char selected_locale[STRING_SIZE];

int inst_get_medium_console(void)
{
	return medium_console;
}

char *lang_gettext(char *txt)
{
    return gettext(txt);
}


int main(int argc, char **argv)
{
    int i;
    int rc;
    int choice;
    char *menuchoices[10];
    char filename[STRING_SIZE];

    /* check cmd line */
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--install"))
            flag_is_state = INST_SETUPCHROOT;
        if (!strcmp(argv[i], "--serial"))
            medium_console = MT_SERIAL;
    }

    if (medium_console == MT_SERIAL) {
        flog = fopen("/tmp/flog", "w");
        fstderr = freopen("/tmp/fstderr", "w", stderr);
    }
    else if (flag_is_state == INST_SETUPCHROOT) {
        if (!(flog = fopen("/dev/tty2", "w+"))) {
            printf("Failed to open /dev/tty2 for logging\n");
            exit(0);
        }

        fstderr = freopen("/dev/tty3", "w+", stderr);
    }
    else {
        // owes: flog is helpful for hw detection, may need to change to something other than tty5 one day
        if (!(flog = fopen("/dev/tty5", "w+"))) {
            printf("Failed to open /dev/tty5 for logging\n");
            exit(0);
        }

        fstderr = freopen("/dev/tty6", "w+", stderr);
    }

    helper_kernel_init();

    newtInit();
    newtCls();

    /* Have to get proper locale here */
    read_kv_from_file(&kv, "/var/ofw/main/settings");
    strcpy(selected_locale, "en_GB");
    find_kv_default(kv, "LOCALE", selected_locale);

    /* Test if .mo exists */
    snprintf(filename, STRING_SIZE, "/usr/share/locale/%s/LC_MESSAGES/install.mo", selected_locale);
    if (access(filename, 0) == -1) {
        /* Translation does not exist, revert to English */
        strcpy(selected_locale, "en_GB");
    }
    
    /* We store locale as en_GB not as en_GB.utf8 in settings 
       append .utf8 to make setlocale happy.
     */
    strcat(selected_locale, ".utf8");

    bindtextdomain("install", "/usr/share/locale");
    textdomain("install");
    setlocale(LC_ALL, selected_locale);

    menuchoices[0] = gettext("TR_KEYBOARD_MAPPING");
    menuchoices[1] = gettext("TR_TIMEZONE");
    menuchoices[2] = gettext("TR_HOSTNAME");
    menuchoices[3] = gettext("TR_DOMAINNAME");
    menuchoices[4] = gettext("TR_NETWORKING");
    menuchoices[5] = gettext("TR_PASSWORDS");
    menuchoices[6] = NULL;

    newtDrawRootText(18, 0, helper_get_title());
    newtPushHelpLine(gettext("TR_HELPLINE"));

    if (flag_is_state == INST_SETUPCHROOT) {
        /* all settings in a row, no main menu */
        handle_keymap();
        handle_hostname();
        handle_domainname();
        handle_networking();
        pwd_set_password("root");
        pwd_set_password("admin");
        pwd_set_password("backup");
        /* The dial user is fully optional and will created after the password is set through the GUI or setup */
    }
    else {
        choice = 0;
        for (;;) {
            rc = newtWinMenu(gettext("TR_SECTION_MENU"),
                             gettext("TR_SELECT_THE_ITEM"), 50, 5, 5, 11,
                             menuchoices, &choice, gettext("TR_SELECT"), gettext("TR_EXIT"), NULL);
            if (rc == 2)
                break;

            switch (choice) {
            case 0:
                handle_keymap();
                break;
            case 1:
                handle_timezone();
                break;
            case 2:
                handle_hostname();
                break;
            case 3:
                handle_domainname();
                break;
            case 4:
                handle_networking();
                break;
            case 5:
                handle_passwords();
                break;

            default:
                break;
            }
        }
    }
    newtFinished();

    fclose(flog);
    fclose(fstderr);
    exit(0);
}
