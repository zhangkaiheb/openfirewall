/* 
 * keymap.c: set the keyboard
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
 * (c) 2007-2009, the IPCop team
 * 
 * $Id: keymap.c 3436 2009-08-14 09:14:53Z owes $
 * 
 */


#include <dirent.h>
#include <libintl.h>
#include <malloc.h>
#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common.h"
#include "common_newt.h"
#include "arch_defs.h"


#define MAX_FILENAMES 5000
#define KEYMAPROOT "/usr/share/kbd/keymaps/i386/"

static int filenamecount;
static char *filenames[MAX_FILENAMES];
static char *displaynames[MAX_FILENAMES];

static int process(char *prefix, char *path);
static int cmp(const void *s1, const void *s2);


static char keymap_setting[STRING_SIZE];

/*  Used by installer to update main/settings after all the files are inplace */ 
int write_keymap(void)
{
    NODEKV *kv = NULL;

    if (! keymap_setting[0]) {
        /* Keyboard was not set, so do not try to save the setting */
        return SUCCESS;
    }

    if (read_kv_from_file(&kv, "/harddisk/var/ipcop/main/settings") != SUCCESS) {
        free_kv(&kv);
        errorbox(ipcop_gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }

    update_kv(&kv, "KEYMAP", keymap_setting);
    write_kv_to_file(&kv, "/harddisk/var/ipcop/main/settings");
    free_kv(&kv);

    return SUCCESS;
}


/*
 * We can be called from 3 different places:
 *  - installer
 *  - setup called during installation (chroot'd)
 *  - 'normal' setup
*/
int handlekeymap(void)
{
    int c;
    int choice;
    char *temp;
    NODEKV *kv = NULL;
    int rc = 0;
    int result;
    char commandstring[STRING_SIZE];

    filenamecount = 0;

    process(KEYMAPROOT "azerty", "");
    process(KEYMAPROOT "dvorak", "");
    process(KEYMAPROOT "fgGIod", "");
    process(KEYMAPROOT "qwerty", "");
    process(KEYMAPROOT "qwertz", "");
    if (filenamecount == 0) {
        /* TODO: no keyboard files, could be floppy installer ? */
        return FAILURE;
    }
    filenames[filenamecount] = NULL;
    qsort(filenames, filenamecount, sizeof(char *), cmp);

    for (c = 0; filenames[c]; c++) {
        displaynames[c] = malloc(STRING_SIZE);
        if ((temp = strrchr(filenames[c], '/')) != NULL) {
            strcpy(displaynames[c], temp + 1);
        }
        else {
            strcpy(displaynames[c], filenames[c]);
        }
        if ((temp = strstr(displaynames[c], ".map.gz")) != NULL) {
            *temp = '\0';
        }
        else if ((temp = strstr(displaynames[c], ".kmap.gz")) != NULL) {
            *temp = '\0';
        }
    }
    displaynames[c] = NULL;

    strcpy(keymap_setting, KEYMAPROOT "qwerty/us.map.gz");
    if (flag_is_state != installer) {
        if (read_kv_from_file(&kv, "/var/ipcop/main/settings") != SUCCESS) {
            free_kv(&kv);
            errorbox(ipcop_gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
            return FAILURE;
        }

        if (flag_is_state == setupchroot) {
            if (find_kv(kv, "KEYMAP") != NULL) {
                /* Keymap already set */
                result = SUCCESS;
                goto KEYMAP_END;
            }
        }

        find_kv_default(kv, "KEYMAP", keymap_setting);
    }

    choice = 0;
    for (c = 0; filenames[c]; c++) {
        if (strcmp(keymap_setting, filenames[c]) == 0)
            choice = c;
    }

    /* In case of serial console we can skip this question, and simply use our default */
    if (! ((flag_is_state != setup) && (medium_console == serial))) {
        rc = newtWinMenu(ipcop_gettext("TR_KEYBOARD_MAPPING"), ipcop_gettext("TR_KEYBOARD_MAPPING_LONG"), 50, 5, 5, 6, displaynames,
                     &choice, ipcop_gettext("TR_OK"), (flag_is_state != setup) ? ipcop_gettext("TR_SKIP") : ipcop_gettext("TR_GO_BACK"), NULL);
    }
    strcpy(keymap_setting, filenames[choice]);

    if (rc != 2) {
        if (flag_is_state != installer) {
            update_kv(&kv, "KEYMAP", keymap_setting);
            write_kv_to_file(&kv, "/var/ipcop/main/settings");
        }
        snprintf(commandstring, STRING_SIZE, "/usr/bin/loadkeys %s", keymap_setting);
        mysystem(commandstring);
        result = SUCCESS;
    }
    else
        result = FAILURE;

KEYMAP_END:
    for (c = 0; filenames[c]; c++) {
        free(filenames[c]);
        free(displaynames[c]);
    }

    if (flag_is_state != installer) {
        free_kv(&kv);
    }

    return result;
}


/* OWES: this function needs review */
static int process(char *prefix, char *path)
{
    DIR *dir;
    struct dirent *de;
    char newpath[PATH_MAX];

    snprintf(newpath, PATH_MAX, "%s%s", prefix, path);

    if (!(dir = opendir(newpath))) {
        if (access(newpath, 0) == -1) {
            return FAILURE;
        }
        if (filenamecount > MAX_FILENAMES)
            return FAILURE;

        filenames[filenamecount] = (char *) strdup(newpath);
        filenamecount++;
        return SUCCESS;
    }

    while ((de = readdir(dir))) {
        if (de->d_name[0] == '.')
            continue;
        snprintf(newpath, PATH_MAX, "%s/%s", path, de->d_name);
        process(prefix, newpath);
    }
    closedir(dir);

    return FAILURE;
}


/* Small wrapper for use with qsort() to sort filename part. */
static int cmp(const void *s1, const void *s2)
{
    /* c1 and c2 are copies. */
    char *c1 = strdup(*(char **) s1);
    char *c2 = strdup(*(char **) s2);
    /* point to somewhere in cN. */
    char *f1, *f2;
    char *temp;
    int res;

    if ((temp = strrchr(c1, '/')))
        f1 = temp + 1;
    else
        f1 = c1;
    if ((temp = strrchr(c2, '/')))
        f2 = temp + 1;
    else
        f2 = c2;
    /* bang off the . */
    if ((temp = strchr(f1, '.')))
        *temp = '\0';
    if ((temp = strchr(f2, '.')))
        *temp = '\0';

    res = strcmp(f1, f2);

    free(c1);
    free(c2);

    return res;
}
