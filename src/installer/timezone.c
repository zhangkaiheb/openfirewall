/* 
 * timezone.c: set timezone and current date/time
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
 * $Id: timezone.c 4410 2010-03-26 07:58:35Z owes $
 * 
 */


#include <dirent.h>
#include <libintl.h>
#include <malloc.h>
#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* for strptime */
#ifndef __USE_XOPEN
#define __USE_XOPEN
#endif
#include <time.h>
#include "common.h"
#include "common_newt.h"


#define MAX_FILENAMES 5000
#define ZONEFILES "/usr/share/zoneinfo/posix"

static int filenamecount;
static char *filenames[MAX_FILENAMES];
static char *displaynames[MAX_FILENAMES];

static int process(char *prefix, char *path);
static int cmp(const void *s1, const void *s2);

static char timezone_setting[STRING_SIZE];
static char command[STRING_SIZE];

/*  Used by installer to update main/settings after all the files are inplace */ 
int write_timezone(void)
{
    NODEKV *kv = NULL;

    if (read_kv_from_file(&kv, "/harddisk/var/ofw/main/settings") != SUCCESS) {
        free_kv(&kv);
        errorbox(ofw_gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }

    update_kv(&kv, "TIMEZONE", timezone_setting);
    write_kv_to_file(&kv, "/harddisk/var/ofw/main/settings");
    free_kv(&kv);

    snprintf(command, STRING_SIZE, "chroot /harddisk /bin/ln -f %s /etc/localtime", timezone_setting);
    mysystem(command);

    return SUCCESS;
}

/*  Can be called from installer (early) and from setup.
    In case of installer there is no /var/ofw so no settings etc. */
int handletimezone(void)
{
    int c;
    int choice;
    char *temp;
    NODEKV *kv = NULL;
    int rc;
    int result;

    filenamecount = 0;

    process(ZONEFILES, "");
    if (filenamecount == 0) {
        /* TODO: no zonefiles, could be floppy installer ? */
        return FAILURE;
    }
    filenames[filenamecount] = NULL;
    qsort(filenames, filenamecount, sizeof(char *), cmp);

    for (c = 0; filenames[c]; c++) {
        displaynames[c] = malloc(STRING_SIZE);
        if ((temp = strstr(filenames[c], ZONEFILES)))
            strcpy(displaynames[c], temp + strlen(ZONEFILES) + 1);
        else
            strcpy(displaynames[c], filenames[c]);
    }
    displaynames[c] = NULL;

    strcpy(timezone_setting, ZONEFILES "/CET");
    if (flag_is_state == INST_SETUP) {
        if (read_kv_from_file(&kv, "/var/ofw/main/settings") != SUCCESS) {
            free_kv(&kv);
            errorbox(ofw_gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
            return FAILURE;
        }

        find_kv_default(kv, "TIMEZONE", timezone_setting);
    }

    choice = 0;
    for (c = 0; filenames[c]; c++) {
        if (strcmp(timezone_setting, filenames[c]) == 0)
            choice = c;
    }

    rc = newtWinMenu(ofw_gettext("TR_TIMEZONE"), ofw_gettext("TR_TIMEZONE_LONG"), 50, 5, 5, 6, displaynames, &choice,
                     ofw_gettext("TR_OK"), (flag_is_state != INST_SETUP) ? ofw_gettext("TR_SKIP") : ofw_gettext("TR_GO_BACK"), NULL);

    strcpy(timezone_setting, filenames[choice]);

    if (rc != 2) {
        if (flag_is_state == INST_SETUP) {
            update_kv(&kv, "TIMEZONE", timezone_setting);
            write_kv_to_file(&kv, "/var/ofw/main/settings");

            snprintf(command, STRING_SIZE, "/usr/bin/logger -t openfirewall \"Timezone set to: %s\"", displaynames[choice]);
            mysystem(command);
        }
        unlink("/etc/localtime");
        if (link(timezone_setting, "/etc/localtime") == 0) {
            if (flag_is_state == INST_INSTALLER) {
                /* Set time from hw clock and configured timezone */
                mysystem("/sbin/hwclock --hctosys --utc");
            }
            result = SUCCESS;
        }
        else {
            result = FAILURE;
        }
    }
    else {
        result = FAILURE;
    }

    for (c = 0; filenames[c]; c++) {
        free(filenames[c]);
        free(displaynames[c]);
    }

    if (flag_is_state == INST_SETUP) {
        free_kv(&kv);
    }

    return result;
}


static int process(char *prefix, char *path)
{
    DIR *dir;
    struct dirent *de;
    char newpath[PATH_MAX];

    snprintf(newpath, PATH_MAX, "%s%s", prefix, path);

    if (!(dir = opendir(newpath))) {
        if (filenamecount > MAX_FILENAMES)
            return 1;

        filenames[filenamecount] = (char *) strdup(newpath);
        filenamecount++;
        return 0;
    }

    while ((de = readdir(dir))) {
        if (de->d_name[0] == '.')
            continue;
        snprintf(newpath, PATH_MAX, "%s/%s", path, de->d_name);
        process(prefix, newpath);
    }
    closedir(dir);

    return 1;
}


/* Small wrapper for use with qsort(). */
static int cmp(const void *s1, const void *s2)
{
    return (strcmp(*(char **) s1, *(char **) s2));
}


/* installer only, afterwards GUI and command line date can change date&time */
int handledatetime(void)
{
    int rc;
    char *values[] = { NULL, NULL, NULL };      /* pointers for the values. */
    struct newtWinEntry entries[] = {
        {ofw_gettext("TR_DATE"), &values[0], 0},
        {ofw_gettext("TR_TIME"), &values[1], 0},
        {NULL, NULL, 0}
    };
    char buffer[STRING_SIZE];
    time_t curtime;
    struct tm *loctime;

    while (1) {
        /* Get the current time. */
        curtime = time(NULL);
        /* Convert it to local time representation. */
        loctime = localtime(&curtime);

        strftime(buffer, STRING_SIZE, "%F", loctime);
        values[0] = strdup(buffer);
        strftime(buffer, STRING_SIZE, "%H:%M:%S", loctime);
        values[1] = strdup(buffer);

        snprintf(buffer, STRING_SIZE, "%s - %s", ofw_gettext("TR_DATE"), ofw_gettext("TR_TIME"));

        rc = newtWinEntries(buffer, ofw_gettext("TR_DATETIMELONG"),
                            68, 5, 5, 12, entries, ofw_gettext("TR_OK"), ofw_gettext("TR_SKIP"), NULL);

        if (rc == 1) {
            memset(loctime, '\0', sizeof(*loctime));

            /* Split user input into date */
            if ((strptime(values[0], "%F", loctime) == NULL) || (strptime(values[1], "%H:%M:%S", loctime) == NULL)) {
                errorbox(ofw_gettext("TR_ERROR_INVALID_TIME"));
            }
            else {
                /* Set the system clock */
                snprintf(command, STRING_SIZE, "/bin/date -s '%s %s'", values[0], values[1]);
                mysystem(command);

                /* Also store in hw clock (in UTC) */
                mysystem("/sbin/hwclock --systohc --utc");

                return SUCCESS;
            }
        }
        else {
            return SUCCESS;
        }
    }
}
