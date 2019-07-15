/* 
 * helper_backup.c: helper functions for backup/restore
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
 * (c) 2017-2020 the Openfirewall Team
 *
 */


#include <string.h>
#include <stdarg.h>
#include "common.h"
#include "common_backup.h"

/*
    Accept backups from older versions, unless the backup is very old with too many differences (< v1.9.9)
    Accept backups from newer versions, where only revision (last number) is different, v2.0.x will accept v2.0.y
*/
int helper_backup_test_version(char *path)
{
    unsigned int backupversion;
    unsigned int ofwversion;

    backupversion = helper_backup_get_version(path);
    if (backupversion == 0) {
        F_LOG("Backup version missing\n");
        return FAILURE;
    }
    ofwversion = helper_getofwversion();
    if (ofwversion == 0) {
        F_LOG("Openfirewall version missing\n");
        return FAILURE;
    }

    /* Do not accept really old backups (think alpha releases here) */
    if (backupversion < 0x010909) {
        F_LOG("Backup 0x%08X too old\n", backupversion);
        return FAILURE;
    }
    /* We know how to deal with old backups */
    if (ofwversion >= backupversion) {
        return SUCCESS;
    }
    /*  'Newer' backups are not a problem if version difference is only minor 
        i.e. backup is 2.0.x and Openfirewall version is 2.0.y         */
    if ((ofwversion & 0xFFFF00) == (backupversion & 0xFFFF00)) {
        return SUCCESS;
    }

    F_LOG("Backup: 0x%08X  >>  Openfirewall: 0x%08X\n", backupversion, ofwversion);
    return FAILURE;
}


unsigned int helper_backup_get_version(char *path)
{
    char filename[STRING_SIZE];
    FILE *f = NULL;
    unsigned int version = 0;
    unsigned int v_major, v_minor, v_revision;

    snprintf(filename, STRING_SIZE, "%s/var/ofw/backup/version", path);
    if ((f = fopen(filename, "r")) == NULL) {
        return 0;
    }

    if (fscanf(f, "%u.%u.%u", &v_major, &v_minor, &v_revision) != 3) {
        return 0;
    }

    if ((v_major > 255) || (v_minor > 255) || (v_revision > 255)) {
        return 0;
    }

    version = (v_major << 16) + (v_minor << 8) + v_revision;

    return version;
}
