/*
 * common_backup.h: Global defines, function definitions for backup/restore
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
 * (c) 2010, the IPCop team
 *
 * $Id: common_backup.h 5049 2010-10-21 07:39:19Z owes $
 *
 */

#ifndef __COMMON_BACKUP_H
#define __COMMON_BACKUP_H


/* defines for backup/restore return status*/
#define BACKUP_ERR_ANY      1           // unspecified error
#define BACKUP_ERR_KEY      2           // error creating key file
#define BACKUP_ERR_TAR      3           // error creating .tar
#define BACKUP_ERR_GZ       4           // error creating .tar.gz
#define BACKUP_ERR_ENCRYPT  5           // error creating .dat
#define BACKUP_ERR_DECRYPT  6           // error decrypting .dat file
#define BACKUP_ERR_UNTARTST 7           // error (test) untarring .tar.gz
#define BACKUP_ERR_UNTAR    8           // error (real) untarring .tar.gz
#define BACKUP_ERR_DAT      9           // missing .dat file
#define BACKUP_ERR_PASSWORD 10          // wrong backup password
#define BACKUP_ERR_VERSION  11          // no version or invalid version in backup

#define BACKUP_ERR_SUID     20          // cannot initsuid
#define BACKUP_ERR_SYNTAX   21          // bad syntax
#define BACKUP_ERR_PARM     22          // parameter error, check usage
#define BACKUP_ERR_FILENAME 23          // bad filename
#define BACKUP_ERR_PATHNAME 24          // no path


/* Test backup version from versionfile.
    path can be empty string or rootdir holding extracted backup archive.
    FAILURE if version file missing or version to old.  */
int testbackupversion(char *path);


/* Get backup version from versionfile.
    path can be empty string or rootdir holding extracted backup archive.
    0 if version file missing or version invalid.
    (a << 16) + (b << 8) + c for version a.b.c          */
unsigned int getbackupversion(char *path);

#endif
