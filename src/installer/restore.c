/* 
 * restore.c: restore from some backup during installation
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
 * (c) 2008, the Openfirewall Team
 * 
 * $Id: restore.c 4963 2010-09-19 17:33:05Z owes $
 * 
 */


#include <dirent.h>
#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "common.h"
#include "common_backup.h"
#include "common_newt.h"
#include "arch_defs.h"


// tweak for errorbox
#define  gettext  ofw_gettext

#define TMP_RESTORE_PATH_FULL       "/harddisk/tmp/restore"
#define TMP_RESTORE_PATH_CHROOT     "/tmp/restore"
#define MOUNT_BACKUP_FULL           "/harddisk/mnt/usb"
#define MOUNT_BACKUP_CHROOT         "/mnt/usb"
#define DATFILE_FULL                "/harddisk/usr/local/apache/html/backup/openfirewall-xxxx-xx-xx_xx-xx-xx.dat"
#define DATFILE_CHROOT              "/usr/local/apache/html/backup/openfirewall-xxxx-xx-xx_xx-xx-xx.dat"

static char command[STRING_SIZE];
static char message[STRING_SIZE_LARGE];
/* these are module global, to make callback function work */
static newtComponent restoreform;
static newtComponent radiofloppy, radiousb, radionetwork;
static newtComponent entryurl, entryhostname, entrypassword;

static char hostname_filter[STRING_SIZE];

/* */
static int copy_change_files(void)
{
    if (access(TMP_RESTORE_PATH_FULL "/var/ofw/main/settings", 0)) {
        errorbox(ofw_gettext("TR_NO_MAIN_SETTINGS_IN_BACKUP"));
        return FAILURE;
    }

    if (testbackupversion(TMP_RESTORE_PATH_FULL) != SUCCESS) {
        errorbox(ofw_gettext("TR_NO_VALID_VERSION_IN_BACKUP"));
        return FAILURE;
    }

    mysystem("chroot /harddisk /bin/cp -af " TMP_RESTORE_PATH_CHROOT "/. /");

    /* TODO: here we will need to add mechanism for upgrade from 1.4.xx configuration files */
    mysystem("chroot /harddisk /usr/local/bin/upgrade.sh");

    return SUCCESS;
}


/* 
    Filter function for scanning mounted USB key
    Return 0 to skip a dir entry
*/
static int filter_dat(const struct dirent *d)
{
    if (strlen(d->d_name) != (strlen("-YYYY-MM-DD_HH-MM-SS.dat") + strlen(hostname_filter))) {
        return 0;
    }
    if (strncmp(d->d_name, hostname_filter, strlen(hostname_filter))) {
        return 0;
    }

    return 1;
}


/* Return SUCCESS when dev contains a backup key and backup dat file.
 * Leave dev mounted and copy backup dat file for use in chroot */
static int test_backup_key(char *dev, char *hostname)
{
    /* Test if device present */
    if (access(dev, 0)) {
        return FAILURE;                 /* no device */
    }

    mysystem("/bin/umount " MOUNT_BACKUP_FULL " 2>/dev/null");
    /* Mount device and verify result */
    snprintf(command, STRING_SIZE, "/bin/mount -t vfat -o ro %s " MOUNT_BACKUP_FULL, dev);
    if (mysystem(command)) {
        return FAILURE;                 /* no mountable dev */
    }

    /* Test backup .key */
    snprintf(command, STRING_SIZE, MOUNT_BACKUP_FULL "/backup.%s.key", hostname);
    if (access(command, 0)) {
        return FAILURE;                 /* no backup key on this dev */
    }
    /* Test backup .dat */
    snprintf(command, STRING_SIZE, MOUNT_BACKUP_FULL "/%s.dat", hostname);
    if (access(command, 0) == 0) {
        /* Copy the backup dat file to make it accessable and useable for ofwrestore */
        snprintf(command, STRING_SIZE, "cp -f " MOUNT_BACKUP_FULL "/%s.dat " DATFILE_FULL, hostname);
        mysystem(command);

        return SUCCESS;
    }

    /* 
        hostname.dat not found, are there any hostname-YYYY-MM-DD_HH-MM-SS.dat files?
        If yes, use the 'newest' .dat file.
    */
    struct dirent **eps;
    int n;

    strcpy(hostname_filter, hostname);
    n = scandir(MOUNT_BACKUP_FULL, &eps, filter_dat, alphasort);
    if (n > 0) {
        /* Copy the latest backup dat file to make it accessable and useable for ofwrestore */
        snprintf(command, STRING_SIZE, "cp -f " MOUNT_BACKUP_FULL "/%s " DATFILE_FULL, eps[n-1]->d_name);
        mysystem(command);

        return SUCCESS;
    }

    return FAILURE;                     /* no backup dat on this dev */
}


/* Try to mount usb device until backup.<hostname>.key is found */
static int mountusb(char *hostname)
{
    char sourcedev[30];
    int i, j;

    /* TODO: instead of scanning sda, sda1 ... sdz3, sdz4 it is probably better to look at /proc/partitions */
    for (i = 'a'; i <= 'z'; i++) {
        for (j = 0; j < 5; j++) {
            if (j) {
                sprintf(sourcedev, "/dev/sd%c%d", i, j);
            }
            else {
                sprintf(sourcedev, "/dev/sd%c", i);
            }
            if (test_backup_key(sourcedev, hostname) == SUCCESS) return SUCCESS;
        }
    }
    return FAILURE;
}


/* Try and grab from /dev/fd0 (1st floppy)
   USB floppy is /dev/sd[a-z], need some magic to walk through sd devices */
static int restorefromfloppy(void)
{
    char device[STRING_SIZE];
    struct stat st;
    int i;

    /* since we do not have floppy.ko, grab from already installed Openfirewall */
#if defined(__powerpc__) || defined(__powerpc64__)
    mysystem("chroot /harddisk /sbin/modprobe swim3");
#else
    mysystem("chroot /harddisk /sbin/modprobe floppy");
#endif
    /* give the device some time to settle */
    sleep(1);


    /* /dev/fd0 first */
    strcpy(device, "/dev/fd0");
    lstat(device, &st);
    if (S_ISBLK(st.st_mode)) {
        if (mysystem
            ("chroot /harddisk /bin/tar -X /var/ofw/backup/exclude.system -C " TMP_RESTORE_PATH_CHROOT
             " -xvzf /dev/fd0") == 0) {
            newtPopWindow();    // Pop status window

            return copy_change_files();
        }
    }

    /* Now USB floppy (needs work) */
    for (i = 'a'; i <= 'z'; i++) {
    }

    newtPopWindow();            // Pop status window
    errorbox(ofw_gettext("TR_UNABLE_TO_INSTALL_FILES"));
    return FAILURE;
}


/* */
static int restorefromusb(char *hostname, char *password)
{
    int rc;

    if (mountusb(hostname) == FAILURE) {
        newtPopWindow();
        errorbox(ofw_gettext("TR_NO_BACKUP_ON_USB_FOUND"));
        return FAILURE;
    }

    /*  device is mounted and contains .key and .dat 
        extract .key first */
    snprintf(command,  STRING_SIZE, "chroot /harddisk /usr/bin/openssl enc"
                        " -a -d -aes256 -salt"
                        " -pass pass:\"%s\""
                        " -in " MOUNT_BACKUP_CHROOT "/backup.%s.key"
                        " -out /var/ofw/backup/backup.key",
                        password, hostname);
    if (mysystem(command)) {
        newtPopWindow();
        errorbox(ofw_gettext("TR_WRONG_PASSWORD_OR_KEYFILE"));
        return FAILURE;
    }

    /* adjust mode */
    mysystem("chroot /harddisk /bin/chmod 400 /var/ofw/backup/backup.key");

    snprintf(command, STRING_SIZE, "chroot /harddisk /usr/local/bin/ofwrestore"
        " --restore=%s --hostname=openfirewall --hardware", DATFILE_CHROOT);
    if ((rc = mysystem(command)) != 0) {
        newtPopWindow();
        fprintf(flog, "ofwrestore returned errorcode: %d (%d)\n", (rc >> 8), rc);
        if (rc == (BACKUP_ERR_VERSION << 8)) {
            /* Special case, inform with some more detail */
            errorbox(ofw_gettext("TR_NO_VALID_VERSION_IN_BACKUP"));
        }
        else {
            errorbox(ofw_gettext("TR_UNABLE_TO_INSTALL_FILES"));
        }
        return FAILURE;
    }

    newtPopWindow();            // Pop status window
    return SUCCESS;
}


/* */
static int restorefromnetwork(char *url, char *hostname, char *password)
{
    int rc;

    snprintf(command, STRING_SIZE, "wget -O /harddisk/tmp/backup.key %s/backup.%s.key", url, hostname);
    if (mysystem(command)) {
        newtPopWindow();
        snprintf(command, STRING_SIZE, "%s/backup.%s.key", url, hostname);
        snprintf(message, STRING_SIZE, ofw_gettext("TR_FILE_NOT_FOUND"), command);
        errorbox(message);
        return FAILURE;
    }

    snprintf(command,  STRING_SIZE, "chroot /harddisk /usr/bin/openssl enc"
                        " -a -d -aes256 -salt"
                        " -pass pass:%s"
                        " -in /tmp/backup.key"
                        " -out /var/ofw/backup/backup.key",
                        password);
    if (mysystem(command)) {
        newtPopWindow();
        errorbox(ofw_gettext("TR_WRONG_PASSWORD_OR_KEYFILE"));
        return FAILURE;
    }

    /* adjust mode */
    mysystem("chroot /harddisk /bin/chmod 400 /var/ofw/backup/backup.key");

    snprintf(command, STRING_SIZE, "wget -O " DATFILE_FULL " %s/%s.dat", url, hostname);
    if (mysystem(command)) {
        newtPopWindow();
        snprintf(command, STRING_SIZE, "%s/%s.dat", url, hostname);
        snprintf(message, STRING_SIZE, ofw_gettext("TR_FILE_NOT_FOUND"), command);
        errorbox(message);
        return FAILURE;
    }

    snprintf(command, STRING_SIZE, "chroot /harddisk /usr/local/bin/ofwrestore"
        " --restore=%s --hostname=openfirewall --hardware", DATFILE_CHROOT);
    rc = mysystem(command);
    if (rc != 0) {
        unlink(DATFILE_FULL);
        newtPopWindow();
        fprintf(flog, "ofwrestore returned errorcode: %d (%d)\n", (rc >> 8), rc);
        if (rc == (BACKUP_ERR_VERSION << 8)) {
            /* Special case, inform with some more detail */
            errorbox(ofw_gettext("TR_NO_VALID_VERSION_IN_BACKUP"));
        }
        else {
            errorbox(ofw_gettext("TR_UNABLE_TO_INSTALL_FILES"));
        }
        
        return FAILURE;
    }

    newtPopWindow();            // Pop status window
    return SUCCESS;
}


/* Change disbabled hostname & password depending on radio selection */
static void restorecallback(newtComponent cm, void *data)
{
    newtComponent selected = newtRadioGetCurrent(radiofloppy);

    if (selected == radionetwork) {
        newtEntrySetFlags(entryurl, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
        newtEntrySetFlags(entryhostname, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
        newtEntrySetFlags(entrypassword, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
    }
    else if (selected == radiousb) {
        if (medium_sources == network) {
            newtEntrySetFlags(entryurl, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
        }
        newtEntrySetFlags(entryhostname, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
        newtEntrySetFlags(entrypassword, NEWT_FLAG_DISABLED, NEWT_FLAGS_RESET);
    }
    else {
        if (medium_sources == network) {
            newtEntrySetFlags(entryurl, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
        }
        newtEntrySetFlags(entryhostname, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
        newtEntrySetFlags(entrypassword, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
    }
    newtRefresh();
    newtDrawForm(restoreform);
}


/* Selection screen for source of backup */
int handlerestore(void)
{
    newtComponent text;
    newtComponent ok, skip;
    newtComponent labelurl, labelhostname, labelpassword;
    char urlinitvalue[STRING_SIZE];
    char hostnameinitvalue[STRING_SIZE];
    char passwordinitvalue[STRING_SIZE];
    char typevalue[32];
    const char *urlvalue;
    const char *hostnamevalue;
    const char *passwordvalue;
    struct newtExitStruct exitstruct;
    char message[STRING_SIZE_LARGE];
    int numLines;
    int httpLines;
    int error;
    int userskip;

    strcpy(hostnameinitvalue, "openfirewall.localdomain");
    strcpy(typevalue, "floppy");

    httpLines = 0;
    if (medium_sources == network) {
        /* Increase height this many lines if http/ftp restore is an option */
        httpLines = 2;
        strcpy(urlinitvalue, network_source);
    }

    do {
        snprintf(message, STRING_SIZE, ofw_gettext("TR_RESTORE_CONFIGURATION"), NAME);
        text = newtTextboxReflowed(1, 1, message, 68, 0, 0, 0);
        numLines = newtTextboxGetNumLines(text);

        newtCenteredWindow(72, 13 + numLines + httpLines, ofw_gettext("TR_RESTORE"));
        restoreform = newtForm(NULL, NULL, 0);
        newtFormAddComponent(restoreform, text);

        /* selections: floppy, usb */
        radiofloppy = newtRadiobutton(12, 2 + numLines, ofw_gettext("TR_FLOPPY"), !strcmp(typevalue, "floppy"), NULL);
        radiousb = newtRadiobutton(12, 3 + numLines, ofw_gettext("TR_USB_KEY"), !strcmp(typevalue, "usb"), radiofloppy);

        newtComponentAddCallback(radiofloppy, restorecallback, NULL);
        newtComponentAddCallback(radiousb, restorecallback, NULL);

        if (medium_sources == network) {
            radionetwork = newtRadiobutton(12, 4 + numLines, "http/ftp", !strcmp(typevalue, "http"), radiousb);
            newtComponentAddCallback(radionetwork, restorecallback, NULL);
            newtFormAddComponents(restoreform, radiofloppy, radiousb, radionetwork, NULL);

            labelurl = newtTextbox(2, 4 + numLines + httpLines, 35, 1, 0);
            newtTextboxSetText(labelurl, "URL");
            newtFormAddComponent(restoreform, labelurl);
            entryurl = newtEntry(25, 4 + numLines + httpLines, urlinitvalue, 35, &urlvalue, 0);
            newtFormAddComponent(restoreform, entryurl);
        }
        else {
            /* when not installing from network source, there is no active and usable network card */
            radionetwork = NULL;
            newtFormAddComponents(restoreform, radiofloppy, radiousb, NULL);
        }

        /* hostname for network restore */
        labelhostname = newtTextbox(2, 5 + numLines + httpLines, 35, 1, 0);
        newtTextboxSetText(labelhostname, ofw_gettext("TR_HOSTNAME"));
        newtFormAddComponent(restoreform, labelhostname);
        entryhostname = newtEntry(25, 5 + numLines + httpLines, hostnameinitvalue, 35, &hostnamevalue, 0);
        newtFormAddComponent(restoreform, entryhostname);
        /* password */
        labelpassword = newtTextbox(2, 6 + numLines + httpLines, 35, 1, 0);
        newtTextboxSetText(labelpassword, ofw_gettext("TR_BACKUP_PASSWORD"));
        newtFormAddComponent(restoreform, labelpassword);
        entrypassword = newtEntry(25, 6 + numLines + httpLines, "", 20, &passwordvalue, 0);
        newtEntrySetFlags(entrypassword, NEWT_FLAG_PASSWORD, NEWT_FLAGS_SET);
        newtFormAddComponent(restoreform, entrypassword);

        if (!strcmp(typevalue, "floppy")) {
            /* disabled for default selection */
            if (medium_sources == network) {
                newtEntrySetFlags(entryurl, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
            }
            newtEntrySetFlags(entryhostname, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
            newtEntrySetFlags(entrypassword, NEWT_FLAG_DISABLED, NEWT_FLAGS_SET);
        }

        ok = newtButton(6, 8 + numLines + httpLines, ofw_gettext("TR_OK"));
        skip = newtButton(26, 8 + numLines + httpLines, gettext("TR_SKIP"));
        newtFormAddComponents(restoreform, ok, skip, NULL);

        newtRefresh();
        newtDrawForm(restoreform);

        error = FAILURE;
        userskip = 0;
        newtFormRun(restoreform, &exitstruct);
        newtPopWindow();
        if (medium_sources == network) {
            strcpy(urlinitvalue, (char *)urlvalue);
        }
        strcpy(hostnameinitvalue, (char *)hostnamevalue);
        strcpy(passwordinitvalue, (char *)passwordvalue);
        newtFormDestroy(restoreform);

        if (exitstruct.u.co == skip) {
            userskip = 1;
        }

        if (exitstruct.u.co == ok) {
            newtComponent selected = newtRadioGetCurrent(radiofloppy);

            statuswindow(72, 5, ofw_gettext("TR_RESTORE"), ofw_gettext("TR_READING_BACKUP"));
            /* cleanout possible leftovers and (re)create temp path */
            mysystem("/bin/rm -rf " TMP_RESTORE_PATH_FULL);
            mkdir(TMP_RESTORE_PATH_FULL, S_IRWXU | S_IRWXG | S_IRWXO);
            mysystem("/bin/rm -rf " MOUNT_BACKUP_FULL);
            mkdir(MOUNT_BACKUP_FULL, S_IRWXU|S_IRWXG|S_IRWXO);

            if (selected == radiofloppy) {
                strcpy(typevalue, "floppy");
                error = restorefromfloppy();
            }
            else if (selected == radiousb) {
                strcpy(typevalue, "usb");
                if (!strcmp(passwordinitvalue, "")) {
                    /* password is mandatory to decrypt the key */
                    newtPopWindow();
                    errorbox(ofw_gettext("TR_PASSWORD_CANNOT_BE_BLANK"));
                    error = FAILURE;
                }
                else {
                    error = restorefromusb(hostnameinitvalue, passwordinitvalue);
                }
            }
            else {
                strcpy(typevalue, "http");
                if (!strcmp(passwordinitvalue, "")) {
                    /* password is mandatory to decrypt the key */
                    newtPopWindow();
                    errorbox(ofw_gettext("TR_PASSWORD_CANNOT_BE_BLANK"));
                    error = FAILURE;
                }
                else {
                    error = restorefromnetwork(urlinitvalue, hostnameinitvalue, passwordinitvalue);
                }
            }
        }
    }
    while ((error != SUCCESS) && (userskip == 0));

    return (error);
}
