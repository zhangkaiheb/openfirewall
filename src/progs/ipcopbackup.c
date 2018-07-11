/*
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
 * Copyright (C) 2002-06-02 Mark Wormgoor <mark@wormgoor.com>
 *
 * $Id: ipcopbackup.c 4410 2010-03-26 07:58:35Z owes $
 *
 */


#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include "setuid.h"

#define MAX_FLOPPY_SIZE 1474560 /* 80*18*2*512 with no files system */

char tempincfilename[STRING_SIZE] = "";     /* temp include file name */
char temptestfilename[STRING_SIZE] = "";
char tmpdir[STRING_SIZE] = "";
char command[STRING_SIZE];
struct stat st;


void exithandler(void)
{
    /* clean up temporary files */
    char command[STRING_SIZE];
    if (tempincfilename[0])
        unlink(tempincfilename);
    if (temptestfilename[0])
        unlink(temptestfilename);
    if (tmpdir[0]) {
        snprintf(command, STRING_SIZE - 1, "/bin/rm -rf %s > /dev/null 2> /dev/null", tmpdir);
        safe_system(command);
    }
}


/* Check for floppy disk in disk drive before continuing
 * Check for write protected floppy by writing to disk
 * Return 0 : success or 1 : no media or no device */
int testfloppywrite(char *device)
{
    /* Test if floppy dev exist as symlink to real dev before testing media
     * or dd could create a file with that floppy device name */
    lstat(device, &st);
    if (S_ISBLK(st.st_mode)) {
        /* symlink point to a real dev, so continue */
        /* dd does not work inside ipcopbackup detecting an absent
         * media on usb floppy but work with standard floppy
         * replacing it with a simple echo work for me 
         * (at least with my USB FDC GOLD-1.11 ) Gilles */
        snprintf(command, STRING_SIZE - 1, "/bin/echo 'test' 2>/dev/null >%s", device);
        return safe_system(command);    /* 1 failure */
    }
    else {
        return 1;
    }
}


int main(void)
{
    int count, systeminclude, userinclude, tempfile;
    char buffer[STRING_SIZE];
    struct statvfs statvfsbuf;
    double spaceavailable;
    char floppydev[13];         /* /dev/floppy or /dev/floppy1 */

    if (!(initsetuid()))
        exit(1);

    /* Error are directly displayed to the GUI, so include program name is useless */
    if (close(0)) {
        fprintf(stderr, "Couldn't close 0\n");
        exit(1);
    }
    if (open("/dev/zero", O_RDONLY) != 0) {
        fprintf(stderr, "Couldn't reopen stdin from /dev/zero\n");
        exit(1);
    }
    if (close(2)) {
        fprintf(stderr, "Couldn't close 2\n");
        exit(1);
    }
    if (!dup(1)) {
        fprintf(stderr, "Couldn't redirect stderr to stdout\n");
        exit(1);
    }

    /* now exithandler will have something to erase */
    atexit(exithandler);

    /* Check enought free space on / partition to create a backup for testing compressed size */
    if (statvfs("/", &statvfsbuf)) {
        fprintf(stderr, "Couldn't test available free space on root partition.\n");
        exit(1);
    }
    spaceavailable = statvfsbuf.f_frsize * statvfsbuf.f_bavail;
    if (spaceavailable < MAX_FLOPPY_SIZE) {
        fprintf(stderr, "You need to free space on disk. Available space is %4.0lf kB\n", spaceavailable / 1024);
        exit(1);
    }
    /* Open temporary file for copying the inclusion files */
    strcpy(tempincfilename, "/tmp/backup-inclusion.XXXXXX");
    if (!(tempfile = mkstemp(tempincfilename)) > 0) {
        fprintf(stderr, "Couldn't create temporary file.\n");
        exit(1);
    }

    /* Duplicate system include to temporary inclusion file */
    if (!(systeminclude = open("/var/ipcop/backup/include.system", O_RDONLY))) {
        fprintf(stderr, "Couldn't open backup system include file\n");
        exit(1);
    }

    while ((count = read(systeminclude, buffer, STRING_SIZE))) {
        if (write(tempfile, buffer, count) < 0) {
            fprintf(stderr, "temp file write failed for systeminclude\n");
            exit(1);
        }
    }
    close(systeminclude);

    /* Duplicate user include to temporary inclusion file */
    if (!(userinclude = open("/var/ipcop/backup/include.user", O_RDONLY))) {
        fprintf(stderr, "Couldn't open backup user include file\n");
        exit(1);
    }

    while ((count = read(userinclude, buffer, STRING_SIZE))) {
        if (write(tempfile, buffer, count) < 0) {
            fprintf(stderr, "temp file write failed for userinclude\n");
            exit(1);
        }
    }
    close(userinclude);
    close(tempfile);

    /* If a floppy controller is enabled on mainboard, it will appear as /dev/fd0
     * usb floppy appear as /dev/sd[a-z] */

    /* owes: this mechanism could do with some further testing */
#if defined(__powerpc__) || defined(__powerpc64__)
    safe_system("/sbin/modprobe swim3");
#else
    safe_system("/sbin/modprobe floppy");
#endif
    /* give the device some time to settle */
    sleep(1);

    /* Darren Critchley - check for floppy disk in disk drive before continuing */
    /* First try on /dev/fd0, if that fail, try on /dev/fd1 (anyone still has 1.2" as drive A: ?)
     * After that continue with sd[a-z] devices (USB floppy) */
    strcpy(floppydev, "/dev/fd0");
    if (testfloppywrite(floppydev)) {
        /* test the other */
        strcpy(floppydev, "/dev/fd1");
        if (testfloppywrite(floppydev)) {
            fprintf(stderr, "Error with bad, write protected or no media in floppy drive\n");
            exit(1);
        }
    }

    /* Test compressed files size less than maximum floppy size
     * Very basic, better than nothing, check only max size (1440 kB)
     * May read media capacity a day (fd0 or usb sda) */
    strcpy(temptestfilename, "/tmp/test.XXXXXX");
    if (!(tempfile = mkstemp(temptestfilename)) > 0) {
        fprintf(stderr, "Couldn't create temporary test file.\n");
        exit(1);
    }
    snprintf(command, STRING_SIZE - 1,
             "/bin/tar -T %s"
             " -X /var/ipcop/backup/exclude.system"
             " -X /var/ipcop/backup/exclude.user" " -C / -czf %s &>/dev/null", tempincfilename, temptestfilename);
    if (safe_system(command)) {
        fprintf(stderr, "Error : Couldn't create test file on harddisk, enough free space?\n");
        exit(1);
    }
    /* Check size of test backup */
    if (lstat(temptestfilename, &st)) {
        fprintf(stderr, "Unable to stat temptestfilename\n");
        exit(1);
    }
    if (st.st_size > MAX_FLOPPY_SIZE) {
        fprintf(stderr, "Backup is too big for floppy %ld > %d B\n", st.st_size, MAX_FLOPPY_SIZE);
        exit(1);
    }
    unlink(temptestfilename);

    /* Clearing disk */
    snprintf(command, STRING_SIZE - 1, "/bin/dd if=/dev/zero of=%s bs=1k 2> /dev/null", floppydev);
    safe_system(command);

    fprintf(stdout, "%s Backup size: %ld / %d B\n", floppydev, st.st_size, MAX_FLOPPY_SIZE);
    fflush(stdout);             /* ensure Backup size will be displayed first on GUI */

    /* Add a marker to indicate which version created this backup */
    if (system("echo `grep -m 1 '::version' /usr/lib/ipcop/general-functions.pl | cut -f 2 -d \"'\"` > /var/ipcop/backup/version")) {
        fprintf(stderr, "Error while writing version marker");
        exit(1);
    }

    /* Start tarring files to floppy */
    snprintf(command, STRING_SIZE - 1,
             "/bin/tar -T %s"
             " -X /var/ipcop/backup/exclude.system"
             " -X /var/ipcop/backup/exclude.user" " -C / -czf %s &>/dev/null", tempincfilename, floppydev);
    safe_system(command);

    unlink(tempincfilename);

    /* Now read the floppy to check it and display list of include files
     * Create temporary directory for testing untar */
    strcpy(tmpdir, "/tmp/cfg_XXXXXX");
    if (mkdtemp(tmpdir) == NULL) {
        exit(1);
    }

    /* Test untarring files from compressed archive */
    snprintf(command, STRING_SIZE - 1, "/bin/tar -C %s -xzvf %s", tmpdir, floppydev);
    if (safe_system(command)) {
        fprintf(stderr, "Error while verifying backup\n");
        exit(1);
    }

    exit(0);
}
