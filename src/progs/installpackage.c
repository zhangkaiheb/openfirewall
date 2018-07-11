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
 * along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2004-05-31 Robert Kerr <rkerr@go.to>
 *
 * Loosely based on the smoothwall helper program by the same name,
 * portions are (c) Lawrence Manning, 2001
 *
 * (c) 2008-2014, the IPCop team
 *
 * $Id: installpackage.c 7362 2014-03-23 15:08:38Z owes $
 * 
 */


#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include "common.h"
#include "setuid.h"


#define ERR_NO_ERROR            0
#define ERR_ANY                 1
#define ERR_TMPDIR              2
#define ERR_SIG                 3
#define ERR_TAR                 4
#define ERR_INFO                5
#define ERR_PACKLIST            6       // not used
#define ERR_INSTALLED           7       // not used, should be returned by setup
#define ERR_SETUP               9
#define ERR_MISSING_PREVIOUS    10      // not used
#define ERR_DISK                11

#define ERR_SUID                20      // identical error code to backup/restore


/* Supplement of available space on disk to be safe to untar on setup. */
#define MINIMUMSPACE 1500 * 1000

static char command[STRING_SIZE];
static char tmpdir[] = "/var/patches/install_XXXXXX";
static int tmpdir_created = 0;
static int ret;


static void ourexit(int err)
{
    if (tmpdir_created) {
        /* Cleanup tmpdir */
        if (chdir("/var/patches") != 0) {
            perror("Couldn't chdir to /var/patches");
        }
        snprintf(command, STRING_SIZE, "/bin/rm -rf %s", tmpdir);
        if(safe_system(command)) {
            perror("Couldn't remove temp dir");
        }
    }

    /* 
     * Log only in case of error, setup will do logging in case of success.
     * Errors might be duplicated, when the error is detected in setup.
     */
    if (err) {
        switch (err) {
        case ERR_TMPDIR:
            snprintf(command, STRING_SIZE, 
                "/usr/bin/logger -t installpackage \"ERROR (%d): Could not create directory.\"", err);
            break;
        case ERR_SIG:
            snprintf(command, STRING_SIZE, 
                "/usr/bin/logger -t installpackage \"ERROR (%d): This is not an authorised update.\"", err);
            break;
        case ERR_TAR:
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d): This is not a valid archive.\"", err);
            break;
        case ERR_INFO:
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d): Could not open update information file. The update file is corrupt.\"", err);
            break;
        case ERR_PACKLIST:
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d): Could not open installed updates file.\"", err);
            break;
        case ERR_INSTALLED:
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d): This update is already installed.\"", err);
            break;
        case ERR_SETUP:
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d): Setup script returned errorcode (%d).\"", err, ret);
            break;
        case ERR_MISSING_PREVIOUS:
            /* no text ? */
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d): ERR_MISSING_PREVIOUS.\"", err);
            break;
        case ERR_DISK:
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d): Not enough disk space.\"", err);
            break;
        case ERR_SUID:
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d): Could not initsetuid.\"", err);
            break;
        default:
            snprintf(command, STRING_SIZE,
                "/usr/bin/logger -t installpackage \"ERROR (%d)\"", err);
            break;
        }
        safe_system(command);

        /* Errorcode for updates.cgi GUI page */
        snprintf(command, STRING_SIZE, "echo %d > /var/patches/error", err);
        safe_system(command);
        snprintf(command, STRING_SIZE, "chown nobody.nobody /var/patches/error");
        safe_system(command);
    }
    exit(err);
}


static void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  --install=FILENAME    Decrypt FILENAME and install upgrade (only if valid)\n"); 
    printf("  --test=FILENAME       Decrypt FILENAME and test if valid upgrade\n"); 
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


void main(int argc, char *argv[])
{
    int flag_install = 0;
    int flag_test = 0;
    char *upgrade_filename = NULL;
    char signature_filename[STRING_SIZE];
    struct stat stbuf;
    struct statvfs statvfsbuf;
    double spaceavailable, rootspacerequired;

    static struct option long_options[] =
    {
        { "install", required_argument, 0, 'i' },
        { "test", required_argument, 0, 't' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        ourexit(ERR_SUID);

    while ((c = getopt_long(argc, argv, "i:t:v", long_options, &option_index)) != -1) {
        switch (c) {
        case 'i':              /* install upgrade */
            flag_install = 1;
            upgrade_filename = strdup(optarg);
            break;
        case 't':              /* test upgrade */
            flag_test = 1;
            upgrade_filename = strdup(optarg);
            break;
        case 'v':              /* verbose */
            flag_verbose++;
            break;
        case 'h':
            usage(argv[0], 0);
        default:
            fprintf(stderr, "unknown option\n");
            usage(argv[0], 1);
        }
    }

    if (!flag_install && !flag_test) {
        fprintf(stderr, "option missing\n");
        usage(argv[0], 1);
    }

    /* Some basic upgrade filename checks */
    if (strchr(upgrade_filename, '/') == NULL) {
        fprintf(stderr, "Incomplete filename %s\n", upgrade_filename);
        ourexit(ERR_ANY);
    }
    if (strstr(upgrade_filename, ".tgz.gpg") == NULL) {
        fprintf(stderr, "Not a compressed gpg file %s\n", upgrade_filename);
        ourexit(ERR_ANY);
    }
    snprintf(signature_filename, STRING_SIZE, "/var/patches/%s", strrchr(upgrade_filename, '/'));
    strcpy(strstr(signature_filename, ".tgz.gpg"), ".sig");

    /* Read size of the patch file */
    if (lstat(upgrade_filename, &stbuf)) {
        fprintf(stderr, "Unable to stat %s\n", upgrade_filename);
        ourexit(ERR_ANY);
    }
    fprintf(stdout, "Update size is %ld KiB\n", stbuf.st_size / 1024);
    rootspacerequired = 2 * stbuf.st_size + MINIMUMSPACE;
    fprintf(stdout,"Required space on rootfs for normal tar zxf is %4.0lf KiB\n", rootspacerequired / 1024 );

    /* Check space available on disk to decrypt the gpg file */
    if (statvfs("/var/patches", &statvfsbuf)) {
        fprintf(stderr, "Couldn't test available space on rootfs partition.\n");
        ourexit(ERR_ANY);
    }
    spaceavailable = statvfsbuf.f_frsize * statvfsbuf.f_bavail;
    fprintf(stdout,"Available space on rootfs is %4.0lf KiB\n", spaceavailable / 1024 );

    if (rootspacerequired > spaceavailable) {
        /* TODO: any way to get more space? */
        fprintf(stderr,
            "You need to free space on rootfs partition for update.\n"
            "Available space is %4.0lf KiB, "
            "required space on rootfs is %4.0lf KiB\n"
            "As disk buffers are smaller on boot, rebooting may help\n",
            spaceavailable / 1024 ,
            rootspacerequired / 1024);
        ourexit(ERR_DISK);
    }

    /* Process is :
       - gpg file is on /var/patches at start
       - file is decrypted to patch-1.tgz.gz inside a tmp dir ( on /var/patches )
       - file is untarred inside tmp dir to patch.tar.gz, information.xml and setup
       - space required on rootfs to untar patch.tar.gz is between
         patch.tar.gz size to patch.tar size. */

    if (!mkdtemp(tmpdir)) {
        perror("Unable to create secure temp dir");
        ourexit(ERR_TMPDIR);
    }
    tmpdir_created = 1;

    /* Verify and extract package */
    snprintf(command, STRING_SIZE,
        "/usr/bin/gpg --batch --logger-fd 1 --homedir /root/.gnupg "
        "-o %s/patch-1.tgz --decrypt %s >%s/signature",
        tmpdir, upgrade_filename, tmpdir);
    ret = safe_system(command) >> 8;
    switch (ret) {
    case 0:         /* no error */
        break;
    case 1:         /* 1=> gpg-key error */
        fprintf(stderr, "Invalid package: signature check failed\n");
        ourexit(ERR_SIG);
    case 2:         /* 2=> gpg pub key not found */
        fprintf(stderr, "Public signature not found (who signed package?) !\n");
        ourexit(ERR_SIG);
    default:
        fprintf(stderr, "gpg returned: %d\n", ret);
        ourexit(ERR_SIG);
    }

    /* prepare signature for display, take only the 2 first lines */
    snprintf(command, STRING_SIZE, "/bin/grep '^gpg' -m 2 %s/signature >%s", tmpdir, signature_filename);
    safe_system(command);
    snprintf(command, STRING_SIZE, "/bin/chown nobody.nobody %s", signature_filename);
    safe_system(command);

    /* fetch information, needed for allowing offline updates */
    snprintf(command, STRING_SIZE, "/bin/tar xzf %s/patch-1.tgz -C /var/patches information.xml", tmpdir);
    if (safe_system(command)) {
        fprintf(stderr, "Invalid package: contains no information file\n");
        ourexit(ERR_INFO);
    }

    if (flag_test) {
        /* update list of available patches */
        snprintf(command, STRING_SIZE,
            "/usr/bin/perl -e \"require '/usr/lib/ipcop/general-functions.pl'; &General::updateavailablepatches('/var/patches/information.xml');\"");
        safe_system(command);

        /* exithandler will do the cleaning */
        ourexit(ERR_NO_ERROR);
    }

    /*
     *  Starting here we are installing the package.
    */

    /* gpg signed package and .sig file are no more needed, free that space */
    unlink(upgrade_filename);
    unlink(signature_filename);
    sync();

    if (chdir (tmpdir)) {
        perror("Unable to chdir to temp dir");
        ourexit(ERR_TMPDIR);
    }
    /* unzip the package */
    snprintf(command, STRING_SIZE, "/bin/tar xzf %s/patch-1.tgz", tmpdir);
    if (safe_system(command)) {
        fprintf(stderr, "Invalid package: untar failed\n");
        ourexit(ERR_TAR);
    }

    /* patch-1 is no more needed, free that space */
    snprintf(command, STRING_SIZE, "%s/patch-1.tgz", tmpdir);
    unlink(command);
    sync();

    /* install package */
    snprintf(command, STRING_SIZE, "%s/setup", tmpdir);
    ret = safe_system(command)>>8;
    if (ret) {
        fprintf(stderr, "setup script returned exit code %d\n", ret);
        ourexit(ERR_SETUP);
    }

    /* update list of installed patches */
    snprintf(command, STRING_SIZE,
        "/usr/bin/perl -e \"require '/usr/lib/ipcop/general-functions.pl'; &General::updateinstalledpatches('%s/information.xml');\"", 
        tmpdir);
    safe_system(command);

    ourexit(0);
}
