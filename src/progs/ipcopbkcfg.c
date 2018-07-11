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
 * Copyright (C) 2003-06-25 Tim Butterfield <timbutterfield@mindspring.com>
 *
 * $Id: ipcopbkcfg.c 5130 2010-11-15 16:49:55Z owes $
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <grp.h>
#include <dirent.h>
#include <glob.h>
#include <time.h>
#include "common.h"
#include "common_backup.h"
#include "setuid.h"


#define EXCLUDE_HARDWARE "exclude.hardware"     // exclude file not used on backup but only optionally on restore
#define MOUNTPOINT "/home/httpd/html/backup"
#define BACKUP_KEY "/var/ipcop/backup/backup.key"
#define TMPLOGFILE "/tmp/logfile.XXXXXX"

char tempincfilename[STRING_SIZE] = "";     /* temp include file name */
char tempexcfilename[STRING_SIZE] = "";     /* temp exclude file name */
char temptarfile[STRING_SIZE] = "";
char temptgzfile[STRING_SIZE] = "";
char hostname[STRING_SIZE];
char timestamp[STRING_SIZE];
FILE *tagfile = NULL;           /* contain date and comment */


/* check whether a file exists */
int file_exists(const char *fname)
{
    int retval = 0;
    struct stat st;
    glob_t globbuf;


    /* do a quick check first */
    stat(fname, &st);
    if (S_ISREG(st.st_mode)) {
        retval = 1;
    }
    else {
        /* check for possible wild cards in name */
        if (glob(fname, GLOB_ERR, NULL, &globbuf) == 0) {
            if (globbuf.gl_pathc > 0) {
                retval = 1;
            }
        }
        globfree(&globbuf);
    }
    return retval;
}


/* add fname contents to outfile */
void add_file(int outfile, const char *fname, const int verbose)
{
    FILE *freadfile;
    char fbuff[STRING_SIZE];

    if (!(freadfile = fopen(fname, "r"))) {
        /* skip this file */
        return;
    }

    while (fgets(fbuff, STRING_SIZE, freadfile) != NULL) {
        int offset = 0;
        char *ch;
        char chk_space = 1;

        /* trim string in place - don't remove spaces in middle */
        ch = fbuff;
        while (*ch) {
            if (*ch == '\r' || *ch == '\n') {
                *ch = '\0';
            }

            if (offset) {
                *(ch - offset) = *ch;
            }

            if (*ch == '\t' || *ch == ' ') {
                if (chk_space) {
                    offset++;
                }
            }
            else {
                chk_space = 0;
            }

            ch++;
        }

        /* remove trailing spaces */
        ch = fbuff + strlen(fbuff) - 1;
        while (*ch) {
            if (*ch == '\t' || *ch == ' ') {
                *ch = '\0';
                --ch;
            }
            else {
                ch = fbuff + strlen(fbuff);
            }
        }

        /* validate name and add it */
        if (chdir("/")) {
            fprintf(stderr, "Couldn't chdir /\n");
            exit(BACKUP_ERR_ANY);
        }
        if (strlen(fbuff) > 0) {
            /* checking if a file exist ensure to have no error
             * on tar creation if a file is not present */
            if (file_exists(fbuff)) {
                strcat(fbuff, "\n");
                if (write(outfile, fbuff, strlen(fbuff)) != -1) {
                    if (verbose)
                        fprintf(stdout, " %s", fbuff);
                }
            }
        }
    }
    fclose(freadfile);
}


/* combine files starting with fnamebase into temp outfilename */
int cmb_files(char *outfilename, const char *outfname, const char *fnamebase, const int verbose)
{
    /* scan the directory and add matching files */
    struct dirent **namelist;
    int namecount;
    char dirname[STRING_SIZE];
    int outfile;
    char addfilename[STRING_SIZE];

    /* empty outfilename */
    outfilename[0] = '\0';

    /* scan the directory and get a count of the files */
    sprintf(dirname, "/var/ipcop/backup");
    namecount = scandir(dirname, &namelist, 0, alphasort);
    if (namecount < 0) {
        fprintf(stderr, "No files found\n");
        exit(1);
    }
    else {
        /* create/open temp output file */
        strcpy(outfilename, outfname);
        if (!(outfile = mkstemp(outfilename)) > 0) {
            fprintf(stderr, "Couldn't create temporary file.\n");
            exit(1);
        }

        /* process the scanned names */
        while (namecount--) {
            /* check names - compare beginning of name, ignoring case */
            if (strncasecmp(fnamebase, namelist[namecount]->d_name, strlen(fnamebase)) == 0) {
                /* hardware settings need not to be exclude on backup but optionally on restore */
                if (strncmp(namelist[namecount]->d_name, EXCLUDE_HARDWARE, strlen(EXCLUDE_HARDWARE))) {
                    /* add the contents for this name to output file */
                    sprintf(addfilename, "/var/ipcop/backup/%s", namelist[namecount]->d_name);
                    if (verbose)
                        fprintf(stdout, "%s\n", namelist[namecount]->d_name);
                    add_file(outfile, addfilename, verbose);
                    free(namelist[namecount]);
                    if (verbose)
                        fprintf(stdout, "\n");
                }
            }
        }
        close(outfile);
        free(namelist);
    }
    return 0;
}


/* Verify that backup password is ok */
int checkbackuppass(const char *passwd)
{
    struct passwd *pw;
    struct spwd *spwd;

    /* check backup user */
    if ((pw = getpwnam("backup")) == NULL) {
        fprintf(stderr, "User backup did not exist.\n");
        return (1);
    }

    /* get shadowed password */
    spwd = getspnam("backup");

    /* and use it in right place */
    if (spwd)
        pw->pw_passwd = spwd->sp_pwdp;
    /* encrypt cleartext, compare to encrypted version and return true or false */
    return (strcmp(crypt(passwd, pw->pw_passwd), pw->pw_passwd) == 0) ? 0 : 1;
}


/* Write tagfile date time and comment */
void writetagfile(const char *filename, const char *timestamp, const char *comment)
{
    if (!(tagfile = fopen(filename, "w"))) {
        perror("ipcopbkcfg : Unable to open tagfile\n");
        exit(BACKUP_ERR_ANY);
    }
    /* get exclusive lock to prevent a mess if 2 copies run at once */
    flock(fileno(tagfile), LOCK_EX);
    fprintf(tagfile, "%s %s\n", timestamp, comment);
    flock(fileno(tagfile), LOCK_UN);
    fclose(tagfile);
}


void exithandler(void)
{
    char command[STRING_SIZE];

    /* clean up temporary files */
    if (temptarfile[0])
        unlink(temptarfile);
    if (temptgzfile[0])
        unlink(temptgzfile);
    if (tempincfilename[0])
        unlink(tempincfilename);
    if (tempexcfilename[0])
        unlink(tempexcfilename);
    /* remove tagfile written for inclusion in backup */
    snprintf(command, STRING_SIZE - 1, "/var/ipcop/backup.dat.time");
    unlink(command);
}


static void usage()
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "ipcopbkcfg --keycat backup_password " TMPLOGFILE "\n");
    fprintf(stderr, "\tDisplay the key crypted with backup_password\n");
    fprintf(stderr, "\tif backup_password match\n");
    fprintf(stderr, "ipcopbkcfg --keyexist\n");
    fprintf(stderr, "\tTest if backup.key file exist\n");
    fprintf(stderr, "ipcopbkcfg --mount sda1\n");
    fprintf(stderr, "\tMount /dev/sda1 device\n");
    fprintf(stderr, "ipcopbkcfg --umount\n");
    fprintf(stderr, "\tUmount removable device mounted on " MOUNTPOINT "\n");
    fprintf(stderr, "ipcopbkcfg --write 'comment' [--verbose]\n");
    fprintf(stderr, "\tWrite backup to mounted device\n");
    fprintf(stderr, "\t'comment' include inside backup tagfile\n");
    fprintf(stderr, "\tverbose option add\n");
    fprintf(stderr, "\t\t display of (ex|in)clude files used\n");
    fprintf(stderr, "\t\t list of include files lists\n");
    exit(BACKUP_ERR_PARM);
}


int main(int argc, char *argv[])
{
    int verbose = 0;
    char command[STRING_SIZE];
    int temptarfilefd;

    if (!(initsetuid()))
        exit(1);

    if (argc < 2) {
        /* need a minima one parameter */
        usage();
    }
    else if (strcmp(argv[1], "--keycat") == 0) {
        /* Write to TMPLOGFILE the backup.key crypted */
        if (argc != 4) {
            fprintf(stderr, "Wrong syntax %d parameters received\n", argc);
            exit(BACKUP_ERR_ANY);
        }
        if (checkbackuppass(argv[2])) {
            fprintf(stderr, "Wrong backup password\n");
            exit(BACKUP_ERR_PASSWORD);
        }
        if (!file_exists(BACKUP_KEY)) {
            fprintf(stderr, "Can't read backup.key\n");
            exit(BACKUP_ERR_KEY);
        }
        /* tmpfile where it should be */
        if (!(strstr(argv[3], "/tmp/logfile.") && strlen(argv[3]) == strlen(TMPLOGFILE))) {
            fprintf(stderr, "Need " TMPLOGFILE "\n");
            exit(BACKUP_ERR_ANY);
        }
        if (!file_exists(argv[3])) {
            fprintf(stderr, "Missing " TMPLOGFILE "\n");
            exit(BACKUP_ERR_ANY);
        }
        snprintf(command, STRING_SIZE - 1,
                 "/usr/bin/openssl enc -a -e -aes256 -salt -pass pass:\"%s\""
                 " -in " BACKUP_KEY " -out %s", argv[2], argv[3]);
        if (safe_system(command)) {
            fprintf(stderr, "Couldn't encrypt key\n");
            exit(BACKUP_ERR_ENCRYPT);  //create other error message?
        }
        exit(0);
    }
    else if (argc == 2 && strcmp(argv[1], "--keyexist") == 0) {
        exit(!file_exists(BACKUP_KEY));
    }
    else if (argc == 3 && strcmp(argv[1], "--mount") == 0 &&
             strlen(argv[2]) > 2 && strlen(argv[2]) < 6 && strspn(argv[2], LETTERS_NUMBERS) == strlen(argv[2])) {
        /* check that device is not our main disk */
        char rootdev[50] = { 0 };
        int len = readlink("/dev/disk/by-label/root", rootdev, sizeof rootdev);
        if (len > 0) {
            // TODO: since the link is returned as ../../sda2 
            //  we need to test differently
            // QUESTION: do we need to test this at all?
            //remove partition number sda4=>sda
            rootdev[--len] = 0;
            //glue /dev/ to passed arg
            char dev[15] = "/dev/";
            strcat(dev, argv[2]);
            //if rootdev is in or equal to dev, stops
            if (!strncmp(rootdev, dev, len)) {
                fprintf(stderr, "Cannot mount or umount root disk !\n");
                exit(1);
            }
        }
        else {
            fprintf(stderr, "Cannot read by-label/root symlink !\n");
            exit(1);
        }
        snprintf(command, STRING_SIZE - 1, "/bin/mount -t vfat -o,uid=99,gid=99 /dev/%s " MOUNTPOINT, argv[2]);
        exit(safe_system(command));
    }
    else if (argc == 2 && strcmp(argv[1], "--umount") == 0) {
        snprintf(command, STRING_SIZE - 1, "/bin/umount " MOUNTPOINT " &>/dev/null");
        safe_system(command);
        //safe_system("/bin/sync");
        exit(0);
    }
    else if (!(argc > 2 && strcmp(argv[1], "--write") == 0)) {
        /* doing the reverse test minimize the diff
         * as the code after is not changed */
        fprintf(stderr, "Not enough parameters for --write !\n");
        exit(BACKUP_ERR_PARM);
    }

    /* check a valid comment */
    int len = 0;
    len = strlen(argv[2]);
    if (len > STRING_SIZE - 1) {
        fprintf(stderr, "%s : Comment too long !\n", argv[0]);
        exit(BACKUP_ERR_ANY);
    }
    if (strspn(argv[2], LETTERS_NUMBERS " '_-") != len) {
        fprintf(stderr, "%s : Invalid character in comment!\n", argv[0]);
        exit(BACKUP_ERR_ANY);
    }

    /* now exithandler will have something to do */
    atexit(exithandler);

    if (argc == 4) {
        /* add possible debug display to stdout */
        if (strcmp(argv[3], "--verbose") == 0) {
            verbose = 1;
        }
        else {
            fprintf(stderr, "%s : Unknow parameter for --write!\n", argv[0]);
            exit(1);
        }
    }

    gethostname(hostname, STRING_SIZE - 1);
    time_t curtime = time(NULL);
    strftime(timestamp, STRING_SIZE, "%Y-%m-%d_%H-%M-%S", gmtime(&curtime));

    if (!file_exists(BACKUP_KEY)) {
        fprintf(stderr, "Couldn't locate encryption key\n");
        exit(BACKUP_ERR_KEY);
    }

    /* combine every include and exclude files in backup directory
     * at the exception of exclude.hardware only used optionally on restore */
    cmb_files(tempincfilename, "/tmp/backup-inclusion.XXXXXX", "include.", verbose);
    cmb_files(tempexcfilename, "/tmp/backup-exclusion.XXXXXX", "exclude.", verbose);

    /* Include date and comment on tagfile inside the backup,
     * to be available on restore.
     * Timestamp is not include on file name for easier extraction */
    snprintf(command, STRING_SIZE - 1, "/var/ipcop/backup.dat.time");
    writetagfile(command, timestamp, argv[2]);

    /* Create temporary tarfile */
    strcpy(temptarfile, "/tmp/backup.tar.XXXXXX");
    if (!(temptarfilefd = mkstemp(temptarfile)) > 0) {
        fprintf(stderr, "Couldn't create temporary tar file.\n");
        exit(1);
    }
    close(temptarfilefd);

    /* Create temporary tgz file */
    strcpy(temptgzfile, "/tmp/backup.tgz.XXXXXX");
    if (!(temptarfilefd = mkstemp(temptgzfile)) > 0) {
        fprintf(stderr, "Couldn't create temporary tgz file.\n");
        exit(1);
    }
    close(temptarfilefd);

    /* Add a marker to indicate which version created this backup */
    if (system("echo `grep -m 1 '::version' /usr/lib/ipcop/general-functions.pl | cut -f 2 -d \"'\"` > /var/ipcop/backup/version")) {
        fprintf(stderr, "Error while writing version marker");
        exit(BACKUP_ERR_ANY);
    }

    /* Start tarring files to temp archive. Separate tar from gzip
     * W (verify) and z (compress) tar options can't be used together */
    snprintf(command, STRING_SIZE - 1,
             "/bin/tar -T %s -X %s -C / -cWf %s &>/dev/null", tempincfilename, tempexcfilename, temptarfile);
    if (safe_system(command)) {
        fprintf(stderr, "Couldn't create %s file\n", temptarfile);
        exit(BACKUP_ERR_TAR);
    }

    /* Compress archive */
    snprintf(command, STRING_SIZE - 1, "/bin/gzip -c < %s > %s", temptarfile, temptgzfile);
    if (safe_system(command)) {
        fprintf(stderr, "Couldn't compress %s file\n", temptgzfile);
        exit(BACKUP_ERR_GZ);
    }
    /* Save place on disk */
    unlink(temptarfile);

    /* Display to stdout include files names */
    if (verbose) {
        snprintf(command, STRING_SIZE - 1, "/bin/tar -ztf %s", temptgzfile);
        if (safe_system(command)) {
            fprintf(stderr, "Couldn't read %s file\n", temptgzfile);
            exit(BACKUP_ERR_GZ);
        }
    }

    /* Encrypt archive */
    snprintf(command, STRING_SIZE - 1,
             "/usr/bin/openssl des3 -e -salt -in %s "
             "-out " MOUNTPOINT "/%s-%s.dat " "-kfile " BACKUP_KEY, temptgzfile, hostname, timestamp);
    if (safe_system(command)) {
        fprintf(stderr, "Couldn't encrypt archive\n");
        exit(BACKUP_ERR_ENCRYPT);
    }

    /* Write tagfile for backup list */
    snprintf(command, STRING_SIZE - 1, MOUNTPOINT "/%s-%s.dat.time", hostname, timestamp);
    writetagfile(command, timestamp, argv[2]);

    /* Make sure web can overwrite */
    snprintf(command, STRING_SIZE - 1, MOUNTPOINT "/%s-%s.dat", hostname, timestamp);
    if (chown(command, 99, 99)) {
        fprintf(stderr, "Couldn't chown .dat file\n");
        exit(BACKUP_ERR_ANY);
    }
    snprintf(command, STRING_SIZE - 1, MOUNTPOINT "/%s-%s.dat.time", hostname, timestamp);
    if (chown(command, 99, 99)) {
        fprintf(stderr, "Couldn't chown .dat.time file\n");
        exit(BACKUP_ERR_ANY);
    }

    /* exithandler clean temp files */
    exit(0);
}
