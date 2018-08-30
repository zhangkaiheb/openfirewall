/*
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
 * Copyright (C) 2003-06-25 Tim Butterfield <timbutterfield@mindspring.com>
 *
 * $Id: ofwrestore.c 7797 2015-01-08 08:45:27Z owes $
 *
 */


#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include "common.h"
#include "common_backup.h"
#include "setuid.h"


#define MOUNTPOINT "/usr/local/apache/html/backup"
#define BACKUP_KEY "/var/ofw/backup/backup.key"


static int flag_hardware = 0;
static int flag_hostname = 0;
static int flag_import = 0;
static int flag_restore = 0;
static char hostname[STRING_SIZE];
static char tmpdir[STRING_SIZE];
static char tmpdatefile[STRING_SIZE];  /* where date is written */


/* Write tagfile date time without comment */
void writetagfile(const char *filename, const char *timestamp)
{
    FILE *fd;

    if (!(fd = fopen(filename, "w"))) {
        perror("ofwrscfg : Unable to open tagfile\n");
        exit(BACKUP_ERR_ANY);
    }
    /* get exclusive lock to prevent a mess if 2 copies run at once */
    flock(fileno(fd), LOCK_EX);
    fprintf(fd, "%s \n", timestamp);
    flock(fileno(fd), LOCK_UN);
    fclose(fd);
}


void exithandler(void)
{
    char command[STRING_SIZE];

    /* clean up temporary files and directory */
    snprintf(command, STRING_SIZE - 1, "/tmp/%s.tar.gz", hostname);
    unlink(command);
    if (tmpdir[0]) {
        snprintf(command, STRING_SIZE - 1, "/bin/rm -rf %s &>/dev/null", tmpdir);
        safe_system(command);
    }
    if (tmpdatefile[0])
        unlink(tmpdatefile);
    /* remove just uploaded file */
    snprintf(command, STRING_SIZE - 1, MOUNTPOINT "/%s.dat", hostname);
    unlink(command);
    snprintf(command, STRING_SIZE - 1, "/tmp/%s.tar", hostname);
    unlink(command);
}


void usage(char *prg, int exit_code)
{
    fprintf(stderr, "Usage: %s [OPTION]\n\n", prg);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --import              rename <hostname>.dat to <hostname>.YYYY-MM-DD_HH-MM-SS.dat\n");
    fprintf(stderr, "  --restore=<file.dat>  restore from <file.dat> backup\n");
    fprintf(stderr, "  --hardware            restore hardware settings\n");
    fprintf(stderr, "  --hostname            force host.domain\n");
    fprintf(stderr, "  -v, --verbose         be verbose\n");
    fprintf(stderr, "  --help                display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char *argv[])
{
    int tempfd;
    char command[STRING_SIZE];
    char filename[STRING_SIZE];
    char buffer[STRING_SIZE];
    char *timestamp = NULL;
    FILE *fd;
    NODEKV *kv_old = NULL;
    NODEKV *kv_new = NULL;
    char port_gui[STRING_SIZE];
    char port_ssh[STRING_SIZE];

    static struct option long_options[] =
    {
        { "hardware", no_argument, &flag_hardware, 1 },
        { "hostname", required_argument, &flag_hostname, 1 },
        { "import", no_argument, &flag_import, 1 },
        { "restore", required_argument, &flag_restore, 1},
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;
    char *opt_filename = NULL;

    while ((c = getopt_long(argc, argv, "r:v", long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            if (!strcmp("hostname", long_options[option_index].name)) {
                strcpy(hostname, optarg);
            }
            else if (!strcmp("restore", long_options[option_index].name)) {
                opt_filename = strdup(optarg);
            }
            break;
        case 'v':       /* verbose */
            flag_verbose++;
            break;
        case 'h':
            usage(argv[0], 0);
        default:
            fprintf(stderr, "unknown option\n");
            usage(argv[0], BACKUP_ERR_PARM);
        }
    }

    if (!flag_import && !flag_restore) {
        /* need at least one of import or restore */
        usage(argv[0], 1);
    }

    /* Init setuid */
    if (!(initsetuid()))
        exit(BACKUP_ERR_SUID);

    if (!flag_hostname) {
        gethostname(hostname, STRING_SIZE - 1);
    }

    if (flag_restore) {
        /* check filename valid, full file name length */
        if (strlen(opt_filename) != (strlen(MOUNTPOINT "/-YYYY-MM-DD_HH-MM-SS.dat")+ strlen(hostname))) {
            fprintf(stderr, "ofwrscfg : bad file name\n");
            fprintf(stderr, "%s\n", hostname);
            fprintf(stderr, "%s\n", opt_filename);
            exit(BACKUP_ERR_FILENAME);
        }
        /* file in the path */
        if (!strstr(opt_filename, MOUNTPOINT)) {
            fprintf(stderr, "ofwrscfg : wrong path\n");
            exit(BACKUP_ERR_PATHNAME);
        }
        /* and exist */
        if (access(opt_filename, F_OK) == -1) {
            fprintf(stderr, "Missing backup\n");
            exit(BACKUP_ERR_DAT);
        }
        strcpy(filename, opt_filename);
    }
    else {
        snprintf(filename, STRING_SIZE - 1, MOUNTPOINT "/%s.dat", hostname);
    }

    /* key file and encrypted .dat are required */
    if (access(BACKUP_KEY, F_OK) == -1) {
        fprintf(stderr, "Missing encryption key\n");
        exit(BACKUP_ERR_DECRYPT);
    }

    /* now exithandler will have something to do */
    atexit(exithandler);

    /* decrypt .dat file to /tmp/hostname.tar.gz */
    snprintf(command, STRING_SIZE - 1,
             "/usr/bin/openssl des3 -d -salt "
             "-in %s " "-out /tmp/%s.tar.gz " "-kfile " BACKUP_KEY "> /dev/null 2> /dev/null", filename, hostname);
    if (safe_system(command)) {
        fprintf(stderr, "Couldn't decrypt %s.dat archive\n", hostname);
        exit(BACKUP_ERR_DECRYPT);
    }

    /* create temporary directory for testing untar */
    strcpy(tmpdir, "/tmp/cfg_XXXXXX");
    if (mkdtemp(tmpdir) == NULL) {
        exit(BACKUP_ERR_ANY);
    }

    /* Start (test) untarring files from compressed archive */
    snprintf(command, STRING_SIZE - 1, "/bin/tar -C %s -xzvf /tmp/%s.tar.gz > /dev/null 2> /dev/null", tmpdir,
             hostname);
    if (safe_system(command)) {
        fprintf(stderr, "Invalid archive\n");
        exit(BACKUP_ERR_UNTARTST);
    }

    /* Backup version OK ? */
    if (testbackupversion(tmpdir) != SUCCESS) {
        fprintf(stderr, "No version or invalid version in archive\n");
        exit(BACKUP_ERR_VERSION);
    }


    /* If in import mode, read tagfile if include
     * or parse backup to read newest file time change */
    if (flag_import) {
        snprintf(filename, STRING_SIZE - 1, "%s/var/ofw/backup.dat.time", tmpdir);
        if (access(filename, F_OK) == -1) {
            /* without tagfile include */
            strcpy(tmpdatefile, "/tmp/date.XXXXXX");
            if (!(tempfd = mkstemp(tmpdatefile)) > 0) {
                fprintf(stderr, "Couldn't create temporary file.\n");
                exit(BACKUP_ERR_ANY);
            }
            /* Parse all files of a backup 
             * to read last modification date.
             * The most recent date is written on tmp file */
            snprintf(command, STRING_SIZE - 1,
                     "/usr/bin/find %s -type f -exec "
                     "/bin/ls --time-style=+%%Y-%%m-%%d_%%H-%%M-%%S -l {} \\; | "
                     "/usr/bin/awk '{print $6}' | " "/usr/bin/sort -rn | /bin/head -n 1 >%s", tmpdir, tmpdatefile);
            if (safe_system(command)) {
                fprintf(stderr, "Couldn't write tmpdatefile\n");
                exit(BACKUP_ERR_ANY);
            }
            /* read the date */
            if (!(fd = fopen(tmpdatefile, "r"))) {
                perror("ofwrscfg : Failed opening file tagfile");
                exit(BACKUP_ERR_ANY);
            }
            if (fgets(buffer, STRING_SIZE, fd)) {
                if (buffer[strlen(buffer) - 1] == '\n')
                    buffer[strlen(buffer) - 1] = '\0';
            }
            fclose(fd);
            timestamp = strtok(buffer, " ");
            /* Write tagfile for backup */
            snprintf(filename, STRING_SIZE - 1, MOUNTPOINT "/%s-%s.dat.time", hostname, timestamp);
            writetagfile(filename, timestamp);
        }
        else {
            /* date is available to be read directly */
            if (!(fd = fopen(filename, "r"))) {
                perror("ofwrscfg : Failed opening file tagfile");
                exit(BACKUP_ERR_ANY);
            }
            if (fgets(buffer, STRING_SIZE, fd)) {
                timestamp = strtok(buffer, " ");
            }
            fclose(fd);

            /* Moving from ext3 to FAT system, system warn not
             * able to preserve ownership, change before */
            if (chown(filename, 99, 99)) {
                fprintf(stderr, "Couldn't chown .dat.time file\n");
                exit(BACKUP_ERR_ANY);
            }
            snprintf(command, STRING_SIZE - 1,
                     "/bin/mv %s " MOUNTPOINT "/%s-%s.dat.time", filename, hostname, timestamp);
            if (safe_system(command)) {
                perror("Failed to copy tagfile");
                exit(BACKUP_ERR_ANY);
            }
        }
        /* backup is valid, move to a name with date */
        snprintf(filename, STRING_SIZE - 1, MOUNTPOINT "/%s.dat", hostname);
        snprintf(command, STRING_SIZE - 1, "/bin/mv %s " MOUNTPOINT "/%s-%s.dat", filename, hostname, timestamp);
        if (safe_system(command)) {
            perror("Failed to copy backup");
            exit(BACKUP_ERR_ANY);
        }
        exit(0);
    }

    /* uncompress archive */
    snprintf(command, STRING_SIZE - 1, "/bin/gunzip -d -f /tmp/%s.tar.gz", hostname);
    safe_system(command);

    /* remove hardware specific settings */
    if (flag_hardware == 0) {
        snprintf(command, STRING_SIZE - 1,
                 "/bin/tar --delete --file=/tmp/%s.tar -T /var/ofw/backup/exclude.hardware", hostname);
        safe_system(command);
    }

    /* get current ports for GUI and ssh */
    if (read_kv_from_file(&kv_old, "/var/ofw/main/settings") == SUCCESS) {
        if (find_kv_default(kv_old, "GUIPORT", port_gui) != SUCCESS) {
            strcpy(port_gui, "8443");
        }
        if (find_kv_default(kv_old, "SSHPORT", port_ssh) != SUCCESS) {
            strcpy(port_ssh, "8022");
        }

        free_kv(&kv_old);
    }

    /* Start (real) untarring files from compressed archive */
    snprintf(command, STRING_SIZE - 1,
             "/bin/tar -X /var/ofw/backup/exclude.system -C / -xvf /tmp/%s.tar &>/dev/null", hostname);
    if (safe_system(command)) {
        fprintf(stderr, "Error restoring archive\n");
        exit(BACKUP_ERR_UNTAR);
    }
    else {
        /* TODO: here we will need to add mechanism for upgrade from 1.4.xx configuration files */

        /* get new ports for GUI and ssh and check for modifications */
        if (read_kv_from_file(&kv_new, "/var/ofw/main/settings") == SUCCESS) {
            if (test_kv(kv_new, "GUIPORT", port_gui) != SUCCESS) {
                find_kv_default(kv_new, "GUIPORT", port_gui);
                snprintf(command, STRING_SIZE, "/usr/local/bin/setreservedports.pl --nocheck --gui %s", port_gui);
                safe_system(command);
            }
            if (test_kv(kv_new, "SSHPORT", port_ssh) != SUCCESS) {
                find_kv_default(kv_new, "SSHPORT", port_ssh);
                snprintf(command, STRING_SIZE, "/usr/local/bin/setreservedports.pl --nocheck --ssh %s", port_ssh);
                safe_system(command);
            }

            free_kv(&kv_new);
        }

        if (safe_system("/usr/local/bin/upgrade.sh &>/dev/null")) {
            fprintf(stderr, "Error upgrading data from backup!\n");
            exit(BACKUP_ERR_ANY);
        }
    }
    exit(0);
}
