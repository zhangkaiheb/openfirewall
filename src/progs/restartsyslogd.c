/*
 * restartsyslogd: restart system log daemon and rewrite logrotate rotate parameter
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
 * along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2003-07-12 Robert Kerr <rkerr@go.to>
 *
 * (c) 2004-2014 The IPCop Team
 *
 * $Id: restartsyslogd.c 7576 2014-05-24 08:45:28Z owes $
 *
 */


#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "common.h"
#include "setuid.h"


#define ERR_ANY 1
#define ERR_SETTINGS 2          /* error in settings file */
#define ERR_ETC 3               /* error with /etc permissions */
#define ERR_CONFIG 4            /* error updated sshd_config */
#define ERR_SYSLOG 5            /* error restarting syslogd */


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char **argv)
{
    char buffer[STRING_SIZE];
    int config_fd;
    int rc;
    int remote_log;
    char hostname[STRING_SIZE];
    char proto[STRING_SIZE];
    char log_keep[STRING_SIZE];
    struct stat st;
    NODEKV *log_kv = NULL;

    static struct option long_options[] =
    {
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    memset(buffer, 0, STRING_SIZE);
    memset(hostname, 0, STRING_SIZE);
    strcpy(proto, "udp");
    if (access("/etc/FLASH", 0) != -1) {
        strcpy(log_keep, "14");
    }
    else {
        strcpy(log_keep, "56");
    }

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "v", long_options, &option_index)) != -1) {
        switch (c) {
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

    verbose_printf(1, "Reading log settings ... \n");
    if (read_kv_from_file(&log_kv, "/var/ipcop/logging/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read syslog settings\n");
        exit(ERR_SETTINGS);
    }

    remote_log = (test_kv(log_kv, "ENABLE_REMOTELOG", "on") == SUCCESS);
    verbose_printf(2, "  remotelog: %s\n", remote_log ? "on" : "off");

    if (find_kv_default(log_kv, "REMOTELOG_ADDR", hostname) != SUCCESS) {
        fprintf(stderr, "Cannot read REMOTELOG_ADDR\n");
        exit(ERR_SETTINGS);
    }

    if (strspn(hostname, VALID_FQDN) != strlen(hostname)) {
        fprintf(stderr, "Bad REMOTELOG_ADDR: %s\n", hostname);
        exit(ERR_SETTINGS);
    }
    if (remote_log) {
        verbose_printf(2, "  remotelog addr: %s\n", hostname);
    }

    /* No error checking, older config files may not have protocol. Use default (udp) in that case. */
    find_kv_default(log_kv, "REMOTELOG_PROTO", proto);
    if (remote_log) {
        verbose_printf(2, "  remotelog proto: %s\n", proto);
    }

    /* No error checking, older config files may not have log_keep. */
    find_kv_default(log_kv, "LOG_KEEP", log_keep);
    if (remote_log) {
        verbose_printf(2, "  log keep: %s\n", log_keep);
    }

    free_kv(&log_kv);


    /* If anyone other than root can write to /etc this would be totally
     * insecure - same if anyone other than root owns /etc, as they could
     * change the file mode to give themselves or anyone else write access. */

    verbose_printf(1, "Verify /etc ... \n");
    if (lstat("/etc", &st)) {
        perror("Unable to stat /etc");
        exit(ERR_ETC);
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "/etc is not a directory?!\n");
        exit(ERR_ETC);
    }
    if (st.st_uid != 0 || st.st_mode & S_IWOTH || ((st.st_gid != 0) && (st.st_mode & S_IWGRP))) {
        fprintf(stderr, "/etc is owned/writable by non-root users\n");
        exit(ERR_ETC);
    }

    snprintf(buffer, STRING_SIZE, "/bin/grep 'rotate %s' /etc/logrotate.conf >/dev/null", log_keep);
    if (safe_system(buffer)) {
        verbose_printf(1, "Modifying logrotate.conf ... \n");
        snprintf(buffer, STRING_SIZE, "/bin/sed -i -e 's/^rotate.*/rotate %s/' /etc/logrotate.conf", log_keep);
        safe_system(buffer);
    }

    verbose_printf(1, "Modifying rsyslogd configfile ... \n");
    /* O_CREAT with O_EXCL will make open() fail if the file already exists -
     * mostly to prevent 2 copies running at once */
    if ((config_fd = open("/etc/rsyslog.conf.new", O_WRONLY | O_CREAT | O_EXCL, 0644)) == -1) {
        perror("Unable to open new config file");
        exit(ERR_CONFIG);
    }

    if (remote_log) {
        if (!strcmp(proto, "tcp")) {
            snprintf(buffer, STRING_SIZE - 1,
                     "/bin/sed -e 's/^#\\?\\(\\*\\.\\*[[:blank:]]\\+@\\).\\+$/\\1@%s/' /etc/rsyslog.conf >&%d", hostname,
                     config_fd);
        }
        else {
            snprintf(buffer, STRING_SIZE - 1,
                    "/bin/sed -e 's/^#\\?\\(\\*\\.\\*[[:blank:]]\\+@\\).\\+$/\\1%s/' /etc/rsyslog.conf >&%d", hostname,
                    config_fd);
        }
    }
    else {
        snprintf(buffer, STRING_SIZE - 1,
                 "/bin/sed -e 's/^#\\?\\(\\*\\.\\*[[:blank:]]\\+@.\\+\\)$/#\\1/' /etc/rsyslog.conf >&%d", config_fd);
    }

    /* if the return code isn't 0 failsafe */
    if ((rc = unpriv_system(buffer, 99, 99)) != 0) {
        fprintf(stderr, "sed returned bad exit code: %d\n", rc);
        close(config_fd);
        unlink("/etc/rsyslog.conf.new");
        exit(ERR_CONFIG);
    }
    close(config_fd);
    if (rename("/etc/rsyslog.conf.new", "/etc/rsyslog.conf") == -1) {
        perror("Unable to replace old config file");
        unlink("/etc/rsyslog.conf.new");
        exit(ERR_CONFIG);
    }

    if (access("/var/run/rsyslogd.pid", 0) != -1) {
        verbose_printf(1, "Stopping rsyslogd ... \n");
    
        mysignalpidfile("/var/run/rsyslogd.pid", SIGTERM);
        unlink("/var/run/rsyslogd.pid");
    }
    
    verbose_printf(1, "Starting rsyslogd ... \n");
    if ((rc = safe_system("/usr/sbin/rsyslogd")) != 0) {
        fprintf(stderr, "Unable to start rsyslogd - returned exit code %d\n", rc);
        exit(ERR_SYSLOG);
    }

    /* Leave some time after restart to make sure we do not loose any log messages */
    sleep(1);
    
    return 0;
}
