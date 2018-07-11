/*
 * restartssh.c: Simple program intended to be installed setuid(0) that can be used for
 * restarting SSHd.
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
 *
 * restartssh originally from the Smoothwall project
 * (c) Mark Wormgoor, 2001
 *
 * $Id: restartssh.c 2265 2009-01-01 18:34:06Z owes $
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
#include <sys/types.h>
#include "common.h"
#include "setuid.h"


void usage(char *prg, int exit_code)
{
    printf("Usage: %s [OPTION]\n\n", prg);
    printf("Options:\n");
    printf("  -b, --boot            when booting no error when PID not OK\n"); 
    printf("  -v, --verbose         be verbose\n");
    printf("      --help            display this help and exit\n");
    exit(exit_code);
}


int main(int argc, char **argv)
{
    int flag_boot = 0;
    int fd, config_fd, rc, pid;
    char buffer[STRING_SIZE_LARGE], command[STRING_SIZE_LARGE] = "/bin/sed -e '";
    NODEKV *ssh_kv = NULL;
    int enabled = 0;

    static struct option long_options[] =
    {
        { "boot", no_argument, 0, 'b' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };
    int c;
    int option_index = 0;

    if (!(initsetuid()))
        exit(1);

    while ((c = getopt_long(argc, argv, "bv", long_options, &option_index)) != -1) {
        switch (c) {
        case 'b':              /* booting */
            flag_boot = 1;
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

    verbose_printf(1, "Reading SSHd settings ... \n");
    if (read_kv_from_file(&ssh_kv, "/var/ipcop/remote/settings") != SUCCESS) {
        fprintf(stderr, "Cannot read remote access settings\n");
        exit(1);
    }

    /* By using O_CREAT with O_EXCL open() will fail if the file already exists,
     * this prevents 2 copies of restartssh both trying to edit the config file
     * at once. It also prevents race conditions, but these shouldn't be
     * possible as /etc/ssh/ should only be writable by root anyhow
     */

    if ((config_fd = open("/etc/ssh/sshd_config.new", O_WRONLY | O_CREAT | O_EXCL, 0644)) == -1) {
        perror("Unable to open new config file");
        free_kv(&ssh_kv);
        exit(1);
    }

    verbose_printf(1, "Rebuilding SSHd config ... \n");
    if (test_kv(ssh_kv, "ENABLE_SSH_PROTOCOL1", "on") == SUCCESS)
        strlcat(command, "s/^Protocol .*$/Protocol 2,1/;", STRING_SIZE_LARGE - 1);
    else
        strlcat(command, "s/^Protocol .*$/Protocol 2/;", STRING_SIZE_LARGE - 1);

    if (test_kv(ssh_kv, "ENABLE_SSH_KEYS", "off") == SUCCESS)
        strlcat(command, "s/^RSAAuthentication .*$/RSAAuthentication no/;"
                "s/^PubkeyAuthentication .*$/PubkeyAuthentication no/;", STRING_SIZE_LARGE - 1);
    else
        strlcat(command, "s/^RSAAuthentication .*$/RSAAuthentication yes/;"
                "s/^PubkeyAuthentication .*$/PubkeyAuthentication yes/;", STRING_SIZE_LARGE - 1);

    if (test_kv(ssh_kv, "ENABLE_SSH_PASSWORDS", "off") == SUCCESS)
        strlcat(command, "s/^PasswordAuthentication .*$/PasswordAuthentication no/;", STRING_SIZE_LARGE - 1);
    else
        strlcat(command, "s/^PasswordAuthentication .*$/PasswordAuthentication yes/;", STRING_SIZE_LARGE - 1);

    if (test_kv(ssh_kv, "ENABLE_SSH_PORTFW", "on") == SUCCESS)
        strlcat(command, "s/^AllowTcpForwarding .*$/AllowTcpForwarding yes/", STRING_SIZE_LARGE - 1);
    else
        strlcat(command, "s/^AllowTcpForwarding .*$/AllowTcpForwarding no/", STRING_SIZE_LARGE - 1);

    if (test_kv(ssh_kv, "ENABLE_SSH", "on") == SUCCESS)
        enabled = 1;

    free_kv(&ssh_kv);

    snprintf(buffer, STRING_SIZE_LARGE - 1, "' /etc/ssh/sshd_config >&%d", config_fd);
    strlcat(command, buffer, STRING_SIZE_LARGE - 1);

    if ((rc = unpriv_system(command, 99, 99)) != 0) {
        fprintf(stderr, "sed returned bad exit code: %d\n", rc);
        close(config_fd);
        unlink("/etc/ssh/sshd_config.new");
        exit(1);
    }
    close(config_fd);
    if (rename("/etc/ssh/sshd_config.new", "/etc/ssh/sshd_config") != 0) {
        perror("Unable to replace old config file");
        unlink("/etc/ssh/sshd_config.new");
        exit(1);
    }

    memset(buffer, 0, STRING_SIZE_LARGE);

    verbose_printf(1, "Shutdown SSHd ... \n");
    if ((fd = open("/var/run/sshd.pid", O_RDONLY)) != -1) {
        if ((read(fd, buffer, STRING_SIZE_LARGE - 1) == -1) && !flag_boot) {
            fprintf(stderr, "Couldn't read from pid file\n");
        }
        else {
            pid = atoi(buffer);
            if (pid <= 1)
                fprintf(stderr, "Bad pid value\n");
            else {
                if (kill(pid, SIGTERM) == -1)
                    fprintf(stderr, "Unable to send SIGTERM\n");
                else
                    unlink("/var/run/sshd.pid");
            }
        }
        close(fd);
    }
    else {
        if (!flag_boot && (errno != ENOENT)) {
            perror("Unable to open pid file");
            exit(1);
        }
    }

    if (enabled) {
        verbose_printf(1, "Starting SSHd ... \n");
        safe_system("/usr/sbin/sshd");

        /* Give SSHd some time to start */
        sleep(1);

        if (access("/var/run/sshd.pid", F_OK) == -1) {
            fprintf(stderr, "Couldn't read from pid file, SSHd not running?\n");
        }
        else if (flag_verbose >= 2) {
            safe_system("echo -n \"SSHd running with PID \" && cat /var/run/sshd.pid");
        }
    }

    return 0;
}
