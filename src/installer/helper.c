/* 
 * helper.c: helper functions
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
 * along with Openfirewall.  If not, see <http://www.gnu.org/licenses/>.
 *
 * (c) 2017-2020, the Openfirewall Team
 * 
 */

#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "common.h"


/* use ---- for non-assigned card */
char *openfw_colours_text[CFG_COLOURS_COUNT] = { "GREEN", "RED", "BLUE", "ORANGE", "----" };
char *openfw_aliases_text[CFG_COLOURS_COUNT] = { "lan", "wan", "wlan", "dmz", "eth" };

char *openfw_red_text[CFG_RED_COUNT] = { "PPPOE", "PPTP", "STATIC", "DHCP" };

/* Global structure with everything from ethernet/settings config file */
struct ethernet_s openfw_ethernet;
/* Verbose level */
int flag_verbose = 0;

NODEKV *eth_kv = NULL;

/* */
struct utsname uts;


/* Compare verbose level against lvl, printf if greater or equal */
void verbose_printf(int lvl, char *fmt, ...)
{
    if (flag_verbose >= lvl) {
        va_list argptr;
        va_start(argptr, fmt);
        vprintf(fmt, argptr);
        va_end(argptr);
    }
}


/* stripnl().  Replaces \n with \0 */
void stripnl(char *s)
{
    char *t = strchr(s, '\n');
    if (t)
        *t = '\0';
}


/* Return a pointer to the actual running version number of Openfirewall.
 * Successive updates increase effective version but not compiled VERSION ! */
char title[STRING_SIZE] = "";
char *helper_get_title(void)
{
    FILE *f_title;

    if (title[0]) {
        /* no need to reread /etc/issue */
        return title;
    }

    if ((f_title = fopen("/etc/issue", "r"))) {
        if (fgets(title, STRING_SIZE, f_title)) {
            stripnl(title);
            if (strchr(title, '(')) {
                /* strip tty name (if present) */
                char *tty = strchr(title, '(');
                *tty = '\0';

                /* strip space too */
                tty--;
                if (*tty == ' ') {
                    *tty = 0;
                }
            }
        }
        fclose(f_title);
    }
    else {
        sprintf(title, "%s /etc/issue not found", NAME);
    }
    return title;
}


/* Get Openfirewall version from /etc/issue.
    0 if version file missing or version invalid.
    (a << 16) + (b << 8) + c for version a.b.c          */
unsigned int helper_getofwversion(void)
{
    FILE *f_version;
    char buffer[STRING_SIZE] = "";
    unsigned int version = 0;
    unsigned int v_major, v_minor, v_revision;

    if ((f_version = fopen("/etc/issue", "r")) == NULL) {
        return 0;
    }
    if (fgets(buffer, STRING_SIZE, f_version) == NULL) {
        fclose(f_version);
        return 0;
    }
    fclose(f_version);
        
    stripnl(buffer);
    if (!buffer[0] || strncmp(buffer, "Openfirewall v", 14)) {
        return 0;
    }

    if (sscanf(buffer+7, "%u.%u.%u", &v_major, &v_minor, &v_revision) != 3) {
        return 0;
    }
    if ((v_major > 255) || (v_minor > 255) || (v_revision > 255)) {
        return 0;
    }

    version = (v_major << 16) + (v_minor << 8) + v_revision;

    return version;
}


FILE *flog = NULL;
FILE *fstderr = NULL;

/* Little wrapper. */
int mysystem(char *command)
{
    char mycommand[STRING_SIZE_LARGE + 64];     //we have a large buffer for the initrd setup!
    int cr = 0;

    if (strchr(command, '\n'))
        cr = 1;

#if 0
    snprintf(mycommand, STRING_SIZE, "%s >>%s 2>>%s", command, flog, flog);
#else
    snprintf(mycommand, STRING_SIZE, "%s >> /dev/tty3", command);
#endif
    if (flog != NULL) {
        F_LOG("Running command: %s\n", command);
        if (cr)
            F_LOG("WARNING mysystem return value is always 0 when a CR is on command\n");
    }
    return system(mycommand);
}


/* Wrapper without cmd output */
int mysystemhidden(char *command)
{
    char mycommand[4096 + 64];  //we have a 4k buffer for the initrd setup!

    snprintf(mycommand, STRING_SIZE, "%s >> /dev/null", command);
    if (flog != NULL) {
        F_LOG("Running command: %s\n", "HIDDEN");
    }
    return system(mycommand);
}


/* retrieves PID from PIDfile and send signal*/
int mysignalpidfile(char *pidfile, int signal)
{
    int fd;
    int pid;
    char buffer[STRING_SIZE];

    if ((fd = open(pidfile, O_RDONLY)) == -1) {
        return FAILURE;
    }

    if (read(fd, buffer, STRING_SIZE - 1) == -1) {
        close(fd);
        fprintf(stderr, "Couldn't read from pid file (%s)\n", pidfile);
        return FAILURE;
    }

    close(fd);
    errno = 0;
    pid = (int) strtol(buffer, (char **) NULL, 10);
    if (errno || pid <= 1) {
        fprintf(stderr, "Bad pid value (%d) in pid file (%s)\n", pid, pidfile);
        return FAILURE;
    }
    else {
        if (kill(pid, signal) == -1) {
            fprintf(stderr, "Unable to send signal (%d) to pid file (%s,%d)\n", signal, pidfile, pid);
            return FAILURE;
        }
    }
    return SUCCESS;
}


/* Insert in front of the list.
   Internal function, use update_kv as alternative.
*/
static void add_kv(NODEKV ** kvhead, char *key, char *value)
{
    NODEKV *p = malloc(sizeof(NODEKV));

    p->item.key = strdup(key);
    p->item.value = strdup(value);
    p->next = *kvhead;
    *kvhead = p;
}


char *find_kv(NODEKV * p, char *key)
{
    while (p != NULL) {
        if (strcmp(p->item.key, key) == 0)
            return p->item.value;

        p = p->next;
    }
    return NULL;
}


/* caller has already space reserved and maybe filled with a default value.
   Return SUCCESS if key exist, value may be changed.
   Return FAILURE if key does not exist, value is unchanged.
*/
int find_kv_default(NODEKV * p, char *key, char *value)
{
    while (p != NULL) {
        if (strcmp(p->item.key, key) == 0) {
            strncpy(value, p->item.value, STRING_SIZE);
            value[STRING_SIZE - 1] = '\0';
            return SUCCESS;
        }

        p = p->next;
    }

    return FAILURE;
}


/* caller just want SUCCESS/FAILURE answer whether key matches */
int test_kv(NODEKV * p, char *key, char *testvalue)
{
    char *value;

    if ((value = find_kv(p, key)) == NULL) {
        /* no key, no match */
        return FAILURE;
    }

    if (strcmp(value, testvalue)) {
        return FAILURE;
    }
    return SUCCESS;
}

/* Update a key or insert it */
void update_kv(NODEKV ** p, char *key, char *value)
{
    NODEKV *b = *p;             //don't loose the head!
    while (b) {
        if (strcmp(b->item.key, key) == 0) {
            free(b->item.value);
            b->item.value = strdup(value);
            return;
        }
        b = b->next;
    }
    add_kv(p, key, value);
}


/* Read from file. Return SUCCESS/FAILURE. */
int read_kv_from_file(NODEKV ** p, char *filename)
{
    FILE *file;
    char buffer[STRING_SIZE];
    char *temp;
    char *key, *value;

    if (!(file = fopen(filename, "r")))
        return FAILURE;

    if (flock(fileno(file), LOCK_SH)) {
        fclose(file);
        return FAILURE;
    }

    while (fgets(buffer, STRING_SIZE, file)) {
        temp = buffer;
        while (*temp) {
            if (*temp == '\n')
                *temp = '\0';
            temp++;
        }
        if (!strlen(buffer))
            continue;
        if (!(temp = strchr(buffer, '='))) {
            flock(fileno(file), LOCK_UN);
            fclose(file);
            return FAILURE;
        }
        *temp = '\0';
        key = buffer;
        value = temp + 1;
        /* See if string is quoted.  If so, skip first quote, and
         * nuke the one at the end. */
        if (value[0] == '\'') {
            value++;
            if ((temp = strrchr(value, '\'')))
                *temp = '\0';
            else {
                flock(fileno(file), LOCK_UN);
                fclose(file);
                return FAILURE;
            }
        }
        if (strlen(key))
            add_kv(p, key, value);
    }

    flock(fileno(file), LOCK_UN);
    fclose(file);

    return SUCCESS;
}


/* save to file */
int write_kv_to_file(NODEKV ** p, char *filename)
{
    FILE *file;
    NODEKV *cur = *p;

    if (!(file = fopen(filename, "w")))
        return FAILURE;

    if (flock(fileno(file), LOCK_EX)) {
        fclose(file);
        return FAILURE;
    }

    while (cur) {
        if (strchr(cur->item.value, ' ') != NULL) {
            fprintf(file, "%s=\'%s\'\n", cur->item.key, cur->item.value);
        }
        else {
            fprintf(file, "%s=%s\n", cur->item.key, cur->item.value);
        }
        cur = cur->next;
    }

    flock(fileno(file), LOCK_UN);
    fclose(file);

    return SUCCESS;
}


/* Free the list from the pointer. */
void free_kv(NODEKV ** p)
{
    NODEKV *b = *p;
    while (b) {
        if (b->item.key)
            free(b->item.key);
        if (b->item.value)
            free(b->item.value);
        NODEKV *deleted = b;
        b = b->next;
        free(deleted);
    }
    *p = NULL;
}

/* Fill the 'keyvalue list with result of parsing a text line
    looking for couple key=value data
    If a key is found without =data, it is assigned =1 (true)
    No spaces are allowed around the '=' sign
    Quotted string no handled.
    Exemple text buffer:
	root=/dev/hda1 selinux=0 splash
    add
	root => /dev/hda1
	selinux => 0
	splash => 1
    in the keyvalue list.
    The keyvalue list must be initialized before calling!
*/
void read_kv_from_line(NODEKV ** list, char *line)
{
    char bufferline[STRING_SIZE], val[STRING_SIZE];
    char *buffer = bufferline;
    char *key, *value;

    strncpy(buffer, line, STRING_SIZE - 1);     /* work on a local copy         */
    if ((value = strchr(buffer, '\n'))) /* convert OEL to null termined */
        *value = 0;

    while (*buffer) {           /* remaing char ? */
        while (*buffer == ' ')  /* skip front space */
            buffer++;

        if (!*buffer)
            continue;           /* that's the end */

        key = buffer;           /* beginning of the key */
        while (*buffer && (*buffer != ' ') && (*buffer != '='))
            buffer++;           /* get the key name     */

        switch (*buffer) {      /* get the key value    */
        case '=':
            *buffer = 0;        /* end of key name      */
            buffer++;           /* skip =               */
            value = &val[0];    /* read the value       */
            while (*buffer && (*buffer != ' '))
                *value++ = *buffer++;
            *value = 0;         /* end of value         */
            break;
        case ' ':              /* no data specified    */
            *buffer = 0;        /* end of key name      */
            buffer++;           /* prepare next key     */
        case 0:                /* assign default true  */
            strcpy(val, "1");
        };

        add_kv(list, key, val); /* create the key entry */
    }
}


/* Return SUCCESS if device exist */
int exist_ethernet_device(char *device)
{
    char filename[STRING_SIZE];

    if ((device == NULL) || (*device == 0)) {
        return FAILURE;
    }
    snprintf(filename, STRING_SIZE, "/sys/class/net/%s", device);

    if (access(filename, F_OK) != -1) {
        return SUCCESS;
    }

    return FAILURE;
}


/* Read 1 specific key, exit immediatelly on error */
static int helper_read_ethernet_key(int colour, int index, char *eth_key, char **ptr, int exitonerror, char *error_description)
{
    char key[STRING_SIZE];

    /* Build the key, for example GREEN_1_ADDRESS */
    snprintf(key, STRING_SIZE, "%s_%d_%s", openfw_colours_text[colour], index, eth_key);
    if (find_kv(eth_kv, key) == NULL) {
        /* Depending on RED type, the key/value may be missing */
        if (colour == RED) {
            /* TODO: do some additional testing here */
            *ptr = strdup("");
            return SUCCESS;
        }

        /* We expect the key, but it is not there */
        if (exitonerror) {
            free_kv(&eth_kv);
			fprintf(stderr, "%s for %s_%d not defined\n", error_description, openfw_colours_text[colour], index);
            exit(1);
        }

		verbose_printf(1, "  %s for %s_%d not defined\n", error_description, openfw_colours_text[colour], index);

        return FAILURE;
    }

    /* Store the keyvalue */
    *ptr = strdup(find_kv(eth_kv, key));
	verbose_printf(2, "  %s for %s_%d: %s\n", error_description, openfw_colours_text[colour], index, *ptr);
    return SUCCESS;
}


/* This to make life easier for SUID helpers. */
int helper_read_ethernet_settings(int exitonerror)
{
	int i, j;
	char key[STRING_SIZE];
	char value[STRING_SIZE];
	FILE *ipfile;

	/* zap contents */
	memset(&openfw_ethernet, 0, sizeof(openfw_ethernet));
	verbose_printf(1, "Reading Ethernet settings ... \n");

	if (read_kv_from_file(&eth_kv, "/var/ofw/ethernet/settings") != SUCCESS) {
		/* What's a Openfirewall without ethernet/settings...  Nothing... */
		if (exitonerror) {
			free_kv(&eth_kv);
			fprintf(stderr, "Cannot read ethernet settings\n");
			exit(1);
		}

		return 1;
	}

	/* special case, default gateway. There can be only one ..... */
	strcpy(value, "");
	find_kv_default(eth_kv, "DEFAULT_GATEWAY", value);
	openfw_ethernet.default_gateway = strdup(value);
	verbose_printf(2, "  Default gateway: %s\n", openfw_ethernet.default_gateway);

	/* special case, red active */
	if (access("/var/ofw/red/active", F_OK) != -1) {
		openfw_ethernet.red_active[1] = 1;
	} else {
		openfw_ethernet.red_active[1] = 0;
	}
	verbose_printf(2, "  RED active: %d\n", openfw_ethernet.red_active[1]);

	/* another special case, (real) red address, from red/local-ipaddress */
	if ((ipfile = fopen("/var/ofw/red/local-ipaddress", "r")) != NULL) {
		if (fgets(value, STRING_SIZE, ipfile)) {
			/* remove possible trailing \n */
			stripnl(value);
		}
		fclose(ipfile);
	} else {
		strcpy(value, "");
	}
	openfw_ethernet.red_address[1] = strdup(value);
	verbose_printf(2, "  RED address: %s\n", openfw_ethernet.red_address[1]);

	/* yet another special case, (real) red device, from red/iface */
	if ((ipfile = fopen("/var/ofw/red/iface", "r")) != NULL) {
		if (fgets(value, STRING_SIZE, ipfile)) {
			/* remove possible trailing \n */
			stripnl(value);
		}
		fclose(ipfile);

		if (!VALID_DEVICE(value)) {
			if (exitonerror) {
				free_kv(&eth_kv);
				fprintf(stderr, "Bad RED iface: %s\n", value);
				exit(1);
			}
			verbose_printf(1, "Bad RED iface: %s\n", value);
			return 1;
		}
	} else {
		strcpy(value, "");
	}
	openfw_ethernet.red_device[1] = strdup(value);
	verbose_printf(2, "  RED device: %s\n", openfw_ethernet.red_device[1]);

	/* for all colours */
	for (i = 0; i < NONE; i++) {
		snprintf(key, STRING_SIZE, "%s_COUNT", openfw_colours_text[i]);
		strcpy(value, "0");
		find_kv_default(eth_kv, key, value);
		openfw_ethernet.count[i] = atoi(value);

		if ((openfw_ethernet.count[i] < 0) || (openfw_ethernet.count[i] > MAX_NETWORK_COLOUR)) {
			/* Count is not a sane value */
			if (exitonerror) {
				free_kv(&eth_kv);
				fprintf(stderr, "Illegal count (%d) for colour %s\n",
					openfw_ethernet.count[i], openfw_colours_text[i]);
				F_LOG("Illegal count (%d) for colour %s\n",
					openfw_ethernet.count[i], openfw_colours_text[i]);
				exit(1);
			}

			return 1;
		}

		for (j = 1; j <= openfw_ethernet.count[i]; j++) {
			if (helper_read_ethernet_key(i, j, "DEV",
						&openfw_ethernet.device[i][j], exitonerror, "Device") != SUCCESS) {
				return FAILURE;
			}
			if (helper_read_ethernet_key(i, j, "ADDRESS",
						&openfw_ethernet.address[i][j], exitonerror, "IP address") != SUCCESS) {
				return FAILURE;
			}
			if (helper_read_ethernet_key(i, j, "NETMASK",
						&openfw_ethernet.netmask[i][j], exitonerror, "Subnetmask") != SUCCESS) {
				return FAILURE;
			}
			if (helper_read_ethernet_key(i, j, "NETADDRESS",
						&openfw_ethernet.netaddress[i][j], exitonerror, "Network address") != SUCCESS) {
				return FAILURE;
			}

			helper_read_ethernet_key(i, j, "DRIVER", &openfw_ethernet.driver[i][j], 0, "Driver");
		}
	}

	/* We need at least 1 RED connection type */
	if (helper_read_ethernet_key(RED, 1, "TYPE", &openfw_ethernet.red_type[1], exitonerror, "Connection type") != SUCCESS)
		return FAILURE;
	/* more red types, we may one day allow for more red devices */
	for (j = 2; j <= openfw_ethernet.count[RED]; j++) {
		if (helper_read_ethernet_key(RED, j, "TYPE", &openfw_ethernet.red_type[j], exitonerror, "Type") != SUCCESS)
			return FAILURE;
	}

	free_kv(&eth_kv);
	eth_kv = NULL;

	return 0;
}


/* Get device MAC address */
char *helper_getmac(char *device)
{
    FILE *f;

    snprintf(mac_buffer, STRING_SIZE, "/sys/class/net/%s/address", device);
    f = fopen(mac_buffer, "r");
    if (f != NULL) {
        if (fgets(mac_buffer, STRING_SIZE, f)) {
            stripnl(mac_buffer);
            return mac_buffer;
        }
        fclose(f);
    }
    return "";
}


/*
    Test for valid IPv4
    Returns TRUE or FALSE
*/
int VALID_IP(const char *ip)
{
    unsigned int b1, b2, b3, b4;
    unsigned char c;

    if ((strlen(ip) < 7) || (strlen(ip) > 15)) return FALSE;
    if (strspn(ip, NUMBERS ".") != strlen(ip)) return FALSE;
    if (sscanf(ip, "%3u.%3u.%3u.%3u%c", &b1, &b2, &b3, &b4, &c) != 4) return FALSE;

    if ((b1 | b2 | b3 | b4) > 255) return FALSE;

    return TRUE;
}


#ifdef TEST
int main(void)
{
    NODEKV *head = NULL;
    read_kv_from_line(&head, "K1=V1 K2 K3=V3");

    printf("K1=%s\n", find_kv(head, "K1"));
    printf("K2=%s\n", find_kv(head, "K2"));
    printf("K3=%s\n", find_kv(head, "K3"));
    printf("K4=%s\n", find_kv(head, "KX"));

    update_kv(&head, "KX", "toto");
    update_kv(&head, "K5", "k5");

    printf("K4=%s\n", find_kv(head, "KX"));
    printf("K5=%s\n", find_kv(head, "K5"));
    free_kv(&head);
    printf("K4=%s\n", find_kv(head, "K4"));
    if (!head)
        printf("head = NIL\n");

}
#endif
