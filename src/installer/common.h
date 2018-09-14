/*
 * common.h: Global defines, function definitions etc.
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
 * (c) 2007-2011, the Openfirewall Team
 *
 */

#ifndef __COMMON_H
#define __COMMON_H

#include <stdio.h>

#define TRUE      1
#define FALSE     0
#define FAILURE   1
#define SUCCESS   0

#define STRING_SIZE 256
#define STRING_SIZE_LARGE 4096

#define DEFAULT_IP "192.168.1.1"
#define DEFAULT_NETMASK "255.255.255.0"

/* Log and error handles are needed for mysystem helper function. */
extern FILE *flog;
extern FILE *fstderr;

/* Global variable used to indicate our environment */
typedef enum
{
    INST_INSTALLER,          /* directly in installer */
    setupchroot,        /* setup called from installer, in chroot */
    INST_SETUPCHROOT,        /* setup called from installer, in chroot */
    INST_SETUP,              /* 'normal' setup */
} installer_setup_t;

extern installer_setup_t flag_is_state;

/*  Verbose output for helper programs */
extern int flag_verbose;
void verbose_printf(int lvl, char *fmt, ...);

/* Various ways to call a shell and run some external app */
int mysystem(char *command);
int mysystemhidden(char *command);

/* Retrieves PID from PIDfile and send signal */
int mysignalpidfile(char *pidfile, int signal);

/* Gets Openfirewall version number, platform and 'slogan'. */
char *get_title(void);

/* Get Openfirewall version.
    0 if version file missing or version invalid.
    (a << 16) + (b << 8) + c for version a.b.c          */
unsigned int getofwversion(void);

/* stripnl().  Replaces \n with \0 */
void stripnl(char *s);

/* Definitions and functions for handling of configuration files. */
typedef struct itemkv
{
    char *key;
    char *value;
} ITEMKV;

typedef struct nodekv
{
    ITEMKV item;
    struct nodekv *next;
} NODEKV;

extern NODEKV *eth_kv;

/* Return value of key. Return NULL if key does not exist. */
char *find_kv(NODEKV * p, char *key);
/* Value must be STRING_SIZE and can be a default value.
   Return SUCCESS if key exist, value may be changed.
   Return FAILURE if key does not exist, value is unchanged.
*/
int find_kv_default(NODEKV * p, char *key, char *value);
/* Return SUCCESS if key exist and equals testvalue. */
int test_kv(NODEKV * p, char *key, char *testvalue);
/* Update or Add a key */
void update_kv(NODEKV ** p, char *key, char *value);
/* Free memory */
void free_kv(NODEKV ** p);
void read_kv_from_line(NODEKV ** list, char *line);
int read_kv_from_file(NODEKV ** p, char *filename);
int write_kv_to_file(NODEKV ** p, char *filename);


/*  Many helper programs need ethernet/settings config file (read only).
    Make life easier, first do read_ethernet_settings then use ofw_ethernet structure.
*/

/* How many colours do we have */
#define CFG_COLOURS_COUNT   5
/* This is not what it appears, do not change (yet) it will break many things */
#define MAX_NETWORK_COLOUR  1
/* Length of list with types for red */
#define CFG_RED_COUNT       7

/*  Exits immediately on error with message when exitonerror is 1.
    Return  0 if no error reading ethernet/settings
            1 otherwise
*/
int read_ethernet_settings(int exitonerror);

typedef enum
{
    GREEN = 0,
    RED,
    BLUE,
    ORANGE,
    NONE,
} ofw_colours;

extern char *ofw_colours_text[CFG_COLOURS_COUNT];     /* GREEN, RED etc. as strings */
extern char *ofw_aliases_text[CFG_COLOURS_COUNT];     /* lan, wan etc. as network aliases */
extern char *ofw_red_text[CFG_RED_COUNT];     /* ANALOG, ISDN, etc. */

struct network_s
{
    char *module;               /* kernel module */
    char *options;              /* modprobe parameters */
    char *device;               /* eth0, eth1 etc. */
    char *description;
    ofw_colours colour;       /* GREEN, RED, BLUE, ORANGE, ---- */
    char *address;              /* MAC address */
    char *vendorid;             /* vendor and device ID for better NIC matching */
    char *modelid;
};

struct ethernet_s
{
    int count[CFG_COLOURS_COUNT];                                 /* 0 or 1 */
    int valid[CFG_COLOURS_COUNT][MAX_NETWORK_COLOUR + 1];         /* Not yet used */
    char *device[CFG_COLOURS_COUNT][MAX_NETWORK_COLOUR + 1];      /* eth? something */
    char *address[CFG_COLOURS_COUNT][MAX_NETWORK_COLOUR + 1];     /* IP */
    char *netmask[CFG_COLOURS_COUNT][MAX_NETWORK_COLOUR + 1];     /* Subnetmask (like 255.255.255.0) */
    char *netaddress[CFG_COLOURS_COUNT][MAX_NETWORK_COLOUR + 1];  /* Network address */
    char *driver[CFG_COLOURS_COUNT][MAX_NETWORK_COLOUR + 1];      /* Kernel module */
    /* following are red-specials */
    char *red_type[MAX_NETWORK_COLOUR + 1];                       /*  */
    char *red_address[MAX_NETWORK_COLOUR + 1];                    /* the DHCP, PPPoE, other, address */
    char *red_device[MAX_NETWORK_COLOUR + 1];                     /* real red, for example ppp0 */
    int  red_active[MAX_NETWORK_COLOUR + 1];                      /* red active (0 or 1), test on device may not be enough in case of DHCP */
    /* this one is very special */
    char *default_gateway;
};
extern struct ethernet_s ofw_ethernet;

/* Return SUCCESS if device exist */
int exist_ethernet_device(char *device);


/* Get device MAC address */
char mac_buffer[STRING_SIZE]; /* to return the value out of the function */
char *getmac(char *device);

/* Some useful defines, tests etc. */
#define LETTERS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define NUMBERS "0123456789"
#define LETTERS_NUMBERS LETTERS NUMBERS
#define IP_NUMBERS "./" NUMBERS
#define PORT_NUMBERS ":-" NUMBERS
#define VALID_FQDN LETTERS_NUMBERS ".-"

#define VARNAME     LETTERS_NUMBERS "_"
/* TODO: spaces are only allowed when quoted, need to add VALID_VARIABLE with such test(s) */
#define VARCHARS    LETTERS_NUMBERS "=/,._@#+- "

int VALID_IP(const char *ip);
#define VALID_IP_AND_MASK(ip) (strlen(ip) > 6 \
                            && strlen(ip) < 32 \
                            && strspn(ip, IP_NUMBERS) == strlen(ip))

#define VALID_PORT(port) (strlen(port) \
                       && strlen(port) < 6 \
                       && strspn(port, NUMBERS) == strlen(port))

#define VALID_PORT_RANGE(port) (strlen(port) \
                             && strlen(port) < 12 \
                             && strspn(port, PORT_NUMBERS) == strlen(port))

#define VALID_SHORT_MASK(ip) (strlen(ip) > 1 \
                             && strlen(ip) < 3 \
                             && strspn(ip, NUMBERS) == strlen(ip))

/* Can't find any info on valid characters/length hopefully these are
 * reasonable guesses */
#define VALID_DEVICE(dev) (strlen(dev) \
                        && strlen(dev) < 16 \
                        && strspn(dev, LETTERS_NUMBERS "-_:.") == strlen(dev))

/* Again, can't find any hard and fast rules for protocol names, these
 * restrictions are based on the keywords currently listed in
 * <http://www.iana.org/assignments/protocol-numbers>
 * though currently the openfirewall cgis will only pass tcp, udp or gre anyway */
#define VALID_PROTOCOL(prot) (strlen(prot) \
                          &&  strlen(prot) <16 \
                          &&  strspn(prot, LETTERS_NUMBERS "-") == strlen(prot))


#endif
