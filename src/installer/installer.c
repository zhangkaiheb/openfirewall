/*
 * main.c: installer main loop
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 * Written by Alan Hourihane <alanh@fairlite.demon.co.uk>
 *
 * (c) 2007-2015, the Openfirewall Team
 *
 * This is the first stage installer.
 * - select language.
 * - probe hardware (takes some time).
 * - select source CDROM / network. Do a quick test.
 * - select target drive
 * - create partitions on drive (takes some time depending on disk size)
 * - wget sources when doing network install
 * - extract sources to harddisk
 * - jump into setup for lots of config
 *
 * Commandline options:
 *
 *   nopcmcia       - Skip PCMCIA hardware detection (do we still need this ?)
 *   nousb          - Skip USB hardware detection (do we still need this ?)
 *   parted         - Run parted instead of sfdisk
 *   partition      - Manual partitioning, use with care!
 *   nodma          - Disable DMA for IDE (for syslinux.cfg / init)
 *   nombr          - Do not write MBR to disk
 *   swap           - Force swap filesize in MB, use 0 to disable swap
 *   disk           - Use only x MB instead of full disk
 *   modules        - Manually add kernel modules after hardware detection
 *
 * $Id: installer.c 7846 2015-02-01 18:35:46Z owes $
 *
 */

#include <ctype.h>
#include <errno.h>
#include <newt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common.h"
#include "common_newt.h"
#include "arch_defs.h"

// tweak for errorbox
#define  gettext  ofw_gettext


/* global variables */
installer_setup_t flag_is_state = installer;
supported_media_t medium_boot = unknown;
supported_media_t medium_sources = none;
supported_media_t medium_target = none;
supported_media_t medium_console = console;
char network_source[STRING_SIZE];
unsigned int memtotal = 0;                  /* Total memory in MB */

unsigned int serial_console = 0;
unsigned int serial_bitrate = 9600;
char *serial_commandline = NULL;


/* local variables */
static int codepath = 0;                    /* for better test, allow testing dhcp and manual path even on pxe boot */
static NODEKV *kv = NULL;                   /* contains a list key=value pairs from boot parameters */
static char command[STRING_SIZE];
static char message[STRING_SIZE_LARGE];
static int scsi_cdrom;
static char local_IP[STRING_SIZE] = "";
static char server_IP[STRING_SIZE] = "";    /* http/ftp server to install from network */
static char itf_name[STRING_SIZE] = "";     /* interface to install */
static char netboot_dhcp_IP[STRING_SIZE] = "";
static char netmask[STRING_SIZE] = "";
static char netboot_mac[STRING_SIZE] = "";
static char domain[STRING_SIZE] = "";
static struct network_s *networks;


/* On x86 netboot, read cmdline value
   With sparc netboot cdmline is empty,
   we may find something looking at openpromfs (currently built-in)
*/
static void read_netboot_values(void)
{
    int i = 0;
    char *buffer = NULL;
    if (find_kv_default(kv, "ip", command) == SUCCESS) {
        buffer = strtok(command, ":" );
        if (buffer) {
            strcpy(local_IP, buffer);
            buffer=strtok(NULL, ":");
            if (buffer) {
                strcpy(server_IP, buffer);
                buffer=strtok(NULL, ":");
                if (buffer) {
                    strcpy(netboot_dhcp_IP, buffer);
                    buffer=strtok(NULL, ":");
                    if (buffer) {
                        strcpy(netmask, buffer);
                    }
                }
            }
        }
        fprintf(flog, "       netmask:%s\n    netboot IP:%s\n"
                      "TFTP server IP:%s\nDHCP server IP:%s\n",
                       netmask, local_IP, server_IP, netboot_dhcp_IP);
        medium_boot = network;
    }
    if (find_kv_default(kv, "BOOTIF", netboot_mac) == SUCCESS) {
        /* convert format to lowercase */
        while ( netboot_mac[i] ) {
            netboot_mac[i] = tolower(netboot_mac[i]);
          i++;
        }
        /* use same ':' separator as sysfs */
        for (i = 2; i < 18; i = i + 3) {
            netboot_mac[i]=':';
        }
        /* remove "01:" ethernet prefix */
        strncpy(netboot_mac, &netboot_mac[3], 18);
        netboot_mac[18] = '\0';
        fprintf(flog, "   netboot MAC:%s\n", netboot_mac);
        medium_boot = network;
    }
}


/* On netboot, we know which interface to use from mac address, so search that one */
static int find_boot_itf(void)
{
    char *mac_addr = NULL;
    int i = -1;

    do {
        i++;
        snprintf(command, STRING_SIZE, "eth%d", i);
        mac_addr = strdup(getmac(command));
    } while ((i < numnetwork) && (strcmp(mac_addr, netboot_mac)));
    if (strcmp(mac_addr, netboot_mac)) {
        fprintf(flog, "Failed to find boot interface\n");
        return FAILURE;
    } else {
        fprintf(flog, "eth%d is the boot interface\n", i);
        snprintf(itf_name, STRING_SIZE, "eth%d", i);
        return SUCCESS;
    }
}

static void build_network_list(void)
{
    int i = 0;
    networks = realloc(networks, sizeof(struct network_s) * (numnetwork + 1));

    for (i = 0; i < numnetwork; i++) {
        snprintf(command, STRING_SIZE, "eth%d", i);
        networks[i].device = strdup(command);
        networks[i].address = strdup(getmac(command));
        /* some ISA drivers does not supply the module name */
        char *kernelmodule = getkernelmodule(command);
        if (!kernelmodule[0]) {
            networks[i].module = strdup("");
            fprintf(flog, "  no kernel module found for device %s\n", command);
        } else {
            networks[i].module = strdup(kernelmodule);
        }
        /* module is the last as length vary */
        fprintf(flog, "  found device:%s MAC:%s  %s\n", networks[i].device, networks[i].address, networks[i].module);
    }
}


static int find_network_by_dhcp(int itf)
{
    char string[STRING_SIZE];
    snprintf(command, STRING_SIZE, "udhcpc -q -n -T 3 -A 1 -t 3 -i eth%d -s /usr/bin/udhcpc.script > /dev/null", itf);
    if (mysystem(command)) {
        fprintf(flog, "udhcpc fail with eth%d\n", itf);
        return FAILURE;
    }
    /* The DHCP server could very well be our http/ftp server,
     * if not probably close enough to present it's IP */
    NODEKV *kv_dhcp_params = NULL;

    snprintf(string, STRING_SIZE, "/etc/dhcp-eth%d.params", itf);
    if (read_kv_from_file(&kv_dhcp_params, string)) {
        return FAILURE;
    }
    snprintf(itf_name, STRING_SIZE, "eth%d", itf);
    if (find_kv(kv_dhcp_params, "SERVERID") == NULL) {
        fprintf(flog, "udhcpc SERVERID not found\n");
        return FAILURE;
    }
    strcpy(server_IP, find_kv(kv_dhcp_params, "SERVERID"));
    if (find_kv(kv_dhcp_params, "IP") == NULL) {
        fprintf(flog, "udhcpc IP not found\n");
        return FAILURE;
    }
    strcpy(local_IP, find_kv(kv_dhcp_params, "IP"));
    if (find_kv(kv_dhcp_params, "NETMASK") == NULL) {
        fprintf(flog, "udhcpc NETMASK not found\n");
        return FAILURE;
    }
    strcpy(netmask, find_kv(kv_dhcp_params, "NETMASK"));
    /* domain is not mandatory */
    if (find_kv(kv_dhcp_params, "DOMAIN") == NULL) {
        fprintf(flog, "udhcpc DOMAIN not found\n");
    } else {
        strcpy(domain, find_kv(kv_dhcp_params, "DOMAIN"));
    }
    free_kv(&kv_dhcp_params);
    return SUCCESS;
}


/* Select manually an interface for network install */
static int select_interface(void)
{
    int i, rc;
    int done = 0;
    int choice = 0;
    char *interfacelist[CFG_COLOURS_COUNT];

    for (i = 0; i < numnetwork; i++) {
        interfacelist[i] = malloc(STRING_SIZE +1);
        snprintf(interfacelist[i], STRING_SIZE, "%s MAC:%s  %s", networks[i].device, networks[i].address, networks[i].module);
    }
    interfacelist[i] = NULL;
    while (done == 0) {
        rc = newtWinMenu(gettext("TR_INTERFACE_SELECTION"),
                         gettext("TR_INTERFACE_SELECTION_LONG"), 65, 5, 5, 6,
                         interfacelist, &choice, gettext("TR_OK"), gettext("TR_GO_BACK"), NULL);

        if ((rc == 0) || (rc == 1)) {
            strcpy(itf_name, networks[choice].device);
            done = 1;
        } else {
            done = 2;       /* canceled by user */
        }
    }
    for (i = 0; i < numnetwork; i++) {
        free(interfacelist[i]);
    }
    if (done == 1 ) {
        fprintf(flog, "  interface %s selected\n",itf_name);
        return SUCCESS;
    } else {
        return FAILURE;
    }
}


/* To ease testing, allow to force dhcp(1) or manual(2) path even on pxe boot
   Just type 'install codepath=(1|2)' */
static void read_codepath(void)
{
    char string[STRING_SIZE];
    char strboot[STRING_SIZE] = "none";

    find_kv_default(kv, "ofwboot", strboot);

    if (find_kv_default(kv, "codepath", string) == SUCCESS) {
        if (!strcmp(string, "1") || !strcmp(string, "2")) {
            codepath = atoi(string);
        } else {
            fprintf(flog, "Bad codepath value\n");
        }
    }
}


/*
  ISO from http/ftp server
  TODO offer a manual / automatic configuration selection
  dhcp server may not be on the same network as the http/ftp server
  modprobe all found network cards
  - first check netboot values (on x86 only for now)
  - secondly start DHCP client on all interfaces
  - third offer a manual solution
  Use wget --spider to test presence of files only,
  at this time in installation we can only store in /tmp (RAM),
  so wait until we've selected a harddisk to fetch the files.
*/
static int source_network(void)
{
    int i = 0;
    int rc;
    char *values[] = { "http://" DEFAULT_IP "/iso", NULL };        /* pointers for the values. */
    static int changed_green = 0;       /* IP and netmask green       */
    char *tmpstring;

    if (numnetwork == 0) {
        fprintf(flog, "Fail to discover at least one network card\n");
        return FAILURE;
    }

    /* Put up status screen here, modprobing can take some time */
    statuswindow(72, 5, ofw_gettext("TR_TITLE_SOURCE"), ofw_gettext("TR_SEARCH_NETWORKS"));

    /* load net drivers from discovered hardware */
    for (i = 0; i < numhardwares; i++) {
        if (hardwares[i].type == network) {
            snprintf(command, STRING_SIZE, "modprobe %s", hardwares[i].module);
            mysystem(command);
        }
    }
    /* on netboot (x86 only now), we already have our own IP, server IP, netmask */
    if (strlen(local_IP) > 0) {
        if (find_boot_itf()) {
            fprintf(flog, "Fail to discover pxe boot nic\n");
        }
    }

    build_network_list();
    newtPopWindow();

    /* if local IP has not been found by pxe, try to find by dhcp */
    if (strlen(local_IP) == 0 || codepath == 1) {
        newtComponent *f;
        newtComponent scale;
        f = (newtComponent *) statuswindow_progress(72, 5, ofw_gettext("TR_TITLE_SOURCE"),
                                                    ofw_gettext("TR_SEARCH_NETWORKS"));
        scale = newtScale(1, 3, 70, 100);
        newtFormAddComponent(*f, scale);
        newtDrawForm(*f);
        newtScaleSet(scale, 1);     /* to display the bar on first detection */
        newtRefresh();
        /* FIXME be smarter if the machine is connected to more than one dhcp server */
        /* we actually keep only the last discovered server */
        /* we don't need to try disconnected cards */
        for (i = 0; i < numnetwork; i++) {
            /* 3 probes at approx. 3 second interval with 1 second pause after failure should suffice */
            if (!find_network_by_dhcp(i)) {
                fprintf(flog, "Found dhcp server at eth%d\n", i);
            }
            newtScaleSet(scale, (i+1) * 100 / numnetwork);
            newtRefresh();
        }
        newtPopWindow();
    }
    /* manual selection */
    if (strlen(local_IP) == 0 || codepath == 2) {
        /* if local IP still not configured, first select which interface to use */
        if (select_interface()) {
            fprintf(flog, "failure for manual interface selection\n");
            return FAILURE;
        }
        if (read_kv_from_file(&eth_kv, "/etc/ethernetsettings") != SUCCESS) {
            free_kv(&eth_kv);
            errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
            return FAILURE;
        }
        update_kv(&eth_kv, "GREEN_COUNT", "0");
        /* set IP netmask */
        changeaddress("GREEN", &changed_green);
    }

    /* configure the selected interface */
    snprintf(command, STRING_SIZE, "ifconfig %s %s netmask %s up", itf_name, local_IP, netmask);
    if (mysystem(command)) {
        /* workaround gcc warning, there is really 1 %s there */
        tmpstring = strdup(gettext("TR_INTERFACE_FAIL_TO_GET_UP_CR"));
        snprintf(message, STRING_SIZE, tmpstring, itf_name);
        free(tmpstring);
        errorbox(message);
        return FAILURE;
    }

    /* check local_IP is not already used by another machine */
    statuswindow(72, 5, ofw_gettext("TR_TITLE_SOURCE"), ofw_gettext("TR_VERIFYING_IP"));
    snprintf(command, STRING_SIZE, "ping %s", local_IP);
    rc = mysystem(command);
    newtPopWindow();
    if (rc == 0) {
        /* workaround gcc warning, there is really 2 %s there */
        tmpstring = strdup(gettext("TR_IP_ALREADY_IN_USE"));
        snprintf(message, STRING_SIZE, tmpstring, local_IP, itf_name);
        free(tmpstring);
        errorbox(message);
        return FAILURE;
    }

    if (strlen(server_IP) > 0) {
        snprintf(command, STRING_SIZE, "http://%s/iso", server_IP);
        values[0] = command;
    }

    char filename[STRING_SIZE];
    while (1) {
        struct newtWinEntry entries[] = { {"", &values[0], 0,}, {NULL, NULL, 0} };
        snprintf(message, STRING_SIZE_LARGE, ofw_gettext("TR_ENTER_URL_FILE"), TARBALL_OFW);
        rc = newtWinEntries(ofw_gettext("TR_TITLE_SOURCE"), message,
                            65, 5, 5, 50, entries, ofw_gettext("TR_OK"), ofw_gettext("TR_GO_BACK"), NULL);
        strncpy(message, values[0], STRING_SIZE);
        fprintf(flog, "URL is %s\n", message);

        if (rc == 2) {
            return FAILURE;     // give up (go back pressed)
        }

        if (strlen(message) == 0)
            continue;           // empty url entered, try again

        /* remove any successive /'s */
        while (message[strlen(message) - 1] == '/')
            message[strlen(message) - 1] = '\0';

        strcpy(network_source, message);
        statuswindow(72, 5, ofw_gettext("TR_TITLE_SOURCE"), ofw_gettext("TR_CHECKING"));

        /* just verify if files exist, download later */
        strcpy(filename, TARBALL_OFW);
        snprintf(command, STRING_SIZE, "wget --spider -O /tmp/%s %s/%s", filename, network_source, filename);
        rc = mysystem(command);
        newtPopWindow();
        if (!rc) {
            fprintf(flog, "NETWORK INSTALL checked tarball URLs\n");
            return SUCCESS;
        }

        /* spider failed, inform user */
        snprintf(message, STRING_SIZE, ofw_gettext("TR_TAR_GZ_NOT_FOUND"), filename, network_source);
        errorbox(message);
    }
}

/*
  Loop through all found hardware and test cdroms.
  If source CD (or USB stick) found, symlink the device to /dev/cdrom and mount at /cdrom.
*/
static int source_cdrom(void)
{
    int i;
    char filename[STRING_SIZE];
    char filepath[STRING_SIZE];

    statuswindow(72, 5, ofw_gettext("TR_TITLE_SOURCE"), ofw_gettext("TR_MOUNTING_CDROM"));

    for (i = 0; i < numhardwares; i++) {
        if ((hardwares[i].type == cdrom) || 
              ((hardwares[i].type == harddisk) && (hardwares[i].device[0] == 's'))) {

            /*  We need to try different partitions here
                hd?, sd? and sr? for IDE CD, usb-fdd and SCSI,SATA CD
                sd?1 for usb-hdd
                sd?4 for usb-zip
            */
            int j;

            fprintf(flog, "Testing CD/USB device %s\n", hardwares[i].device);

            for (j = 0; j < 3; j++) {
                char test_partitions[3] = { ' ', '1', '4' };
                char test_device[STRING_SIZE];

                snprintf(test_device, STRING_SIZE, "%s%c", hardwares[i].device, test_partitions[j]);

                snprintf(command, STRING_SIZE, "ln -sf /dev/%s /dev/cdrom", test_device);
                if (mysystem(command)) {
                    fprintf(flog, "Couldn't create /dev/cdrom\n");
                    continue;
                }

                snprintf(command, STRING_SIZE, "/bin/mount -o ro /dev/%s /cdrom", test_device);
                if (mysystem(command)) {
                    fprintf(flog, "Failed to mount CDROM on device %s\n", test_device);
                    continue;
                }

                /* Let us see if this is an Openfirewall CD or USB key */
                strcpy(filename, TARBALL_OFW);
                snprintf(filepath, STRING_SIZE, "/cdrom/%s", filename);
                if (!access(filepath, 0)) {
                    /* TODO: some fancy test (md5 ?) to verify CD */
                    newtPopWindow();
                    if (hardwares[i].type == harddisk) {
                        /* USB key, change type to remove from destination selection list */
                        hardwares[i].type = cdrom;
                    }
                    medium_sources = cdrom;
                    scsi_cdrom = (hardwares[i].device[0] == 's');
                    fprintf(flog, "Source tarball found on device %s\n", test_device);
                    return SUCCESS;
                }

                /* It is a CD (or something) but not ours */
                fprintf(flog, "No targz found on device %s\n", test_device);
                mysystem("/bin/umount /cdrom");
            }

            /* Tried all variations on this dev */
        }
    }

    newtPopWindow();
    fprintf(flog, "no cdroms\n");
    errorbox(ofw_gettext("TR_NO_CDROM"));

    return FAILURE;
}


/*
    Select source (CDROM / HTTP)
    set medium_source accordingly
*/
static int findsource(void)
{
    char *installtypes[] = { "CDROM/USB-KEY", "HTTP/FTP", NULL };
    int installtype;        /* depending on menu, 0 = cdrom, 1 = http/ftp */
    int i, rc;
    int numnetworks = 0;
    char line[STRING_SIZE_LARGE];


    if ((medium_boot == cdrom) || (medium_boot == usb)) {
        if (source_cdrom() == SUCCESS) {
            /* We boot from media with all we need, no point to ask for HTTP/FTP install */
            return SUCCESS;
        }
    }

    for (i = 0; i < numhardwares; i++) {
        if (hardwares[i].type == network)
            numnetworks++;
    }

    if (medium_boot == network) {
        /* Set default selection for source to http/ftp */
        installtype = 1;
    }
    else {
        installtype = 0;
    }

    /* Choose source for tarball. Very basic. */
    while (1) {
        snprintf(line, STRING_SIZE_LARGE, ofw_gettext("TR_SELECT_INSTALLATION_MEDIA_LONG"), NAME);
        rc = newtWinMenu(ofw_gettext("TR_TITLE_SOURCE"),
                         line, 65, 5, 5, 8,
                         installtypes, &installtype, ofw_gettext("TR_OK"), ofw_gettext("TR_CANCEL"), NULL);
        if (rc == 2) {
            return FAILURE;     // give up
        }

        if (installtype == 1) {
            if (source_network() == SUCCESS) {
                medium_sources = network;
                return SUCCESS;
            }
        }
        else {
            if (source_cdrom() == SUCCESS) {
                medium_sources = cdrom;
                return SUCCESS;
            }
        }
    }
}


/* Choose a destination disk (harddisk, cf?) and verify it can support Openfirewall */
int selectdestination(int *ddisk, int *ddisk2, long int *disk_size, long int *ramdisk_size)
{
    int rc;
    char string[STRING_SIZE];
    FILE *handle;
    char **harddisklist = NULL;
    int i;
    int c;
    int raid;               // 0 = no raid, 1 = working on disk 1, 2 = working on disk 2

    int disklist[3];
    long int disksize[3];

    /* Loop until user chooses cancel or proper disk is choosen. */
    while (1) {

        if (harddisklist != NULL) {
            /* Zap harddisklist */
            for (i = 0; harddisklist[i] != NULL; i++) {
                free(harddisklist[i]);
                harddisklist[i] = NULL;
            }
        }

        for (c = 0, i = 0; i < numhardwares; i++) {
            if (hardwares[i].type == harddisk) {
                snprintf(string, STRING_SIZE, "%s: %s", hardwares[i].device, hardwares[i].description);
                harddisklist = realloc(harddisklist, sizeof(char *) * (c + 1));
                harddisklist[c] = strdup(string);
                c++;
            }
        }

        if ((c >= 2) && (access("/sbin/mdadm", 0) == 0)) {
            harddisklist = realloc(harddisklist, sizeof(char *) * (c + 1));
            harddisklist[c] = strdup("Software RAID");
            c++;
        }

        /* end with a null pointer */
        harddisklist = realloc(harddisklist, sizeof(char *) * (c + 1));
        harddisklist[c] = NULL;
        raid = 0;
        disklist[0] = 0;
        disklist[1] = 0;
        disklist[2] = 0;
        disksize[0] = 0;
        disksize[1] = 0;
        disksize[2] = 0;

NEXTDISK:
        /* Default to the first disk */
        c = 0;

        // Choose the disk to use
        switch (raid) {
        case 0:
            strcpy(string, ofw_gettext("TR_TITLE_DISK"));
            break;
        case 1:
            strcpy(string, "RAID disk 1");
            break;
        case 2:
            strcpy(string, "RAID disk 2");
            break;
        }
        rc = newtWinMenu(string, ofw_gettext("TR_SELECT_DEVICE_FOR_INSTALLATION"),
                         65, 5, 5, 8, harddisklist, &c, 
                         ofw_gettext("TR_OK"), (raid != 0) ? ofw_gettext("TR_GO_BACK") : ofw_gettext("TR_CANCEL"), NULL);

        if ((rc == 2) && (raid == 0))   // cancel choosed!
            return FAILURE;
        if (rc == 2)                    // go back choosed but already selected something, try again Sam
            continue;

        if (!strcmp(harddisklist[c], "Software RAID")) {
            raid = 1;
            free(harddisklist[c]);
            harddisklist[c] = NULL;
            goto NEXTDISK;
        }

        disklist[raid] = -1;
        /* retrieve selection from hardwares list */
        for (i = 0; i < numhardwares; i++) {
            if (!strncmp(harddisklist[c], hardwares[i].device, 3)) {
                disklist[raid] = i;
                break;
            }
        }
        /* should not happen, should it ? */
        if (disklist[raid] == -1) {
            fprintf(flog, "WOW, error 42\n");
            return FAILURE;
        }

        sprintf(string, "/sys/block/%s/size", hardwares[disklist[raid]].device);
        /* Calculate amount of disk space */
        handle = fopen(string, "r");
        if (fgets(string, STRING_SIZE - 1, handle)) {
            /* Value is in 512 byte sectors, convert to MiB */
            disksize[raid] = strtoull(string, NULL, 10) >> 11;
        }
        fclose(handle);

        if (disksize[raid] < DISK_MINIMUM) {
            fprintf(flog, "HARDDISK %s: really too small.\n", hardwares[disklist[raid]].device);
            errorbox(ofw_gettext("TR_DISK_TOO_SMALL"));
            continue;           // give option to choose another disk
        }
        fprintf(flog, "Hard disk selected %s. Size:%ld MiB\n", hardwares[disklist[raid]].device, disksize[raid]);

        if (raid == 1) {
            raid = 2;
            free(harddisklist[c]);
            while (harddisklist[c+1] != NULL) {
                harddisklist[c] = harddisklist[c+1];
                c++;
            }
            harddisklist[c] = NULL;
            goto NEXTDISK;
        }

        /* warn about disk destroying and ask for (additional) confirmation */
        rc = newtWinChoice(ofw_gettext("TR_TITLE_DISK"),
                           ofw_gettext("TR_GO_BACK"), ofw_gettext("TR_OK"),
                           ofw_gettext("TR_CONFIRM_DEVICE_INSTALLATION"));

        if (rc != 2) {
            fprintf(flog, "Installation cancelled by user.\n");
            continue;           // give option to choose another disk
        }

        if (raid) {
            *ddisk = disklist[1];
            *ddisk2 = disklist[2];
            *disk_size = (disksize[1] < disksize[2]) ? disksize[1] : disksize[2];
            fprintf(flog, "RAID size:%ld MiB\n", *disk_size);
        }
        else {
            *ddisk = disklist[0];
            *ddisk2 = 0;
            *disk_size = disksize[0];
        }

        while (1) {
            /* Should this be a harddisk or flash installation? */
            medium_target = harddisk;

            rc = newtWinTernary(ofw_gettext("TR_TITLE_DISK"),
                                ofw_gettext("TR_HARDDISK"), ofw_gettext("TR_FLASH"), ofw_gettext("TR_GO_BACK"),
                                ofw_gettext("TR_HARDDISK_FLASH_LONG"));

            if (rc == 3) {
                /* Cancel */
                break;
            }

            if (rc == 1) {
                /* Harddisk */
                return SUCCESS;
            }

            if (rc == 2) {
                /* Flash choosen, test for and ask wanted RAM disk size */

                /*  First check for enough RAM available, set a minimum of 96 MiB 
                 *  check for value slightly below 96, since kernel reported memory is not 96 */
                if (memtotal < 90) {
                    snprintf(message, STRING_SIZE, ofw_gettext("TR_FLASH_NOT_ENOUGH_MEMORY"), 96);
                    errorbox(message);
                    continue;
                }

                /* Calculate a default value, 50% of total memory rounded to 16 MB block */
                snprintf(string, STRING_SIZE, "%d", ((memtotal+15)/16) * 8);
                while (1) {
                    char *values[] = { string, NULL };
                    struct newtWinEntry entries[] =
                        { {gettext("TR_SIZE_MB"), &values[0], 0,}, {NULL, NULL, 0} };


                    rc = newtWinEntries(gettext("TR_TITLE_DISK"), gettext("TR_RAMDISKSIZE_LONG"),
                                        65, 5, 5, 10, entries, gettext("TR_OK"), gettext("TR_GO_BACK"), NULL);

                    if (rc == 2) {
                        break;
                    }
                    *ramdisk_size = atoi(values[0]);

                    /* Verify against minimum sensible size and total available memory here.
                       Maximize against total memory minus 16 MiB, though we probably need more than 16 MiB. */
                    if ((strlen(values[0]) < 5) && (*ramdisk_size >= 32) && (*ramdisk_size <= (memtotal - 16))) {
                        medium_target = flash;
                        fprintf(flog, "FLASH installation, RAM disk size wanted: %ld MiB\n", *ramdisk_size);
                        return SUCCESS; // OK flash      
                    }
                }
            }
        }
    }

    /* We will not get this far. */
}


int main(int argc, char **argv)
{
    FILE *handle;
    char line[STRING_SIZE_LARGE];       //general purpose buffer
    int restore_success = SUCCESS;
    int rc;

    /* read the parameters from the kernel cmdline */
    if (!(handle = fopen("/proc/cmdline", "r"))) {
        /* This must succeed, what do to in error case? */
        fprintf(stderr, "FATAL ERROR: Cannot read /proc/cmdline");
        exit(1);
    }

    if (fgets(line, STRING_SIZE, handle) == NULL) {
        printf("/proc/cmdline is empty");
        read_kv_from_line(&kv, "");
    }
    else {
        read_kv_from_line(&kv, line);
    }
    fclose(handle);

    if (find_kv(kv, "console") == NULL) {
        /* Standard console, business as usual. */
        if (!(flog = fopen("/dev/tty2", "w+"))) {
            printf("Failed to open /dev/tty2 for logging\n");
            exit(0);
        }
        fstderr = freopen("/dev/tty3", "w+", stderr);
        medium_console = console;
    }
    else {
        /* Special console, do not use tty2/tty3 but temporary files. */
        flog = fopen("/tmp/flog", "w");
        fstderr = freopen("/tmp/fstderr", "w", stderr);
        medium_console = serial;
        serial_commandline = strdup(find_kv(kv, "console"));

        /* serial_commandline is of format ttyS0,38400n81 */
        /* TODO: make some better test */
        serial_console = serial_commandline[4] - '0';
        serial_bitrate = atoi(serial_commandline+6);
    }

    /* Small information about these consoles. */
    fprintf(flog, "Logging from installer.\n");
    fprintf(fstderr, "Error messages and more logging from installer.\n");

    helper_kernel_init();

    /* Want our tester have a better coverage of the code path */
    read_codepath();   /* actually only force dhcp or manual path on pxe boot */
    /* On x86 netboot, read own IP, tftp server IP, dhcp server IP, netmask and boot MAC */
    read_netboot_values();

    /* Determine total memory */
    if ((handle = fopen("/proc/meminfo", "r"))) {
        while (fgets(line, STRING_SIZE, handle)) {
            char value[STRING_SIZE];

            if (sscanf(line, "MemTotal: %s kB", value)) {
                memtotal = atoi(value) / 1024;
            }
        }
        fclose(handle);
    }
    fprintf(flog, "MemTotal is %d MB\n", memtotal);

    /* Determine boot medium, in case of i486 with netboot it is already detected */
    if (medium_boot == unknown) {
        if (access("/CDROMBOOT", 0) != -1) {
            /* CDROM, NET, USB key, boot floppy + CDROM detected */
            char strboot[STRING_SIZE] = "none";

            find_kv_default(kv, "ofwboot", strboot);
            fprintf(flog, "ofwboot=%s\n", strboot);
            if (!strcmp(strboot, "usb")) {
                mysystem("/sbin/modprobe vfat");    /* necessary for usb-key */
                medium_boot = usb;
            }
            else if (!strcmp(strboot, "net")) {
                medium_boot = network;
            }
            else if (!strcmp(strboot, "cdrom")) {
                medium_boot = cdrom;
            }
            else {
                medium_boot = unknown;
            }
        }
        else if (access("/FLOPPYBOOT", 0) != -1) {
            /* boot + root floppy */
            medium_boot = floppy;
        }
    }

    switch(medium_boot) {
    case cdrom:
        fprintf(flog, "Boot is cdrom (or others)\n");
        break;
    case floppy:
        fprintf(flog, "Boot is floppy\n");
        break;
    case network:
        fprintf(flog, "Boot is net\n");
        break;
    case usb:
        fprintf(flog, "Boot is usb\n");
        break;
    case unknown:
    default:
        /* actually this cannot be, boot must have used something */
        fprintf(flog, "Boot is unknown or sparc netboot ?!\n");
        break;
    }

    /* USB keyboard modules are already loaded so no need to load them */
    /* usbcore, ehci_hcd, ohci_hcd, uhci_hcd, hid, usbhid */


    /* fetch boot options, our user may have selected something
       set no* option to 1 to disable detection
     */
    int nopcmcia = 0;
    int nousb = 0;
    int part_options = 0;
    long int swapfilesize = -1;
    int32_t userdisksize = INT32_MAX;
    int manualmodule = 0;
    if (find_kv(kv, "nopcmcia") != NULL) {
        nopcmcia = 1;
        fprintf(flog, "Skip PCMCIA/PC-CARD detection\n");
    }
    if (find_kv(kv, "nousb") != NULL) {
        nousb = 1;
        fprintf(flog, "Skip USB detection\n");
    }
    if (find_kv(kv, "parted") != NULL) {
        part_options |= PART_OPTIONS_PARTED;
        fprintf(flog, "Use parted\n");
    }
    if (find_kv(kv, "partition") != NULL) {
        part_options |= PART_OPTIONS_MANUAL;
        fprintf(flog, "Manual partitioning\n");
    }
    if (find_kv(kv, "nombr") != NULL) {
        part_options |= PART_OPTIONS_NO_MBR;
        fprintf(flog, "Skip MBR\n");
    }
    strcpy(line, "-1");
    if (find_kv_default(kv, "swap", line) == SUCCESS) {
        swapfilesize = atoi(line);
        if ((swapfilesize == 0) || ((swapfilesize >= SWAP_MINIMUM) && (swapfilesize <= SWAP_MAXIMUM))) {
            fprintf(flog, "swapfilesize %ld MiB\n", swapfilesize);
        }
        else {
            fprintf(flog, "Ignoring swapfilesize %ld MiB\n", swapfilesize);
            swapfilesize = -1;
        }
    }
    sprintf(line, "%d", userdisksize);
    if (find_kv_default(kv, "disk", line) == SUCCESS) {
        userdisksize = atoi(line);
        if (userdisksize < DISK_MINIMUM) {
            fprintf(flog, "Ignoring disksize %d MiB\n", userdisksize);
            userdisksize = INT32_MAX;
        }
        else {
            fprintf(flog, "User max. disksize %d MiB\n", userdisksize);
        }
    }
    if (find_kv(kv, "modules") != NULL) {
        manualmodule = 1;
        fprintf(flog, "Manually add kernel module(s)\n");
    }


    newtInit();
    newtCls();

    /* first things first, installer language */
    handlelanguage(kv);
    /* Starting here we have a language selected, use ofw_gettext to get translated texts */

    free_kv(&kv);

    char *install_status = ofw_gettext("TR_INSTALLATION_CANCELED");

    /* Screen setup and welcome window */
    newtDrawRootText(18, 0, get_title());
    newtPushHelpLine(ofw_gettext("TR_HELPLINE"));
    snprintf(line, STRING_SIZE_LARGE, ofw_gettext("TR_WELCOME"), NAME);
    rc = newtWinChoice(get_title(),
                       ofw_gettext("TR_OK"), ofw_gettext("TR_CANCEL"),
                       line);
    if (rc == 2) {
        goto EXIT;
    }

    /*  Set the keyboard if we have the needed files */
    handlekeymap();
    /*  Ask for timezone and give option to modify date&time, 
        this makes sure we have the time correct when partitioning and installing files */
    handletimezone();
    handledatetime();

    // find nics cdrom harddisk & floppies
    scan_hardware(1, nopcmcia, nousb, manualmodule);

    /* any possible target drives found */
    if (numharddisk == 0) {
        errorbox(ofw_gettext("TR_NO_HARDDISK"));
        fprintf(flog, "NO HARDDRIVES\n");
        goto EXIT;
    }

    /* find location of tarballs */
    if (findsource() != SUCCESS) {
        fprintf(flog, "NO Source selected\n");
        goto EXIT;
    }

    /* select destination drive & partition scheme */
    int selected_hd = 0;
    int selected_hd2 = 0;
    long int disk_size = 0;
    long int ramdisk_size = 0;

    if (selectdestination(&selected_hd, &selected_hd2, &disk_size, &ramdisk_size) != SUCCESS) {
        /* CANCEL, too small or some other problem */
        goto EXIT;
    }

    if (userdisksize < disk_size) {
        disk_size = userdisksize;
        fprintf(flog, "Use user selected max. disksize: %ld MiB\n", disk_size);
        part_options |= PART_OPTIONS_USER_SIZE;
    }

    /*  Partition, format, mount, initramfs and make bootable
       manual partitioning if PART_OPTIONS_PARTED set */
    if (make_ofw_disk(hardwares[selected_hd].device, hardwares[selected_hd2].device, disk_size, swapfilesize, part_options) != SUCCESS)
        goto EXIT;


    // Now, /harddisk           is mounted
    //      /harddisk/var/log   is mounted

        fprintf(flog, "Writing MBR 30\n");
    /* Target is up&running so we can store some previously made settings */
    write_lang_configs();
        fprintf(flog, "Writing MBR 31\n");
    write_keymap();
        fprintf(flog, "Writing MBR 32\n");
    write_timezone();
    /* Copy the info about detected HW for later reference */
    mysystem("/bin/cp /tmp/hwdetect /harddisk/var/log/hwdetect");

    if (medium_target == flash) {
        /* Specials for flash disk */
        NODEKV *kv_flash = NULL;
        char value[STRING_SIZE];

        read_kv_from_file(&kv_flash, "/harddisk/var/ofw/main/flashsettings");
        snprintf(value, STRING_SIZE, "%ldM", ramdisk_size);
        update_kv(&kv_flash, "TMPFS_MAX_SIZE", value);
        write_kv_to_file(&kv_flash, "/harddisk/var/ofw/main/flashsettings");

        mysystem("chroot /harddisk /usr/local/sbin/flashfinal.sh");
    }


    /* Some tidbits for serial console */
    if (medium_console == serial) {
        snprintf(line, STRING_SIZE, "echo \"ttyS%u\" >> /harddisk/etc/securetty", serial_console);
        if (system(line)) {
            /* TODO: make this a fatal error ? */
            fprintf(fstderr, "ERROR writing to /etc/inittab\n");
        }

        snprintf(line, STRING_SIZE, "echo \"7:2345:respawn:/sbin/agetty -I '\033(K' ttyS%u %u vt102\" >> /harddisk/etc/inittab",
            serial_console, serial_bitrate);
        if (system(line)) {
            /* TODO: make this a fatal error ? */
            fprintf(fstderr, "ERROR writing to /etc/inittab\n");
        }
    }

        fprintf(flog, "Writing MBR 40\n");
    /* Offer restore here, if no restore -> launch setup later */
    restore_success = handlerestore();

    /* Installation is done, time to congratulate and then turn to configuration */
    snprintf(message, STRING_SIZE_LARGE, ofw_gettext("TR_CONGRATULATIONS_LONG"), NAME, SNAME, SNAME, NAME, NAME, NAME);
    newtWinMessage(get_title(), ofw_gettext("TR_CONGRATULATIONS"), message);

    if ((medium_sources == network) && (restore_success == FAILURE)) {
        /* running udhcp may have given us some acceptable defaults */
        mysystem("[ -e /etc/dhcp-eth*.params ] && /bin/cp /etc/dhcp-eth*.params /harddisk/tmp/");
    }
    else if (medium_sources == cdrom) {
        mysystem("/bin/umount /cdrom");
    }

    /* Now that we've unmounted the cdrom, try to eject it 
        If we use medium_boot here, we would also eject when installing from other media,
        since CDROM, PXE and USB source have the CDROMBOOT flagfile */
    if (medium_sources == cdrom) {
        if (scsi_cdrom) {
            /* Might need something additionally/different here */
            strcpy(line, "eject -s /dev/cdrom");
        }
        else {
            strcpy(line, "eject /dev/cdrom");
        }

        if (mysystem(line)) {
            errorbox(ofw_gettext("TR_UNABLE_TO_EJECT_CDROM"));
        }
    }

    if (restore_success == FAILURE) {
        unlink("/harddisk/tmp/udevsed.sh");
        mysystem("/bin/touch /harddisk/tmp/udevsed.sh");

        /* Run setup to configure remaining bits & pieces */
        snprintf(command, STRING_SIZE, "chroot /harddisk /usr/local/sbin/setup --install %s", 
            (medium_console == serial) ? "--serial" : "");
        if (system(command))
            printf("Unable to run setup.\n");
    }

    // All done, just have to unmount everything...
    statuswindow(72, 5, get_title(), ofw_gettext("TR_UNMOUNTING"));

    mysystem("swapoff -a");
    mysystem("/bin/umount -n /harddisk/tmp");

    /* No need to make this complicated, we know what we've mounted */
/*
    mysystem("/bin/umount -n /harddisk/boot");
    if (medium_target == flash) {
        mysystem("/bin/umount -n /harddisk/var/log_compressed");
    }
    else {
        mysystem("/bin/umount -n /harddisk/var/log");
    }
    if (access("/proc/mdstat", 0) == 0) {
        mysystem("/sbin/mdadm --stop --scan");
        sleep(2);
    }
    mysystem("/bin/mount  -n -o remount,ro /harddisk/");
*/
    newtPopWindow();
    install_status = ofw_gettext("TR_CONGRATULATIONS");

  EXIT:

    if (restore_success == FAILURE) {
        /* install_status can be TR_CONGRATULATIONS or TR_INSTALLATION_CANCELED */
        newtWinMessage(get_title(), ofw_gettext("TR_OK"), install_status);
    }

    newtFinished();
    fclose(flog);
    fclose(fstderr);
    if (system("/etc/halt")) {
        /* Can /etc/halt fail ?  What now ? */
    }
    while (1);
    return 0;
}
