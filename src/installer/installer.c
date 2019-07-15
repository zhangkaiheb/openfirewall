/*
 * main.c: installer main loop
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 * Written by Alan Hourihane <alanh@fairlite.demon.co.uk>
 *
 * (c) 2017-2020, the Openfirewall Team
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
#define  gettext  lang_gettext


/* global variables */
installer_setup_t flag_is_state = INST_INSTALLER;
//int medium_boot = MT_UNKNOWN;
static int medium_sources = MT_NONE;
static int medium_target = MT_NONE;
static int medium_console = MT_CONSOLE;
char network_source[STRING_SIZE];
//unsigned int memtotal = 0;                  /* Total memory in MB */
char *serial_commandline = NULL;

unsigned int serial_console = 0;
unsigned int serial_bitrate = 9600;


/* local variables */
static int codepath = 0;                    /* for better test, allow testing dhcp and manual path even on pxe boot */
static NODEKV *kv = NULL;                   /* contains a list key=value pairs from boot parameters */
//static char command[STRING_SIZE];
//static char message[STRING_SIZE_LARGE];
static int scsi_cdrom;
static char local_IP[STRING_SIZE] = "";
static char server_IP[STRING_SIZE] = "";    /* http/ftp server to install from network */
static char itf_name[STRING_SIZE] = "";     /* interface to install */
static char netboot_dhcp_IP[STRING_SIZE] = "";
static char netmask[STRING_SIZE] = "";
static char netboot_mac[STRING_SIZE] = "";
static char domain[STRING_SIZE] = "";
static struct network_dev_s *inst_networks;


int inst_get_medium_console(void)
{
	return medium_console;
}

int inst_get_medium_target(void)
{
	return medium_target;
}

int inst_get_medium_sources(void)
{
	return medium_sources;
}

char *inst_get_serial_commandline(void)
{
	return serial_commandline;
}

static unsigned int inst_get_sys_memory(void)
{
	FILE *handle;
	char line[STRING_SIZE_LARGE];
	unsigned int memtotal = -1;

	if ((handle = fopen("/proc/meminfo", "r"))) {
		while (fgets(line, STRING_SIZE, handle)) {
			char value[STRING_SIZE];

			if (sscanf(line, "MemTotal: %s kB", value)) {
				memtotal = atoi(value) / 1024;
			}
		}
		fclose(handle);
	}

	return memtotal;
}

/* On x86 netboot, read cmdline value
   With sparc netboot cdmline is empty,
   we may find something looking at openpromfs (currently built-in)
*/
static int inst_read_netboot_params(void)
{
	int i = 0;
	char *buffer = NULL;
	char cmd[STRING_SIZE];
	int netboot = 0;

	if (find_kv_default(kv, "ip", cmd) == SUCCESS) {
		buffer = strtok(cmd, ":" );
		if (buffer) {
			strcpy(local_IP, buffer);
			buffer = strtok(NULL, ":");
			if (buffer) {
				strcpy(server_IP, buffer);
				buffer = strtok(NULL, ":");
				if (buffer) {
					strcpy(netboot_dhcp_IP, buffer);
					buffer = strtok(NULL, ":");
					if (buffer) {
						strcpy(netmask, buffer);
					}
				}
			}
		}
		F_LOG("       netmask:%s\n    netboot IP:%s\n"
				"TFTP server IP:%s\nDHCP server IP:%s\n",
				netmask, local_IP, server_IP, netboot_dhcp_IP);
		//medium_boot = MT_NETWORK;
		netboot = 1;
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
		F_LOG("   netboot MAC:%s\n", netboot_mac);
		//medium_boot = MT_NETWORK;
		netboot = 1;
	}

	return (netboot ? MT_NETWORK : MT_UNKNOWN);
}


static int inst_find_boot_medium(void)
{
	int boot_mt;

    /* On x86 netboot, read own IP, tftp server IP, dhcp server IP, netmask and boot MAC */
    boot_mt = inst_read_netboot_params();

    /* Determine boot medium, in case of i486 with netboot it is already detected */
    if (boot_mt == MT_UNKNOWN) {
        if (access("/CDROMBOOT", F_OK) != -1) {
            /* CDROM, NET, USB key, boot floppy + CDROM detected */
            char strboot[STRING_SIZE] = "none";

            find_kv_default(kv, "ofwboot", strboot);
            F_LOG("ofwboot=%s\n", strboot);
            if (!strcmp(strboot, "usb")) {
                mysystem("/sbin/modprobe vfat");    /* necessary for usb-key */
                boot_mt = MT_USB;
            }
            else if (!strcmp(strboot, "net")) {
                boot_mt = MT_NETWORK;
            }
            else if (!strcmp(strboot, "cdrom")) {
                boot_mt = MT_CDROM;
            }
            else {
                boot_mt = MT_UNKNOWN;
            }
        }
//        else if (access("/FLOPPYBOOT", F_OK) != -1) {
//            /* boot + root floppy */
//            boot_mt = MT_FLOPPY;
//        }
    }

    switch (boot_mt) {
    case MT_CDROM:
        F_LOG("Boot is cdrom (or others)\n");
        break;
//    case MT_FLOPPY:
//        F_LOG("Boot is floppy\n");
//        break;
    case MT_NETWORK:
        F_LOG("Boot is net\n");
        break;
    case MT_USB:
        F_LOG("Boot is usb\n");
        break;
    case MT_UNKNOWN:
    default:
        /* actually this cannot be, boot must have used something */
        F_LOG("Boot is unknown or sparc netboot ?!\n");
        break;
    }
	return boot_mt;
}

static void inst_parse_kv_params(int *nopcmcia, int *nousb, int *part_options,
			long int *swapfilesize, int32_t *userdisksize, int *manualmodule)
{
    char line[STRING_SIZE_LARGE];

    if (find_kv(kv, "nopcmcia") != NULL) {
        *nopcmcia = 1;
        F_LOG("Skip PCMCIA/PC-CARD detection\n");
    }
    if (find_kv(kv, "nousb") != NULL) {
        *nousb = 1;
        F_LOG("Skip USB detection\n");
    }
    if (find_kv(kv, "parted") != NULL) {
        *part_options |= PART_OPTIONS_PARTED;
        F_LOG("Use parted\n");
    }
    if (find_kv(kv, "partition") != NULL) {
        *part_options |= PART_OPTIONS_MANUAL;
        F_LOG("Manual partitioning\n");
    }
    if (find_kv(kv, "nombr") != NULL) {
        *part_options |= PART_OPTIONS_NO_MBR;
        F_LOG("Skip MBR\n");
    }
    strcpy(line, "-1");
    if (find_kv_default(kv, "swap", line) == SUCCESS) {
        *swapfilesize = atoi(line);
        if ((*swapfilesize == 0) ||
			((*swapfilesize >= SWAP_MINIMUM) && (*swapfilesize <= SWAP_MAXIMUM))) {
            F_LOG("swapfilesize %ld MiB\n", *swapfilesize);
        }
        else {
            F_LOG("Ignoring swapfilesize %ld MiB\n", *swapfilesize);
            *swapfilesize = -1;
        }
    }
    sprintf(line, "%d", *userdisksize);
    if (find_kv_default(kv, "disk", line) == SUCCESS) {
        *userdisksize = atoi(line);
        if (*userdisksize < DISK_MINIMUM) {
            F_LOG("Ignoring disksize %d MiB\n", *userdisksize);
            *userdisksize = INT32_MAX;
        }
        else {
            F_LOG("User max. disksize %d MiB\n", *userdisksize);
        }
    }
    if (find_kv(kv, "modules") != NULL) {
        *manualmodule = 1;
        F_LOG("Manually add kernel module(s)\n");
    }
}


/* On netboot, we know which interface to use from mac address, so search that one */
static int inst_find_boot_itf(void)
{
	char *mac_addr = NULL;
	int i = -1;
	char buf[STRING_SIZE];

	do {
		i++;
		snprintf(buf, STRING_SIZE, "eth%d", i);
		mac_addr = strdup(helper_getmac(buf));
	} while ((i < hw_get_network_num()) && (strcmp(mac_addr, netboot_mac)));

	if (strcmp(mac_addr, netboot_mac)) {
		F_LOG("Failed to find boot interface\n");
		return FAILURE;
	} else {
		F_LOG("eth%d is the boot interface\n", i);
		snprintf(itf_name, STRING_SIZE, "eth%d", i);
		return SUCCESS;
	}
}

static void inst_build_network_list(void)
{
	int i = 0;
	char buf[STRING_SIZE];

	inst_networks = realloc(inst_networks,
			sizeof(struct network_dev_s) * (hw_get_network_num() + 1));

	for (i = 0; i < hw_get_network_num(); i++) {
		snprintf(buf, STRING_SIZE, "eth%d", i);
		inst_networks[i].device = strdup(buf);
		inst_networks[i].address = strdup(helper_getmac(buf));
		/* some ISA drivers does not supply the module name */
		char *kernel_mod = helper_kernel_get_netdev_info(buf);
		if (!kernel_mod[0]) {
			inst_networks[i].module = strdup("");
			F_LOG("  no kernel module found for device %s\n", buf);
		} else {
			inst_networks[i].module = strdup(kernel_mod);
		}
		/* module is the last as length vary */
		F_LOG("  found device:%s MAC:%s  %s\n", inst_networks[i].device,
				inst_networks[i].address, inst_networks[i].module);
	}
}


static int inst_find_network_by_dhcp(int itf)
{
    char string[STRING_SIZE];
	char buf[STRING_SIZE];

    snprintf(buf, STRING_SIZE,
			"udhcpc -q -n -T 3 -A 1 -t 3 -i eth%d -s /usr/bin/udhcpc.script > /dev/null",
			itf);
    if (mysystem(buf)) {
        F_LOG("udhcpc fail with eth%d\n", itf);
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
        F_LOG("udhcpc SERVERID not found\n");
        return FAILURE;
    }
    strcpy(server_IP, find_kv(kv_dhcp_params, "SERVERID"));
    if (find_kv(kv_dhcp_params, "IP") == NULL) {
        F_LOG("udhcpc IP not found\n");
        return FAILURE;
    }
    strcpy(local_IP, find_kv(kv_dhcp_params, "IP"));
    if (find_kv(kv_dhcp_params, "NETMASK") == NULL) {
        F_LOG("udhcpc NETMASK not found\n");
        return FAILURE;
    }
    strcpy(netmask, find_kv(kv_dhcp_params, "NETMASK"));
    /* domain is not mandatory */
    if (find_kv(kv_dhcp_params, "DOMAIN") == NULL) {
        F_LOG("udhcpc DOMAIN not found\n");
    } else {
        strcpy(domain, find_kv(kv_dhcp_params, "DOMAIN"));
    }
    free_kv(&kv_dhcp_params);

    return SUCCESS;
}


/* Select manually an interface for network install */
static int inst_select_interface(void)
{
	int i, rc;
	int done = 0;
	int choice = 0;
	char *interfacelist[CFG_COLOURS_COUNT];

	for (i = 0; i < hw_get_network_num(); i++) {
		interfacelist[i] = malloc(STRING_SIZE +1);
		snprintf(interfacelist[i], STRING_SIZE, "%s MAC:%s  %s",
				inst_networks[i].device, inst_networks[i].address, inst_networks[i].module);
	}

	interfacelist[i] = NULL;
	while (done == 0) {
		rc = newtWinMenu(gettext("TR_INTERFACE_SELECTION"),
				gettext("TR_INTERFACE_SELECTION_LONG"), 65, 5, 5, 6,
				interfacelist, &choice, gettext("TR_OK"), gettext("TR_GO_BACK"), NULL);

		if ((rc == 0) || (rc == 1)) {
			strcpy(itf_name, inst_networks[choice].device);
			done = 1;
		} else {
			done = 2;       /* canceled by user */
		}
	}
	for (i = 0; i < hw_get_network_num(); i++) {
		free(interfacelist[i]);
	}
	if (done == 1 ) {
		F_LOG("  interface %s selected\n",itf_name);
		return SUCCESS;
	} else {
		return FAILURE;
	}
}


/* To ease testing, allow to force dhcp(1) or manual(2) path even on pxe boot
   Just type 'install codepath=(1|2)' */
static void inst_read_codepath(void)
{
	char string[STRING_SIZE];
	char strboot[STRING_SIZE] = "none";

	find_kv_default(kv, "ofwboot", strboot);

	if (find_kv_default(kv, "codepath", string) == SUCCESS) {
		if (!strcmp(string, "1") || !strcmp(string, "2")) {
			codepath = atoi(string);
		} else {
			F_LOG("Bad codepath value\n");
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
static int inst_source_network_check(void)
{
	int i = 0;
	int rc;
	char *values[] = { "http://" DEFAULT_IP "/iso", NULL };        /* pointers for the values. */
	static int changed_green = 0;       /* IP and netmask green       */
	char *tmpstring;
	char buf[STRING_SIZE];
	char message[STRING_SIZE_LARGE];

	if (hw_get_network_num() == 0) {
		F_LOG("Fail to discover at least one network card\n");
		return FAILURE;
	}

	/* Put up status screen here, modprobing can take some time */
	helper_nt_statuswindow(72, 5,
			lang_gettext("TR_TITLE_SOURCE"), lang_gettext("TR_SEARCH_NETWORKS"));

	/* load net drivers from discovered hardware */
	for (i = 0; i < hw_get_hardwares_num(); i++) {
		if (hardwares[i].type == MT_NETWORK) {
			snprintf(buf, STRING_SIZE, "modprobe %s", hardwares[i].module);
			mysystem(buf);
		}
	}
	/* on netboot (x86 only now), we already have our own IP, server IP, netmask */
	if (strlen(local_IP) > 0) {
		if (inst_find_boot_itf()) {
			F_LOG("Fail to discover pxe boot nic\n");
		}
	}

	inst_build_network_list();
	newtPopWindow();

	/* if local IP has not been found by pxe, try to find by dhcp */
	if (strlen(local_IP) == 0 || codepath == 1) {
		newtComponent *f;
		newtComponent scale;
		f = (newtComponent *) statuswindow_progress(72, 5, lang_gettext("TR_TITLE_SOURCE"),
				lang_gettext("TR_SEARCH_NETWORKS"));
		scale = newtScale(1, 3, 70, 100);
		newtFormAddComponent(*f, scale);
		newtDrawForm(*f);
		newtScaleSet(scale, 1);     /* to display the bar on first detection */
		newtRefresh();
		/* FIXME be smarter if the machine is connected to more than one dhcp server */
		/* we actually keep only the last discovered server */
		/* we don't need to try disconnected cards */
		for (i = 0; i < hw_get_network_num(); i++) {
			/* 3 probes at approx. 3 second interval with 1 second pause after failure should suffice */
			if (!inst_find_network_by_dhcp(i)) {
				F_LOG("Found dhcp server at eth%d\n", i);
			}
			newtScaleSet(scale, (i+1) * 100 / hw_get_network_num());
			newtRefresh();
		}
		newtPopWindow();
	}
	/* manual selection */
	if (strlen(local_IP) == 0 || codepath == 2) {
		/* if local IP still not configured, first select which interface to use */
		if (inst_select_interface()) {
			F_LOG("failure for manual interface selection\n");
			return FAILURE;
		}
		if (read_kv_from_file(&eth_kv, "/etc/ethernetsettings") != SUCCESS) {
			free_kv(&eth_kv);
			errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
			return FAILURE;
		}
		update_kv(&eth_kv, "GREEN_COUNT", "0");
		/* set IP netmask */
		helper_nt_change_address("GREEN", &changed_green);
	}

	/* configure the selected interface */
	snprintf(buf, STRING_SIZE, "ifconfig %s %s netmask %s up", itf_name, local_IP, netmask);
	if (mysystem(buf)) {
		/* workaround gcc warning, there is really 1 %s there */
		tmpstring = strdup(gettext("TR_INTERFACE_FAIL_TO_GET_UP_CR"));
		snprintf(buf, STRING_SIZE, tmpstring, itf_name);
		free(tmpstring);
		errorbox(buf);
		return FAILURE;
	}

	/* check local_IP is not already used by another machine */
	helper_nt_statuswindow(72, 5,
			lang_gettext("TR_TITLE_SOURCE"), lang_gettext("TR_VERIFYING_IP"));
	snprintf(buf, STRING_SIZE, "ping %s", local_IP);
	rc = mysystem(buf);
	newtPopWindow();
	if (rc == 0) {
		/* workaround gcc warning, there is really 2 %s there */
		tmpstring = strdup(gettext("TR_IP_ALREADY_IN_USE"));
		snprintf(message, STRING_SIZE_LARGE, tmpstring, local_IP, itf_name);
		free(tmpstring);
		errorbox(message);
		return FAILURE;
	}

	if (strlen(server_IP) > 0) {
		snprintf(buf, STRING_SIZE, "http://%s/iso", server_IP);
		values[0] = buf;
	}

	while (1) {
		char filename[STRING_SIZE];
		struct newtWinEntry entries[] = { {"", &values[0], 0,}, {NULL, NULL, 0} };

		snprintf(message, STRING_SIZE_LARGE,
				lang_gettext("TR_ENTER_URL_FILE"), TARBALL_OFW);
		rc = newtWinEntries(lang_gettext("TR_TITLE_SOURCE"), message,
				65, 5, 5, 50, entries, lang_gettext("TR_OK"),
				lang_gettext("TR_GO_BACK"), NULL);
		strncpy(message, values[0], STRING_SIZE);
		F_LOG("URL is %s\n", message);

		if (rc == 2) {
			return FAILURE;     // give up (go back pressed)
		}

		if (strlen(message) == 0)
			continue;           // empty url entered, try again

		/* remove any successive /'s */
		while (message[strlen(message) - 1] == '/')
			message[strlen(message) - 1] = '\0';

		strcpy(network_source, message);
		helper_nt_statuswindow(72, 5,
				lang_gettext("TR_TITLE_SOURCE"), lang_gettext("TR_CHECKING"));

		/* just verify if files exist, download later */
		strcpy(filename, TARBALL_OFW);
		snprintf(buf, STRING_SIZE, "wget --spider -O /tmp/%s %s/%s", filename, network_source, filename);
		rc = mysystem(buf);
		newtPopWindow();
		if (!rc) {
			F_LOG("NETWORK INSTALL checked tarball URLs\n");
			return SUCCESS;
		}

		/* spider failed, inform user */
		snprintf(buf, STRING_SIZE, lang_gettext("TR_TAR_GZ_NOT_FOUND"), filename, network_source);
		errorbox(buf);
	}
}

/*
  Loop through all found hardware and test cdroms.
  If source CD (or USB stick) found, symlink the device to /dev/cdrom and mount at /cdrom.
*/
static int inst_source_cdrom_check(int *source_mt)
{
    int i;
    char filename[STRING_SIZE];
    char filepath[STRING_SIZE];
	char buf[STRING_SIZE];

    helper_nt_statuswindow(72, 5,
			lang_gettext("TR_TITLE_SOURCE"), lang_gettext("TR_MOUNTING_CDROM"));

	for (i = 0; i < hw_get_hardwares_num(); i++) {
		int j;

//		if ((hardwares[i].type != MT_CDROM) ||
//				((hardwares[i].type == MT_HARDDISK) &&
//				 (hardwares[i].device[0] != 's')))
//			continue;

		if ((hardwares[i].type != MT_CDROM) &&
			(hardwares[i].type != MT_HARDDISK))
			continue;

		if ((hardwares[i].type == MT_HARDDISK) &&
				(hardwares[i].device[0] != 's'))
			continue;

		/*  We need to try different partitions here
			hd?, sd? and sr? for IDE CD, usb-fdd and SCSI,SATA CD
			sd?1 for usb-hdd
			sd?4 for usb-zip
		 */
		F_LOG("Testing HW[%d]: CD/USB device %s, \n", i, hardwares[i].device);

		for (j = 0; j < 3; j++) {
			char test_partitions[3] = { ' ', '1', '4' };
			char test_device[STRING_SIZE];

			snprintf(test_device, STRING_SIZE, "%s%c",
					hardwares[i].device, test_partitions[j]);

			snprintf(buf, STRING_SIZE, "ln -sf /dev/%s /dev/cdrom", test_device);
			if (mysystem(buf)) {
				F_LOG("Couldn't create /dev/cdrom\n");
				continue;
			}

			snprintf(buf, STRING_SIZE, "/bin/mount -o ro /dev/%s /cdrom", test_device);
			if (mysystem(buf)) {
				F_LOG("Failed to mount CDROM on device %s\n", test_device);
				continue;
			}

			/* Let us see if this is an Openfirewall CD or USB key */
			strcpy(filename, TARBALL_OFW);
			snprintf(filepath, STRING_SIZE, "/cdrom/%s", filename);
			if (!access(filepath, F_OK)) {
				/* TODO: some fancy test (md5 ?) to verify CD */
				newtPopWindow();
				if (hardwares[i].type == MT_HARDDISK) {
					/* USB key, change type to remove from destination selection list */
					hardwares[i].type = MT_CDROM;
				}
				//medium_sources = MT_CDROM;
				*source_mt = MT_CDROM;
				scsi_cdrom = (hardwares[i].device[0] == 's');
				F_LOG("Source tarball found on device %s\n", test_device);
				return SUCCESS;
			}

			/* It is a CD (or something) but not ours */
			F_LOG("No tar.gz found on device %s\n", test_device);
			mysystem("/bin/umount /cdrom");
		}

		/* Tried all variations on this dev */
	}

    newtPopWindow();
    F_LOG("no cdroms\n");
    errorbox(lang_gettext("TR_NO_CDROM"));

    return FAILURE;
}


/*
    Select source (CDROM / HTTP)
    set medium_source accordingly
*/
static int inst_find_medium_source(int boot_mt, int *source_mt)
{
	int i, rc;
	char *installtypes[] = { "CDROM/USB-KEY", "HTTP/FTP", NULL };
	int installtype;        /* depending on menu, 0 = cdrom, 1 = http/ftp */
	int numnetworks = 0;
	char line[STRING_SIZE_LARGE];


	if ((boot_mt == MT_CDROM) || (boot_mt == MT_USB)) {
		if (inst_source_cdrom_check(source_mt) == SUCCESS) {
			/* We boot from media with all we need,
			 * no point to ask for HTTP/FTP install
			 */
			*source_mt = MT_CDROM;
			return SUCCESS;
		}
	}

	for (i = 0; i < hw_get_hardwares_num(); i++) {
		if (hardwares[i].type == MT_NETWORK)
			numnetworks++;
	}

	if (boot_mt == MT_NETWORK) {
		/* Set default selection for source to http/ftp */
		installtype = 1;
	} else {
		installtype = 0;
	}

	/* Choose source for tarball. Very basic. */
	while (1) {
		snprintf(line, STRING_SIZE_LARGE,
				lang_gettext("TR_SELECT_INSTALLATION_MEDIA_LONG"), NAME);
		rc = newtWinMenu(lang_gettext("TR_TITLE_SOURCE"),
				line, 65, 5, 5, 8,
				installtypes, &installtype, lang_gettext("TR_OK"),
				lang_gettext("TR_CANCEL"), NULL);
		if (rc == 2) {
			return FAILURE;     // give up
		}

		if (installtype == 1) {
			if (inst_source_network_check() == SUCCESS) {
				*source_mt = MT_NETWORK;
				return SUCCESS;
			}
		} else {
			if (inst_source_cdrom_check(source_mt) == SUCCESS) {
				*source_mt = MT_CDROM;
				return SUCCESS;
			}
		}
	}
}


/* Choose a destination disk (harddisk, cf?) and verify it can support Openfirewall */
static int inst_select_destination(unsigned int memtotal, int *ddisk,
		int *ddisk2, long int *disk_size, long int *ramdisk_size, int *target)
{
	int rc;
	char string[STRING_SIZE];
	FILE *handle;
	char **harddisklist = NULL;
	int i, c;
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

		for (c = 0, i = 0; i < hw_get_hardwares_num(); i++) {
			if (hardwares[i].type == MT_HARDDISK) {
				snprintf(string, STRING_SIZE, "%s: %s", hardwares[i].device, hardwares[i].description);
				harddisklist = realloc(harddisklist, sizeof(char *) * (c + 1));
				harddisklist[c] = strdup(string);
				c++;
			}
		}

		if ((c >= 2) && (access("/sbin/mdadm", F_OK) == 0)) {
			harddisklist = realloc(harddisklist, sizeof(char *) * (c + 1));
			harddisklist[c] = strdup("Software RAID");
			c++;
		}

		/* end with a null pointer */
		harddisklist = realloc(harddisklist, sizeof(char *) * (c + 1));
		harddisklist[c] = NULL;
		raid = 0;
		memset(disklist, 0, sizeof(disklist));
		memset(disksize, 0, sizeof(disksize));

NEXTDISK:
		/* Default to the first disk */
		c = 0;

		// Choose the disk to use
		switch (raid) {
		case 0:
			strcpy(string, lang_gettext("TR_TITLE_DISK"));
			break;
		case 1:
			strcpy(string, "RAID disk 1");
			break;
		case 2:
			strcpy(string, "RAID disk 2");
			break;
		}
		rc = newtWinMenu(string, lang_gettext("TR_SELECT_DEVICE_FOR_INSTALLATION"),
					65, 5, 5, 8, harddisklist, &c, 
					lang_gettext("TR_OK"),
					(raid != 0) ? lang_gettext("TR_GO_BACK") : lang_gettext("TR_CANCEL"),
					NULL);

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
		for (i = 0; i < hw_get_hardwares_num(); i++) {
			if (!strncmp(harddisklist[c], hardwares[i].device, 3)) {
				disklist[raid] = i;
				break;
			}
		}
		/* should not happen, should it ? */
		if (disklist[raid] == -1) {
			F_LOG("WOW, error 42\n");
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
			F_LOG("HARDDISK %s: really too small.\n", hardwares[disklist[raid]].device);
			errorbox(lang_gettext("TR_DISK_TOO_SMALL"));
			continue;           // give option to choose another disk
		}
		F_LOG("Hard disk selected %s. Size:%ld MiB\n",
				hardwares[disklist[raid]].device, disksize[raid]);

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
		rc = newtWinChoice(lang_gettext("TR_TITLE_DISK"),
				lang_gettext("TR_GO_BACK"), lang_gettext("TR_OK"),
				lang_gettext("TR_CONFIRM_DEVICE_INSTALLATION"));
		if (rc != 2) {
			F_LOG("Installation cancelled by user.\n");
			continue;           // give option to choose another disk
		}

		if (raid) {
			*ddisk = disklist[1];
			*ddisk2 = disklist[2];
			*disk_size = (disksize[1] < disksize[2]) ? disksize[1] : disksize[2];
			F_LOG("RAID size:%ld MiB\n", *disk_size);
		} else {
			*ddisk = disklist[0];
			*ddisk2 = 0;
			*disk_size = disksize[0];
		}

		while (1) {
			/* Should this be a harddisk or flash installation? */
			*target = MT_HARDDISK;

			rc = newtWinTernary(lang_gettext("TR_TITLE_DISK"),
					lang_gettext("TR_HARDDISK"), lang_gettext("TR_FLASH"), lang_gettext("TR_GO_BACK"),
					lang_gettext("TR_HARDDISK_FLASH_LONG"));
			if (rc == 3) {
				/* Cancel */
				break;
			}
			if (rc == 1) {
				/* Harddisk */
				return SUCCESS;
			}
			if (rc != 2)
				continue;

			/* Flash choosen, test for and ask wanted RAM disk size */

			/*  First check for enough RAM available, set a minimum of 96 MiB 
			 *  check for value slightly below 96, since kernel reported memory is not 96 */
			if (memtotal < 90) {
				char message[STRING_SIZE_LARGE];
				snprintf(message, STRING_SIZE_LARGE, lang_gettext("TR_FLASH_NOT_ENOUGH_MEMORY"), 96);
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
				if ((strlen(values[0]) < 5) && (*ramdisk_size >= 32) &&
						(*ramdisk_size <= (memtotal - 16))) {
					*target = MT_FLASH;
					F_LOG("FLASH installation, RAM disk size wanted: %ld MiB\n", *ramdisk_size);
					return SUCCESS; // OK flash      
				}
			}
		}
	}

	/* We will not get this far. */
}


static int inst_log_init(int *console)
{
    FILE *handle;
    char line[STRING_SIZE_LARGE];

    /* read the parameters from the kernel cmdline */
    if (!(handle = fopen("/proc/cmdline", "r"))) {
        /* This must succeed, what do to in error case? */
        fprintf(stderr, "FATAL ERROR: Cannot read /proc/cmdline");
		//exit(-1);
        return -1;
    }

    if (fgets(line, STRING_SIZE, handle) == NULL) {
        printf("/proc/cmdline is empty");
        read_kv_from_line(&kv, "");
    } else {
        read_kv_from_line(&kv, line);
    }
    fclose(handle);

    if (find_kv(kv, "console") == NULL) {
        /* Standard console, business as usual. */
        if (!(flog = fopen("/dev/tty2", "w+"))) {
            printf("Failed to open /dev/tty2 for logging\n");
			//exit(0);
            return -1;
        }
        fstderr = freopen("/dev/tty3", "w+", stderr);
        *console = MT_CONSOLE;
    }
    else {
        /* Special console, do not use tty2/tty3 but temporary files. */
        flog = fopen("/tmp/flog", "w");
        fstderr = freopen("/tmp/fstderr", "w", stderr);
        *console = MT_SERIAL;
        serial_commandline = strdup(find_kv(kv, "console"));

        /* serial_commandline is of format ttyS0,38400n81 */
        /* TODO: make some better test */
        serial_console = serial_commandline[4] - '0';
        serial_bitrate = atoi(serial_commandline+6);
    }
	return 0;
}


int main(int argc, char **argv)
{
    int rc;
    //FILE *handle;
    char line[STRING_SIZE_LARGE];       //general purpose buffer
    int restore_success = SUCCESS;
	char message[STRING_SIZE_LARGE];

	int medium_boot = MT_UNKNOWN;

	unsigned int memtotal = 0;                  /* Total memory in MB */

	if (inst_log_init(&medium_console))
		exit(-1);

    /* Small information about these consoles. */
    F_LOG("Logging from installer.\n");
    fprintf(fstderr, "Error messages and more logging from installer.\n");

    /* Determine total memory */
	memtotal = inst_get_sys_memory();
    F_LOG("MemTotal is %d MB\n", memtotal);

    helper_kernel_init();

    /* Want our tester have a better coverage of the code path */
    inst_read_codepath();   /* actually only force dhcp or manual path on pxe boot */

	medium_boot = inst_find_boot_medium();

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

	inst_parse_kv_params(&nopcmcia, &nousb, &part_options,
			&swapfilesize, &userdisksize, &manualmodule);

    newtInit();
    newtCls();

    /* first things first, installer language */
    handle_language(kv);
    /* Starting here we have a language selected, use lang_gettext to get translated texts */

    free_kv(&kv);

    char *install_status = lang_gettext("TR_INSTALLATION_CANCELED");

    /* Screen setup and welcome window */
    newtDrawRootText(18, 0, helper_get_title());
    newtPushHelpLine(lang_gettext("TR_HELPLINE"));
    snprintf(line, STRING_SIZE_LARGE, lang_gettext("TR_WELCOME"), NAME);
    rc = newtWinChoice(helper_get_title(),
                       lang_gettext("TR_OK"), lang_gettext("TR_CANCEL"),
                       line);
    if (rc == 2) {
        goto EXIT;
    }

    /*  Set the keyboard if we have the needed files */
    handle_keymap();
    /*  Ask for timezone and give option to modify date&time, 
        this makes sure we have the time correct when partitioning and installing files */
    handle_timezone();
    handle_datetime();

    // find nics cdrom harddisk & floppies
    hw_scan_hardware(1, nopcmcia, nousb, manualmodule);

    /* any possible target drives found */
    if (hw_get_harddisk_num() == 0) {
        errorbox(lang_gettext("TR_NO_HARDDISK"));
        F_LOG("NO HARDDRIVES\n");
        goto EXIT;
    }

    /* find location of tarballs */
    if (inst_find_medium_source(medium_boot, &medium_sources) != SUCCESS) {
        F_LOG("NO Source selected\n");
        goto EXIT;
    }

    /* select destination drive & partition scheme */
    int selected_hd = 0;
    int selected_hd2 = 0;
    long int disk_size = 0;
    long int ramdisk_size = 0;

    if (inst_select_destination(memtotal, &selected_hd, &selected_hd2,
				&disk_size, &ramdisk_size, &medium_target) != SUCCESS) {
        /* CANCEL, too small or some other problem */
        goto EXIT;
    }

    if (userdisksize < disk_size) {
        disk_size = userdisksize;
        F_LOG("Use user selected max. disksize: %ld MiB\n", disk_size);
        part_options |= PART_OPTIONS_USER_SIZE;
    }

    /*  Partition, format, mount, initramfs and make bootable
       manual partitioning if PART_OPTIONS_PARTED set */
    if (pt_make_ofw_disk(hardwares[selected_hd].device,
			hardwares[selected_hd2].device,
			disk_size, swapfilesize, part_options) != SUCCESS)
        goto EXIT;


    // Now, /harddisk           is mounted
    //      /harddisk/var/log   is mounted

    /* Target is up&running so we can store some previously made settings */
    lang_write_lang_configs();
    kmap_write_keymap();
    tzone_write_timezone();
    /* Copy the info about detected HW for later reference */
    mysystem("/bin/cp /tmp/hwdetect /harddisk/var/log/hwdetect");

    if (medium_target == MT_FLASH) {
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
    if (medium_console == MT_SERIAL) {
        snprintf(line, STRING_SIZE, "echo \"ttyS%u\" >> /harddisk/etc/securetty", serial_console);
        if (system(line)) {
            /* TODO: make this a fatal error ? */
            fprintf(fstderr, "ERROR writing to /etc/inittab\n");
        }

        snprintf(line, STRING_SIZE,
				"echo \"7:2345:respawn:/sbin/agetty -I '\033(K' ttyS%u %u vt102\" >> /harddisk/etc/inittab",
            	serial_console, serial_bitrate);
        if (system(line)) {
            /* TODO: make this a fatal error ? */
            fprintf(fstderr, "ERROR writing to /etc/inittab\n");
        }
    }

    /* Offer restore here, if no restore -> launch setup later */
    restore_success = handle_restore();

    /* Installation is done, time to congratulate and then turn to configuration */
    snprintf(message, STRING_SIZE_LARGE,
			lang_gettext("TR_CONGRATULATIONS_LONG"), NAME, SNAME, SNAME, NAME, NAME, NAME);
    newtWinMessage(helper_get_title(), lang_gettext("TR_CONGRATULATIONS"), message);

    if ((medium_sources == MT_NETWORK) && (restore_success == FAILURE)) {
        /* running udhcp may have given us some acceptable defaults */
        mysystem("[ -e /etc/dhcp-eth*.params ] && /bin/cp /etc/dhcp-eth*.params /harddisk/tmp/");
    }
    else if (medium_sources == MT_CDROM) {
        mysystem("/bin/umount /cdrom");
    }

    /* Now that we've unmounted the cdrom, try to eject it 
        If we use medium_boot here, we would also eject when installing from other media,
        since CDROM, PXE and USB source have the CDROMBOOT flagfile */
    if (medium_sources == MT_CDROM) {
        if (scsi_cdrom) {
            /* Might need something additionally/different here */
            strcpy(line, "eject -s /dev/cdrom");
        } else {
            strcpy(line, "eject /dev/cdrom");
        }

        if (mysystem(line))
            errorbox(lang_gettext("TR_UNABLE_TO_EJECT_CDROM"));
    }

    if (restore_success == FAILURE) {
		char buf[STRING_SIZE];

        unlink("/harddisk/tmp/udevsed.sh");
        mysystem("/bin/touch /harddisk/tmp/udevsed.sh");

        /* Run setup to configure remaining bits & pieces */
        snprintf(buf, STRING_SIZE, "chroot /harddisk /usr/local/sbin/setup --install %s", 
            (medium_console == MT_SERIAL) ? "--serial" : "");
        if (system(buf))
            printf("Unable to run setup.\n");
    }

    // All done, just have to unmount everything...
    helper_nt_statuswindow(72, 5, helper_get_title(), lang_gettext("TR_UNMOUNTING"));

    mysystem("swapoff -a");
    mysystem("/bin/umount -n /harddisk/tmp");

    /* No need to make this complicated, we know what we've mounted */
/*
    mysystem("/bin/umount -n /harddisk/boot");
    if (medium_target == MT_FLASH) {
        mysystem("/bin/umount -n /harddisk/var/log_compressed");
    }
    else {
        mysystem("/bin/umount -n /harddisk/var/log");
    }
    if (access("/proc/mdstat", F_OK) == 0) {
        mysystem("/sbin/mdadm --stop --scan");
        sleep(2);
    }
    mysystem("/bin/mount  -n -o remount,ro /harddisk/");
*/
    newtPopWindow();
    install_status = lang_gettext("TR_CONGRATULATIONS");

EXIT:

    if (restore_success == FAILURE) {
        /* install_status can be TR_CONGRATULATIONS or TR_INSTALLATION_CANCELED */
        newtWinMessage(helper_get_title(), lang_gettext("TR_OK"), install_status);
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
