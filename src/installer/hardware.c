/*
 * hardware.c: Probing, Scanning, everything to find out what's there
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


#include <dirent.h>
#include <newt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libusb-1.0/libusb.h"
#include "usbnames.h"
#include "pci/pci.h"

#include "common.h"
#include "common_newt.h"
#include "arch_defs.h"


// List of all interesting hardware items
struct hardware_s *hardwares;
// How many did we find
static unsigned int numhardwares;
static unsigned int numharddisk;
static unsigned int numcdrom;
static unsigned int numnetwork;


static FILE *fhwdetect = NULL;
//static int install_setup = 0;   /* 0 when running setup (NIC detection), 1 for installer */


#if 0
static void hw_log(FILE *fd1, FILE *fd2, const char *msg, ...)
{
	va_list args;
	char buf[STRING_SIZE];

	va_start(args, msg);
	vsnprintf(buf, sizeof(buf) - 1, msg, args);
	va_end(args);
	buf[sizeof(buf) - 1] = '\0';

	if (fd1)
		fprintf(fd1, "%s\n", buf);
	if (fd2)
		fprintf(fd2, "%s\n", buf);
}

#define F_LOG(args...) hw_log(flog, NULL, args)
#define HW_DETECT_LOG(args...) hw_log(fhwdetect, NULL, args)
#define HW_DETECT_F_LOG(args...) hw_log(flog, fhwdetect, args)
#endif

static void hw_log_init(int install_setup)
{
    /* also write HW detection to file, for easier reference */
    if (install_setup) {
        /* Installer: write hwdetect, this will later be copied to /var/log on target system */
        fhwdetect = fopen("/tmp/hwdetect", "w");
    } else {
        /* Setup: used for network card detection only */
        fhwdetect = fopen("/tmp/netdetect", "w");
    }
}


int hw_get_hardwares_num(void)
{
	return numhardwares;
}

int hw_get_harddisk_num(void)
{
	return numharddisk;
}

int hw_get_network_num(void)
{
	return numnetwork;
}
void hw_set_network_num(int num)
{
	numnetwork = num;
}

/* Retrieve disk capacity from proc or sys.
   Size is reported in blocks of 512 bytes, make a string with info GiB, MiB, KiB.
   Return size in MiB.
*/
static unsigned long hw_get_drive_size(char *procname, char *strsize)
{
    FILE *f;
    uint64_t size;              /* using 32bit would limit to 1000 GB, which is not too far away in the future */
    unsigned long mbsize;

    mbsize = 0;
    strcpy(strsize, "? KiB");

    if ((f = fopen(procname, "r")) != NULL) {
        if (fgets(strsize, STRING_SIZE, f)) {
            size = strtoull(strsize, NULL, 10);
            size = size * 512 / 1024;   /* do not use the disk vendor way of specifying KBytes */
            mbsize = size / 1024;

            if (size >= 4000000) {
                /* Everything larger than 4000 MB */
                snprintf(strsize, STRING_SIZE, "%llu GiB", size / (1024*1024));
            }
            else if (size >= 4000) {
                /* Everything larger than 4000 KB */
                snprintf(strsize, STRING_SIZE, "%llu MiB", size / 1024);
            }
            else {
                /* Anything else, unlikely since we need something like 100+ MB anyway */
                snprintf(strsize, STRING_SIZE, "%llu KiB", size);
            }
        }
    }

    return mbsize;
}


/* Add something to our hardware list */
static void hw_add_hardware(int type, char *module,
		char *device, char *vendor, char *description, u16 vendorid, u16 modelid)
{
	char vendordesc[STRING_SIZE] = "";
	char tmpstring[STRING_SIZE];

	if ((device != NULL) && (numhardwares != 0)) {
		/* avoid duplicates */
		int i;

		for (i = 0; i < numhardwares; i++) {
			if (!strcmp(device, hardwares[i].device))
				return;
		}
	}

	hardwares = realloc(hardwares, sizeof(struct hardware_s) * (numhardwares + 1));

	hardwares[numhardwares].type = type;

	if (module != NULL)
		hardwares[numhardwares].module = strdup(module);
	else
		hardwares[numhardwares].module = strdup("");

	if (device != NULL)
		hardwares[numhardwares].device = strdup(device);
	else
		hardwares[numhardwares].device = strdup("");

	snprintf(tmpstring, STRING_SIZE, "%04x", vendorid);
	hardwares[numhardwares].vendorid = vendorid ? strdup(tmpstring) : strdup("");

	snprintf(tmpstring, STRING_SIZE, "%04x", modelid);
	hardwares[numhardwares].modelid = modelid ? strdup(tmpstring) : strdup("");

	// Now build full description from vendor name and description
	// if description is NULL, full description becomes "Unknown" + IDs
	if (description != NULL) {
		if (vendor != NULL) {
			strcpy(vendordesc, vendor);
			strcat(vendordesc, " ");
		}
		strcat(vendordesc, description);
	} else {
		/* no description, use IDs */
		snprintf(vendordesc, STRING_SIZE, "Unknown %04x:%04x", vendorid, modelid);
	}
	hardwares[numhardwares].description = strdup(vendordesc);

	HW_DETECT_F_LOG("  HWadd %3d, %s, %s, %s\n", type, hardwares[numhardwares].module,
			hardwares[numhardwares].device, hardwares[numhardwares].description);

	// increment tallies
	numhardwares++;
	switch (type) {
		case MT_NETWORK:
			numnetwork++;
			break;
		case MT_HARDDISK:
			numharddisk++;
			break;
		case MT_CDROM:
			numcdrom++;
			break;
		default:
			break;
	}
}


/* 
    Filter function for scanning /sys/bus/ide/devices
    Used by scandir in hw_scan_proc_drives function.
    Return 0 to skip a device
*/
int ide_filter(const struct dirent *b)
{
    char string[STRING_SIZE_LARGE];

    snprintf(string, STRING_SIZE_LARGE,
			"/sys/bus/ide/devices/%s/media", b->d_name);

    if (access(string, F_OK) == 0)
        return 1;

    return 0;
}


/* Scan /sys/bus/ide and /sys/block for drives */
static void hw_scan_proc_drives(int modprobe)
{
    int i;
    FILE *f = NULL;
    char procname[STRING_SIZE_LARGE];
    char media[STRING_SIZE];
    char model[STRING_SIZE];
    int type = MT_NONE;
//    char command[STRING_SIZE];
    char deviceletter;
    char strsize[STRING_SIZE];
    struct dirent **names;
    int numdevices = 0;
	static int have_idecd = 0;

    /* look for IDE harddisk and cdrom */
    numdevices = scandir("/sys/bus/ide/devices", &names, &ide_filter, alphasort);
    for (i = 0; i < numdevices; i++) {
        snprintf(procname, STRING_SIZE_LARGE,
				"/sys/bus/ide/devices/%s/media", names[i]->d_name);
        if ((f = fopen(procname, "r")) == NULL)
            continue;

        /* media holds disk or cdrom */
        if (fgets(media, STRING_SIZE, f)) {
            stripnl(media);
            if (!strcmp(media, "disk")) {
                type = MT_HARDDISK;
            }
            else if (!strcmp(media, "cdrom")) {
                type = MT_CDROM;
                if (modprobe && !have_idecd) {
                    have_idecd = 1;
                    /* Since kernel 2.6.25 ide-cd is ide-cd_mod */
///                    snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "ide-cd_mod");
///                    mysystem(command);
                    /* no need to put in hardware list */

                    /* give some time to settle */
                    sleep(1);
                }
            }
        }
        fclose(f);

        if (type != MT_NONE) {
            char device[STRING_SIZE];
            char description[STRING_SIZE] = "Unknown";

            /* found something, get device name (hd?), model and size */
            snprintf(procname, STRING_SIZE_LARGE,
					"/sys/bus/ide/devices/%s/drivename", names[i]->d_name);
            if ((f = fopen(procname, "r")) != NULL) {
                if (fgets(device, STRING_SIZE, f)) {
                    stripnl(device);
                    fclose(f);

                    snprintf(procname, STRING_SIZE_LARGE, "/sys/bus/ide/devices/%s/model", names[i]->d_name);
                    if ((f = fopen(procname, "r")) != NULL) {
                        if (fgets(model, STRING_SIZE, f)) {
                            stripnl(model);
                            if (type == MT_HARDDISK) {
                                snprintf(procname, STRING_SIZE, "/sys/block/%s/size", device);
                                hw_get_drive_size(procname, strsize);

                                snprintf(description, STRING_SIZE, "%-30.30s (%s)", model, strsize);
                            } else {
                                /* size is not interesting for CDROM */
                                strcpy(description, model);
                            }
                        }
                    }
                }
                fclose(f);
            }

            hw_add_hardware(type, NULL, device, NULL, description, 0, 0);
        }
    }


    /* Look for SCSI, SATA harddisk, USB attached devices */
    for (deviceletter = 'a'; deviceletter <= 'z'; deviceletter++) {
        snprintf(procname, STRING_SIZE_LARGE,
				"/sys/block/sd%c/device/model", deviceletter);

        if ((f = fopen(procname, "r")) == NULL)
            continue;

        /* We need some mechanism to differentiate between installation from USB stick
           or installation on USB device
         */

        if (fgets(model, STRING_SIZE, f)) {
            char device[4];
            char description[STRING_SIZE] = "Unknown";
            unsigned long drivesize;

            stripnl(model);
            sprintf(device, "sd%c", deviceletter);

            snprintf(procname, STRING_SIZE_LARGE, "/sys/block/sd%c/size", deviceletter);
            drivesize = hw_get_drive_size(procname, strsize);
            snprintf(description, STRING_SIZE, "%-30.30s (%s)", model, strsize);
            if (drivesize < 32) {
                /* Discard if too small for installation and too small as target drive */
                //snprintf(logline, STRING_SIZE, "   discard sd%c %-30.30s (%s)\n", deviceletter, model, strsize);
                //fprintf(flog, "%s", logline);
                //fprintf(fhwdetect, "%s", logline);
				HW_DETECT_F_LOG("   discard sd%c %-30.30s (%s)\n", deviceletter, model, strsize);
                continue;
            }
            else if (drivesize < DISK_MINIMUM) {
                /* Too small as target drive but could be installation USB stick */
                hw_add_hardware(MT_CDROM, NULL, device, NULL, description, 0, 0);
            }
            else {
                hw_add_hardware(MT_HARDDISK, NULL, device, NULL, description, 0, 0);
            }
        }
        fclose(f);
    }

    /* Look for SCSI, SATA, USB cdrom */
    for (deviceletter = '0'; deviceletter <= '9'; deviceletter++) {
        snprintf(procname, STRING_SIZE_LARGE, "/sys/block/sr%c/device/model", deviceletter);

        if ((f = fopen(procname, "r")) == NULL)
            continue;

        if (fgets(model, STRING_SIZE, f)) {
            char device[4];

            stripnl(model);
            sprintf(device, "sr%c", deviceletter);
            hw_add_hardware(MT_CDROM, NULL, device, NULL, model, 0, 0);
        }

        fclose(f);
    }
}


/* USB function to get vendor name from usbids.gz */
static int get_vendor_string(char *buf, size_t size, u_int16_t vid)
{
    const char *cp;

    if (size < 1)
        return 0;
    *buf = 0;
    if (!(cp = names_vendor(vid)))
        return 0;
    return snprintf(buf, size, "%s", cp);
}


/* USB function to get product name from usbids.gz */
static int get_product_string(char *buf, size_t size, u_int16_t vid, u_int16_t pid)
{
    const char *cp;

    if (size < 1)
        return 0;
    *buf = 0;

    if (!(cp = names_product(vid, pid)))
        return 0;
    return snprintf(buf, size, "%s", cp);
}


/*
 *  USB scanning by using libusb, pci.ids.gz and modules.alias
 */
static int hw_scan_usb_bus(FILE *logfd, int numbusses,
			newtComponent text, newtComponent scale)
{
	int i;
	char line[STRING_SIZE];
//	newtComponent text;
//	newtComponent scale;
	libusb_device **usbdevs;
	ssize_t cnt = 0;
	char vendor[STRING_SIZE];
	char description[STRING_SIZE];
	int type;
	char command[STRING_SIZE];


	fprintf(logfd, "Scan USB\n");

	snprintf(line, STRING_SIZE, lang_gettext("TR_SCANNING_HARDWARE"), "USB");
	strcat(line, "           ");
	newtLabelSetText(text, line);
	newtRefresh();

	newtScaleSet(scale, numbusses * 10 + 1);
	newtRefresh();

	names_init("/usr/share/usb.ids.gz");

	if (libusb_init(NULL) >= 0)
		cnt = libusb_get_device_list(NULL, &usbdevs);

	for (i = 0; (i < cnt) && (usbdevs[i] != NULL); i++) {
		struct libusb_device_descriptor descriptor;

		if (libusb_get_device_descriptor(usbdevs[i], &descriptor) < 0) {
			//fprintf(logfd, "libusb failed to get device descriptor\n");
			//fprintf(fhwdetect, "libusb failed to get device descriptor\n");
			HW_DETECT_F_LOG("libusb failed to get device descriptor\n");
			continue;
		}

		type = MT_NONE;
		strcpy(vendor, "");
		strcpy(line, "");
		get_vendor_string(vendor, sizeof(vendor), descriptor.idVendor);
		get_product_string(line, sizeof(line), descriptor.idVendor, descriptor.idProduct);
		snprintf(description, STRING_SIZE, "%s %s", vendor, line);

		/* TODO: find a better way to differentiate network devices from other USB devices */
		switch (descriptor.bDeviceClass) {
			case LIBUSB_CLASS_PER_INTERFACE:
				type = MT_NETWORK;
				break;

			case LIBUSB_CLASS_COMM:
				type = MT_NETWORK;
				break;

			case LIBUSB_CLASS_WIRELESS:
				type = MT_NETWORK;
				break;

			case LIBUSB_CLASS_VENDOR_SPEC:
				type = MT_NETWORK;
				break;
		}

		if (type == MT_NONE) {
			//snprintf(logline, STRING_SIZE, "  Skip %02x %04x:%04x, %s\n",
			//        descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct, description);
			//fprintf(logfd, "%s", logline);
			//fprintf(fhwdetect, "%s", logline);
			HW_DETECT_F_LOG("  Skip %02x %04x:%04x, %s\n",
					descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct, description);
		} else {
			char *module = NULL;

			module = helper_kernel_find_modulename("usb", descriptor.idVendor, descriptor.idProduct);
			if (module != NULL) {
				snprintf(command, STRING_SIZE, "/sbin/modprobe %s", module);
				mysystem(command);

				//snprintf(logline, STRING_SIZE, "  Add  %02x %04x:%04x, %s\n",
				//        descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct, description);
				//fprintf(logfd, "%s", logline);
				//fprintf(fhwdetect, "%s", logline);
				HW_DETECT_F_LOG("  Add  %02x %04x:%04x, %s\n",
						descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct, description);

				hw_add_hardware(MT_NETWORK, module, NULL, NULL, description, descriptor.idVendor, descriptor.idProduct);
			} else {
				/* There is little to add if there is no module */
				//snprintf(logline, STRING_SIZE, "  Skip (no module) %02x %04x:%04x\n",
				//        descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct);
				//fprintf(logfd, "%s", logline);
				//fprintf(fhwdetect, "%s", logline);
				HW_DETECT_F_LOG("  Skip (no module) %02x %04x:%04x\n",
						descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct);
			}
		}
	}

	//numBusses++;
	if (cnt > 0) {
		libusb_free_device_list(usbdevs, 1);
		libusb_exit(NULL);
	}

	return 0;
}

/*
 *  PCMCIA scanning (this needs work)
 */
static int hw_scan_pcmcia_bus(FILE *logfd, int numbusses, newtComponent text, newtComponent scale)
{
    char line[STRING_SIZE];
//    newtComponent text;
//    newtComponent scale;

    //fprintf(flog, "Scan PCMCIA\n");
	F_LOG("Scan PCMCIA\n");

    snprintf(line, STRING_SIZE, lang_gettext("TR_SCANNING_HARDWARE"), "PCMCIA");
    strcat(line, "           ");
    newtLabelSetText(text, line);
    newtRefresh();

    newtScaleSet(scale, numbusses * 10 + 1);
    newtRefresh();

    /* TODO: verify that yenta_socket is loaded and identified above. If not forcebly load it for dev. class 0x0607 */

    /* TODO: scanning? what? */

    //numBusses++;
    sleep(1);

	return 0;
}


/*
 *  PCI scanning (this needs work)
 */
static void hw_scan_pci_bus(int install_setup, int nopcmcia, int nousb,
		int *have_scsidisk, int *have_idedisk, int *have_usbdisk)
{
	char line[STRING_SIZE];
	struct pci_access *pciacc;
	struct pci_dev *pcidev;
	char vendor[STRING_SIZE];
	char description[STRING_SIZE];
	int type;
	char command[STRING_SIZE];

	pciacc = pci_alloc();               /* Get the pci_access structure */
	pci_init(pciacc);                   /* Initialize the PCI library */

	pci_scan_bus(pciacc);
	for (pcidev = pciacc->devices; pcidev; pcidev = pcidev->next) {
		type = MT_NONE;
		pci_fill_info(pcidev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);

		strcpy(vendor, "");
		strcpy(line, "");
		pci_lookup_name(pciacc, vendor, STRING_SIZE-1, PCI_LOOKUP_VENDOR, pcidev->vendor_id);
		pci_lookup_name(pciacc, line, STRING_SIZE-1, PCI_LOOKUP_DEVICE, pcidev->vendor_id, pcidev->device_id);
		snprintf(description, STRING_SIZE, "%s %s", vendor, line);

		switch((pcidev->device_class >> 8) & 0xFF) {
			case PCI_BASE_CLASS_STORAGE:        // 0x01
				if (install_setup)
					type = MT_SPECIAL_MODULE;
				break;

			case PCI_BASE_CLASS_NETWORK:        // 0x02
				type = MT_NETWORK;
				break;

			case PCI_BASE_CLASS_BRIDGE:         // 0x06
				/* A forcedeth onboard NIC that identifies as 0680 instead of 0200.
				 *  At least device ID 0x00df and 0x03ef, maybe more.
				 *  Filter out true bridge devices below, after searching for the module.
				 */
				if ((pcidev->device_class == PCI_CLASS_BRIDGE_OTHER) && (pcidev->vendor_id == 0x10de))
					type = MT_NETWORK;

				if (install_setup && !nopcmcia 
						&& ((pcidev->device_class == PCI_CLASS_BRIDGE_PCMCIA) ||
							(pcidev->device_class == PCI_CLASS_BRIDGE_CARDBUS))) {
					type = MT_SPECIAL_MODULE;
				}
				break;            

			case PCI_BASE_CLASS_SERIAL:         // 0x0c
				if (install_setup && !nousb && (pcidev->device_class == PCI_CLASS_SERIAL_USB))
					type = MT_SPECIAL_MODULE;

				break;
		}

		if (type == MT_NONE) {
			HW_DETECT_F_LOG( "  Skip %04x %04x:%04x, %s\n",
					pcidev->device_class, pcidev->vendor_id, pcidev->device_id, description);
		} else {
			char *module = NULL;

			module = helper_kernel_find_modulename("pci", pcidev->vendor_id, pcidev->device_id);
			if (module != NULL) {
				snprintf(command, STRING_SIZE, "/sbin/modprobe %s", module);
				mysystem(command);

				if ((type == MT_NETWORK) &&
						(pcidev->device_class == PCI_CLASS_BRIDGE_OTHER) &&
						(pcidev->vendor_id == 0x10de) && strcmp(module, "forcedeth")) {
					/* Special case, nVidia PCI bridge_other not using forcedeth driver */
					HW_DETECT_F_LOG("  Skip (bridge_other) %04x %04x:%04x\n",
							pcidev->device_class, pcidev->vendor_id, pcidev->device_id);
				}
				else {
					HW_DETECT_F_LOG("  Add  %04x %04x:%04x, %s\n",
							pcidev->device_class, pcidev->vendor_id, pcidev->device_id, description);

					hw_add_hardware(type, module, NULL, NULL, description, pcidev->vendor_id, pcidev->device_id);
				}
			} else {
				/* There is little to add if there is no module */
				HW_DETECT_F_LOG("  Skip (no module) %04x %04x:%04x\n",
						pcidev->device_class, pcidev->vendor_id, pcidev->device_id);
			}
		}

		/* Some special handling for special devices */
		if (install_setup && (type == MT_SPECIAL_MODULE)) {
			fprintf(fhwdetect, "special module scsidisk %d device class 0x%x(%d) scsi 0x%x(%d) sata 0x%x(%d)\n",
					*have_scsidisk, pcidev->device_class, pcidev->device_class,
					PCI_CLASS_STORAGE_SCSI, PCI_CLASS_STORAGE_SCSI,
					PCI_CLASS_STORAGE_SATA, PCI_CLASS_STORAGE_SATA);
			/* SCSI, SATA, add some modules */
			if (!*have_scsidisk &&
					((pcidev->device_class == PCI_CLASS_STORAGE_SCSI) ||
					 (pcidev->device_class == PCI_CLASS_STORAGE_SATA)))
			{
				fprintf(fhwdetect, "scsidisk\n");
				*have_scsidisk = 1;
				snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sd_mod");
				mysystem(command);
				hw_add_hardware(MT_SPECIAL_MODULE, "sd_mod", NULL, NULL, NULL, 0, 0);

				snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sr_mod");
				mysystem(command);
				/* no need to put in hardware list */
			}

			/* IDE, add some modules */
			if (!*have_idedisk && (pcidev->device_class == PCI_CLASS_STORAGE_IDE)) {
				*have_idedisk = 1;
				fprintf(fhwdetect, "idedisk IDE class 0x%x(%d)\n", PCI_CLASS_STORAGE_IDE, PCI_CLASS_STORAGE_IDE);
				// snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "ide-generic");
				// mysystem(command);
				// hw_add_hardware(MT_SPECIAL_MODULE, "ide-generic", NULL, NULL, NULL, 0, 0);
				/* Kernel >= 2.6.28 have ide-gd_mod instead of ide-disk */
				////snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "ide-gd_mod");
				////hw_add_hardware(MT_SPECIAL_MODULE, "ide-gd_mod", NULL, NULL, NULL, 0, 0);
			}

			/* USB, probe */
			if (!*have_usbdisk && (pcidev->device_class == PCI_CLASS_SERIAL_USB)) {
				*have_usbdisk = 1;
				fprintf(fhwdetect, "usbdisk USB class 0x%x(%d)\n", PCI_CLASS_SERIAL_USB, PCI_CLASS_SERIAL_USB);
				/* 
				   Dependancies will load sd_mod, but sd_mod will not be in initramfs .
				   Not sure if installing onto USB stick is a good idea though.
				 */
				snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sd_mod");
				mysystem(command);
				hw_add_hardware(MT_SPECIAL_MODULE, "sd_mod", NULL, NULL, NULL, 0, 0);
				snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "usb-storage");
				mysystem(command);
				hw_add_hardware(MT_SPECIAL_MODULE, "usb-storage", NULL, NULL, NULL, 0, 0);

				/* need sr_mod when installing from USB CDROM */
				snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sr_mod");
				mysystem(command);
				/* no need to put in hardware list */
			}
		} // if (install_setup && (type == MT_SPECIAL_MODULE))
	} // for (pcidev=pciacc->devices; pcidev; pcidev = pcidev->next)

	pci_cleanup(pciacc);                  /* Close PCI */
}



/* fill in tables with data */
void hw_scan_hardware(int install_setup, int nopcmcia, int nousb, int manualmodule)
{
    char command[STRING_SIZE];
    newtComponent form;
    newtComponent text;
    newtComponent scale;
    char line[STRING_SIZE];
    int numBusses;
    int firstscan;
//    int type;
//    struct pci_access *pciacc;
//    struct pci_dev *pcidev;
//    char vendor[STRING_SIZE];
//    char description[STRING_SIZE];
    int i;
	static int have_usbdisk = 0;
	static int have_idedisk = 0;
	static int have_scsidisk = 0;   /* Also for SATA controller */

	hw_log_init(install_setup);
	HW_DETECT_F_LOG("Initializing and starting HW scan\n");

    numhardwares = 0;
    numharddisk = 0;
    numcdrom = 0;
    numnetwork = 0;

	// Add dummy one.
    hw_add_hardware(MT_NONE, NULL, NULL, NULL, "Dummy for initialization", 0, 0);

    numBusses = 3;
    /* disable stuff the user does not want or does not need */
    if (nopcmcia)
        numBusses--;
    if (nousb)
        numBusses--;

    snprintf(line, STRING_SIZE, lang_gettext("TR_SCANNING_HARDWARE"), "");
    text = newtLabel(1, 1, line);
    scale = newtScale(1, 3, 70, numBusses * 10);
    newtCenteredWindow(72, 5, lang_gettext("TR_TITLE_HARDWARE"));
    form = newtForm(NULL, NULL, 0);
    newtFormAddComponents(form, text, scale, NULL);

    newtDrawForm(form);
    newtRefresh();
    numBusses = 0;

    /*
     *  PCI scanning by using libpci, pci.ids.gz and modules.alias
     */
    snprintf(line, STRING_SIZE, lang_gettext("TR_SCANNING_HARDWARE"), "PCI");
    strcat(line, "           ");
    newtLabelSetText(text, line);
    newtRefresh();

    newtScaleSet(scale, numBusses * 10 + 1);
    newtRefresh();

    //fprintf(flog, "Scan PCI\n");
	F_LOG("Scan PCI\n");

	hw_scan_pci_bus(install_setup, nopcmcia, nousb,
			&have_scsidisk, &have_idedisk, &have_usbdisk);

#if 0
    pciacc = pci_alloc();               /* Get the pci_access structure */
    pci_init(pciacc);                   /* Initialize the PCI library */

    pci_scan_bus(pciacc);
    for (pcidev = pciacc->devices; pcidev; pcidev = pcidev->next) {
        type = MT_NONE;
        pci_fill_info(pcidev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);

        strcpy(vendor, "");
        strcpy(line, "");
        pci_lookup_name(pciacc, vendor, STRING_SIZE-1, PCI_LOOKUP_VENDOR, pcidev->vendor_id);
        pci_lookup_name(pciacc, line, STRING_SIZE-1, PCI_LOOKUP_DEVICE, pcidev->vendor_id, pcidev->device_id);
        snprintf(description, STRING_SIZE, "%s %s", vendor, line);

        switch((pcidev->device_class >> 8) & 0xFF) {
        case PCI_BASE_CLASS_STORAGE:        // 0x01
            if (install_setup)
                type = MT_SPECIAL_MODULE;
            break;

        case PCI_BASE_CLASS_NETWORK:        // 0x02
            type = MT_NETWORK;
            break;

        case PCI_BASE_CLASS_BRIDGE:         // 0x06
            /* A forcedeth onboard NIC that identifies as 0680 instead of 0200.
             *  At least device ID 0x00df and 0x03ef, maybe more.
             *  Filter out true bridge devices below, after searching for the module.
             */
            if ((pcidev->device_class == PCI_CLASS_BRIDGE_OTHER) && (pcidev->vendor_id == 0x10de))
                type = MT_NETWORK;
        
            if (install_setup && !nopcmcia 
                    && ((pcidev->device_class == PCI_CLASS_BRIDGE_PCMCIA) ||
					(pcidev->device_class == PCI_CLASS_BRIDGE_CARDBUS))) {
                type = MT_SPECIAL_MODULE;
            }
            break;            

        case PCI_BASE_CLASS_SERIAL:         // 0x0c
            if (install_setup && !nousb && (pcidev->device_class == PCI_CLASS_SERIAL_USB))
                type = MT_SPECIAL_MODULE;

            break;
        }

        if (type == MT_NONE) {
			HW_DETECT_F_LOG( "  Skip %04x %04x:%04x, %s\n",
					pcidev->device_class, pcidev->vendor_id, pcidev->device_id, description);
        } else {
            char *module = NULL;

            module = helper_kernel_find_modulename("pci", pcidev->vendor_id, pcidev->device_id);
            if (module != NULL) {
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", module);
                mysystem(command);

                if ((type == MT_NETWORK) && (pcidev->device_class == PCI_CLASS_BRIDGE_OTHER) &&
						(pcidev->vendor_id == 0x10de) && strcmp(module, "forcedeth")) {
                    /* Special case, nVidia PCI bridge_other not using forcedeth driver */
					HW_DETECT_F_LOG("  Skip (bridge_other) %04x %04x:%04x\n",
							pcidev->device_class, pcidev->vendor_id, pcidev->device_id);
                }
                else {
					HW_DETECT_F_LOG("  Add  %04x %04x:%04x, %s\n",
							pcidev->device_class, pcidev->vendor_id, pcidev->device_id, description);

                    hw_add_hardware(type, module, NULL, NULL, description, pcidev->vendor_id, pcidev->device_id);
                }
            } else {
                /* There is little to add if there is no module */
				HW_DETECT_F_LOG("  Skip (no module) %04x %04x:%04x\n",
						pcidev->device_class, pcidev->vendor_id, pcidev->device_id);
            }
        }

        /* Some special handling for special devices */
        if (install_setup && (type == MT_SPECIAL_MODULE)) {

fprintf(fhwdetect, "special module scsidisk %d device class 0x%x(%d) scsi 0x%x(%d) sata 0x%x(%d)\n", have_scsidisk, pcidev->device_class, pcidev->device_class, PCI_CLASS_STORAGE_SCSI, PCI_CLASS_STORAGE_SCSI, PCI_CLASS_STORAGE_SATA, PCI_CLASS_STORAGE_SATA);
            /* SCSI, SATA, add some modules */
            if (!have_scsidisk &&
					((pcidev->device_class == PCI_CLASS_STORAGE_SCSI) ||
					(pcidev->device_class == PCI_CLASS_STORAGE_SATA)))
			{
fprintf(fhwdetect, "scsidisk\n");
                have_scsidisk = 1;
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sd_mod");
                mysystem(command);
                hw_add_hardware(MT_SPECIAL_MODULE, "sd_mod", NULL, NULL, NULL, 0, 0);

                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sr_mod");
                mysystem(command);
                /* no need to put in hardware list */
            }

            /* IDE, add some modules */
            if (!have_idedisk && (pcidev->device_class == PCI_CLASS_STORAGE_IDE)) {
                have_idedisk = 1;
fprintf(fhwdetect, "idedisk IDE class 0x%x(%d)\n", PCI_CLASS_STORAGE_IDE, PCI_CLASS_STORAGE_IDE);
                // snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "ide-generic");
                // mysystem(command);
                // hw_add_hardware(MT_SPECIAL_MODULE, "ide-generic", NULL, NULL, NULL, 0, 0);
                /* Kernel >= 2.6.28 have ide-gd_mod instead of ide-disk */
                ////snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "ide-gd_mod");
                ////hw_add_hardware(MT_SPECIAL_MODULE, "ide-gd_mod", NULL, NULL, NULL, 0, 0);
            }

            /* USB, probe */
            if (!have_usbdisk && (pcidev->device_class == PCI_CLASS_SERIAL_USB)) {
                have_usbdisk = 1;
fprintf(fhwdetect, "usbdisk USB class 0x%x(%d)\n", PCI_CLASS_SERIAL_USB, PCI_CLASS_SERIAL_USB);
                /* 
                   Dependancies will load sd_mod, but sd_mod will not be in initramfs .
                   Not sure if installing onto USB stick is a good idea though.
                 */
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sd_mod");
                mysystem(command);
                hw_add_hardware(MT_SPECIAL_MODULE, "sd_mod", NULL, NULL, NULL, 0, 0);
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "usb-storage");
                mysystem(command);
                hw_add_hardware(MT_SPECIAL_MODULE, "usb-storage", NULL, NULL, NULL, 0, 0);

                /* need sr_mod when installing from USB CDROM */
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sr_mod");
                mysystem(command);
                /* no need to put in hardware list */
            }
        } // if (install_setup && (type == MT_SPECIAL_MODULE))
    } // for (pcidev=pciacc->devices; pcidev; pcidev = pcidev->next)

    pci_cleanup(pciacc);                  /* Close PCI */
#endif

    numBusses++;
    sleep(1);

    /*
     *  USB scanning by using libusb, pci.ids.gz and modules.alias
     */

//    if (nousb)
//        goto skipusb;

#if 0
    fprintf(flog, "Scan USB\n");

    snprintf(line, STRING_SIZE, lang_gettext("TR_SCANNING_HARDWARE"), "USB");
    strcat(line, "           ");
    newtLabelSetText(text, line);
    newtRefresh();

    newtScaleSet(scale, numBusses * 10 + 1);
    newtRefresh();

    names_init("/usr/share/usb.ids.gz");
    libusb_device **usbdevs;
    ssize_t cnt = 0;

    if (libusb_init(NULL) >= 0)
        cnt = libusb_get_device_list(NULL, &usbdevs);

    for (i = 0; (i < cnt) && (usbdevs[i] != NULL); i++) {
        struct libusb_device_descriptor descriptor;

        if (libusb_get_device_descriptor(usbdevs[i], &descriptor) < 0) {
            fprintf(flog, "libusb failed to get device descriptor\n");
            fprintf(fhwdetect, "libusb failed to get device descriptor\n");
            continue;
        }

        type = MT_NONE;
        strcpy(vendor, "");
        strcpy(line, "");
        get_vendor_string(vendor, sizeof(vendor), descriptor.idVendor);
        get_product_string(line, sizeof(line), descriptor.idVendor, descriptor.idProduct);
        snprintf(description, STRING_SIZE, "%s %s", vendor, line);

        /* TODO: find a better way to differentiate network devices from other USB devices */
        switch (descriptor.bDeviceClass) {
        case LIBUSB_CLASS_PER_INTERFACE:
            type = MT_NETWORK;
            break;

        case LIBUSB_CLASS_COMM:
            type = MT_NETWORK;
            break;

        case LIBUSB_CLASS_WIRELESS:
            type = MT_NETWORK;
            break;

        case LIBUSB_CLASS_VENDOR_SPEC:
            type = MT_NETWORK;
            break;
        }

        if (type == MT_NONE) {
            snprintf(logline, STRING_SIZE, "  Skip %02x %04x:%04x, %s\n",
                    descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct, description);
            fprintf(flog, "%s", logline);
            fprintf(fhwdetect, "%s", logline);
        }
        else {
            char *module = NULL;

            module = helper_kernel_find_modulename("usb", descriptor.idVendor, descriptor.idProduct);

            if (module != NULL) {
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", module);
                mysystem(command);

                snprintf(logline, STRING_SIZE, "  Add  %02x %04x:%04x, %s\n",
                        descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct, description);
                fprintf(flog, "%s", logline);
                fprintf(fhwdetect, "%s", logline);

                hw_add_hardware(MT_NETWORK, module, NULL, NULL, description, descriptor.idVendor, descriptor.idProduct);
            }
            else {
                /* There is little to add if there is no module */
                snprintf(logline, STRING_SIZE, "  Skip (no module) %02x %04x:%04x\n",
                        descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct);
                fprintf(flog, "%s", logline);
                fprintf(fhwdetect, "%s", logline);
            }
        }
    }

    numBusses++;
    if (cnt > 0) {
        libusb_free_device_list(usbdevs, 1);
        libusb_exit(NULL);
    }
#endif

	if (!nousb) {
		hw_scan_usb_bus(flog, numBusses, text, scale);
		numBusses++;
    	sleep(1);
	}

//skipusb:

    /*
     *  PCMCIA scanning (this needs work)
     */

#if 0
    if (nopcmcia)
        goto skippcmcia;

    fprintf(flog, "Scan PCMCIA\n");

    snprintf(line, STRING_SIZE, lang_gettext("TR_SCANNING_HARDWARE"), "PCMCIA");
    strcat(line, "           ");
    newtLabelSetText(text, line);
    newtRefresh();

    newtScaleSet(scale, numBusses * 10 + 1);
    newtRefresh();

    /* TODO: verify that yenta_socket is loaded and identified above. If not forcebly load it for dev. class 0x0607 */

    /* TODO: scanning? what? */

    numBusses++;
#endif

	if (!nopcmcia) {
		hw_scan_pcmcia_bus(flog, numBusses, text, scale);
		numBusses++;
		sleep(1);
	}

//skippcmcia:

    newtFormDestroy(form);
    newtPopWindow();

    //fprintf(flog, "Scanned busses. Continue with manual etc.\n");
	F_LOG("Scanned busses. Continue with manual etc.\n");

    while (manualmodule) {
        newtComponent button_done, button_add;
        newtComponent module, moduleentry;
        struct newtExitStruct exitstruct;
        const char *modulename;
        int numLines;

        text = newtTextboxReflowed(1, 1, "Load and add a specific kernel module.", 68, 0, 0, 0);
        numLines = newtTextboxGetNumLines(text);
        newtCenteredWindow(72, numLines + 10, lang_gettext("TR_TITLE_HARDWARE"));
        form = newtForm(NULL, NULL, 0);
        newtFormAddComponent(form, text);

        module = newtTextbox(2, numLines + 2, 25, 1, 0);
        newtTextboxSetText(module, "Module (without .ko):");
        newtFormAddComponent(form, module);
        moduleentry = newtEntry(12, numLines + 3, "", 20, &modulename, 0);
        newtFormAddComponent(form, moduleentry);

        button_add = newtButton(6, numLines + 5, lang_gettext("TR_OK"));
        button_done = newtButton(26, numLines + 5, lang_gettext("TR_DONE"));
        newtFormAddComponents(form, button_add, button_done, NULL);

        newtRefresh();
        newtDrawForm(form);
        newtFormRun(form, &exitstruct);

        if (exitstruct.u.co == button_add) {
            snprintf(command, STRING_SIZE, "/sbin/modprobe %s", modulename);
            if (!mysystem(command)) {
                hw_add_hardware(MT_SPECIAL_MODULE, (char *) modulename, NULL, NULL, NULL, 0, 0);
            } else {
                /* owes: show errorbox here */
            }
        }

        newtFormDestroy(form);
        newtPopWindow();

        if (exitstruct.u.co == button_done)
            break;
    }

    firstscan = TRUE;
    while (install_setup && (numharddisk == 0)) {
        fflush(fhwdetect);
        helper_nt_statuswindow(72, 5,
				lang_gettext("TR_TITLE_HARDWARE"), lang_gettext("TR_SCANNING_HARDWARE"), "drives");

        if (!firstscan) {
            /* since we've not yet waited since last modprobe, sleep now */
            sleep(2);
        }
        firstscan = FALSE;

        /* go hunting for drives */
        //fprintf(flog, "Scan for drives\n");
        //fprintf(fhwdetect, "Scan for drives\n");
		HW_DETECT_F_LOG("Scan for drives\n");
        hw_scan_proc_drives(1);

        newtPopWindow();

        if (numharddisk == 0) {
            newtComponent button_rescan, button_modprobe, button_cancel;
            newtComponent module, moduleentry;
            struct newtExitStruct exitstruct;
            const char *modulename;
            int numLines;

            text = newtTextboxReflowed(1, 1, lang_gettext("TR_NO_HARDDISK_MODPROBE"), 68, 0, 0, 0);
            numLines = newtTextboxGetNumLines(text);
            newtCenteredWindow(72, numLines + 9, lang_gettext("TR_TITLE_HARDWARE"));
            form = newtForm(NULL, NULL, 0);
            newtFormAddComponent(form, text);

            module = newtTextbox(2, numLines + 2, 10, 1, 0);
            newtTextboxSetText(module, "Module:");
            newtFormAddComponent(form, module);
            moduleentry = newtEntry(12, numLines + 2, "", 20, &modulename, 0);
            newtFormAddComponent(form, moduleentry);

            button_rescan = newtButton(6, numLines + 4, lang_gettext("TR_RESCAN"));
            button_modprobe = newtButton(26, numLines + 4, "Modprobe");
            button_cancel = newtButton(46, numLines + 4, lang_gettext("TR_CANCEL"));
            newtFormAddComponents(form, button_rescan, button_modprobe, button_cancel, NULL);

            newtRefresh();
            newtDrawForm(form);
            newtFormRun(form, &exitstruct);

            if (exitstruct.u.co == button_modprobe) {
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", modulename);
                if (!mysystem(command)) {
                    hw_add_hardware(MT_SPECIAL_MODULE, (char *) modulename, NULL, NULL, NULL, 0, 0);
                } else {
                    /* owes: show errorbox here */
                }
            }

            newtFormDestroy(form);
            newtPopWindow();

            if (exitstruct.u.co == button_cancel)
                return;
        }
    }

	HW_DETECT_F_LOG("Scan complete. Hardware %d, Harddisk %d, CDROM %d, Network %d\n",
			numhardwares, numharddisk, numcdrom, numnetwork);
    fclose(fhwdetect);
	fhwdetect = NULL;
}

