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
 * (c) 2007-2015, the Openfirewall Team
 *
 * $Id: hardware.c 7909 2015-03-01 11:25:39Z owes $
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
unsigned int numhardwares;
unsigned int numharddisk;
unsigned int numcdrom;
unsigned int numnetwork;


static FILE *fhwdetect;
static char logline[STRING_SIZE];
static int have_idedisk = 0;
static int have_scsidisk = 0;   /* Also for SATA controller */
static int have_usbdisk = 0;
static int have_idecd = 0;
static int install_setup = 0;   /* 0 when running setup (NIC detection), 1 for installer */


/* Retrieve disk capacity from proc or sys.
   Size is reported in blocks of 512 bytes, make a string with info GiB, MiB, KiB.
   Return size in MiB.
*/
static unsigned long getdrivesize(char *procname, char *strsize)
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
static void hardwareadd(supported_media_t type, char *module, char *device, char *vendor, char *description,
                        u16 vendorid, u16 modelid)
{
    char vendordesc[STRING_SIZE] = "";
    char tmpstring[STRING_SIZE];

    if ((device != NULL) && (numhardwares != 0)) {
        /* avoid duplicates */
        int i;

        for (i = 0; i < numhardwares; i++) {
            if (!strcmp(device, hardwares[i].device)) {
                return;
            }
        }
    }

    hardwares = realloc(hardwares, sizeof(struct hardware_s) * (numhardwares + 1));

    hardwares[numhardwares].type = type;

    if (module != NULL) {
        hardwares[numhardwares].module = strdup(module);
    }
    else {
        hardwares[numhardwares].module = strdup("");
    }

    if (device != NULL) {
        hardwares[numhardwares].device = strdup(device);
    }
    else {
        hardwares[numhardwares].device = strdup("");
    }

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
    }
    else {
        /* no description, use IDs */
        snprintf(vendordesc, STRING_SIZE, "Unknown %04x:%04x", vendorid, modelid);
    }
    hardwares[numhardwares].description = strdup(vendordesc);

    snprintf(logline, STRING_SIZE, "  HWadd %3d, %s, %s, %s\n", type, hardwares[numhardwares].module,
            hardwares[numhardwares].device, hardwares[numhardwares].description);
    fprintf(flog, "%s", logline);
    fprintf(fhwdetect, "%s", logline);
    // increment tallies
    numhardwares++;
    switch (type) {
    case network:
        numnetwork++;
        break;
    case harddisk:
        numharddisk++;
        break;
    case cdrom:
        numcdrom++;
        break;
    default:
        break;
    }
}


/* 
    Filter function for scanning /sys/bus/ide/devices
    Used by scandir in scanprocdrives function.
    Return 0 to skip a device
*/
int ide_filter(const struct dirent *b)
{
    char string[STRING_SIZE];

    snprintf(string, STRING_SIZE, "/sys/bus/ide/devices/%s/media", b->d_name);

    if (access(string, 0) == 0) {
        return 1;
    }

    return 0;
}


/* Scan /sys/bus/ide and /sys/block for drives */
static void scanprocdrives(int modprobe)
{
    FILE *f = NULL;
    char procname[STRING_SIZE];
    char media[STRING_SIZE];
    char model[STRING_SIZE];
    supported_media_t type = none;
    char command[STRING_SIZE];
    char deviceletter;
    char strsize[STRING_SIZE];
    struct dirent **names;
    int numdevices = 0;
    int i;

    /* look for IDE harddisk and cdrom */
    numdevices = scandir("/sys/bus/ide/devices", &names, &ide_filter, alphasort);
    for (i = 0; i < numdevices; i++) {
        snprintf(procname, STRING_SIZE, "/sys/bus/ide/devices/%s/media", names[i]->d_name);
        if ((f = fopen(procname, "r")) == NULL) {
            continue;
        }

        /* media holds disk or cdrom */
        if (fgets(media, STRING_SIZE, f)) {
            stripnl(media);
            if (!strcmp(media, "disk")) {
                type = harddisk;
            }
            else if (!strcmp(media, "cdrom")) {
                type = cdrom;
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

        if (type != none) {
            char device[STRING_SIZE];
            char description[STRING_SIZE] = "Unknown";

            /* found something, get device name (hd?), model and size */
            snprintf(procname, STRING_SIZE, "/sys/bus/ide/devices/%s/drivename", names[i]->d_name);
            if ((f = fopen(procname, "r")) != NULL) {
                if (fgets(device, STRING_SIZE, f)) {
                    stripnl(device);
                    fclose(f);

                    snprintf(procname, STRING_SIZE, "/sys/bus/ide/devices/%s/model", names[i]->d_name);
                    if ((f = fopen(procname, "r")) != NULL) {
                        if (fgets(model, STRING_SIZE, f)) {
                            stripnl(model);
                            if (type == harddisk) {
                                snprintf(procname, STRING_SIZE, "/sys/block/%s/size", device);
                                getdrivesize(procname, strsize);

                                snprintf(description, STRING_SIZE, "%-30.30s (%s)", model, strsize);
                            }
                            else {
                                /* size is not interesting for CDROM */
                                strcpy(description, model);
                            }
                        }
                    }
                }
                fclose(f);
            }

            hardwareadd(type, NULL, device, NULL, description, 0, 0);
        }
    }


    /* Look for SCSI, SATA harddisk, USB attached devices */
    for (deviceletter = 'a'; deviceletter <= 'z'; deviceletter++) {
        snprintf(procname, STRING_SIZE, "/sys/block/sd%c/device/model", deviceletter);

        if ((f = fopen(procname, "r")) == NULL) {
            continue;
        }

        /* We need some mechanism to differentiate between installation from USB stick
           or installation on USB device
         */

        if (fgets(model, STRING_SIZE, f)) {
            char device[4];
            char description[STRING_SIZE] = "Unknown";
            unsigned long drivesize;

            stripnl(model);
            sprintf(device, "sd%c", deviceletter);

            snprintf(procname, STRING_SIZE, "/sys/block/sd%c/size", deviceletter);
            drivesize = getdrivesize(procname, strsize);
            snprintf(description, STRING_SIZE, "%-30.30s (%s)", model, strsize);
            if (drivesize < 32) {
                /* Discard if too small for installation and too small as target drive */
                snprintf(logline, STRING_SIZE, "   discard sd%c %-30.30s (%s)\n", deviceletter, model, strsize);
                fprintf(flog, "%s", logline);
                fprintf(fhwdetect, "%s", logline);
                continue;
            }
            else if (drivesize < DISK_MINIMUM) {
                /* Too small as target drive but could be installation USB stick */
                hardwareadd(cdrom, NULL, device, NULL, description, 0, 0);
            }
            else {
                hardwareadd(harddisk, NULL, device, NULL, description, 0, 0);
            }
        }

        fclose(f);
    }

    /* Look for SCSI, SATA, USB cdrom */
    for (deviceletter = '0'; deviceletter <= '9'; deviceletter++) {
        snprintf(procname, STRING_SIZE, "/sys/block/sr%c/device/model", deviceletter);

        if ((f = fopen(procname, "r")) == NULL) {
            continue;
        }

        if (fgets(model, STRING_SIZE, f)) {
            char device[4];

            stripnl(model);
            sprintf(device, "sr%c", deviceletter);
            hardwareadd(cdrom, NULL, device, NULL, model, 0, 0);
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


/* fill in tables with data */
void scan_hardware(int flag_i_s, int nopcmcia, int nousb, int manualmodule)
{
    char command[STRING_SIZE];
    newtComponent form;
    newtComponent text;
    newtComponent scale;
    char line[STRING_SIZE];
    int numBusses;
    int firstscan;
    supported_media_t type;
    struct pci_access *pciacc;
    struct pci_dev *pcidev;
    char vendor[STRING_SIZE];
    char description[STRING_SIZE];
    int i;


    install_setup = flag_i_s;
    /* also write HW detection to file, for easier reference */
    if (install_setup) {
        /* Installer: write hwdetect, this will later be copied to /var/log on target system */
        fhwdetect = fopen("/tmp/hwdetect", "w");
    }
    else {
        /* Setup: used for network card detection only */
        fhwdetect = fopen("/tmp/netdetect", "w");
    }
    fprintf(flog, "Initializing and starting HW scan\n");
    fprintf(fhwdetect, "Initializing and starting HW scan\n");

    numhardwares = 0;
    numharddisk = 0;
    numcdrom = 0;
    numnetwork = 0;
    hardwareadd(none, NULL, NULL, NULL, "Dummy for initialization", 0, 0);

    numBusses = 3;
    /* disable stuff the user does not want or does not need */
    if (nopcmcia) {
        numBusses--;
    }
    if (nousb) {
        numBusses--;
    }

    snprintf(line, STRING_SIZE, ofw_gettext("TR_SCANNING_HARDWARE"), "");
    text = newtLabel(1, 1, line);
    scale = newtScale(1, 3, 70, numBusses * 10);
    newtCenteredWindow(72, 5, ofw_gettext("TR_TITLE_HARDWARE"));
    form = newtForm(NULL, NULL, 0);
    newtFormAddComponents(form, text, scale, NULL);

    newtDrawForm(form);
    newtRefresh();
    numBusses = 0;

    /*
     *  PCI scanning by using libpci, pci.ids.gz and modules.alias
     *
     *
     */

    snprintf(line, STRING_SIZE, ofw_gettext("TR_SCANNING_HARDWARE"), "PCI");
    strcat(line, "           ");
    newtLabelSetText(text, line);
    newtRefresh();

    newtScaleSet(scale, numBusses * 10 + 1);
    newtRefresh();

    fprintf(flog, "Scan PCI\n");

    pciacc = pci_alloc();               /* Get the pci_access structure */
    pci_init(pciacc);                   /* Initialize the PCI library */

    pci_scan_bus(pciacc);
    for (pcidev=pciacc->devices; pcidev; pcidev = pcidev->next) {
        type = none;
        pci_fill_info(pcidev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);

        strcpy(vendor, "");
        strcpy(line, "");
        pci_lookup_name(pciacc, vendor, STRING_SIZE-1, PCI_LOOKUP_VENDOR, pcidev->vendor_id);
        pci_lookup_name(pciacc, line, STRING_SIZE-1, PCI_LOOKUP_DEVICE, pcidev->vendor_id, pcidev->device_id);
        snprintf(description, STRING_SIZE, "%s %s", vendor, line);

        switch((pcidev->device_class >> 8) & 0xFF) {
        case PCI_BASE_CLASS_STORAGE:        // 0x01
            if (install_setup) {
                type = specialmodule;
            }
            break;

        case PCI_BASE_CLASS_NETWORK:        // 0x02
            type = network;
            break;

        case PCI_BASE_CLASS_BRIDGE:         // 0x06
            /* A forcedeth onboard NIC that identifies as 0680 instead of 0200.
             *  At least device ID 0x00df and 0x03ef, maybe more.
             *  Filter out true bridge devices below, after searching for the module.
             */
            if ((pcidev->device_class == PCI_CLASS_BRIDGE_OTHER) && (pcidev->vendor_id == 0x10de)) {
                type = network;
            }
        
            if (install_setup && !nopcmcia 
                    && ((pcidev->device_class == PCI_CLASS_BRIDGE_PCMCIA) || (pcidev->device_class == PCI_CLASS_BRIDGE_CARDBUS))) {
                type = specialmodule;
            }
            break;            

        case PCI_BASE_CLASS_SERIAL:         // 0x0c
            if (install_setup && !nousb && (pcidev->device_class == PCI_CLASS_SERIAL_USB)) {
                type = specialmodule;
            }
            break;
        }

        if (type == none) {
            snprintf(logline, STRING_SIZE, "  Skip %04x %04x:%04x, %s\n",
                    pcidev->device_class, pcidev->vendor_id, pcidev->device_id, description);
            fprintf(flog, "%s", logline);
            fprintf(fhwdetect, "%s", logline);
        }
        else {
            char *module = NULL;

            module = find_modulename("pci", pcidev->vendor_id, pcidev->device_id);

            if (module != NULL) {
                if ((type == network) && (pcidev->device_class == PCI_CLASS_BRIDGE_OTHER) && (pcidev->vendor_id == 0x10de) && strcmp(module, "forcedeth")) {
                    /* Special case, nVidia PCI bridge_other not using forcedeth driver */
                    snprintf(logline, STRING_SIZE, "  Skip (bridge_other) %04x %04x:%04x\n",
                            pcidev->device_class, pcidev->vendor_id, pcidev->device_id);
                    fprintf(flog, "%s", logline);
                    fprintf(fhwdetect, "%s", logline);
                }
                else {
                    snprintf(logline, STRING_SIZE, "  Add  %04x %04x:%04x, %s\n",
                            pcidev->device_class, pcidev->vendor_id, pcidev->device_id, description);
                    fprintf(flog, "%s", logline);
                    fprintf(fhwdetect, "%s", logline);

                    hardwareadd(type, module, NULL, NULL, description, pcidev->vendor_id, pcidev->device_id);
                }
            }
            else {
                /* There is little to add if there is no module */
                snprintf(logline, STRING_SIZE, "  Skip (no module) %04x %04x:%04x\n",
                        pcidev->device_class, pcidev->vendor_id, pcidev->device_id);
                fprintf(flog, "%s", logline);
                fprintf(fhwdetect, "%s", logline);
            }
        }

        /* Some special handling for special devices */
        if (install_setup && (type == specialmodule)) {

            /* SCSI, SATA, add some modules */
            if (!have_scsidisk && ((pcidev->device_class == PCI_CLASS_STORAGE_SCSI) || (pcidev->device_class == PCI_CLASS_STORAGE_SATA))) {
                have_scsidisk = 1;
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sd_mod");
                mysystem(command);
                hardwareadd(specialmodule, "sd_mod", NULL, NULL, NULL, 0, 0);

                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sr_mod");
                mysystem(command);
                /* no need to put in hardware list */
            }

            /* IDE, add some modules */
            if (!have_idedisk && (pcidev->device_class == PCI_CLASS_STORAGE_IDE)) {
                have_idedisk = 1;
                // snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "ide-generic");
                // mysystem(command);
                // hardwareadd(specialmodule, "ide-generic", NULL, NULL, NULL, 0, 0);
                /* Kernel >= 2.6.28 have ide-gd_mod instead of ide-disk */
                ////snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "ide-gd_mod");
                ////hardwareadd(specialmodule, "ide-gd_mod", NULL, NULL, NULL, 0, 0);
            }

            /* USB, probe */
            if (!have_usbdisk && (pcidev->device_class == PCI_CLASS_SERIAL_USB)) {
                have_usbdisk = 1;
                /* 
                   Dependancies will load sd_mod, but sd_mod will not be in initramfs .
                   Not sure if installing onto USB stick is a good idea though.
                 */
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sd_mod");
                mysystem(command);
                hardwareadd(specialmodule, "sd_mod", NULL, NULL, NULL, 0, 0);
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "usb-storage");
                mysystem(command);
                hardwareadd(specialmodule, "usb-storage", NULL, NULL, NULL, 0, 0);

                /* need sr_mod when installing from USB CDROM */
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", "sr_mod");
                mysystem(command);
                /* no need to put in hardware list */
            }
        } // if (install_setup && (type == specialmodule))
    } // for (pcidev=pciacc->devices; pcidev; pcidev = pcidev->next)

    pci_cleanup(pciacc);                  /* Close PCI */

    numBusses++;
    sleep(1);

    /*
     *  USB scanning by using libusb, pci.ids.gz and modules.alias
     *
     *
     */

    if (nousb) {
        goto skipusb;
    }

    fprintf(flog, "Scan USB\n");

    snprintf(line, STRING_SIZE, ofw_gettext("TR_SCANNING_HARDWARE"), "USB");
    strcat(line, "           ");
    newtLabelSetText(text, line);
    newtRefresh();

    newtScaleSet(scale, numBusses * 10 + 1);
    newtRefresh();

    names_init("/usr/share/usb.ids.gz");
    libusb_device **usbdevs;
    ssize_t cnt = 0;
    if (libusb_init(NULL) >= 0) {
        cnt = libusb_get_device_list(NULL, &usbdevs);
    }

    for (i = 0; (i < cnt) && (usbdevs[i] != NULL); i++) {
        struct libusb_device_descriptor descriptor;

        if (libusb_get_device_descriptor(usbdevs[i], &descriptor) < 0) {
            fprintf(flog, "libusb failed to get device descriptor\n");
            fprintf(fhwdetect, "libusb failed to get device descriptor\n");
            continue;
        }

        type = none;
        strcpy(vendor, "");
        strcpy(line, "");
        get_vendor_string(vendor, sizeof(vendor), descriptor.idVendor);
        get_product_string(line, sizeof(line), descriptor.idVendor, descriptor.idProduct);
        snprintf(description, STRING_SIZE, "%s %s", vendor, line);

        /* TODO: find a better way to differentiate network devices from other USB devices */
        switch (descriptor.bDeviceClass) {
        case LIBUSB_CLASS_PER_INTERFACE:
            type = network;
            break;

        case LIBUSB_CLASS_COMM:
            type = network;
            break;

        case LIBUSB_CLASS_WIRELESS:
            type = network;
            break;

        case LIBUSB_CLASS_VENDOR_SPEC:
            type = network;
            break;
        }

        if (type == none) {
            snprintf(logline, STRING_SIZE, "  Skip %02x %04x:%04x, %s\n",
                    descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct, description);
            fprintf(flog, "%s", logline);
            fprintf(fhwdetect, "%s", logline);
        }
        else {
            char *module = NULL;

            module = find_modulename("usb", descriptor.idVendor, descriptor.idProduct);

            if (module != NULL) {
                snprintf(logline, STRING_SIZE, "  Add  %02x %04x:%04x, %s\n",
                        descriptor.bDeviceClass, descriptor.idVendor, descriptor.idProduct, description);
                fprintf(flog, "%s", logline);
                fprintf(fhwdetect, "%s", logline);

                hardwareadd(network, module, NULL, NULL, description, descriptor.idVendor, descriptor.idProduct);
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
    sleep(1);

skipusb:

    /*
     *  PCMCIA scanning (this needs work)
     *
     *
     */

    if (nopcmcia) {
        goto skippcmcia;
    }

    fprintf(flog, "Scan PCMCIA\n");

    snprintf(line, STRING_SIZE, ofw_gettext("TR_SCANNING_HARDWARE"), "PCMCIA");
    strcat(line, "           ");
    newtLabelSetText(text, line);
    newtRefresh();

    newtScaleSet(scale, numBusses * 10 + 1);
    newtRefresh();

    /* TODO: verify that yenta_socket is loaded and identified above. If not forcebly load it for dev. class 0x0607 */

    /* TODO: scanning? what? */

    numBusses++;
    sleep(1);

skippcmcia:

    newtFormDestroy(form);
    newtPopWindow();

    fprintf(flog, "Scanned busses. Continue with manual etc.\n");

    while (manualmodule) {
        newtComponent button_done, button_add;
        newtComponent module, moduleentry;
        struct newtExitStruct exitstruct;
        const char *modulename;
        int numLines;

        text = newtTextboxReflowed(1, 1, "Load and add a specific kernel module.", 68, 0, 0, 0);
        numLines = newtTextboxGetNumLines(text);
        newtCenteredWindow(72, numLines + 10, ofw_gettext("TR_TITLE_HARDWARE"));
        form = newtForm(NULL, NULL, 0);
        newtFormAddComponent(form, text);

        module = newtTextbox(2, numLines + 2, 25, 1, 0);
        newtTextboxSetText(module, "Module (without .ko):");
        newtFormAddComponent(form, module);
        moduleentry = newtEntry(12, numLines + 3, "", 20, &modulename, 0);
        newtFormAddComponent(form, moduleentry);

        button_add = newtButton(6, numLines + 5, ofw_gettext("TR_OK"));
        button_done = newtButton(26, numLines + 5, ofw_gettext("TR_DONE"));
        newtFormAddComponents(form, button_add, button_done, NULL);

        newtRefresh();
        newtDrawForm(form);
        newtFormRun(form, &exitstruct);

        if (exitstruct.u.co == button_add) {
            snprintf(command, STRING_SIZE, "/sbin/modprobe %s", modulename);
            if (!mysystem(command)) {
                hardwareadd(specialmodule, (char *) modulename, NULL, NULL, NULL, 0, 0);
            }
            else {
                /* owes: show errorbox here */
            }
        }

        newtFormDestroy(form);
        newtPopWindow();

        if (exitstruct.u.co == button_done) {
            break;
        }
    }

    firstscan = TRUE;
    while (install_setup && (numharddisk == 0)) {
        fflush(fhwdetect);
        statuswindow(72, 5, ofw_gettext("TR_TITLE_HARDWARE"), ofw_gettext("TR_SCANNING_HARDWARE"), "drives");

        if (!firstscan) {
            /* since we've not yet waited since last modprobe, sleep now */
            sleep(2);
        }
        firstscan = FALSE;

        /* go hunting for drives */
        fprintf(flog, "Scan for drives\n");
        fprintf(fhwdetect, "Scan for drives\n");
        scanprocdrives(1);

        newtPopWindow();

        if (numharddisk == 0) {
            newtComponent button_rescan, button_modprobe, button_cancel;
            newtComponent module, moduleentry;
            struct newtExitStruct exitstruct;
            const char *modulename;
            int numLines;

            text = newtTextboxReflowed(1, 1, ofw_gettext("TR_NO_HARDDISK_MODPROBE"), 68, 0, 0, 0);
            numLines = newtTextboxGetNumLines(text);
            newtCenteredWindow(72, numLines + 9, ofw_gettext("TR_TITLE_HARDWARE"));
            form = newtForm(NULL, NULL, 0);
            newtFormAddComponent(form, text);

            module = newtTextbox(2, numLines + 2, 10, 1, 0);
            newtTextboxSetText(module, "Module:");
            newtFormAddComponent(form, module);
            moduleentry = newtEntry(12, numLines + 2, "", 20, &modulename, 0);
            newtFormAddComponent(form, moduleentry);

            button_rescan = newtButton(6, numLines + 4, ofw_gettext("TR_RESCAN"));
            button_modprobe = newtButton(26, numLines + 4, "Modprobe");
            button_cancel = newtButton(46, numLines + 4, ofw_gettext("TR_CANCEL"));
            newtFormAddComponents(form, button_rescan, button_modprobe, button_cancel, NULL);

            newtRefresh();
            newtDrawForm(form);
            newtFormRun(form, &exitstruct);

            if (exitstruct.u.co == button_modprobe) {
                snprintf(command, STRING_SIZE, "/sbin/modprobe %s", modulename);
                if (!mysystem(command)) {
                    hardwareadd(specialmodule, (char *) modulename, NULL, NULL, NULL, 0, 0);
                }
                else {
                    /* owes: show errorbox here */
                }
            }

            newtFormDestroy(form);
            newtPopWindow();

            if (exitstruct.u.co == button_cancel) {
                return;
            }
        }
    }

    snprintf(logline, STRING_SIZE, "Scan complete. Hardware %d, Harddisk %d, CDROM %d, Network %d\n", numhardwares, numharddisk,
            numcdrom, numnetwork);
    fprintf(flog, "%s", logline);
    fprintf(fhwdetect, "%s", logline);
    fclose(fhwdetect);
}
