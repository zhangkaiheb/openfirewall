/*
 * networking.c: 
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
 * (c) 2018-2020, the Openfirewall Team
 *
 */


#include <dirent.h>
#include <libintl.h>
#include <malloc.h>
#include <newt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include "common_newt.h"
#include "arch_defs.h"


/* list of ISA (and others) cards that are not auto-detected */
#define ISA_MAX     256         // arbitrary value, should be more than sufficient
                                // to hold all non auto detectable cards
char *isa_nics_module[ISA_MAX];
char *isa_nics_description[ISA_MAX];

static char kv_red_type[STRING_SIZE] = "";      /* extra variable for red type */
static struct network_dev_s *sys_netdevices;      /* make our own table for easier handling */

static int changed_type;        /* red type                   */
static int changed_hostname;    /* hostname (DHCP Red)        */
static int changed_green;       /* IP and netmask green       */
static int changed_red;         /* IP and netmask red         */
static int changed_blue;        /* IP and netmask blue        */
static int changed_orange;      /* IP and netmask orange      */
static int changed_dnsgateway;  /* DNS1, DNS2 and gateway     */


#if 1
/* Read list of ISA network cards */
static void readisanics(void)
{
    int i;
    FILE *f;
    char buffer[STRING_SIZE];

    /* clean the list */
    for (i = 0; i < ISA_MAX; i++) {
        if (isa_nics_module[i] != NULL) {
            free(isa_nics_module[i]);
            isa_nics_module[i] = NULL;
        }
        if (isa_nics_description[i] != NULL) {
            free(isa_nics_description[i]);
            isa_nics_description[i] = NULL;
        }
    }

    if (!(f = fopen("/etc/nic-modules-list", "r")))
        return;

    /* Insert MANUAL at top */
    isa_nics_description[0] = strdup(gettext("TR_MANUAL"));
    isa_nics_module[0] = strdup("");
    i = 1;

    while ((fgets(buffer, STRING_SIZE, f) != NULL) && (i < ISA_MAX)) {
        char *ptr = strchr(buffer, ',');

        stripnl(buffer);
        /* We expect at least 3 characters.
           Simply skip lines containing comment character.
           Also skip lines not containing comma.
         */
        if ((strlen(buffer) < 3) || strchr(buffer, '#') || (ptr == NULL)) {
            continue;
        }

        isa_nics_description[i] = strdup(ptr + 1);
        *ptr = 0;
        isa_nics_module[i] = strdup(buffer);
        i++;
    }
    fclose(f);


    /* Output the found list for testing purposes */
	F_LOG("ISA list\n");
    for (i = 0; isa_nics_module[i] != NULL; i++) {
		F_LOG("%s, %s\n", isa_nics_module[i], isa_nics_description[i]);
    }
}
#endif

/* 
    Filter function for scanning directory /sys/class/net
    Used by scandir in probe_card function.
    Return 0 to skip a dir entry
*/
static int net_skip_network_dev(const struct dirent *d)
{
    int i;

    if (!strcmp(d->d_name, "lo") || !strcmp(d->d_name, ".") ||
		!strcmp(d->d_name, "..") || !strncmp(d->d_name, "ppp", 3)) {
        /* these are not really interesting */
        return 0;
    }

    if (!strncmp(d->d_name, "tun", 3)) {
        /* this is kind of a special device, might be interesting one day */
        return 0;
    }

    if (!strncmp(d->d_name, "wmaster", 7)) {
        /* special device, additional for WLAN cards */
        return 0;
    }

    for (i = 0; i < hw_get_network_num(); i++) {
        if (sys_netdevices[i].device[0] &&
			!strcmp(d->d_name, sys_netdevices[i].device)) {
            /* we've already got this one listed */
            return 0;
        }
    }

    /* not in our list (yet) */
    return 1;
}


/*  Modprobe some module, then look for new network device(s)
    or look for already present network device(s) without modprobing
*/
static int net_probe_netdev_card(char *module, char *description, char *options, int error)
{
    char command[STRING_SIZE];
    struct dirent **dir;
    int card_num;
    int i, j, k;
	int num = hw_get_network_num();

    if (module != NULL) {
        /* ToDo test if module already loaded ? */
        /* errorbox(gettext("TR_THIS_DRIVER_MODULE_IS_ALREADY_LOADED")); */
        snprintf(command, STRING_SIZE-1, "/sbin/modprobe %s %s", module, options);
        if (mysystem(command)) {
            if (error)
                errorbox(gettext("TR_UNABLE_TO_LOAD_DRIVER_MODULE"));

            return FAILURE;
        }
    }

    /* this needs some more thinking and testing,
	 * give me some time to try and test imaginable combinations.
	 */
    card_num = scandir("/sys/class/net", &dir, net_skip_network_dev, alphasort);
    if (!card_num) {
        /* no new card found, but modprobe did not report an error ? */
        return FAILURE;
    }

    if (module == NULL) {
        F_LOG("nothing probed, found %d new network cards\n", card_num);

        /* walk thru all interfaces and try to match to our information list */
        for (i = 0, j = 0; (i < card_num); i++) {
            int found = 0;
            char *kernel_mod = helper_kernel_get_netdev_info(dir[i]->d_name);

            /* First match on Vendor and Device ID (if present) */
            F_LOG("  %s %s %s %s\n",
					dir[i]->d_name, kernel_mod, vendorid_buffer, deviceid_buffer);

            if ((strlen(vendorid_buffer) > 0) && (strlen(deviceid_buffer) > 0)) {
                for (k = 0; !found && (k < num); k++) {
                    if (!sys_netdevices[k].device[0] && 
                            (strlen(sys_netdevices[k].vendorid) > 0) &&
							!strcmp(sys_netdevices[k].vendorid, vendorid_buffer) &&
                            (strlen(sys_netdevices[k].modelid) > 0) &&
							!strcmp(sys_netdevices[k].modelid, deviceid_buffer)) {

                        free(sys_netdevices[k].device);
                        sys_netdevices[k].device = strdup(dir[i]->d_name);
                        sys_netdevices[k].address = strdup(helper_getmac(sys_netdevices[k].device));
                        F_LOG("  hwlist %s device %s MAC %s\n", 
                            	sys_netdevices[k].module, sys_netdevices[k].device, sys_netdevices[k].address);
                        found = 1;
                        j++;
                    }
                }
            }

            if (!kernel_mod[0]) {
                F_LOG("  no kernel module found for device %s\n", dir[i]->d_name);
                continue;
            }

            for (k = 0; !found && (k < num); k++) {
                if (!sys_netdevices[k].device[0] &&
					!strcmp(kernel_mod, sys_netdevices[k].module)) {

                    free(sys_netdevices[k].device);
                    sys_netdevices[k].device = strdup(dir[i]->d_name);
                    sys_netdevices[k].address = strdup(helper_getmac(sys_netdevices[k].device));
                    F_LOG("  hwlist %s device %s MAC %s\n", 
                        sys_netdevices[k].module, sys_netdevices[k].device, sys_netdevices[k].address);
                    j++;
                    break;
                }
            }
        }
    } else { /* (module != NULL */
        F_LOG("probed kernel module %s, found %d new network cards\n", module, card_num);

        /* walk thru our information list and try to match kernel modules */
        for (i = 0, j = 0; (i < num) && (j < card_num); i++) {
            if (!sys_netdevices[i].device[0] && !strcmp(module, sys_netdevices[i].module)) {
                free(sys_netdevices[i].device);
                sys_netdevices[i].device = strdup(dir[j]->d_name);
                /* get and store MAC address */
                sys_netdevices[i].address = strdup(helper_getmac(sys_netdevices[i].device));
                j++;
                F_LOG("  hwlist %s device %s MAC %s\n",
						module, sys_netdevices[i].device, sys_netdevices[i].address);
            }
        }

        /* After modprobe and scanning through our list of detected HW, we are still left with a NIC 
            This can be ISA NIC or manually modprobed (multiple NICS possible?) */
        while ((j < card_num) && (description != NULL)) {

            sys_netdevices = realloc(sys_netdevices, sizeof(struct network_dev_s) * (num + 1));
            sys_netdevices[num].module = strdup(module);
            sys_netdevices[num].options = strdup(options);
            sys_netdevices[num].device = strdup(dir[j]->d_name);
            sys_netdevices[num].description = strdup(description);
            sys_netdevices[num].colour = NONE;
            sys_netdevices[num].address = strdup(helper_getmac(sys_netdevices[num].device));
            sys_netdevices[num].vendorid = "";
            sys_netdevices[num].modelid = "";
            F_LOG("  hwlist (ISA/manual) %s device %s MAC %s\n",
					module, sys_netdevices[num].device, sys_netdevices[num].address);

			num++;
            j++;
        }
		hw_set_network_num(num);
    }

    if (j < card_num) {
        F_LOG("  some stray modprobe?\n");

        /* Should remember these, because a next net_probe_netdev_card() might assign this stray one to a wrong driver */
    }
    return SUCCESS;
}


/* Use discover to find hardware, build list with detected network cards */
static void net_scan_cards(void)
{
    int i;
	int num = 0;
	static int scanned = 0;

    if (scanned)
        return;
    scanned = 1;

    /* scan for NICs, disable SCSI, no need to add modules manually */
    hw_scan_hardware(0, 0, 0, 0);
    hw_set_network_num(0);

    /* setup our own table */
    for (i = 0; i < hw_get_hardwares_num(); i++) {
        if (hardwares[i].type == MT_NETWORK) {
            sys_netdevices = realloc(sys_netdevices, sizeof(struct network_dev_s) * (num + 1));
            sys_netdevices[num].module = hardwares[i].module;
            sys_netdevices[num].options = strdup("");
            sys_netdevices[num].device = strdup("");
            sys_netdevices[num].description = hardwares[i].description;
            sys_netdevices[num].colour = NONE;
            sys_netdevices[num].address = strdup("");
            sys_netdevices[num].vendorid = hardwares[i].vendorid;
            sys_netdevices[num].modelid = hardwares[i].modelid;

			num++;
        }
    }
	hw_set_network_num(num);

    if (flag_is_state == INST_SETUP) {
        /* 
           special case, we already have module(s) and card(s) 
           match ethernet/settings to hwlist

           owes: this may need some more intelligence to cover situations where NICs were added/removed etc.
         */
        int c, j, n;
        char key[STRING_SIZE];

        for (i = 0; i < CFG_COLOURS_COUNT - 1; i++) {
            snprintf(key, STRING_SIZE, "%s_COUNT", openfw_colours_text[i]);
            c = atoi(find_kv(eth_kv, key));

            for (j = 1; j <= c; j++) {
                int found = 0;
                char *device;

                snprintf(key, STRING_SIZE, "%s_%d_DEV", openfw_colours_text[i], j);
                device = strdup(find_kv(eth_kv, key));

                /* Test if the configured device is still present */
                if (exist_ethernet_device(device) == FAILURE) {
                    free(device);
                    continue;
                }

                /* Check for Vendor / Device ID first */
                helper_kernel_get_netdev_info(device);

                if ((strlen(vendorid_buffer) > 0) && (strlen(deviceid_buffer) > 0)) {
                    for (n = 0; !found && (n < num); n++) {
                        if (!sys_netdevices[n].device[0] && 
                            (strlen(sys_netdevices[n].vendorid) > 0) &&
							!strcmp(sys_netdevices[n].vendorid, vendorid_buffer) &&
                            (strlen(sys_netdevices[n].modelid) > 0) &&
							!strcmp(sys_netdevices[n].modelid, deviceid_buffer)) {
                            /* 6,5,4,3,2,1 meins */
                            sys_netdevices[n].colour = i;
                            sys_netdevices[n].device = device;

                            /* owes: copy driver options here */

                            /* find MAC address */
                            sys_netdevices[n].address = strdup(helper_getmac(sys_netdevices[n].device));
                            found = 1;
                        }
                    }
                }

                snprintf(key, STRING_SIZE, "%s_%d_DRIVER", openfw_colours_text[i], j);
                for (n = 0; !found && (n < num); n++) {
                    if (!sys_netdevices[n].device[0] && (find_kv(eth_kv, key) != NULL)
                        && !strcmp(sys_netdevices[n].module, find_kv(eth_kv, key))) {
                        /* 3,2,1 meins */
                        sys_netdevices[n].colour = i;
                        sys_netdevices[n].device = strdup(device);

                        /* owes: copy driver options here */

                        /* find MAC address */
                        sys_netdevices[n].address = strdup(helper_getmac(sys_netdevices[n].device));
                        found = 1;
                    }
                }

                if (!found && strlen(module_buffer) &&
					strlen(vendorid_buffer) && strlen(deviceid_buffer)) {
                    /* Not detected by our HW scanner, but plenty of information from device itself */
                    sys_netdevices = realloc(sys_netdevices, sizeof(struct network_dev_s) * (num + 1));

                    sys_netdevices[num].module = module_buffer;
                    sys_netdevices[num].options = strdup("");
                    sys_netdevices[num].device = device;
                    sys_netdevices[num].description = strdup("Unknown card");
                    sys_netdevices[num].colour = i;
                    /* find MAC address */
                    sys_netdevices[n].address = strdup(helper_getmac(sys_netdevices[n].device));
                    sys_netdevices[num].vendorid = vendorid_buffer;
                    sys_netdevices[num].modelid = deviceid_buffer;

					num++;
                    hw_set_network_num(num);
                    found = 1;
                    F_LOG("  HW undetected %s_%d %s\n", openfw_colours_text[i], j, device);
                }

                if (!found) {
                    F_LOG("  setup problem with %s_%d %s\n", openfw_colours_text[i], j, device);
                    free(device);
                }
            }
        }
    }

    /* scan for any network interfaces already present (autoloaded by udev magic) */
    net_probe_netdev_card(NULL, NULL, "", 0);

    /* modprobe cards found by hardware detection */
    for (i = 0; i < num; i++) {
        if (!sys_netdevices[i].device[0])
            net_probe_netdev_card(sys_netdevices[i].module, NULL, "", 0);
    }
}


/* Choose type of internet connection: PPPoE, PPtP, static (ethernet), dhcp (ethernet) */
static void net_redconfigtype(void)
{
    int i;
    newtComponent networkform;
    newtComponent text;
    newtComponent ok, cancel;
    struct newtExitStruct exitstruct;
    char keyvalue[STRING_SIZE];
    char message[STRING_SIZE_LARGE];
    int numLines;
    char *tmpstring;

    snprintf(message, STRING_SIZE, gettext("TR_RED_CONFIGURATION_TYPE_LONG"));
    text = newtTextboxReflowed(1, 1, message, 68, 0, 0, 0);
    numLines = newtTextboxGetNumLines(text);

    /* workaround gcc warning, there is really 1 %s there */
    tmpstring = strdup(gettext("TR_INTERFACE"));
    snprintf(message, STRING_SIZE, tmpstring, "RED");
    free(tmpstring);
    newtCenteredWindow(72, 8 + CFG_RED_COUNT + numLines, message);
    networkform = newtForm(NULL, NULL, 0);
    newtFormAddComponent(networkform, text);

    /* No point in translating all */
    char *radio_text[CFG_RED_COUNT] =
        { "PPPoE", "PPTP", gettext("TR_STATIC"), "DHCP" };
    newtComponent radio[CFG_RED_COUNT];

    /* default value is PPPoE if nothing found in cfg file */
    strcpy(keyvalue, "PPPOE");
    if (find_kv_default(eth_kv, "RED_1_TYPE", keyvalue) == FAILURE) {
        update_kv(&eth_kv, "RED_1_TYPE", "PPPOE");
        changed_config = 1;
    }
    /* build radio buttons and add to window */
    for (i = 0; i < CFG_RED_COUNT; i++) {
        radio[i] = newtRadiobutton(2, i + numLines + 2, radio_text[i],
						(strcmp(keyvalue, openfw_red_text[i]) == 0),
						i == 0 ? NULL : radio[i - 1]);
        newtFormAddComponents(networkform, radio[i], NULL);
    }

    ok = newtButton(6, 3 + CFG_RED_COUNT + numLines, gettext("TR_OK"));
    /* In case of installer we must make a decision */
    if (flag_is_state == INST_SETUPCHROOT) {
        newtFormAddComponent(networkform, ok);
    }
    else {
        cancel = newtButton(26, 3 + CFG_RED_COUNT + numLines, gettext("TR_GO_BACK"));
        newtFormAddComponents(networkform, ok, cancel, NULL);
    }

    newtRefresh();
    newtDrawForm(networkform);

    newtFormRun(networkform, &exitstruct);

    if (exitstruct.u.co == ok) {
        newtComponent selected = newtRadioGetCurrent(radio[1]);
        for (i = 0; i < CFG_RED_COUNT; i++) {
            if ((selected == radio[i]) && strcmp(keyvalue, openfw_red_text[i])) {
                /* config type has changed, update cfg file and set flag  */
                update_kv(&eth_kv, "RED_1_TYPE", openfw_red_text[i]);
                strcpy(kv_red_type, openfw_red_text[i]);

                update_kv(&eth_kv, "RED_COUNT", "1");

                changed_config = 1;
                changed_type = 1;
                break;
            }
        }
    }

    newtFormDestroy(networkform);
    newtPopWindow();
}


/* Update some settings */
static void net_update_settings(char *colour, int n)
{
    char key[STRING_SIZE];

    F_LOG("colour %s, index %d\n", colour, n);

    if (n == -1) {
        /* was occupied, now empty */
        snprintf(key, STRING_SIZE, "%s_1_DEV", colour);
        update_kv(&eth_kv, key, "");
        snprintf(key, STRING_SIZE, "%s_1_OPTIONS", colour);
        update_kv(&eth_kv, key, "");
        snprintf(key, STRING_SIZE, "%s_1_DRIVER", colour);
        update_kv(&eth_kv, key, "");
        snprintf(key, STRING_SIZE, "%s_1_MAC", colour);
        update_kv(&eth_kv, key, "");
        snprintf(key, STRING_SIZE, "%s_COUNT", colour);
        update_kv(&eth_kv, key, "0");
    }
    else {
        snprintf(key, STRING_SIZE, "%s_1_DEV", colour);
        update_kv(&eth_kv, key, sys_netdevices[n].device);
        snprintf(key, STRING_SIZE, "%s_1_OPTIONS", colour);
        update_kv(&eth_kv, key, sys_netdevices[n].options);
        snprintf(key, STRING_SIZE, "%s_1_DRIVER", colour);
        update_kv(&eth_kv, key, sys_netdevices[n].module);
        snprintf(key, STRING_SIZE, "%s_1_MAC", colour);
        update_kv(&eth_kv, key, sys_netdevices[n].address);
        snprintf(key, STRING_SIZE, "%s_COUNT", colour);
        update_kv(&eth_kv, key, "1");
    }
}


/* Assign 1 card to some colour */
static void net_card_config(int n)
{
	char info[STRING_SIZE_LARGE];
	int i, j;
	int rc, choice;
	char *colourchoices[10];
	char command[STRING_SIZE];
	int blinking;

	/* owes: ToDo could do with some fancy text here */
	snprintf(info, STRING_SIZE_LARGE,
			"%s\nMAC Address: %s Device: %s\nCurrently assigned to: %s",
			sys_netdevices[n].description, sys_netdevices[n].address,
			sys_netdevices[n].device, openfw_colours_text[sys_netdevices[n].colour]);

	for (choice = 0, i = 0; i < CFG_COLOURS_COUNT - 1; i++) {
		int used = 0;

		/* test for already used colours here */
		for (j = 0; j < hw_get_network_num() && !used; j++) {
			if (i == sys_netdevices[j].colour)
				used = 1;
		}

		if (!used)
			colourchoices[choice++] = openfw_colours_text[i];
	}

	colourchoices[choice++] = gettext("TR_NOT_USED");
	colourchoices[choice++] = NULL;
	choice = 0;
	blinking = 0;
	for (;;) {
		char *blink_text;
		blink_text = blinking ? gettext("TR_ETH_BLINK_OFF") : gettext("TR_ETH_BLINK_ON");
		rc = newtWinMenu(gettext("TR_CARD_ASSIGNMENT"),
				info, 65, 5, 5, 11, colourchoices, &choice, gettext("TR_ASSIGN"),
				blink_text, gettext("TR_GO_BACK"), NULL);

		if ((rc == 0) || (rc == 1)) {
			changed_config = 1;
			if (!strcmp(colourchoices[choice], gettext("TR_NOT_USED"))) {
				if (sys_netdevices[n].colour != NONE)
					net_update_settings(openfw_colours_text[sys_netdevices[n].colour], -1);

				sys_netdevices[n].colour = NONE;
			} else {
				if (sys_netdevices[n].colour != NONE)
					net_update_settings(openfw_colours_text[sys_netdevices[n].colour], -1);

				/* since choices is a selected list of colours, we cannot directly correlate numeric choice to a colour */
				for (i = 0; i < CFG_COLOURS_COUNT - 1; i++) {
					if (!strcmp(openfw_colours_text[i], colourchoices[choice])) {
						sys_netdevices[n].colour = i;
						net_update_settings(openfw_colours_text[sys_netdevices[n].colour], n);
					}
				}
			}
		}

		if (rc == 2) {
			blinking = 1 - blinking;
			if (blinking) {
				snprintf(command, STRING_SIZE, "/sbin/ifconfig %s up", sys_netdevices[n].device);
				mysystem(command);
				/* On a Netvista with onboard NIC (8086:103b, e100 driver) network setup crashes (as in stuck, nothing working)
				   if we do not give some time here. Do not know why, but I guess it does not hurt to do a little sleep here.
				   With 1.4.20 we do not need this sleep, but things are different now. */
				sleep(1);
				snprintf(command, STRING_SIZE, "/usr/sbin/ethtool -p %s &", sys_netdevices[n].device);
				mysystem(command);
			}
			else {
				strcpy(command, "killall ethtool");
				mysystem(command);
			}
		}
		else {
			break;
		}
	}

	if (blinking) {
		strcpy(command, "killall ethtool");
		mysystem(command);
	}
}


/*  Hack udev persistent-net-rules and ethernet/settings.
    Note: this does not (directly) work when installing since we are chroot'd. 
    Workaround that by writing the modifications to a shell script, which will 
    be executed after we are done.
*/
static void net_udev_config(void)
{
    int i;
    int counter = 1;
    char device[STRING_SIZE];
    char key[STRING_SIZE];
    FILE *fnet = NULL;

    if ((fnet = fopen("/etc/udev/rules.d/70-persistent-net.rules", "w+")) == NULL) {
        // TODO: throw some error message here
        return;
    }

    fprintf(fnet, "# This file was generated by Openfirewall setup.\n");
    fprintf(fnet, "# Do not make any modifications, rerun setup instead.\n\n");

    /* set the device names with the help of udev */
    for (i = 0; i < hw_get_network_num(); i++) {
        if (sys_netdevices[i].address[0]) {
            if (sys_netdevices[i].colour == NONE) {
                snprintf(device, STRING_SIZE, "%s-%d", openfw_aliases_text[NONE], counter++);
            }
            else {
                snprintf(device, STRING_SIZE, "%s-%d", openfw_aliases_text[sys_netdevices[i].colour], 1);
                snprintf(key, STRING_SIZE, "%s_%d_DEV", openfw_colours_text[sys_netdevices[i].colour], 1);
                update_kv(&eth_kv, key, device);
            }

            fprintf(fnet, "\n# device 0x%s:0x%s (%s)\n",
					sys_netdevices[i].vendorid, sys_netdevices[i].modelid, sys_netdevices[i].module);
            fprintf(fnet, "SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\"," \
						" ATTR{address}==\"%s\", ATTR{type}==\"1\", NAME=\"%s\"\n", 
                    	sys_netdevices[i].address, device);
        }
    }

    fclose(fnet);
}


/*  Window with field for module and options 
    Return SUCCESS if we modprobe'd a module and have an additional interface
*/
static int net_add_manual(void)
{
    char *values[] = { NULL, NULL };    /* pointers for the values. */
    struct newtWinEntry entries[] =
        { { "", &values[0], 0,}, { NULL, NULL, 0 } };
    int rc;

    while (1) {
        rc = newtWinEntries(gettext("TR_SELECT_NETWORK_DRIVER"),
                gettext("TR_MODULE_PARAMETERS"), 50, 5, 5, 40, entries, 
                gettext("TR_OK"), gettext("TR_GO_BACK"), NULL);  
        if (rc == 0 || rc == 1) {
            char *ptr;

            if (strlen(values[0]) == 0) {
                errorbox(gettext("TR_MODULE_NAME_CANNOT_BE_BLANK"));
                continue;
            }

            if ((ptr = strchr(values[0], ' ')) != NULL) {
                /* module and option, copy first so we can reuse the edit field (values[0]) in case of error */
                char *modulewithoption = strdup(values[0]);
                ptr = strchr(modulewithoption, ' ');
                *ptr = 0;
                rc = net_probe_netdev_card(modulewithoption, "Unknown card", ptr+1, 1);
                free(modulewithoption);
                if (rc == SUCCESS)
                    return SUCCESS;
            } else {
                rc = net_probe_netdev_card(values[0], "Unknown card", "", 1);
                if (rc)
                    return SUCCESS;
            }
        } else {
            return FAILURE; /* canceled by user */
        }
    }
}


/* Add a card manually from the ISA nic list */
static void net_manual_list(void)
{
    int done;
    int rc;
    int choice;

    choice = 0;
    done = 0;
    while (done == 0) {
        rc = newtWinMenu(gettext("TR_SELECT_NETWORK_DRIVER"),
						gettext("TR_SELECT_NETWORK_DRIVER_LONG"), 65, 5, 5, 6,
						isa_nics_description, &choice, gettext("TR_OK"),
						gettext("TR_GO_BACK"), NULL);

        if ((rc == 0) || (rc == 1)) {
            if (choice == 0) {
                /* If manual addition succeeded, return directly to the list of interfaces */
                done = (net_add_manual() == SUCCESS);
            } else {
                done = (net_probe_netdev_card(isa_nics_module[choice], isa_nics_description[choice], "", 1) == SUCCESS);
            }
        } else {
            done = 1;       /* canceled by user */    
        }
    }
}


/* Detect cards, list cards and assign colours to them.
 * There is currently no escape if there are no network cards since
 * a firewall is pretty useless without networking.
 * When installing allow to change RED type in case there are not enough network cards. */
static void net_init_card_list(void)
{
    int i, count, notused;
    int rc, choice;
    char *cardchoices[10];

    net_scan_cards();

    for (;;) {
        choice = -1;
        for (count = 0, i = 0; i < hw_get_network_num(); i++) {
            char line[STRING_SIZE];

            /* set first unused card as default choice */
            if ((choice == -1) && (sys_netdevices[i].colour == NONE))
                choice = count;

            snprintf(line, STRING_SIZE, "%-60.60s (%s)",
					sys_netdevices[i].description, openfw_colours_text[sys_netdevices[i].colour]);
            cardchoices[count++] = strdup(line);
        }
        cardchoices[count] = NULL;

        /* TODO: we probably need an option to bail out, without changing anything here */
        rc = newtWinMenu(gettext("TR_CARD_ASSIGNMENT"),
						gettext("TR_CARD_ASSIGNMENT_LONG"), 65, 5, 5, 11,
						cardchoices, &choice, gettext("TR_SELECT"),
						gettext("TR_MANUAL"), gettext("TR_DONE"), NULL);

        for (i = 0; i < hw_get_network_num(); i++)
            free(cardchoices[i]);

        switch (rc) {
        case 0:
        case 1:
            net_card_config(choice);
            break;
        case 2:
            net_manual_list();
            break;
        case 3:
            /* Do we have GREEN ? */
            for (i = 0, count = 0; i < hw_get_network_num() && !count; i++) {
                if (sys_netdevices[i].colour == GREEN)
                    count++;
            }
            if (!count) {
                /* We will always need at least 1 green NIC */
                errorbox(gettext("TR_NO_GREEN_INTERFACE"));
                break;
            }

			/* Do we have RED ? */
			for (i = 0, count = 0, notused = 0; i < hw_get_network_num(); i++) {
				if (sys_netdevices[i].colour == RED)
					count++;

				if (sys_netdevices[i].colour == NONE)
					notused++;
			}
			if (!count && notused) {
				/* RED needed but not configured, at least 1 NIC currently not used */
				errorbox(gettext("TR_NO_RED_INTERFACE"));
				break;
			}
			if (!count) {
				rc = newtWinChoice(lang_gettext("TR_TITLE_DISK"),
						lang_gettext("TR_GO_BACK"), lang_gettext("TR_OK"),
						lang_gettext("TR_NO_RED_INTERFACE_RESET_TYPE"));
				if (rc == 2) {
					/* Bail out by resetting RED type to analog */
					strcpy(kv_red_type, "ANALOG");
					update_kv(&eth_kv, "RED_1_TYPE", kv_red_type);
					update_kv(&eth_kv, "RED_1_DEV", "");
					update_kv(&eth_kv, "RED_COUNT", "0");

					changed_config = 1;
					changed_type = 1;
				} else {
					break;
				}
			}

            if (changed_config)
                net_udev_config();

            return;
        }
    }
}


/* Change red hostname, used if type is DHCP */
static void net_change_hostname(void)
{
    newtComponent networkform;
    newtComponent text;
    newtComponent ok, cancel;
    struct newtExitStruct exitstruct;
    char keyvalue[STRING_SIZE];
    char message[STRING_SIZE_LARGE];
    newtComponent dhcphostnamelabel;
    newtComponent dhcphostnameentry;
    const char *dhcphostnameresult;
    int error;
    int numLines;
    char *tmpstring;

    snprintf(message, STRING_SIZE_LARGE, gettext("TR_DHCP_HOSTNAME_LONG"));
    text = newtTextboxReflowed(1, 1, message, 68, 0, 0, 0);
    numLines = newtTextboxGetNumLines(text);

    /* workaround gcc warning, there is really 1 %s there */
    tmpstring = strdup(gettext("TR_INTERFACE"));
    snprintf(message, STRING_SIZE, tmpstring, "RED");
    free(tmpstring);
    newtCenteredWindow(72, 9 + numLines, message);
    networkform = newtForm(NULL, NULL, 0);
    newtFormAddComponent(networkform, text);

    /* DHCP hostname */
    dhcphostnamelabel = newtTextbox(2, 2 + numLines, 18, 1, 0);
    newtTextboxSetText(dhcphostnamelabel, gettext("TR_DHCP_HOSTNAME"));
    strcpy(keyvalue, "");
    if (find_kv_default(eth_kv, "RED_DHCP_HOSTNAME", keyvalue) == FAILURE) {
        NODEKV *main_kv = NULL;
        if (read_kv_from_file(&main_kv, "/var/ofw/main/settings") == SUCCESS) {
            find_kv_default(main_kv, "HOSTNAME", keyvalue);
            free_kv(&main_kv);
        }
    }
    dhcphostnameentry = newtEntry(20, 2 + numLines, keyvalue, 20, &dhcphostnameresult, 0);
    newtFormAddComponent(networkform, dhcphostnamelabel);
    newtFormAddComponent(networkform, dhcphostnameentry);

    ok = newtButton(6, 4 + numLines, gettext("TR_OK"));
    cancel = newtButton(26, 4 + numLines,
				(flag_is_state == INST_SETUPCHROOT) ? gettext("TR_SKIP") : gettext("TR_GO_BACK"));
    newtFormAddComponents(networkform, ok, cancel, NULL);

    newtRefresh();
    newtDrawForm(networkform);

    do {
        error = 0;
        newtFormRun(networkform, &exitstruct);

        if (exitstruct.u.co == ok) {
            if (!strlen(dhcphostnameresult)) {
                errorbox(gettext("TR_DHCP_HOSTNAME_CR"));
                error = 1;
            } else {
                update_kv(&eth_kv, "RED_DHCP_HOSTNAME", (char *) dhcphostnameresult);
                changed_config = 1;
                changed_hostname = 1;
            }
        }
    }
    while (error);

    newtFormDestroy(networkform);
    newtPopWindow();
}


/* Small window to select which colour IP to change */
static void net_select_change_address(void)
{
    char *menuchoices[10];
    char key[STRING_SIZE];
    char keyvalue[STRING_SIZE];
    int rc;
    int i;
    int choice;

    choice = 0;
    for (i = 0; i < CFG_COLOURS_COUNT; i++) {
        if ((i == RED) && strcmp(kv_red_type, "STATIC") &&
			strcmp(kv_red_type, "PPPOE") && strcmp(kv_red_type, "PPTP")) {
            /* Skip RED if it is not set to STATIC, PPPoE or PPTP */
            continue;
        }
        snprintf(key, STRING_SIZE, "%s_1_DEV", openfw_colours_text[i]);
        strcpy(keyvalue, "");
        find_kv_default(eth_kv, key, keyvalue);
        if (keyvalue[0])
            menuchoices[choice++] = openfw_colours_text[i];
    }

    menuchoices[choice] = NULL;
    choice = 0;

    for (;;) {
        rc = newtWinMenu(gettext("TR_CARD_ASSIGNMENT"),
                         gettext("TR_SELECT_THE_INTERFACE_YOU_WISH_TO_RECONFIGURE"), 65, 5, 5, 11,
                         menuchoices, &choice, gettext("TR_SELECT"), gettext("TR_GO_BACK"), NULL);
        if (rc == 2)
            break;

        if (!strcmp(menuchoices[choice], "GREEN"))
            helper_nt_change_address("GREEN", &changed_green);

        if (!strcmp(menuchoices[choice], "RED"))
            helper_nt_change_address("RED", &changed_red);

        if (!strcmp(menuchoices[choice], "BLUE"))
            helper_nt_change_address("BLUE", &changed_blue);

        if (!strcmp(menuchoices[choice], "ORANGE"))
            helper_nt_change_address("ORANGE", &changed_orange);
    }
}


/* Change DNS Server(s) for type DHCP and STATIC
 * and default gateway for type STATIC. */
static void net_change_dnsgateway(void)
{
    newtComponent networkform;
    newtComponent text;
    newtComponent ok, cancel;
    struct newtExitStruct exitstruct;
    char keyvalue[STRING_SIZE];
    newtComponent dns1label;
    newtComponent dns2label;
    newtComponent gatewaylabel;
    newtComponent dns1entry;
    newtComponent dns2entry;
    newtComponent gatewayentry;
    const char *dns1result;
    const char *dns2result;
    const char *gatewayresult;
    char message[STRING_SIZE_LARGE];
    int error;
    int numLines;

    snprintf(message, STRING_SIZE, gettext("TR_DNS_AND_GATEWAY_SETTINGS_LONG"));
    text = newtTextboxReflowed(1, 1, message, 68, 0, 0, 0);
    numLines = newtTextboxGetNumLines(text);

    newtCenteredWindow(72, 11 + numLines, gettext("TR_DNS_AND_GATEWAY_SETTINGS"));
    networkform = newtForm(NULL, NULL, 0);
    newtFormAddComponent(networkform, text);

    /* DNS1 */
    dns1label = newtTextbox(2, 2 + numLines, 18, 1, 0);
    newtTextboxSetText(dns1label, gettext("TR_PRIMARY_DNS"));
    strcpy(keyvalue, "");
    find_kv_default(eth_kv, "DNS1", keyvalue);
    dns1entry = newtEntry(20, 2 + numLines, keyvalue, 20, &dns1result, 0);
    newtEntrySetFilter(dns1entry, filterip, NULL);
    newtFormAddComponent(networkform, dns1label);
    newtFormAddComponent(networkform, dns1entry);

    /* DNS2 */
    dns2label = newtTextbox(2, 3 + numLines, 18, 1, 0);
    newtTextboxSetText(dns2label, gettext("TR_SECONDARY_DNS"));
    strcpy(keyvalue, "");
    find_kv_default(eth_kv, "DNS2", keyvalue);
    dns2entry = newtEntry(20, 3 + numLines, keyvalue, 20, &dns2result, 0);
    newtEntrySetFilter(dns2entry, filterip, NULL);
    newtFormAddComponent(networkform, dns2label);
    newtFormAddComponent(networkform, dns2entry);

    /* Gateway */
    gatewaylabel = newtTextbox(2, 4 + numLines, 18, 1, 0);
    newtTextboxSetText(gatewaylabel, gettext("TR_DEFAULT_GATEWAY"));
    strcpy(keyvalue, "");
    find_kv_default(eth_kv, "DEFAULT_GATEWAY", keyvalue);
    gatewayentry = newtEntry(20, 4 + numLines, keyvalue, 20, &gatewayresult, 0);
    newtEntrySetFilter(gatewayentry, filterip, NULL);
    newtFormAddComponent(networkform, gatewaylabel);
    newtFormAddComponent(networkform, gatewayentry);

    ok = newtButton(8, 6 + numLines, gettext("TR_OK"));
    cancel = newtButton(26, 6 + numLines,
				(flag_is_state == INST_SETUPCHROOT) ? gettext("TR_SKIP") : gettext("TR_GO_BACK"));
    newtFormAddComponents(networkform, ok, cancel, NULL);

    newtRefresh();
    newtDrawForm(networkform);

    do {
        error = 0;
        newtFormRun(networkform, &exitstruct);

        if (exitstruct.u.co == ok) {
            strcpy(message, gettext("TR_INVALID_FIELDS"));
            if (strlen(dns1result) && (inet_addr(dns1result) == INADDR_NONE)) {
                strcat(message, gettext("TR_PRIMARY_DNS_CR"));
                error = 1;
            }
            if (strlen(dns2result) && (inet_addr(dns2result) == INADDR_NONE)) {
                strcat(message, gettext("TR_SECONDARY_DNS_CR"));
                error = 1;
            }
            if (strlen(gatewayresult) && (inet_addr(gatewayresult) == INADDR_NONE)) {
                strcat(message, gettext("TR_DEFAULT_GATEWAY_CR"));
                error = 1;
            }

            if (error) {
                errorbox(message);
            } else {
                update_kv(&eth_kv, "DNS1", (char *) dns1result);
                update_kv(&eth_kv, "DNS2", (char *) dns2result);
                update_kv(&eth_kv, "DEFAULT_GATEWAY", (char *) gatewayresult);

                changed_config = 1;
                changed_dnsgateway = 1;
            }
        }
    }
    while (error);

    newtFormDestroy(networkform);
    newtPopWindow();
}


/* Open a window with network config menus or simply go through them 1 by 1 (installer). */
int handle_networking(void)
{
    int rc;
    int choice;
    char *menuchoices[10];
    char keyvalue[STRING_SIZE];

    menuchoices[0] = gettext("TR_RED_CONFIGURATION_TYPE");
    menuchoices[1] = gettext("TR_DRIVERS_AND_CARD_ASSIGNMENTS");
    menuchoices[2] = gettext("TR_ISDN_CONFIGURATION");
    menuchoices[3] = gettext("TR_ADDRESS_SETTINGS");
    menuchoices[4] = gettext("TR_DNS_AND_GATEWAY_SETTINGS");
    menuchoices[5] = gettext("TR_HOSTNAME");

    menuchoices[6] = NULL;

    changed_config = 0;
    changed_type = 0;
    changed_hostname = 0;
    changed_green = 0;
    changed_red = 0;
    changed_dnsgateway = 0;

    if (read_kv_from_file(&eth_kv, "/var/ofw/ethernet/settings") != SUCCESS) {
        free_kv(&eth_kv);
        errorbox(gettext("TR_UNABLE_TO_OPEN_SETTINGS_FILE"));
        return FAILURE;
    }

    readisanics();

    /* make sure these are always present */
    for (rc = 0; rc < CFG_COLOURS_COUNT - 1; rc++) {
        snprintf(keyvalue, STRING_SIZE, "%s_COUNT", openfw_colours_text[rc]);
        if ((find_kv(eth_kv, keyvalue)) == NULL)
            update_kv(&eth_kv, keyvalue, "0");
    }

    strcpy(kv_red_type, "");
    find_kv_default(eth_kv, "RED_1_TYPE", kv_red_type);
    update_kv(&eth_kv, "RED_1_TYPE", kv_red_type);
    strcpy(keyvalue, "");
    find_kv_default(eth_kv, "RED_1_DEV", keyvalue);
    update_kv(&eth_kv, "RED_1_DEV", keyvalue);

    if (flag_is_state == INST_SETUPCHROOT) {
        int i, n;
        /* When installing we run (some) configwindows in sequence */
        NODEKV *kv_dhcp_params = NULL;

        read_kv_from_file(&kv_dhcp_params, "/tmp/dhcp-eth0.params");
        find_kv_default(kv_dhcp_params, "IP", DEFAULT_IP);
        find_kv_default(kv_dhcp_params, "NETMASK", DEFAULT_NETMASK);
        free_kv(&kv_dhcp_params);

        net_redconfigtype();
        /* RED_TYPE is now set */
        net_init_card_list();

        helper_nt_change_address("GREEN", &changed_green);

        if (!strcmp(kv_red_type, "PPPOE")) {
            helper_nt_change_address("RED", &changed_red);
        }
        else if (!strcmp(kv_red_type, "PPTP")) {
            helper_nt_change_address("RED", &changed_red);
        }
        else if (!strcmp(kv_red_type, "STATIC")) {
            helper_nt_change_address("RED", &changed_red);
            net_change_dnsgateway();
        }
        else if (!strcmp(kv_red_type, "DHCP")) {
            net_change_hostname();
            net_change_dnsgateway();
        }
//        else if (!strcmp(kv_red_type, "ISDN")) {
//            handleisdn();
//        }

#if 1
        find_kv_default(eth_kv, "BLUE_COUNT", keyvalue);
        if (keyvalue[0] != '0') {
            helper_nt_change_address("BLUE", &changed_blue);
        }

        find_kv_default(eth_kv, "ORANGE_COUNT", keyvalue);
        if (keyvalue[0] != '0') {
            helper_nt_change_address("ORANGE", &changed_orange);
        }
#endif

        /* For NONE colour interfaces */
        for (i = 0, n = 0; i < hw_get_network_num(); i++) {
            char key[STRING_SIZE];
            char prefix[32] = "IF";

            if (sys_netdevices[i].colour != NONE)
                continue;

			snprintf(key, STRING_SIZE, "%s_%d_DEV", prefix, n);
			update_kv(&eth_kv, key, sys_netdevices[i].device);

			snprintf(key, STRING_SIZE, "%s_%d_DRIVER", prefix, n);
			update_kv(&eth_kv, key, sys_netdevices[i].module);

			snprintf(key, STRING_SIZE, "%s_%d_MAC", prefix, n);
			update_kv(&eth_kv, key, sys_netdevices[i].address);

            n++;
        }
        if (n) {
            char val[STRING_SIZE];

            snprintf(val, STRING_SIZE, "%d", n);
            update_kv(&eth_kv, "IF_NONE_COUNT", val);
        }

        write_kv_to_file(&eth_kv, "/var/ofw/ethernet/settings");
        free_kv(&eth_kv);
        mysystem("/usr/local/bin/rebuildhosts");

        /* TODO: other settings / services we need to trigger ? */

        /* Last but not least, optionally confgure DHCP server for GREEN */
        change_dhcp_server();
F_LOG("after change dhcp server\n");

        return SUCCESS;
    }

    /* Non-Installer section
     *
     */

    choice = 0;
    mysystem("cp -f /var/ofw/ethernet/settings /var/ofw/ethernet/settings.old");

    for (;;) {

        rc = newtWinMenu(gettext("TR_NETWORK_CONFIGURATION_MENU"),
                         gettext("TR_SELECT_THE_ITEM"), 65, 5, 5, 11,
                         menuchoices, &choice, gettext("TR_SELECT"), gettext("TR_GO_BACK"), NULL);

        if (rc == 2)
            break;

        switch (choice) {
        case 0: {
            int i, count;
            net_redconfigtype();
            /* Do we have RED ? */
            for (i = 0, count = 0; i < hw_get_network_num() && !count; i++) {
                if (sys_netdevices[i].colour == RED)
                    count++;
            }
            if (!count)
                net_init_card_list();
            break;
        }
        case 1:
            net_init_card_list();
            break;
        case 2:
            if (access("/var/ofw/red/active", F_OK) != -1) {
                errorbox(gettext("TR_RED_IN_USE"));
            }
//            else {
//                handleisdn();
//            }
            break;
        case 3:
            net_select_change_address();
            break;
        case 4:
            net_change_dnsgateway();
            break;
        case 5:
            net_change_hostname();
            break;
        default:
            break;
        }
    }

    if (changed_config) {
        write_kv_to_file(&eth_kv, "/var/ofw/ethernet/settings");
        helper_nt_statuswindow(72, 5,
				gettext("TR_NETWORKING"), lang_gettext("TR_RECONFIGURE_NETWORK"));
        mysystem("/etc/rc.d/rc.net --reconfigure");
        newtPopWindow();
    }

    /* What options have changed and what needs restarting ?? */

    free_kv(&eth_kv);
    return SUCCESS;
}
