/*
 * common_newt.h: Global defines, function definitions for installer and setup
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
 * (c) 2008, the Openfirewall Team
 *
 * $Id: common_newt.h 3360 2009-07-30 10:16:12Z owes $
 *
 */

#ifndef __COMMON_NEWT_H
#define __COMMON_NEWT_H


#define errorbox(msg) newtWinMessage(gettext("TR_ERROR"), gettext("TR_OK"), (msg))


/* Implemented in helper_newt.c */
void statuswindow(int width, int height, char *title, char *text, ...);
void *statuswindow_progress(int width, int height, char *title, char *text, ...);

int mysystem_progress(char *command, void *form, int left, int top, int width, int lines, int offset);


/*  Verify IP address and netmask for newt entry fields.
    Return 0 if the character is invalid.
*/
int filterip(newtComponent entry, void *data, int ch, int cursor);


/* All kinds of functions used by setup */
void handlelanguage(NODEKV * kv);
void write_lang_configs(void);
int handlerestore(void);
int handlekeymap(void);
int write_keymap(void);
int handletimezone(void);
int write_timezone(void);
int handledatetime(void);
int handlehostname(void);
int handledomainname(void);
int handleisdn(void);
int handlenetworking(void);
int handlepasswords(void);

/* These belong to setup - networking */
int changedhcpserver(void);

/* Dialogs for changing passwords. Possible user: "root", "admin", "backup" */
int password(char *user);

/* Translation functions used in installer */
void ofw_locale(char *locale);
char *ofw_gettext(char *txt);

/* Small window to change IP and Netmask of some colour */
int changed_config;      /* something has changed      */
void changeaddress(char *colour, int *changed_flag);


#endif
