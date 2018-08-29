/*
 * language.c: Language selection used in installer only
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
 * (c) 2007-2010, the Openfirewall Team
 *
 * $Id: language.c 4410 2010-03-26 07:58:35Z owes $
 *
 */


#include <sys/file.h>
#include <wchar.h>

#include <locale.h>

#include <ctype.h>
#include <libintl.h>
#include <newt.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "common_newt.h"


/* Set this to 1 this to get (much) more logging on console2 */
#define _DEBUG_GETTEXT 0


struct language
{
    int inuse;
    char shortname[4];          /* language codes (ISO-639) are 2 or 3 characters long */
    char locale[6];             /* format is language_COUNTRY */
    char longname[STRING_SIZE];
    char font[STRING_SIZE];     /* which font to set, lat0-16, viscii10-8x16 etc. */
    void *next;
};

static char selected_lang[STRING_SIZE];
static char selected_locale[STRING_SIZE];

struct language *languages;


void write_lang_configs(void)
{
    NODEKV *kv = NULL;

    /* default stuff for main/settings. */
    read_kv_from_file(&kv, "/harddisk/var/ofw/main/settings");
    update_kv(&kv, "LANGUAGE", selected_lang);
    update_kv(&kv, "LOCALE", selected_locale);
    update_kv(&kv, "HOSTNAME", SNAME);
    write_kv_to_file(&kv, "/harddisk/var/ofw/main/settings");
    free_kv(&kv);

    /* initial language for VPN certs */
    char temp[STRING_SIZE];
    int i;
    for (i = 0; selected_lang[i]; i++) {
        temp[i] = toupper(selected_lang[i]);
    }
    temp[i] = '\0';
    kv = NULL;
    read_kv_from_file(&kv, "/harddisk/var/ofw/ipsec/settings");
    update_kv(&kv, "ROOTCERT_COUNTRY", temp);
    write_kv_to_file(&kv, "/harddisk/var/ofw/ipsec/settings");
    free_kv(&kv);
}


static void set_language(char *shortname, char *locale, char *font)
{
    char command[STRING_SIZE];

    fprintf(flog, "Setting language %s.\n", shortname);

    sprintf(command, "/usr/bin/setfont %s", font);
    mysystem(command);

    strcpy(selected_locale, locale);
    bindtextdomain("install", "/usr/share/locale");
    textdomain("install");
    setlocale(LC_MESSAGES, selected_locale);

    strcpy(selected_lang, shortname);

    ofw_locale(selected_locale);
}


/*
    Retrieve list (/usr/share/locale/language.lst) of languages.
    Format is:
      short name:locale:full name:translated full name:usable in installer:screenfont
    Then present list of languages and set our language to selected choice.
*/
void handlelanguage(NODEKV * kv)
{
#ifdef LANG_EN_ONLY
    set_language("en", "en_GB", "lat0-16");
#else
    FILE *f;
    int choice;
    int count;
    char line[STRING_SIZE];
    char **langnames;
    struct language *p_lang;
    struct language *tmp_lang;
    int userselect;
    char *userlang;

    languages = NULL;
    p_lang = NULL;
    tmp_lang = NULL;
    f = fopen("/usr/share/locale/language.lst", "rb");
    if (f == NULL) {
        fprintf(fstderr, "Could not open language list.\n");
        set_language("en", "en_GB", "lat0-16");
        return;
    }

    userlang = find_kv(kv, "lang");
    if (userlang != NULL) {
        fprintf(flog, "Language userselect %s\n", userlang);
    }

    userselect = -1;
    count = 0;

    while (fgets(line, STRING_SIZE, f)) {
        int c;
        int stopline;
        char *key, *s;

        s = line;
        c = 0;
        stopline = 0;

        key = strsep(&s, ":");
        while ((key != NULL) && (stopline == 0)) {
            switch (c) {
            case 0:            /* short languages name */
                tmp_lang = calloc(1, sizeof(struct language));
                if (languages == NULL) {
                    languages = tmp_lang;
                }
                strcpy(tmp_lang->shortname, key);

                if ((userlang != NULL) && !strcmp(userlang, key)) {
                    userselect = count;
                }
                break;

            case 1:            /* locale */
                /* TODO: test for existence of .mo file */

                strcpy(tmp_lang->locale, key);
                break;

            case 2:            /* language name */
                strcpy(tmp_lang->longname, key);
                break;

            case 3:            /* translated language name */
                break;

            case 4:            /* installer or no-installer */
                if (strcmp(key, "installer") == 0) {
                    tmp_lang->inuse = 1;
                }
                break;

            case 5:            /* font */
                strcpy(tmp_lang->font, key);
                break;
            }

            key = strsep(&s, ":");
            c++;

            if (c == 6) {
                /* found every item we need */
                stopline = 1;

                if (tmp_lang->inuse == 0) {
#if _DEBUG_GETTEXT
                    fprintf(flog, "Language skip %s %s %s\n", tmp_lang->shortname, tmp_lang->locale,
                            tmp_lang->longname);
#endif
                    free(tmp_lang);
                    if (p_lang == NULL) {
                        languages = NULL;
                    }
                }
                else {
#if _DEBUG_GETTEXT
                    fprintf(flog, "Language add %s %s %s\n", tmp_lang->shortname, tmp_lang->locale, tmp_lang->longname);
#endif
                    count++;

                    if (p_lang != NULL) {
                        /* only if we are not first */
                        p_lang->next = tmp_lang;
                    }
                    p_lang = tmp_lang;
                }
            }
        }
    }

    /* no languages found ? */
    if (count == 0) {
        set_language("en", "en_GB", "lat0-16");
        fclose(f);
        return;
    }

    langnames = calloc(count + 1, sizeof(char *));

    p_lang = languages;
    count = 0;
    choice = -1;
    while (p_lang) {
        langnames[count] = strdup(p_lang->longname);
        if (strcmp(langnames[count], "English") == 0)
            choice = count;

        p_lang = p_lang->next;
        count++;
    }

    if (userselect == -1) {
        newtWinMenu("Language selection",
                    "Select the language you wish to use for the " NAME
                    ".", 50, 5, 5, 8, langnames, &choice, "Ok", NULL);
    }
    else {
        choice = userselect;
    }

    p_lang = languages;
    count = 0;
    while (p_lang) {
        if (choice == count) {
            set_language(p_lang->shortname, p_lang->locale, p_lang->font);
        }

        tmp_lang = p_lang;
        p_lang = p_lang->next;

        free(tmp_lang);
        free(langnames[count]);
        count++;
    }

    fclose(f);
    free(langnames);
#endif // not defined LANG_EN_ONLY
}



#define _MAGIC 0x950412de
#define _MAGIC_SWAPPED 0xde120495

#if UINT_MAX == UINT_MAX_32_BITS
typedef unsigned nls_uint32;
#else
# if USHRT_MAX == UINT_MAX_32_BITS
typedef unsigned short nls_uint32;
# else
#  if ULONG_MAX == UINT_MAX_32_BITS
typedef unsigned long nls_uint32;
#  else
/* The following line is intended to throw an error.  Using #error is
   not portable enough.  */
"Cannot determine unsigned 32-bit data type."
#  endif
# endif
#endif
#define MO_MAGIC              0x950412de
#define MO_MAGIC_SWAPPED      0xde120495
#define mo_swap(x) ( (must_swap) ? SWAP(x) : (x) )
    struct mo_header
{
    nls_uint32 magic;           // 0x950412de
    nls_uint32 revision;
    nls_uint32 count;           // number of strings
    nls_uint32 offset_org;      //
    nls_uint32 offset_trans;    //
};


char **strings_org;
char **strings_trans;
static struct mo_header mo_h;
static int b_locale = 0;
static int must_swap = 0;

static inline nls_uint32 SWAP(i)
     nls_uint32 i;
{
    return (i << 24) | ((i & 0xff00) << 8) | ((i >> 8) & 0xff00) | (i >> 24);
}


/*
    Set locale and read .mo file.
    Parameter should something like en_GB, de_DE
*/
void ofw_locale(char *locale)
{
    FILE *f;
    char filename[STRING_SIZE];
    char string[4096];
    int i;

    nls_uint32 *len_org;
    nls_uint32 *pos_org;
    nls_uint32 *len_trans;
    nls_uint32 *pos_trans;


    mo_h.count = 0;
    snprintf(filename, STRING_SIZE, "/usr/share/locale/%s/LC_MESSAGES/install.mo", locale);
    f = fopen(filename, "rb");
    if (f == NULL) {
        /* TODO: revert to en_GB if not found */
        fprintf(flog, "ERROR: install.mo file not found for locale %s. \n", locale);
        return;
    }
    if (fread(&mo_h, sizeof(mo_h), 1, f) != 1) {
        fprintf(flog, "ERROR: no header in install.mo file\n");
        return;
    }
    if (mo_h.magic == MO_MAGIC) {
    }
    else if (mo_h.magic == MO_MAGIC_SWAPPED) {
        must_swap = 1;
    }
    else {
        fprintf(flog, "ERROR: no MAGIC in install.mo file\n");
        return;
    }

    if (mo_h.count == 0) {
        fprintf(flog, "ERROR: .mo file does not have strings\n");
        return;
    }
    mo_h.count = mo_swap(mo_h.count);

    fprintf(flog, "LOCALE: so far so good, .mo contains %u strings\n", mo_h.count);

    mo_h.offset_org = mo_swap(mo_h.offset_org);
    mo_h.offset_trans = mo_swap(mo_h.offset_trans);

//  fprintf(flog, "offset org 0x%X, trans 0x%X\n", mo_h.offset_org, mo_h.offset_trans);

    len_org = calloc(mo_h.count, sizeof(nls_uint32));
    pos_org = calloc(mo_h.count, sizeof(nls_uint32));
    len_trans = calloc(mo_h.count, sizeof(nls_uint32));
    pos_trans = calloc(mo_h.count, sizeof(nls_uint32));
    strings_org = calloc(mo_h.count, sizeof(char *));
    strings_trans = calloc(mo_h.count, sizeof(char *));


    /*
       Read length and offset of original text and translated text
       then get the strings.

       There is little verification, if .mo is wrong we'll probably get hit by
       a seg fault somewhere later and start all over again.
     */

    fseek(f, mo_h.offset_org, SEEK_SET);
    for (i = 0; i < mo_h.count; i++) {
        if (fread(&len_org[i], sizeof(nls_uint32), 1, f) != 1) {
            goto ERROR_EXIT;
        }
        len_org[i] = mo_swap(len_org[i]);
        if (fread(&pos_org[i], sizeof(nls_uint32), 1, f) != 1) {
            goto ERROR_EXIT;
        }
        pos_org[i] = mo_swap(pos_org[i]);
    }

    for (i = 0; i < mo_h.count; i++) {
        fseek(f, pos_org[i], SEEK_SET);
        if (fread(string, 1, len_org[i] + 1, f) != len_org[i] + 1) {
            goto ERROR_EXIT;
        }
        strings_org[i] = strdup(string);
    }

    fseek(f, mo_h.offset_trans, SEEK_SET);
    for (i = 0; i < mo_h.count; i++) {
        if (fread(&len_trans[i], sizeof(nls_uint32), 1, f) != 1) {
            goto ERROR_EXIT;
        }
        len_trans[i] = mo_swap(len_trans[i]);
        if (fread(&pos_trans[i], sizeof(nls_uint32), 1, f) != 1) {
            goto ERROR_EXIT;
        }
        pos_trans[i] = mo_swap(pos_trans[i]);
    }

    for (i = 0; i < mo_h.count; i++) {
        fseek(f, pos_trans[i], SEEK_SET);
        if (fread(string, 1, len_trans[i] + 1, f) != len_trans[i] + 1) {
            goto ERROR_EXIT;
        }
        strings_trans[i] = strdup(string);
    }

    b_locale = 1;

ERROR_EXIT:
    free(len_org);
    free(pos_org);
    free(len_trans);
    free(pos_trans);

    fclose(f);

    if (!b_locale) {
        fprintf(flog, "ERROR: ofw_locale()\n");
    }
}


/*
    Look for a translated text.
    If non found simply return the original text.
*/
char *ofw_gettext(char *txt)
{
    int i;

#if _DEBUG_GETTEXT
    fprintf(flog, "LOCALE: %s\n", txt);
#endif

    if (!b_locale) {
#if _DEBUG_GETTEXT
        fprintf(flog, "not initialised\n");
#endif
        return (txt);
    }

    for (i = 0; i < mo_h.count; i++) {
        if (!strcmp(strings_org[i], txt)) {
#if _DEBUG_GETTEXT
            fprintf(flog, "-> %s\n", strings_trans[i]);
#endif
            return (strings_trans[i]);
        }
    }

    return (txt);
}
