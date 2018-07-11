#!/usr/bin/perl
#
# lang.pl: retrieve the translated texts for GUI
#
# This file is part of the IPCop Firewall.
#
# IPCop is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# IPCop is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IPCop.  If not, see <http://www.gnu.org/licenses/>.
#
# (c) 2007-2013, the IPCop team
#
# Copyright (c) 2007-11-13 owes  This is almost a full cleanup, texts are now fetched from .MO files.
#
# $Id: lang.pl 7061 2013-06-08 09:51:01Z owes $
#


# When you want to add your own language strings/entries to IPCop,
# you create a file with <PREFIX>.<LANG>.pl in the /var/ipcop/addons/lang directory
#   <PREFIX> can be freely chosen but must be unique. An example could be "myAddonName"
#   <LANG> is a mnemonic of the used language like en, de, it, nl etc.
#       You can find a detailed list of possible mnemonics in the file /var/ipcop/main/language.lst
# A file could for example be named "myAddonName.en.pl".
#
# Note that you should always add 'en' (English) file, as this will be taken as the default for all
# languages.
#
# The file content has to start with (of course without the leading #):
# --------- CODE ---------
#%tr = (%tr,
# 'key1' => 'value',            # add all your entries key/values here 
# 'key2' => 'value'             # and end with (of course without the leading #):
#);
# --------- CODE END---------
#
# After you have copied all your files to /var/ipcop/addons/lang you use the SUID 
# helper rebuildlangtexts which will call &Lang::BuildAddonLang
# to assemble all texts for a language in one file.


package Lang;
require '/usr/lib/ipcop/general-functions.pl';
use Locale::Maketext::Gettext::Functions;
use strict;

my %settings = ();
# language variable also used by makegraphs script
our $language;
my $locale;
langsettings();

# Setup for __('text')
bindtextdomain("ipcop", "/usr/share/locale");
textdomain("ipcop");

# Used in both functions
$Lang::CacheDir = "/var/ipcop/addons/lang";
$Lang::CacheLang = "$Lang::CacheDir/texts.pl";


# Use reload function
reload(0);


sub langsettings
{
    &General::readhash('/var/ipcop/main/settings', \%settings);
    $language = $settings{'LANGUAGE'};
    $locale = $settings{'LOCALE'};
}

# call with 0 if main/settings already read (don't use in CGIs)
# call with 1 to reread main/settings for language info (gui.cgi)
# call with 2 to use en_GB as language (makegraphs)
sub reload
{
    my $rereadsettings = shift;
    if ($rereadsettings == 1) {
        langsettings();
    }
    elsif ($rereadsettings == 2) {
        $language = 'en';
        $locale = 'en_GB';
    }
        

    # Set locale for __('text')
    get_handle($locale);

    # Get lexicon for $Lang :: tr{'text'}
    #   (note: 2 spaces intentionally added around :: so 'text' is not added to .po file)
    %Lang::tr = read_mo("/usr/share/locale/${locale}/LC_MESSAGES/ipcop.mo");

    # Now fetch additional addon texts (if any)
    if (-s "$Lang::CacheLang.${language}" ) {
        # TODO: need to put a lock_shared on it in case rebuild is active ?
        do "$Lang::CacheLang.${language}";
    }

    # set admin manual URL
    if ($locale eq 'de_DE') {
        $General::adminmanualurl = 'http://www.ipcop.org/2.0.0/de/admin/html';
    }
    elsif (($locale eq 'es_ES') || ($locale eq 'es_UY')) {
        $General::adminmanualurl = 'http://www.ipcop.org/2.0.0/es/admin/html';
    }
    else {
        $General::adminmanualurl = 'http://www.ipcop.org/2.0.0/en/admin/html';
    }
}


# Called when texts are added or removed.
# Build file for current language only.
sub BuildAddonLang {
    &General::log("Building Addon textsfile for: $language ($locale)");

    # Empty the text table
    %Lang::tr = ();
    # Get a list of all files
    opendir(DIR, $Lang::CacheDir);
    my @files = readdir (DIR);
    closedir (DIR);

    # Fill text table with 'en' texts first
    foreach my $file ( grep (/.*\.en.pl$/,@files)) {
        do "$Lang::CacheDir/$file";
    }

    # Add our current language if it is not 'en'
    if ($language ne 'en') {
        foreach my $file (grep (/.*\.$language\.pl$/,@files) ) {
            do "$Lang::CacheDir/$file";
        }
    }

    # Write assembled texts to file
    open (FILE, ">$Lang::CacheLang.$language") or return 1;
    flock (FILE, 2) or return 1;
    print FILE "%tr=(%tr,\n";
    foreach my $k (keys %Lang::tr) {
        $Lang::tr{$k} =~ s/\'/\\\'/g;           # quote ' => \'
        print FILE "'$k'=>'$Lang::tr{$k}',\n";  # key => value,
    }
    print FILE ');';
    close (FILE);

    # Force our permissions (Addon installer may set wrong properties)
    system('/bin/chown root:root /var/ipcop/addons/lang/*');
    system('/bin/chmod 444 /var/ipcop/addons/lang/*');
}

1;
