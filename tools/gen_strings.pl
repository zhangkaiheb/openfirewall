#!/usr/bin/perl
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
# Copyright (C) 2004-03-12 Mark Wormgoor <mark@wormgoor.com>
# (c) 2006-2012 The IPCop Team
#
# Achim Weber - 12. August 2006:
#   Merge and modify check_strings.pl and fetchlangs.pl to generate lang files
#   which are only contain those lang entries which are really used.
#
# Usage: gen_strings.pl [baseDir targetDir]
#       gen_strings.pl searches all language entries in IPCop sourcefiles and
#       generates lang files with used text strings.
#
#       baseDir:    is the dir where all the ipcop sources are located (SVN trunk)
#       targetDir:  is the dir where the script stores/saves lang files (SVN trunk/langs)
#
#       If there is no base and no target dir given, we use the parent dir of
#       script/current location (we assume that we are in tools/) as base dir
#       and the the langs/ dir in base as target dir.
#
#       In target directory there must be the 'list' with supported languages.
#
#       On start gen_strings.pl:
#       - first fetches the translations from the lang repository on ipcop.org,
#       - second it searches in sources for language entries and stores them in
#         a hash for later use.
#       - Last step is generation of language files with all used lang entries.
#         The original head/top comment (which language, license, authors, etc.)
#         is written in every new lang file too.
#
# $Id: gen_strings.pl 6543 2012-04-14 14:46:43Z owes $
#

my ( %tr_en, %tr_wanted, $basedir, $targetdir);
our (%tr, %tr_new);

use Cwd;
use File::Find;
use warnings;
use strict;

# Run script for single language only
my $test = 0;

# base and target dir given? Example target: build_i486_glibc/....
if (defined($ARGV[0]) && defined($ARGV[1])) {
    $basedir = $ARGV[0];
    $targetdir = $ARGV[1];
    print "\nBase and target dir are given:\n";
}
else {
    $basedir = cwd();
    # we are in tools/ dir
    $basedir .= "/..";

    $targetdir = "$basedir/langs";
    print "\nNo base and target dir given:\n";
}

# remove trailing /
$basedir =~ s/\/$//;
$targetdir =~ s/\/$//;

print "Base = $basedir/\n";
print "Target = $targetdir/\n\n";


### Main
# first fetch langs
print "Fetch lang files:\n";
open(LIST, "$targetdir/list") or die 'Unable to open language list $targetdir/list';
while (<LIST>) {
    next if $_ =~ m/^#/;
    my @temp = split(/:/,$_);
    my $lang = $temp[0];
    my $uclang = uc($lang);
    my $dir = $temp[1];
    my $lang_full = $temp[2];

    # TEST:
    next if ($test && ($dir ne "de_DE"));

    if ( $dir ne "" ) {
        print "Downloading files for ${lang_full} ";
        system("mkdir -p $targetdir/${dir}");

        &wget_retry("install", ${uclang}, "$targetdir/${dir}");
        # generate temp .pl file for the installer texts
        &po2pl( "$targetdir/${dir}/install.po.tmp", "$targetdir/${dir}/install.pl.tmp");
        unlink( "$targetdir/${dir}/install.po.tmp") unless ($test);

        # Patch TR_CONFIGURATION_LONG with new https port number
        # First, change https port from 445 to 8443
        system ('sed','-i','-e','s/:445/:8443/',"$targetdir/${dir}/install.pl.tmp");
        # Second, remove http port and replace with https 
        system ('sed','-i','-e','s/http:\/\/%s:81/https:\/\/192.168.1.1:8443/',"$targetdir/${dir}/install.pl.tmp");

        print " ";

        &wget_retry("ipcop", ${uclang}, "$targetdir/${dir}");
        # generate temp .pl file for GUI texts
        &po2pl( "$targetdir/${dir}/ipcop.po.tmp", "$targetdir/${dir}/ipcop.pl.tmp");
        unlink( "$targetdir/${dir}/ipcop.po.tmp") unless ($test);

        system ('sed','-i','-e','s/222/8022/',"$targetdir/${dir}/ipcop.pl.tmp");

        print "\n";
    }
}
close (LIST);
print "Done.\n\n";



# one of 'ipcop' (CGI) and 'install' (installer/setup)
our $file_typ = 'ipcop';
# generate the lang files for CGI
&generateFiles();
# generate the lang files for installer
$file_typ = 'install';
&generateFiles();

### End Main


sub wget_retry
{
    my $file = shift;       # install or ipcop
    my $language = shift;   # 
    my $targetdir = shift;
    my $targetfile = $targetdir."/${file}.po.tmp";

    my $fetchscript = "create-c3.php";
    $fetchscript = "create-pl2.php" if ($file eq "ipcop");
    my $retries = 0;

    while (! -e "${fetchscript}?Lang=${language}" && (++$retries <= 5)) {
        print ".";
        system ('wget','--quiet','-N','-c','--cache=off',"http://www.ipcop.org/langs/${fetchscript}?Lang=${language}");

        if (!system("grep 'Failed to connect to Database Server' ${fetchscript}?Lang=${language}")) {
            unlink("${fetchscript}?Lang=${language}");
        }
    }

    rename("${fetchscript}?Lang=${language}", "$targetfile") or die "Failed to download $file file for language $language";
}


sub wanted {
    if ( -f $File::Find::name && (index($File::Find::name,'.svn') == -1) && open(FILE, $File::Find::name)) {
        if ($file_typ eq 'ipcop') {
            while (<FILE>) {
                while ($_ =~ /\$Lang::tr{'([A-Za-z0-9,:_\s\/\.-]+)'}/g) {
                    $tr_wanted{$1} = 'empty string';
                }
            }
        }
        else {
            # 'install'
            while (<FILE>) {
                while ($_ =~ /gettext\((\"|\')(TR_[A-Z_0-9]+)/g) {
                    $tr_wanted{$2} = 'empty string';
                }
            }
        }
        close(FILE);
    }
}

sub generateFiles
{
    %tr = ();
    %tr_en = ();
    %tr_new = ();
    %tr_wanted = ();

    # find all texts in source
    # search only IPCop source directories e.g. no need to search in cache/
    print "Search used '$file_typ' lang entries:\n";
    find (\&wanted, "$basedir/config");
    #find (\&wanted, "$basedir/doc");
    find (\&wanted, "$basedir/html");
    find (\&wanted, "$basedir/langs");
    #find (\&wanted, "$basedir/lfs");
    find (\&wanted, "$basedir/src");
    #find (\&wanted, "$basedir/tools");
    #find (\&wanted, "$basedir/updates");
    print "Done.\n\n";

    # fill tr_en hash with english texts which are used
    print "Load default (== English) '$file_typ' lang entries:\n";

    # Load english "new texts" file from svn as the lang DB does not contain all lang entries yet.
    do "$targetdir/$file_typ.new.en.pl";
    print "Check for *new* '$file_typ' en texts: ". (keys %tr_new)." \n";

    #Load english texts from lang DB
    do "$targetdir/en_GB/$file_typ.pl.tmp";
    print "Check for '$file_typ' en texts: ". (keys %tr)." \n";


    for my $key ( sort (keys %tr) ) {
        my $value = $tr{$key};
        if (! $tr_wanted{$key}) {
            print "WARNING: translation string unused: $key\n";
        }
        else {
            $tr_en{$key} = $value;
        }
    }
    print "Done.\n\n";


    open(LIST, "$targetdir/list") or die 'Unable to open language list $targetdir/list';
    open(LIST_PROGRESS, ">$targetdir/list_progress") or die 'Unable to open progress list $targetdir/list_progress'  if ($file_typ eq 'ipcop');

    while (<LIST>) {
        next if $_ =~ m/^#/;
        my @temp = split(/:/,$_);
        my $lang = $temp[0];
        my $locale = $temp[1];
        my $lang_full = $temp[2];
        next if($locale eq "");

        # TEST:
        next if ($test && ($locale ne "de_DE"));

        my $file = "$file_typ.pl";
        my $relativePath_pl= "$locale/$file.tmp";
        my $relativePath_miss= "$locale/$file.missing";
        my $relativePath_gt= "$locale/$file_typ.po";

        undef %tr;
        if (-e "$targetdir/$relativePath_pl") {
            do "$targetdir/$relativePath_pl";
        }
        else {
            print "\n Could not generate '$file_typ' lang file for ${lang_full}. Tmp File not found.\n";
        }
        my %tr_trans = %tr;
        print "Check for translated '$file_typ' en texts: ". (keys %tr_trans)." \n";

        # generate new lang file(s)
        print "\nGenerate '$file_typ' lang file for ${lang_full}\n";
        open(FILE_MISS,">$targetdir/$relativePath_miss") or die "Unable to write new $relativePath_miss file.";
        flock FILE_MISS, 2;
        open(FILE_GT,">$targetdir/$relativePath_gt") or die "Unable to write new '$locale' gettext file.";
        flock FILE_GT, 2;

        # write comment
        open(SOURCE_FILE, "$targetdir/$relativePath_pl") or die "Unable to open source $relativePath_pl file.";
        flock SOURCE_FILE, 2;
        foreach my $line (<SOURCE_FILE>) {
            chomp($line);
            if($line =~ /^#/) {
                # write original head comment
                print FILE_GT "$line\n";
            }
            else {
                # end of head comment: one single blank line and finished with comment
                # add type and encoding info to .po file
                print FILE_GT <<END
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\\n"
"Content-Transfer-Encoding: 8bit\\n"

END
        ;
                last;
            }
        }
        close(SOURCE_FILE);

        my $cnt_translated = 0;
        # loop over wanted lang entries
        for my $key (sort (keys %tr_wanted)) {
            if (defined($tr_trans{$key})) {
                my $value = &escapeValue_po($tr_trans{$key});

                print FILE_GT "msgid \"$key\"\n";
                print FILE_GT "msgstr \"$value\"\n";
                $cnt_translated++;
            }
            elsif (defined($tr_en{$key})) {
                # DEBUG:
#~              print "Untranslated string: $key -> '$tr_en{$key}'\n";
                my $value = &escapeValue_po($tr_en{$key});
                my $value_miss = &escapeValue_pl($tr_en{$key});
#~              print FILE_MISS "#### UNTRANSLATED:\n";
                print FILE_MISS "'$key' => '$value_miss',\n";
                print FILE_GT "#### UNTRANSLATED:\n";
                print FILE_GT "msgid \"$key\"\n";
                print FILE_GT "msgstr \"$value\"\n";
            }
            elsif (defined($tr_new{$key})) {
                my $value = &escapeValue_po($tr_new{$key});

                print FILE_GT "#### NEW:\n";
                print FILE_GT "msgid \"$key\"\n";
                print FILE_GT "msgstr \"$value\"\n";
            }
            else {
                print "WARNING: String not defined (not in '$lang', nor in 'en'): $key\n";

                print FILE_MISS "#### UNTRANSLATED:\n";
                print FILE_MISS "'$key' => '$key',\n";
#~              print FILE_GT "#### UNTRANSLATED:\n";
                print FILE_GT "msgid \"$key\"\n";
                print FILE_GT "msgstr \"$key\"\n";
            }
        }
        close(FILE_MISS);
        close(FILE_GT);
        if (-z "$targetdir/$relativePath_miss") {
            unlink("$targetdir/$relativePath_miss");
        }
        unlink("$targetdir/$relativePath_pl");
        print "Done.\n";

        if (($file_typ eq 'ipcop') && ($temp[2] ne 'English')) {
            print LIST_PROGRESS "$temp[2],$cnt_translated,".int($cnt_translated * 100 /(keys %tr_wanted))."\n";
        }
    }
    close (LIST);
    close (LIST_PROGRESS) if ($file_typ eq 'ipcop');

    # en_US to en_GB
    # Change Color to Colour
    system ('sed','-i','-e','/msgstr/s/olor/olour/g',"$targetdir/en_GB/ipcop.po");

    # Remove UNTRANSLATED markers from en_US files
    system ('sed','-i','-e','/UNTRANSLATED/d',"$targetdir/en_US/install.po");
    system ('sed','-i','-e','/UNTRANSLATED/d',"$targetdir/en_US/ipcop.po");

}

sub escapeValue_po
{
    my $value = shift;
    $value =~ s+\\'+'+g;
    # Workaround trailing linefeed mismatch error reported by msgfmt
    $value =~ s+\\n$+\\n +;
    $value =~ s+:\s*$++;

    return $value;
}

sub escapeValue_pl
{
    my $value = shift;
    $value =~ s/'/\\'/g;
    $value =~ s+:\s*$++;

    return $value;
}

sub po2pl
{
    my $poFile = shift;
    my $plFile = shift;

    open(FILE_PL,">$plFile") or die "Unable to write $plFile file.";
    flock FILE_PL, 2;

    # write comment
    open(SOURCE_FILE, "$poFile") or die "Unable to open source $poFile file.";
    flock SOURCE_FILE, 2;
    my @current = <SOURCE_FILE>;
    close(SOURCE_FILE);

    foreach my $line (@current) {
        chomp($line);
        if ($line =~ /^#/) {
            # write original head comment
            print FILE_PL "$line\n";
        }
        else {

            # end of head comment: one single blank line and finished with comment
            # add type and encoding info to .po file
            print FILE_PL <<END;

\%tr = (
END

            last;
        }
    }


    my $key = "";
    my $value="";
    foreach my $line (@current) {
        chomp($line);

        # msgid "TR_ADDRESS_SETTINGS"
        # msgstr "Address settings"

        if ($key ne "" &&  $line =~ /^\s*msgstr \"(.*)\"\s*$/) {
            # this line is a value line
            $value  = $1;
            $value =~ s/'/\\'/g;
            print FILE_PL "'$key' => '$value',\n";

            # reset key and value
            $key = "";
            $value="";
        }
        elsif ($line =~ /^\s*msgid \"(.*)\"\s*$/) {
            # this is a key line
            # remember key
            $key = $1;
        }
    }

    # "close" hash definition
    print FILE_PL <<END;
);

# always return true
1;

END

    close(FILE_PL);
}

