#!/usr/bin/perl
#
# This file is part of the Openfirewall.
#
# Openfirewall is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Openfirewall is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Openfirewall.  If not, see <http://www.gnu.org/licenses/>.
#
# (c) 2018-2019 The Openfirewall Team
#
#

# Add entry in menu
# MENUENTRY services 020 "url filter" "urlfilter configuration"
#
# Make sure translation exists $Lang::tr{'url filter'}

use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

use File::Copy;
use IO::Socket;

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

# enable(==1)/disable(==0) HTML Form debugging
my $debugFormparams = 0;

my $http_port      = '81';
my %netsettings    = ();
my %mainsettings   = ();
my %proxysettings  = ();
my %filtersettings = ();
my %tcsettings     = ();
my %uqsettings     = ();
my %besettings     = ();
my %updatesettings = ();
my %checked        = ();
my %selected       = ();
my $id             = 0;
my $line           = '';
my $i              = 0;
my $n              = 0;
my $time           = '';
my $filesize;
my $category    = '';
my $section     = '';
my $blacklist   = '';
my $blistbackup = '';

my $changed    = 'no';
my $tcfile     = "/var/ofw/proxy/timeconst";
my $uqfile     = "/var/ofw/proxy/userquota";
my $dbdir      = "/var/lib/squidguard/db";
my $editdir    = "/var/ofw/proxy/editor";

my $sourceurlfile = "/var/ofw/proxy/blacklistupdate/blacklistupdate.urls";
my $updconffile   = "/var/ofw/proxy/blacklistupdate/blacklistupdate.conf";

my $errormessage   = '';
my $updatemessage  = '';
my $restoremessage = '';
my $buttontext     = '';
my $source_name    = '';
my $source_url     = '';

my @categories         = ();
my @filtergroups       = ();
my @tclist             = ();
my @uqlist             = ();
my @source_urllist     = ();
my @clients            = ();
my @temp               = ();

my $lastslashpos = 0;

my $toggle = '';
my $gif    = '';
my $led    = '';
my $ldesc  = '';
my $gdesc  = '';

if (!-d $dbdir)         { mkdir("$dbdir"); }
if (!-e $tcfile)        { system("touch $tcfile"); }
if (!-e $uqfile)        { system("touch $uqfile"); }
if (!-e $sourceurlfile) { system("touch $sourceurlfile"); }

&General::readhash("/var/ofw/ethernet/settings", \%netsettings);
&General::readhash("/var/ofw/main/settings",     \%mainsettings);
&General::readhash("/var/ofw/proxy/settings",    \%proxysettings);

&readblockcategories;

open(FILE, $tcfile);
@tclist = <FILE>;
close(FILE);
open(FILE, $uqfile);
@uqlist = <FILE>;
foreach (@uqlist) { s/%5c/\\/g; }
close(FILE);
open(FILE, $sourceurlfile);
@source_urllist = <FILE>;
close(FILE);

$filtersettings{'ENABLED'}   = 'off';
$filtersettings{'ENABLE_CUSTOM_BLACKLIST'}   = 'off';
$filtersettings{'ENABLE_CUSTOM_WHITELIST'}   = 'off';
$filtersettings{'ENABLE_CUSTOM_EXPRESSIONS'} = 'off';
$filtersettings{'BLOCK_EXECUTABLES'}         = 'off';
$filtersettings{'BLOCK_AUDIO-VIDEO'}         = 'off';
$filtersettings{'BLOCK_ARCHIVES'}            = 'off';
$filtersettings{'ENABLE_REWRITE'}            = 'off';
$filtersettings{'UNFILTERED_CLIENTS'}        = '';
$filtersettings{'BANNED_CLIENTS'}            = '';
$filtersettings{'SHOW_CATEGORY'}             = 'off';
$filtersettings{'SHOW_URL'}                  = 'off';
$filtersettings{'SHOW_IP'}                   = 'off';
$filtersettings{'ENABLE_DNSERROR'}           = 'off';
$filtersettings{'ENABLE_BG_IMAGE'}           = 'off';
$filtersettings{'REDIRECT_PAGE'}             = '';
$filtersettings{'MSG_TEXT_1'}                = '';
$filtersettings{'MSG_TEXT_2'}                = '';
$filtersettings{'MSG_TEXT_3'}                = '';
$filtersettings{'ENABLE_EXPR_LISTS'}         = 'off';
$filtersettings{'BLOCK_IP_ADDR'}             = 'off';
$filtersettings{'BLOCK_ALL'}                 = 'off';
$filtersettings{'ENABLE_EMPTY_ADS'}          = 'off';
$filtersettings{'ENABLE_GLOBAL_WHITELIST'}   = 'off';
$filtersettings{'ENABLE_SAFESEARCH'}         = 'off';
$filtersettings{'ENABLE_LOG'}                = 'off';
$filtersettings{'ENABLE_USERNAME_LOG'}       = 'off';
$filtersettings{'ENABLE_CATEGORY_LOG'}       = 'off';
$filtersettings{'ENABLE_AUTOUPDATE'}         = 'off';
$filtersettings{'CHECKUPDATES'}              = 'off';
$filtersettings{'ENABLE_FULLBACKUP'}         = 'off';

&resetTcSettings();

$filtersettings{'ACTION'} = '';
$filtersettings{'VALID'}  = '';
$filtersettings{'MODE'}   = '';

&resetUqSettings();

$besettings{'BE_NAME'}      = '';
$besettings{'BE_BLACKLIST'} = '';
$besettings{'NORESTART'}    = 'off';
$besettings{'ACTION'}       = '';
$besettings{'MODE'}         = '';

&General::getcgihash(\%filtersettings);
&General::getcgihash(\%tcsettings);
&General::getcgihash(\%uqsettings);
&General::getcgihash(\%besettings);

if (   (($filtersettings{'ACTION'} eq $Lang::tr{'save'}) && ($filtersettings{'MODE'} eq ''))
    || ($filtersettings{'ACTION'} eq $Lang::tr{'save and restart'})
    || ($filtersettings{'ACTION'} eq $Lang::tr{'upload'})
    || ($filtersettings{'ACTION'} eq $Lang::tr{'create backup file'})
    || ($filtersettings{'ACTION'} eq $Lang::tr{'import backup file'}))
{
    if($filtersettings{'ENABLED'} ne 'on') {
        $filtersettings{'ENABLED'} = 'off';
    }

    @clients = split(/\n/, $filtersettings{'UNFILTERED_CLIENTS'});
    foreach (@clients) {
        s/^\s+//g;
        s/\s+$//g;
        s/\s+-\s+/-/g;
        s/\s+/ /g;
        s/\n//g;
        if (/.*-.*-.*/) {
            $errormessage .= "$Lang::tr{'errmsg invalid ip or mask'}<br />";
        }
        @temp = split(/-/);
        foreach (@temp) {
            unless ((&General::validipormask($_)) || (&General::validipandmask($_))) {
                $errormessage .= "$Lang::tr{'errmsg invalid ip or mask'}<br />";
            }
        }
    }
    @clients = split(/\n/, $filtersettings{'BANNED_CLIENTS'});
    foreach (@clients) {
        s/^\s+//g;
        s/\s+$//g;
        s/\s+-\s+/-/g;
        s/\s+/ /g;
        s/\n//g;
        if (/.*-.*-.*/) {
            $errormessage .= "$Lang::tr{'errmsg invalid ip or mask'}<br />";
        }
        @temp = split(/-/);
        foreach (@temp) {

            unless ((&General::validipormask($_)) || (&General::validipandmask($_))) {
                $errormessage .= "$Lang::tr{'errmsg invalid ip or mask'}<br />";
            }
        }
    }
    if ($errormessage) { goto ERROR; }

    if ((!($filtersettings{'REDIRECT_PAGE'} eq '')) && (!($filtersettings{'REDIRECT_PAGE'} =~ /^https?:\/\//))) {
        $filtersettings{'REDIRECT_PAGE'} = "http://" . $filtersettings{'REDIRECT_PAGE'};
    }

    if ($filtersettings{'ACTION'} eq $Lang::tr{'upload'}) {
        &General::getcgihash(\%filtersettings, {'wantfile' => 1, 'filevar' => 'UPDATEFILE'});

        if (!($filtersettings{'UPDATEFILE'} =~ /.tar.gz$/)) {
            $errormessage .= "$Lang::tr{'errmsg wrong filetype'}<br />";
            goto ERROR;
        }

        if (copy($filtersettings{'UPDATEFILE'}, "/var/ofw/proxy/blacklists.tar.gz") != 1) {
            $errormessage .= "$!<br />";
            goto ERROR;
        }

        if (!(-d "/var/ofw/proxy/update")) { mkdir("/var/ofw/proxy/update"); }

        my $exitcode =
            system("/bin/tar --no-same-owner -xzf /var/ofw/proxy/blacklists.tar.gz -C /var/ofw/proxy/update");

        if ($exitcode > 0) {
            $errormessage .= "$Lang::tr{'errmsg extract tar'}<br />"
        }
        else {

            if (-d "/var/ofw/proxy/update/BL") {
                system("mv /var/ofw/proxy/update/BL /var/ofw/proxy/update/blacklists");
            }

            if (-d "/var/ofw/proxy/update/category") {
                system("mv /var/ofw/proxy/update/category /var/ofw/proxy/update/blacklists");
            }

            if (!(-d "/var/ofw/proxy/update/blacklists")) {
                $errormessage .= "$Lang::tr{'errmsg invalid blacklist content'}<br />";
            }
            else {
                # remove old blacklists (except custom lists)
                system("rm -rf `find $dbdir/* -maxdepth 0 | grep -v $dbdir/custom` ");

                system("cp -r /var/ofw/proxy/update/blacklists/* $dbdir");

                &readblockcategories;
                &readcustomlists;

                &writeconfigfile;

                $updatemessage = $Lang::tr{'blacklist upload success'};
                `/usr/local/bin/blacklistupdate.pl --perm < /dev/null > /dev/null &`;
                system(
"logger -t installpackage[urlfilter] \"URL filter blacklist - Blacklist update from local source completed\""
                );
            }
        }
        if (-d "/var/ofw/proxy/update")            { system("rm -rf /var/ofw/proxy/update"); }
        if (-e "/var/ofw/proxy/blacklists.tar.gz") { unlink("/var/ofw/proxy/blacklists.tar.gz"); }
        if ($errormessage)                           { goto ERROR; }
    }

    if ($filtersettings{'ACTION'} eq $Lang::tr{'create backup file'}) {
        $blistbackup = ($filtersettings{'ENABLE_FULLBACKUP'} eq 'on') ? "blacklists" : "blacklists/custom";
        if (
            system(
"/bin/tar -C /var/ofw/proxy -czf /var/ofw/proxy/backup.tar.gz settings timeconst userquota blacklistupdate $blistbackup"
            )
            )
        {
            $errormessage .= "$Lang::tr{'err create backup file'}<br />";
            goto ERROR;
        }
        else {
            print "Content-type: application/gzip\n";
            print "Content-length: ";
            print(-s "/var/ofw/proxy/backup.tar.gz");
            print "\n";
            print "Content-disposition: attachment; filename=urlfilter-backup.tar.gz\n\n";

            open(FILE, "/var/ofw/proxy/backup.tar.gz");
            while (<FILE>) { print; }
            close(FILE);

            if (-e "/var/ofw/proxy/backup.tar.gz") { unlink("/var/ofw/proxy/backup.tar.gz"); }
            exit;
        }
    }

    if ($filtersettings{'ACTION'} eq $Lang::tr{'import backup file'}) {
        &General::getcgihash(\%filtersettings, {'wantfile' => 1, 'filevar' => 'UPDATEFILE'});

        if (!($filtersettings{'UPDATEFILE'} =~ /.tar.gz$/)) {
            $errormessage .= "$Lang::tr{'errmsg wrong filetype'}<br />";
            goto ERROR;
        }

        if (!(-d "/var/ofw/proxy/restore")) { mkdir("/var/ofw/proxy/restore"); }

        if (copy($filtersettings{'UPDATEFILE'}, "/var/ofw/proxy/backup.tar.gz") != 1) {
            $errormessage .= "$!<br />";
        }

        my $exitcode = system(
"/bin/tar --no-same-owner --preserve-permissions -xzf /var/ofw/proxy/backup.tar.gz -C /var/ofw/proxy/restore"
        );
        if ($exitcode > 0) {
            $errormessage .= "$Lang::tr{'errmsg extract tar'}<br />";
        }
        else {
            if (!(-e "/var/ofw/proxy/restore/settings")) {
                $errormessage .= "$Lang::tr{'errmsg invalid restore file'}<br />";
            }
            else {
                system("cp -rp /var/ofw/proxy/restore/* /var/ofw/proxy/");
                &readblockcategories;
                &readcustomlists;
                &writeconfigfile;

                $restoremessage = $Lang::tr{'urlfilter restore success'};
            }
        }

        if (-e "/var/ofw/proxy/backup.tar.gz") { unlink("/var/ofw/proxy/backup.tar.gz"); }
        if (-d "/var/ofw/proxy/restore")       { system("rm -rf /var/ofw/proxy/restore"); }
        if ($errormessage)                       { goto ERROR; }
    }

    if ($filtersettings{'ACTION'} eq $Lang::tr{'save'}) {
        $filtersettings{'VALID'} = 'yes';
        &savesettings;
    }

    if ($filtersettings{'ACTION'} eq $Lang::tr{'save and restart'}) {
        if ((!($proxysettings{'ENABLED_GREEN_1'} eq 'on')) && (!($proxysettings{'ENABLED_BLUE_1'} eq 'on')) && (!($proxysettings{'ENABLED_OVPN'} eq 'on'))) {
            $errormessage .= "$Lang::tr{'errmsg web proxy service required'}<br />";
            goto ERROR;
        }
        if (!($proxysettings{'ENABLE_REDIRECTOR'} eq 'on')) {
            $errormessage .= "$Lang::tr{'redirectors are disabled'}<br />";
            goto ERROR;
        }

        $filtersettings{'VALID'} = 'yes';
        &savesettings;

        if (-e "$dbdir/custom/allowed/domains.db") { unlink("$dbdir/custom/allowed/domains.db"); }
        if (-e "$dbdir/custom/allowed/urls.db")    { unlink("$dbdir/custom/allowed/urls.db"); }
        if (-e "$dbdir/custom/blocked/domains.db") { unlink("$dbdir/custom/blocked/domains.db"); }
        if (-e "$dbdir/custom/blocked/urls.db")    { unlink("$dbdir/custom/blocked/urls.db"); }

        &setpermissions($dbdir);

        &restartexit(1);
    }
}

if ($tcsettings{'ACTION'} eq $Lang::tr{'set time constraints'}) {
    $tcsettings{'TCMODE'} = 'on'
}

if (($tcsettings{'MODE'} eq 'TIMECONSTRAINT') && ($tcsettings{'ACTION'} eq $Lang::tr{'add'})) {
    $tcsettings{'TCMODE'} = 'on';

    if (!$tcsettings{'DST'}) {
        $errormessage .= "$Lang::tr{'errmsg at least one category must be selected'}<br />";
    }

    if (!$tcsettings{'SRC'}) {
        $errormessage .= "$Lang::tr{'errmsg src empty'}<br />";
    }

    if (!($tcsettings{'TO_HOUR'} . $tcsettings{'TO_MINUTE'} gt $tcsettings{'FROM_HOUR'} . $tcsettings{'FROM_MINUTE'})) {
        $errormessage .= "$Lang::tr{'error time space'}<br />";
    }

    if (
        !(
               ($tcsettings{'MON'} eq 'on')
            || ($tcsettings{'TUE'} eq 'on')
            || ($tcsettings{'WED'} eq 'on')
            || ($tcsettings{'THU'} eq 'on')
            || ($tcsettings{'FRI'} eq 'on')
            || ($tcsettings{'SAT'} eq 'on')
            || ($tcsettings{'SUN'} eq 'on')
        )
        )
    {
        $errormessage .= "$Lang::tr{'errmsg weekday'}<br />";
    }

    if (!$errormessage) {

        # transform to pre1.8 client definitions
        @clients = split(/\n/, $tcsettings{'SRC'});
        undef $tcsettings{'SRC'};
        foreach (@clients) {
            s/^\s+//g;
            s/\s+$//g;
            s/\s+-\s+/-/g;
            s/\s+/ /g;
            s/\n//g;
            $tcsettings{'SRC'} .= "$_ ";
        }
        $tcsettings{'SRC'} =~ s/\s+$//;

        if ($tcsettings{'DST'} =~ /^any/) {
            $tcsettings{'DST'} = 'any';
        }
        if (defined($tcsettings{'ENABLERULE'}) && $tcsettings{'ENABLERULE'} eq 'on') {
            $tcsettings{'ACTIVE'} = $tcsettings{'ENABLERULE'};
        }
        else {
            $tcsettings{'ACTIVE'} = 'off'
        }

        $tcsettings{'ENABLERULE'} = 'on';
        if ($tcsettings{'EDITING'} eq 'no') {
            open(FILE, ">>$tcfile");
            flock FILE, 2;
            print FILE
"$tcsettings{'DEFINITION'},$tcsettings{'MON'},$tcsettings{'TUE'},$tcsettings{'WED'},$tcsettings{'THU'},$tcsettings{'FRI'},$tcsettings{'SAT'},$tcsettings{'SUN'},$tcsettings{'FROM_HOUR'},$tcsettings{'FROM_MINUTE'},$tcsettings{'TO_HOUR'},$tcsettings{'TO_MINUTE'},$tcsettings{'SRC'},$tcsettings{'DST'},$tcsettings{'ACCESS'},$tcsettings{'ACTIVE'},$tcsettings{'COMMENT'}\n";
        }
        else {
            open(FILE, ">$tcfile");
            flock FILE, 2;
            $id = 0;
            foreach $line (@tclist) {
                $id++;
                if ($tcsettings{'EDITING'} eq $id) {
                    print FILE
"$tcsettings{'DEFINITION'},$tcsettings{'MON'},$tcsettings{'TUE'},$tcsettings{'WED'},$tcsettings{'THU'},$tcsettings{'FRI'},$tcsettings{'SAT'},$tcsettings{'SUN'},$tcsettings{'FROM_HOUR'},$tcsettings{'FROM_MINUTE'},$tcsettings{'TO_HOUR'},$tcsettings{'TO_MINUTE'},$tcsettings{'SRC'},$tcsettings{'DST'},$tcsettings{'ACCESS'},$tcsettings{'ACTIVE'},$tcsettings{'COMMENT'}\n";
                }
                else {
                    print FILE "$line";
                }
            }
        }
        close(FILE);

        undef %tcsettings;
        &resetTcSettings();

        $tcsettings{'CHANGED'} = 'yes';
        $tcsettings{'MODE'}    = 'TIMECONSTRAINT';
        $tcsettings{'TCMODE'}  = 'on';
        $changed               = 'yes';
    }
    else {
        if ($tcsettings{'EDITING'} ne 'no') {
            $tcsettings{'ACTION'} = $Lang::tr{'edit'};
            $tcsettings{'ID'}     = $tcsettings{'EDITING'};
        }
    }
}

if (   ($tcsettings{'MODE'} eq 'TIMECONSTRAINT')
    && ($tcsettings{'ACTION'} eq $Lang::tr{'copy rule'})
    && (!$errormessage))
{
    $id = 0;
    foreach $line (@tclist) {
        $id++;
        if ($tcsettings{'ID'} eq $id) {
            chomp($line);
            @temp = split(/\,/, $line);

            $temp[16] = '' unless(defined($temp[16]));

            $tcsettings{'DEFINITION'}  = $temp[0];
            $tcsettings{'MON'}         = $temp[1];
            $tcsettings{'TUE'}         = $temp[2];
            $tcsettings{'WED'}         = $temp[3];
            $tcsettings{'THU'}         = $temp[4];
            $tcsettings{'FRI'}         = $temp[5];
            $tcsettings{'SAT'}         = $temp[6];
            $tcsettings{'SUN'}         = $temp[7];
            $tcsettings{'FROM_HOUR'}   = $temp[8];
            $tcsettings{'FROM_MINUTE'} = $temp[9];
            $tcsettings{'TO_HOUR'}     = $temp[10];
            $tcsettings{'TO_MINUTE'}   = $temp[11];
            $tcsettings{'SRC'}         = $temp[12];
            $tcsettings{'DST'}         = $temp[13];
            $tcsettings{'ACCESS'}      = $temp[14];
            $tcsettings{'ENABLERULE'}  = $temp[15];
            $tcsettings{'COMMENT'}     = $temp[16];
        }
    }
    $tcsettings{'TCMODE'} = 'on';
}

if (($tcsettings{'MODE'} eq 'TIMECONSTRAINT') && ($tcsettings{'ACTION'} eq $Lang::tr{'remove'})) {
    $id = 0;
    open(FILE, ">$tcfile");
    flock FILE, 2;
    foreach $line (@tclist) {
        $id++;
        unless ($tcsettings{'ID'} eq $id) { print FILE "$line"; }
    }
    close(FILE);
    $tcsettings{'CHANGED'} = 'yes';
    $tcsettings{'TCMODE'}  = 'on';
}

if (($tcsettings{'MODE'} eq 'TIMECONSTRAINT') && ($tcsettings{'ACTION'} eq $Lang::tr{'urlfilter restart'})) {
    # does not work, we do not have settings from configfile yet.
    #if ($filtersettings{'ENABLED'} ne 'on') {
    #    $errormessage .= "$Lang::tr{'urlfilter not enabled'}<br />";
    #}
    if ($proxysettings{'ENABLE_REDIRECTOR'} ne 'on') {
        $errormessage .= "$Lang::tr{'redirectors are disabled'}<br />";
    }
    if ((!($proxysettings{'ENABLED_GREEN_1'} eq 'on')) && (!($proxysettings{'ENABLED_BLUE_1'} eq 'on')) && (!($proxysettings{'ENABLED_OVPN'} eq 'on'))) {
        $errormessage .= "$Lang::tr{'errmsg web proxy service required'}<br />";
    }

    if (!$errormessage) {
        &restartexit(1);
    }
    $tcsettings{'TCMODE'} = 'on';
}

if (($tcsettings{'MODE'} eq 'TIMECONSTRAINT') && ($tcsettings{'ACTION'} eq $Lang::tr{'toggle enable disable'})) {
    open(FILE, ">$tcfile");
    flock FILE, 2;
    $id = 0;
    foreach $line (@tclist) {
        $id++;
        unless ($tcsettings{'ID'} eq $id) { print FILE "$line"; }
        else {
            chomp($line);
            @temp = split(/\,/, $line);
            if ($temp[15] eq 'on') { $temp[15] = 'off'; }
            else                     { $temp[15] = 'on' }
            print FILE
"$temp[0],$temp[1],$temp[2],$temp[3],$temp[4],$temp[5],$temp[6],$temp[7],$temp[8],$temp[9],$temp[10],$temp[11],$temp[12],$temp[13],$temp[14],$temp[15],$temp[16]\n";
        }
    }
    close(FILE);
    $tcsettings{'CHANGED'} = 'yes';
    $tcsettings{'TCMODE'}  = 'on';
}

if (($tcsettings{'MODE'} eq 'TIMECONSTRAINT') && ($tcsettings{'ACTION'} eq $Lang::tr{'edit'}) && (!$errormessage)) {
    $id = 0;
    foreach $line (@tclist) {
        $id++;
        if ($tcsettings{'ID'} eq $id) {
            chomp($line);
            @temp = split(/\,/, $line);

            $temp[16] = '' unless(defined($temp[16]));

            $tcsettings{'DEFINITION'}  = $temp[0];
            $tcsettings{'MON'}         = $temp[1];
            $tcsettings{'TUE'}         = $temp[2];
            $tcsettings{'WED'}         = $temp[3];
            $tcsettings{'THU'}         = $temp[4];
            $tcsettings{'FRI'}         = $temp[5];
            $tcsettings{'SAT'}         = $temp[6];
            $tcsettings{'SUN'}         = $temp[7];
            $tcsettings{'FROM_HOUR'}   = $temp[8];
            $tcsettings{'FROM_MINUTE'} = $temp[9];
            $tcsettings{'TO_HOUR'}     = $temp[10];
            $tcsettings{'TO_MINUTE'}   = $temp[11];
            $tcsettings{'SRC'}         = $temp[12];
            $tcsettings{'DST'}         = $temp[13];
            $tcsettings{'ACCESS'}      = $temp[14];
            $tcsettings{'ENABLERULE'}  = $temp[15];
            $tcsettings{'COMMENT'}     = $temp[16];
        }
    }
    $tcsettings{'TCMODE'} = 'on';
}

if (   (!$errormessage)
    && (!($tcsettings{'ACTION'} eq $Lang::tr{'copy rule'}))
    && (!($tcsettings{'ACTION'} eq $Lang::tr{'edit'})))
{
    $tcsettings{'ENABLERULE'} = 'on';
}

if ($uqsettings{'ACTION'} eq $Lang::tr{'set user quota'}) { $uqsettings{'UQMODE'} = 'on' }

if (($uqsettings{'MODE'} eq 'USERQUOTA') && ($uqsettings{'ACTION'} eq $Lang::tr{'add'})) {
    $uqsettings{'UQMODE'} = 'on';

    if ((!($uqsettings{'TIME_QUOTA'} =~ /^\d+/)) || ($uqsettings{'TIME_QUOTA'} < '1')) {
        $errormessage .= "$Lang::tr{'errmsg quota time'}<br />";
    }

    @temp = split(/\n/, $uqsettings{'QUOTA_USERS'});
    $uqsettings{'QUOTA_USERS'} = '';
    foreach (@temp) {
        s/^\s+//g;
        s/\s+$//g;
        s/%5c/\\/;
        if ($_) { $uqsettings{'QUOTA_USERS'} .= $_ . "\n"; }
    }

    if ($uqsettings{'QUOTA_USERS'} eq '') {
        $errormessage .= "$Lang::tr{'errmsg quota user'}<br />";
    }

    $_ = $uqsettings{'QUOTA_USERS'};
    chomp;
    s/\n/|/g;
    my $quota_users = $_;

    if (!$errormessage) {
        if ($uqsettings{'ENABLEQUOTA'} eq 'on') {
            $uqsettings{'ACTIVE'} = $uqsettings{'ENABLEQUOTA'};
        }
        else {
            $uqsettings{'ACTIVE'} = 'off';
        }

        $uqsettings{'ENABLERULE'} = 'on';
        if ($uqsettings{'EDITING'} eq 'no') {
            open(FILE, ">>$uqfile");
            flock FILE, 2;
            print FILE
"$uqsettings{'TIME_QUOTA'},$uqsettings{'SPORADIC'},$uqsettings{'RENEWAL'},$quota_users,$uqsettings{'ACTIVE'}\n";
        }
        else {
            open(FILE, ">$uqfile");
            flock FILE, 2;
            $id = 0;
            foreach $line (@uqlist) {
                $id++;
                if ($uqsettings{'EDITING'} eq $id) {
                    print FILE
"$uqsettings{'TIME_QUOTA'},$uqsettings{'SPORADIC'},$uqsettings{'RENEWAL'},$quota_users,$uqsettings{'ACTIVE'}\n";
                }
                else { print FILE "$line"; }
            }
        }
        close(FILE);

        undef %uqsettings;
        &resetUqSettings();

        $uqsettings{'CHANGED'} = 'yes';
        $uqsettings{'MODE'}    = 'USERQUOTA';
        $uqsettings{'UQMODE'}  = 'on';
        $changed               = 'yes';
    }
    else {
        if ($uqsettings{'EDITING'} ne 'no') {
            $uqsettings{'ACTION'} = $Lang::tr{'edit'};
            $uqsettings{'ID'}     = $uqsettings{'EDITING'};
        }
    }
}

if (($uqsettings{'MODE'} eq 'USERQUOTA') && ($uqsettings{'ACTION'} eq $Lang::tr{'remove'})) {
    $id = 0;
    open(FILE, ">$uqfile");
    flock FILE, 2;
    foreach $line (@uqlist) {
        $id++;
        unless ($uqsettings{'ID'} eq $id) { print FILE "$line"; }
    }
    close(FILE);
    $uqsettings{'CHANGED'} = 'yes';
    $uqsettings{'UQMODE'}  = 'on';
}

if (!$errormessage) {
    $uqsettings{'ENABLEQUOTA'} = 'on';
}

if (($uqsettings{'MODE'} eq 'USERQUOTA') && ($uqsettings{'ACTION'} eq $Lang::tr{'edit'}) && (!$errormessage)) {
    $id = 0;
    foreach $line (@uqlist) {
        $id++;
        if ($uqsettings{'ID'} eq $id) {
            chomp($line);
            @temp = split(/\,/, $line);
            $uqsettings{'TIME_QUOTA'}  = $temp[0];
            $uqsettings{'SPORADIC'}    = $temp[1];
            $uqsettings{'RENEWAL'}     = $temp[2];
            $uqsettings{'QUOTA_USERS'} = $temp[3];
            $uqsettings{'ENABLEQUOTA'} = $temp[4];
        }
    }
    $uqsettings{'UQMODE'} = 'on';
}

if (($uqsettings{'MODE'} eq 'USERQUOTA') && ($uqsettings{'ACTION'} eq $Lang::tr{'toggle enable disable'})) {
    open(FILE, ">$uqfile");
    flock FILE, 2;
    $id = 0;
    foreach $line (@uqlist) {
        $id++;
        unless ($uqsettings{'ID'} eq $id) { print FILE "$line"; }
        else {
            chomp($line);
            @temp = split(/\,/, $line);
            if ($temp[4] eq 'on') { $temp[4] = 'off'; }
            else                    { $temp[4] = 'on' }
            print FILE "$temp[0],$temp[1],$temp[2],$temp[3],$temp[4]\n";
        }
    }
    close(FILE);
    $uqsettings{'CHANGED'} = 'yes';
    $uqsettings{'UQMODE'}  = 'on';
}

if (($uqsettings{'MODE'} eq 'USERQUOTA') && ($uqsettings{'ACTION'} eq $Lang::tr{'urlfilter restart'})) {
    # does not work, we do not have settings from configfile yet.
    #if ($filtersettings{'ENABLED'} ne 'on') {
    #    $errormessage .= "$Lang::tr{'urlfilter not enabled'}<br />";
    #}
    if (!($proxysettings{'ENABLE_REDIRECTOR'} eq 'on')) {
        $errormessage .= "$Lang::tr{'redirectors are disabled'}<br />";
    }
	if ((!($proxysettings{'ENABLED_GREEN_1'} eq 'on')) && (!($proxysettings{'ENABLED_BLUE_1'} eq 'on')) && (!($proxysettings{'ENABLED_OVPN'} eq 'on'))) {
        $errormessage .= "$Lang::tr{'errmsg web proxy service required'}<br />";
    }

    if (!$errormessage) { 
        &restartexit(1);
    }
    $uqsettings{'UQMODE'} = 'on';
}

if ($besettings{'ACTION'} eq $Lang::tr{'blacklist editor'}) { $besettings{'BEMODE'} = 'on'; }

if ($besettings{'MODE'} eq 'BLACKLIST_EDITOR') {
    @temp = split(/\n/, $besettings{'BE_DOMAINS'});
    $besettings{'BE_DOMAINS'} = '';
    foreach (@temp) {
        s/^\s+//g;
        s/\s+$//g;
        if ($_) { $besettings{'BE_DOMAINS'} .= $_ . "\n"; }
    }
    chomp($besettings{'BE_DOMAINS'});

    @temp = split(/\n/, $besettings{'BE_URLS'});
    $besettings{'BE_URLS'} = '';
    foreach (@temp) {
        s/^\s+//g;
        s/\s+$//g;
        if ($_) { $besettings{'BE_URLS'} .= $_ . "\n"; }
    }
    chomp($besettings{'BE_URLS'});

    @temp = split(/\n/, $besettings{'BE_EXPRESSIONS'});
    $besettings{'BE_EXPRESSIONS'} = '';
    foreach (@temp) {
        s/^\s+//g;
        s/\s+$//g;
        if ($_) { $besettings{'BE_EXPRESSIONS'} .= $_ . "\n"; }
    }
    chomp($besettings{'BE_EXPRESSIONS'});
}

if (($besettings{'ACTION'} eq $Lang::tr{'load blacklist'}) && ($besettings{'MODE'} = 'BLACKLIST_EDITOR')) {
    $besettings{'BEMODE'} = 'on';

    $besettings{'BE_NAME'} = $besettings{'BE_BLACKLIST'};

    delete $besettings{'BE_DOMAINS'};
    delete $besettings{'BE_URLS'};
    delete $besettings{'BE_EXPRESSIONS'};

    if (-e "$dbdir/$besettings{'BE_NAME'}/domains") {
        open(FILE, "$dbdir/$besettings{'BE_NAME'}/domains");
        while (<FILE>) {
            unless ($_ eq '\n') { $besettings{'BE_DOMAINS'} .= $_ }
        }
        close FILE;
        chomp($besettings{'BE_DOMAINS'});
    }
    if (-e "$dbdir/$besettings{'BE_NAME'}/urls") {
        open(FILE, "$dbdir/$besettings{'BE_NAME'}/urls");
        while (<FILE>) {
            unless ($_ eq '\n') { $besettings{'BE_URLS'} .= $_ }
        }
        close FILE;
        chomp($besettings{'BE_URLS'});
    }
    if (-e "$dbdir/$besettings{'BE_NAME'}/expressions") {
        open(FILE, "$dbdir/$besettings{'BE_NAME'}/expressions");
        while (<FILE>) {
            unless ($_ eq '\n') { $besettings{'BE_EXPRESSIONS'} .= $_ }
        }
        close FILE;
        chomp($besettings{'BE_EXPRESSIONS'});
    }
}

if (($besettings{'ACTION'} eq $Lang::tr{'import blacklist'}) && ($besettings{'MODE'} = 'BLACKLIST_EDITOR')) {
    $besettings{'BEMODE'} = 'on';

    &General::getcgihash(\%besettings, {'wantfile' => 1, 'filevar' => 'IMPORTFILE'});

    if (!($besettings{'IMPORTFILE'} =~ /.tar.gz$/)) {
        $errormessage .= "$Lang::tr{'errmsg wrong filetype'}<br />";
    }
    else {
        if (!-d "$editdir") { mkdir("$editdir"); }

        if (copy($besettings{'IMPORTFILE'}, "$editdir/blacklist.tar.gz") != 1) {
            $errormessage .= "$!<br />";
        }
        else {

            my $exitcode =
                system("/bin/tar --no-same-owner --preserve-permissions -xzf $editdir/blacklist.tar.gz -C $editdir");
            if ($exitcode > 0) {
                $errormessage .= "$Lang::tr{'errmsg extract tar'}<br />";
            }
            else {
                $i = 0;
                foreach (<$editdir/blacklists/*>) {
                    if (-d) {
                        $i++;
                        $besettings{'BE_NAME'} = substr($_, rindex($_, "/") + 1);
                    }
                }

                if (!($i == 1)) {
                    $errormessage .= "$Lang::tr{'errmsg invalid import file'}<br />";
                }
                else {
                    delete $besettings{'BE_DOMAINS'};
                    delete $besettings{'BE_URLS'};
                    delete $besettings{'BE_EXPRESSIONS'};

                    if (-e "$editdir/blacklists/$besettings{'BE_NAME'}/domains") {
                        open(FILE, "$editdir/blacklists/$besettings{'BE_NAME'}/domains");
                        while (<FILE>) {
                            unless ($_ eq '\n') { $besettings{'BE_DOMAINS'} .= $_ }
                        }
                        close FILE;
                        chomp($besettings{'BE_DOMAINS'});
                    }
                    if (-e "$editdir/blacklists/$besettings{'BE_NAME'}/urls") {
                        open(FILE, "$editdir/blacklists/$besettings{'BE_NAME'}/urls");
                        while (<FILE>) {
                            unless ($_ eq '\n') { $besettings{'BE_URLS'} .= $_ }
                        }
                        close FILE;
                        chomp($besettings{'BE_URLS'});
                    }
                    if (-e "$editdir/blacklists/$besettings{'BE_NAME'}/expressions") {
                        open(FILE, "$editdir/blacklists/$besettings{'BE_NAME'}/expressions");
                        while (<FILE>) {
                            unless ($_ eq '\n') { $besettings{'BE_EXPRESSIONS'} .= $_ }
                        }
                        close FILE;
                        chomp($besettings{'BE_EXPRESSIONS'});
                    }
                }
            }

            if (-d $editdir) { system("rm -rf $editdir"); }

        }
    }
}

if (($besettings{'ACTION'} eq $Lang::tr{'export blacklist'}) && ($besettings{'MODE'} = 'BLACKLIST_EDITOR')) {
    $besettings{'BEMODE'} = 'on';

    if ($besettings{'BE_NAME'} eq '') {
        $errormessage .= "$Lang::tr{'errmsg category name error'}<br />";
    }
    elsif ($besettings{'BE_DOMAINS'} || $besettings{'BE_URLS'} || $besettings{'BE_EXPRESSIONS'}) {

        $_ = $besettings{'BE_NAME'};
        tr/A-Z/a-z/;
        s/ /_/g;
        $besettings{'BE_NAME'} = $_;

        if (!(-d "$editdir"))                                   { mkdir("$editdir"); }
        if (!(-d "$editdir/blacklists"))                        { mkdir("$editdir/blacklists"); }
        if (!(-d "$editdir/blacklists/$besettings{'BE_NAME'}")) { mkdir("$editdir/blacklists/$besettings{'BE_NAME'}"); }

        open(FILE, ">$editdir/blacklists/$besettings{'BE_NAME'}/domains");
        flock FILE, 2;
        print FILE "$besettings{'BE_DOMAINS'}\n";
        close FILE;
        open(FILE, ">$editdir/blacklists/$besettings{'BE_NAME'}/urls");
        flock FILE, 2;
        print FILE "$besettings{'BE_URLS'}\n";
        close FILE;
        open(FILE, ">$editdir/blacklists/$besettings{'BE_NAME'}/expressions");
        flock FILE, 2;
        print FILE "$besettings{'BE_EXPRESSIONS'}\n";
        close FILE;

        if (system("/bin/tar -C $editdir -czf $editdir/$besettings{'BE_NAME'}.tar.gz blacklists")) {
            $errormessage .= "$Lang::tr{'err create export file'}<br />";
        }
        else {
            print "Content-type: application/gzip\n";
            print "Content-length: ";
            print(-s "$editdir/$besettings{'BE_NAME'}.tar.gz");
            print "\n";
            print "Content-disposition: attachment; filename=$besettings{'BE_NAME'}.tar.gz\n\n";

            open(FILE, "$editdir/$besettings{'BE_NAME'}.tar.gz");
            while (<FILE>) { print; }
            close(FILE);

            if (-d $editdir) { system("rm -rf $editdir"); }
            exit;
        }
    }
    else {
        $errormessage .= "$Lang::tr{'errmsg blacklist empty'}<br />";
    }
}

if (($besettings{'ACTION'} eq $Lang::tr{'install blacklist'}) && ($besettings{'MODE'} = 'BLACKLIST_EDITOR')) {
    $besettings{'BEMODE'} = 'on';

    if ($besettings{'BE_NAME'} eq '') {
        $errormessage .= "$Lang::tr{'errmsg category name error'}<br />";
    }
    elsif ($besettings{'BE_DOMAINS'} || $besettings{'BE_URLS'} || $besettings{'BE_EXPRESSIONS'}) {

        $_ = $besettings{'BE_NAME'};
        tr/A-Z/a-z/;
        s/ /_/g;
        $besettings{'BE_NAME'} = $_;

        if (!-d "$editdir") { mkdir("$editdir"); }

        if (!-d "$dbdir/$besettings{'BE_NAME'}") { mkdir("$dbdir/$besettings{'BE_NAME'}"); }

        if (-e "$dbdir/$besettings{'BE_NAME'}/domains") { unlink("$dbdir/$besettings{'BE_NAME'}/domains"); }
        if ($besettings{'BE_DOMAINS'}) {
            open(FILE, ">$dbdir/$besettings{'BE_NAME'}/domains");
            flock FILE, 2;
            print FILE "$besettings{'BE_DOMAINS'}\n";
            close FILE;
        }
        if (-e "$dbdir/$besettings{'BE_NAME'}/urls") { unlink("$dbdir/$besettings{'BE_NAME'}/urls"); }
        if ($besettings{'BE_URLS'}) {
            open(FILE, ">$dbdir/$besettings{'BE_NAME'}/urls");
            flock FILE, 2;
            print FILE "$besettings{'BE_URLS'}\n";
            close FILE;
        }
        if (-e "$dbdir/$besettings{'BE_NAME'}/expressions") { unlink("$dbdir/$besettings{'BE_NAME'}/expressions"); }
        if ($besettings{'BE_EXPRESSIONS'}) {
            open(FILE, ">$dbdir/$besettings{'BE_NAME'}/expressions");
            flock FILE, 2;
            print FILE "$besettings{'BE_EXPRESSIONS'}\n";
            close FILE;
        }

        open(FILE, ">$editdir/install.conf");
        flock FILE, 2;
        print FILE "logdir /var/log/squidGuard\n";
        print FILE "syslog enable\n";
        print FILE "dbhome $dbdir/$besettings{'BE_NAME'}\n\n";
        print FILE "dest $besettings{'BE_NAME'} {\n";
        if ($besettings{'BE_DOMAINS'})     { print FILE "    domainlist  domains\n"; }
        if ($besettings{'BE_URLS'})        { print FILE "    urllist     urls\n"; }
        if ($besettings{'BE_EXPRESSIONS'}) { print FILE "    expressionlist expressions\n"; }
        print FILE "}\n\n";
        print FILE "acl {\n";
        print FILE "    default {\n";
        print FILE "        pass none\n";
        print FILE "    }\n";
        print FILE "}\n";
        close FILE;

        if(-e "$dbdir/$besettings{'BE_NAME'}") {
            system("rm -f $dbdir/$besettings{'BE_NAME'}/*.db");
        }
        system("/usr/bin/squidGuard -c $editdir/install.conf -C all");
        system("chmod a+w $dbdir/$besettings{'BE_NAME'}/*.db");

        &readblockcategories;
        &readcustomlists;

        &writeconfigfile;

        if (-d $editdir) { system("rm -rf $editdir"); }
        unless ($besettings{'NORESTART'} eq 'on') {
            &restartexit(1);
        }
    }
    else {
        $errormessage .= "$Lang::tr{'errmsg blacklist empty'}<br />";
    }
}

if (($filtersettings{'ACTION'} eq $Lang::tr{'save'}) && ($filtersettings{'MODE'} eq 'blacklist update')) {
    if (($filtersettings{'UPDATE_SOURCE'} eq 'custom') && ($filtersettings{'CUSTOM_UPDATE_URL'} eq '')) {
        $errormessage .= "$Lang::tr{'custom blacklist url required'}<br />";
    }
    else {
        my %updateConf = ();
        $updateConf{'ENABLE_AUTOUPDATE'} = $filtersettings{'ENABLE_AUTOUPDATE'};
        $updateConf{'CHECKUPDATES'} = $filtersettings{'CHECKUPDATES'};
        $updateConf{'UPDATE_SOURCE'} = $filtersettings{'UPDATE_SOURCE'};
        $updateConf{'CUSTOM_UPDATE_URL'} = $filtersettings{'CUSTOM_UPDATE_URL'};

        &General::writehash("$updconffile", \%updateConf);
    }
}

if ($filtersettings{'ACTION'} eq $Lang::tr{'instant update'}) {
    if ($filtersettings{'UPDATE_SOURCE'} eq 'custom' && $filtersettings{'CUSTOM_UPDATE_URL'} eq '') {
        $errormessage .= "$Lang::tr{'custom blacklist url required'}<br />";
    }
    else {
        # lockfile will trigger display of box with update message
        `/usr/local/bin/blacklistupdate.pl --force < /dev/null > /dev/null &`;
        sleep(1);
    }
}

if (-e "/var/ofw/proxy/filtersettings") {
    &General::readhash("/var/ofw/proxy/filtersettings", \%filtersettings);
}

&readcustomlists;

ERROR:

if ($errormessage) { $filtersettings{'VALID'} = 'no'; }

$checked{'ENABLED'}{'off'}                                          = '';
$checked{'ENABLED'}{'on'}                                           = '';
$checked{'ENABLED'}{$filtersettings{'ENABLED'}}     = "checked='checked'";
$checked{'ENABLE_CUSTOM_BLACKLIST'}{'off'}                                          = '';
$checked{'ENABLE_CUSTOM_BLACKLIST'}{'on'}                                           = '';
$checked{'ENABLE_CUSTOM_BLACKLIST'}{$filtersettings{'ENABLE_CUSTOM_BLACKLIST'}}     = "checked='checked'";
$checked{'ENABLE_CUSTOM_WHITELIST'}{'off'}                                          = '';
$checked{'ENABLE_CUSTOM_WHITELIST'}{'on'}                                           = '';
$checked{'ENABLE_CUSTOM_WHITELIST'}{$filtersettings{'ENABLE_CUSTOM_WHITELIST'}}     = "checked='checked'";
$checked{'ENABLE_CUSTOM_EXPRESSIONS'}{'off'}                                        = '';
$checked{'ENABLE_CUSTOM_EXPRESSIONS'}{'on'}                                         = '';
$checked{'ENABLE_CUSTOM_EXPRESSIONS'}{$filtersettings{'ENABLE_CUSTOM_EXPRESSIONS'}} = "checked='checked'";
$checked{'BLOCK_EXECUTABLES'}{'off'}                                                = '';
$checked{'BLOCK_EXECUTABLES'}{'on'}                                                 = '';
$checked{'BLOCK_EXECUTABLES'}{$filtersettings{'BLOCK_EXECUTABLES'}}                 = "checked='checked'";
$checked{'BLOCK_AUDIO-VIDEO'}{'off'}                                                = '';
$checked{'BLOCK_AUDIO-VIDEO'}{'on'}                                                 = '';
$checked{'BLOCK_AUDIO-VIDEO'}{$filtersettings{'BLOCK_AUDIO-VIDEO'}}                 = "checked='checked'";
$checked{'BLOCK_ARCHIVES'}{'off'}                                                   = '';
$checked{'BLOCK_ARCHIVES'}{'on'}                                                    = '';
$checked{'BLOCK_ARCHIVES'}{$filtersettings{'BLOCK_ARCHIVES'}}                       = "checked='checked'";
$checked{'ENABLE_REWRITE'}{'off'}                                                   = '';
$checked{'ENABLE_REWRITE'}{'on'}                                                    = '';
$checked{'ENABLE_REWRITE'}{$filtersettings{'ENABLE_REWRITE'}}                       = "checked='checked'";
$checked{'SHOW_CATEGORY'}{'off'}                                                    = '';
$checked{'SHOW_CATEGORY'}{'on'}                                                     = '';
$checked{'SHOW_CATEGORY'}{$filtersettings{'SHOW_CATEGORY'}}                         = "checked='checked'";
$checked{'SHOW_URL'}{'off'}                                                         = '';
$checked{'SHOW_URL'}{'on'}                                                          = '';
$checked{'SHOW_URL'}{$filtersettings{'SHOW_URL'}}                                   = "checked='checked'";
$checked{'SHOW_IP'}{'off'}                                                          = '';
$checked{'SHOW_IP'}{'on'}                                                           = '';
$checked{'SHOW_IP'}{$filtersettings{'SHOW_IP'}}                                     = "checked='checked'";
$checked{'ENABLE_DNSERROR'}{'off'}                                                  = '';
$checked{'ENABLE_DNSERROR'}{'on'}                                                   = '';
$checked{'ENABLE_DNSERROR'}{$filtersettings{'ENABLE_DNSERROR'}}                     = "checked='checked'";
$checked{'ENABLE_BG_IMAGE'}{'off'}                                                  = '';
$checked{'ENABLE_BG_IMAGE'}{'on'}                                                   = '';
$checked{'ENABLE_BG_IMAGE'}{$filtersettings{'ENABLE_BG_IMAGE'}}                     = "checked='checked'";
$checked{'ENABLE_EXPR_LISTS'}{'off'}                                                = '';
$checked{'ENABLE_EXPR_LISTS'}{'on'}                                                 = '';
$checked{'ENABLE_EXPR_LISTS'}{$filtersettings{'ENABLE_EXPR_LISTS'}}                 = "checked='checked'";
$checked{'BLOCK_IP_ADDR'}{'off'}                                                    = '';
$checked{'BLOCK_IP_ADDR'}{'on'}                                                     = '';
$checked{'BLOCK_IP_ADDR'}{$filtersettings{'BLOCK_IP_ADDR'}}                         = "checked='checked'";
$checked{'BLOCK_ALL'}{'off'}                                                        = '';
$checked{'BLOCK_ALL'}{'on'}                                                         = '';
$checked{'BLOCK_ALL'}{$filtersettings{'BLOCK_ALL'}}                                 = "checked='checked'";
$checked{'ENABLE_EMPTY_ADS'}{'off'}                                                 = '';
$checked{'ENABLE_EMPTY_ADS'}{'on'}                                                  = '';
$checked{'ENABLE_EMPTY_ADS'}{$filtersettings{'ENABLE_EMPTY_ADS'}}                   = "checked='checked'";
$checked{'ENABLE_GLOBAL_WHITELIST'}{'off'}                                          = '';
$checked{'ENABLE_GLOBAL_WHITELIST'}{'on'}                                           = '';
$checked{'ENABLE_GLOBAL_WHITELIST'}{$filtersettings{'ENABLE_GLOBAL_WHITELIST'}}     = "checked='checked'";
$checked{'ENABLE_SAFESEARCH'}{'off'}                                                = '';
$checked{'ENABLE_SAFESEARCH'}{'on'}                                                 = '';
$checked{'ENABLE_SAFESEARCH'}{$filtersettings{'ENABLE_SAFESEARCH'}}                 = "checked='checked'";
$checked{'ENABLE_LOG'}{'off'}                                                       = '';
$checked{'ENABLE_LOG'}{'on'}                                                        = '';
$checked{'ENABLE_LOG'}{$filtersettings{'ENABLE_LOG'}}                               = "checked='checked'";
$checked{'ENABLE_USERNAME_LOG'}{'off'}                                              = '';
$checked{'ENABLE_USERNAME_LOG'}{'on'}                                               = '';
$checked{'ENABLE_USERNAME_LOG'}{$filtersettings{'ENABLE_USERNAME_LOG'}}             = "checked='checked'";
$checked{'ENABLE_CATEGORY_LOG'}{'off'}                                              = '';
$checked{'ENABLE_CATEGORY_LOG'}{'on'}                                               = '';
$checked{'ENABLE_CATEGORY_LOG'}{$filtersettings{'ENABLE_CATEGORY_LOG'}}             = "checked='checked'";


$selected{'ACCESS'}{'block'} = '';
$selected{'ACCESS'}{'allow'} = '';
$selected{'ACCESS'}{$tcsettings{'ACCESS'}} = "selected='selected'";

$checked{'ENABLERULE'}{'off'}                     = '';
$checked{'ENABLERULE'}{'on'}                      = '';
if(defined($tcsettings{'ENABLERULE'})) {
    $checked{'ENABLERULE'}{$tcsettings{'ENABLERULE'}} = "checked='checked'";
}
else {
    $checked{'ENABLERULE'}{'off'} = "checked='checked'";
}
$checked{'MON'}{'off'}                            = '';
$checked{'MON'}{'on'}                             = '';
$checked{'MON'}{$tcsettings{'MON'}}               = "checked='checked'";
$checked{'TUE'}{'off'}                            = '';
$checked{'TUE'}{'on'}                             = '';
$checked{'TUE'}{$tcsettings{'TUE'}}               = "checked='checked'";
$checked{'WED'}{'off'}                            = '';
$checked{'WED'}{'on'}                             = '';
$checked{'WED'}{$tcsettings{'WED'}}               = "checked='checked'";
$checked{'THU'}{'off'}                            = '';
$checked{'THU'}{'on'}                             = '';
$checked{'THU'}{$tcsettings{'THU'}}               = "checked='checked'";
$checked{'FRI'}{'off'}                            = '';
$checked{'FRI'}{'on'}                             = '';
$checked{'FRI'}{$tcsettings{'FRI'}}               = "checked='checked'";
$checked{'SAT'}{'off'}                            = '';
$checked{'SAT'}{'on'}                             = '';
$checked{'SAT'}{$tcsettings{'SAT'}}               = "checked='checked'";
$checked{'SUN'}{'off'}                            = '';
$checked{'SUN'}{'on'}                             = '';
$checked{'SUN'}{$tcsettings{'SUN'}}               = "checked='checked'";


$checked{'ENABLEQUOTA'}{'off'}                      = '';
$checked{'ENABLEQUOTA'}{'on'}                       = '';
$checked{'ENABLEQUOTA'}{$uqsettings{'ENABLEQUOTA'}} = "checked='checked'";

# In case proxy is still restarting, show box and refresh
if (! system("/bin/ps ax | /bin/grep -q [r]estartsquid") ) {
    &restartexit(0);
}

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'urlfilter configuration'}, 1, '');

&Header::openbigbox('100%', 'left', '', $errormessage);

###############
# DEBUG DEBUG
if ($debugFormparams == 1) {
    &Header::openbox('100%', 'left', 'DEBUG');
    my $debugCount = 0;
    foreach my $line (sort keys %filtersettings) {
        print "$line = $filtersettings{$line}<br />\n";
        $debugCount++;
    }
    print "&nbsp;Count: $debugCount\n";
    &Header::closebox();
}

# DEBUG DEBUG
###############

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();
}
elsif (($tcsettings{'CHANGED'} eq 'yes') || ($uqsettings{'CHANGED'} eq 'yes')) {
    &writeconfigfile;
    print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";
    &Header::openbox('100%', 'left', "$Lang::tr{'urlfilter restart notification'}:");
    print "<p class='base'>$Lang::tr{'urlfilter restart message'}</p>\n";
    if ($uqsettings{'MODE'} eq 'USERQUOTA') {
        print "<p class='base'>$Lang::tr{'quota restart message'}</p>\n";
    }
    print "<p><input type='submit' name='ACTION' value='$Lang::tr{'urlfilter restart'}' /></p>";
    if ($tcsettings{'MODE'} eq 'TIMECONSTRAINT') {
        print "<input type='hidden' name='MODE' value='TIMECONSTRAINT' />";
    }
    if ($uqsettings{'MODE'} eq 'USERQUOTA') {
        print "<input type='hidden' name='MODE' value='USERQUOTA' />";
    }
    &Header::closebox();
    print "</form>\n";
}

if (-e "${dbdir}/.lock") {
    # Blacklist update in progress. Show box and exit.
    &Header::openbox('100%', 'left', "$Lang::tr{'information messages'}:", 'warning');
    print "<font class='base'>$Lang::tr{'blacklist upload information'}&nbsp;</font>\n";
    &Header::closebox();
    &Header::closebigbox();
    &Header::closepage();

    exit 0;
}

if ($updatemessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'blacklist update results'}:", 'warning');
    print "<font class='base'>${updatemessage}&nbsp;</font>\n";
    &Header::closebox();
}

if ($restoremessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'restore results'}:", 'warning');
    print "<font class='base'>${restoremessage}&nbsp;</font>\n";
    &Header::closebox();
}

if ((!$tcsettings{'TCMODE'}) && (!$uqsettings{'UQMODE'}) && (!$besettings{'BEMODE'})) {

    #==========================================================
    #
    # Section: Main Configuration
    #
    #==========================================================

    print "<form method='post' action='$ENV{'SCRIPT_NAME'}' enctype='multipart/form-data'>\n";

    &Header::openbox('100%', 'left', "$Lang::tr{'settings'}:");
    my $sactive = &General::isrunning('squidguard', 'nosize');
    my $blacklistage = &General::ageupdate('blacklist.last');

    print <<END
<table width='100%'>
<tr>
    <td>$Lang::tr{'url filter'}:</td>
    $sactive
    <td>&nbsp;</td>
    <td>&nbsp;</td>
END
    ;
    if ($blacklistage != -1) {
        print "</tr><tr><td colspan='4'>$Lang::tr{'blacklist is old1'} <b>$blacklistage</b> $Lang::tr{'updates is old3'}</td>";
    }
    print <<END
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td colspan='4' class='base'><b>$Lang::tr{'common settings'}</b></td>
</tr><tr>
    <td width='25%'>$Lang::tr{'enabled'}:</td>
    <td width='25%'><input type='checkbox' name='ENABLED' $checked{'ENABLED'}{'on'} /></td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr><tr>
    <td class='base'>$Lang::tr{'log enabled'}:</td>
    <td><input type='checkbox' name='ENABLE_LOG' $checked{'ENABLE_LOG'}{'on'} /></td>
    <td class='base'>$Lang::tr{'split log by categories'}:</td>
    <td><input type='checkbox' name='ENABLE_CATEGORY_LOG' $checked{'ENABLE_CATEGORY_LOG'}{'on'} /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'log username'}:</td>
    <td><input type='checkbox' name='ENABLE_USERNAME_LOG' $checked{'ENABLE_USERNAME_LOG'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr>
<tr>
    <td colspan='4'><b>$Lang::tr{'block categories'}</b></td>
</tr>
</table>
<table width='100%'>
END
    ;

    if (@categories == 0) {
        print <<END
<tr>
    <td><i>$Lang::tr{'no categories'}</i></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
END
        ;
    }
    else {

        my $count = @categories;

        my $quaterCount = 0;

        # if count is a multiple of four its easy, if it is not a multiple we have to tricks a bit
        if($count % 4 == 0) {
            $quaterCount = $count / 4;
        }
        else {
            $quaterCount = ($count + 4 - ($count % 4) ) / 4;
        }

        for (my $row = 0; $row < $quaterCount; $row++) {
            print "<tr>\n";

            for (my $col = 0; $col <= 3; $col++) {
                my $id = ($quaterCount * $col) + $row;

                if(defined($categories[$id])) {
                    my $name = $categories[$id];
                    my $category = $filtergroups[$id];

                    my $checked = '';
                    if(defined($filtersettings{$category}) && $filtersettings{$category} eq 'on') {
                        $checked = "checked='checked'";
                    }
                    print "<td width='15%'>$name:<\/td>\n";
                    print "<td width='10%'><input type='checkbox' name='$category' $checked /></td>\n";
                }
                else
                {
                    print "<td width='25%' colspan='2'></td>\n";
                }
            }
            print "<\/tr>\n";
        }
    }
    print <<END
</table>
<table width='100%'>
<tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td width='25%'><b>$Lang::tr{'custom blacklist'}</b></td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr><tr>
    <td class='base'>$Lang::tr{'enabled'}:</td>
    <td><input type='checkbox' name='ENABLE_CUSTOM_BLACKLIST' $checked{'ENABLE_CUSTOM_BLACKLIST'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='2'>$Lang::tr{'blocked domains'}&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='2'>$Lang::tr{'blocked urls'}&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr><tr>
    <td colspan='2'><textarea name='CUSTOM_BLACK_DOMAINS' cols='32' rows='6' wrap='off'>
END
    ;

    if(defined($filtersettings{'CUSTOM_BLACK_DOMAINS'})) {
        print $filtersettings{'CUSTOM_BLACK_DOMAINS'};
    }

    print <<END
</textarea></td>
    <td colspan='2'><textarea name='CUSTOM_BLACK_URLS' cols='32' rows='6' wrap='off'>
END
    ;

    if (defined($filtersettings{'CUSTOM_BLACK_URLS'})) {
        print $filtersettings{'CUSTOM_BLACK_URLS'};
    }

    print <<END
</textarea></td>
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td><b>$Lang::tr{'custom whitelist'}</b></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td class='base'>$Lang::tr{'enabled'}:</td>
    <td><input type='checkbox' name='ENABLE_CUSTOM_WHITELIST' $checked{'ENABLE_CUSTOM_WHITELIST'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='2'>$Lang::tr{'allowed domains'}&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='2'>$Lang::tr{'allowed urls'}&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr><tr>
    <td colspan='2'><textarea name='CUSTOM_WHITE_DOMAINS' cols='32' rows='6' wrap='off'>
END
    ;

    if(defined($filtersettings{'CUSTOM_WHITE_DOMAINS'})) {
        print $filtersettings{'CUSTOM_WHITE_DOMAINS'};
    }

    print <<END
</textarea></td>
    <td colspan='2'><textarea name='CUSTOM_WHITE_URLS' cols='32' rows='6' wrap='off'>
END
    ;

    if (defined($filtersettings{'CUSTOM_WHITE_URLS'})) {
        print $filtersettings{'CUSTOM_WHITE_URLS'};
    }

    print <<END
</textarea></td>
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td colspan='4'><b>$Lang::tr{'custom expression list'}</b></td>
</tr><tr>
    <td class='base'>$Lang::tr{'enabled'}:</td>
    <td><input type='checkbox' name='ENABLE_CUSTOM_EXPRESSIONS' $checked{'ENABLE_CUSTOM_EXPRESSIONS'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>

<tr>
    <td colspan='4'>$Lang::tr{'blocked expressions'}&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr>
<tr>
    <td colspan='4'><textarea name='CUSTOM_EXPRESSIONS' cols='70' rows='3' wrap='off'>
END
    ;

    if (defined($filtersettings{'CUSTOM_EXPRESSIONS'})) {
        print $filtersettings{'CUSTOM_EXPRESSIONS'};
    }

    print <<END
</textarea></td>
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td colspan='4'><b>$Lang::tr{'file extension blocking'}</b></td>
</tr><tr>
    <td class='base'>$Lang::tr{'binary files'}:</td>
    <td><input type='checkbox' name='BLOCK_EXECUTABLES' $checked{'BLOCK_EXECUTABLES'}{'on'} /></td>
    <td class='base'>$Lang::tr{'multimedia'}:</td>
    <td><input type='checkbox' name='BLOCK_AUDIO-VIDEO' $checked{'BLOCK_AUDIO-VIDEO'}{'on'} /></td>
</tr><tr>
    <td>$Lang::tr{'compressed archive files'}:</td>
    <td><input type='checkbox' name='BLOCK_ARCHIVES' $checked{'BLOCK_ARCHIVES'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td colspan='2'><b>$Lang::tr{'network based access'}</b></td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td colspan='2'>$Lang::tr{'unrestricted ip clients'}&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='2'>$Lang::tr{'banned ip clients'}&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr><tr>
    <td colspan='2'><textarea name='UNFILTERED_CLIENTS' cols='32' rows='6' wrap='off'>
END
    ;

    # transform from pre1.8 client definitions
    $filtersettings{'UNFILTERED_CLIENTS'} =~ s/^\s+//g;
    $filtersettings{'UNFILTERED_CLIENTS'} =~ s/\s+$//g;
    $filtersettings{'UNFILTERED_CLIENTS'} =~ s/\s+-\s+/-/g;
    $filtersettings{'UNFILTERED_CLIENTS'} =~ s/\s+/ /g;

    @clients = split(/ /, $filtersettings{'UNFILTERED_CLIENTS'});
    undef $filtersettings{'UNFILTERED_CLIENTS'};
    foreach my $client (@clients) {
        $filtersettings{'UNFILTERED_CLIENTS'} .= "$client\n";
    }

    if (defined($filtersettings{'UNFILTERED_CLIENTS'})) {
        print $filtersettings{'UNFILTERED_CLIENTS'};
    }

    print <<END
</textarea></td>
    <td colspan='2'><textarea name='BANNED_CLIENTS' cols='32' rows='6' wrap='off'>
END
    ;

    # transform from pre1.8 client definitions
    $filtersettings{'BANNED_CLIENTS'} =~ s/^\s+//g;
    $filtersettings{'BANNED_CLIENTS'} =~ s/\s+$//g;
    $filtersettings{'BANNED_CLIENTS'} =~ s/\s+-\s+/-/g;
    $filtersettings{'BANNED_CLIENTS'} =~ s/\s+/ /g;

    @clients = split(/ /, $filtersettings{'BANNED_CLIENTS'});
    undef $filtersettings{'BANNED_CLIENTS'};
    foreach my $client (@clients) {
        $filtersettings{'BANNED_CLIENTS'} .= "$client\n";
    }

    if (defined($filtersettings{'BANNED_CLIENTS'})) {
        print $filtersettings{'BANNED_CLIENTS'};
    }

    print <<END
</textarea></td>
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td colspan='4'><b>$Lang::tr{'timebased access control'}</b></td>
</tr><tr>
    <td><input type='submit' name='ACTION' value='$Lang::tr{'set time constraints'}' /></td>
    <td><input type='submit' name='ACTION' value='$Lang::tr{'set user quota'}' /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td colspan='4'><b>$Lang::tr{'block page settings'}</b></td>
</tr><tr>
    <td class='base'>$Lang::tr{'show category on block page'}:</td>
    <td><input type='checkbox' name='SHOW_CATEGORY' $checked{'SHOW_CATEGORY'}{'on'} /></td>
    <td class='base' colspan='2'>$Lang::tr{'redirect to this url'}:&nbsp;<img src='/blob.gif' alt='*' /><br />
    <input type='text' name='REDIRECT_PAGE' value='$filtersettings{'REDIRECT_PAGE'}' size='40' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'show url on block page'}:</td>
    <td><input type='checkbox' name='SHOW_URL' $checked{'SHOW_URL'}{'on'} /></td>
    <td class='base' colspan='2'>$Lang::tr{'message line 1'}:&nbsp;<img src='/blob.gif' alt='*' /><br />
    <input type='text' name='MSG_TEXT_1' value='$filtersettings{'MSG_TEXT_1'}' size='40' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'show ip on block page'}:</td>
    <td><input type='checkbox' name='SHOW_IP' $checked{'SHOW_IP'}{'on'} /></td>
    <td class='base' colspan='2'>$Lang::tr{'message line 2'}:&nbsp;<img src='/blob.gif' alt='*' /><br />
    <input type='text' name='MSG_TEXT_2' value='$filtersettings{'MSG_TEXT_2'}' size='40' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'use dns error to block'}:</td>
    <td><input type='checkbox' name='ENABLE_DNSERROR' $checked{'ENABLE_DNSERROR'}{'on'} /></td>
    <td class='base' colspan='2'>$Lang::tr{'message line 3'}:&nbsp;<img src='/blob.gif' alt='*' /><br />
    <input type='text' name='MSG_TEXT_3' value='$filtersettings{'MSG_TEXT_3'}' size='40' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'enable background image'}:</td>
    <td><input type='checkbox' name='ENABLE_BG_IMAGE' $checked{'ENABLE_BG_IMAGE'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='4' class='base'><hr /></td>
</tr><tr>
    <td colspan='4'><b>$Lang::tr{'adv options'}</b></td>
</tr><tr>
    <td class='base'>$Lang::tr{'enable expression lists'}:</td>
    <td><input type='checkbox' name='ENABLE_EXPR_LISTS' $checked{'ENABLE_EXPR_LISTS'}{'on'} /></td>
    <td class='base'>$Lang::tr{'enable safesearch'}:</td>
    <td><input type='checkbox' name='ENABLE_SAFESEARCH' $checked{'ENABLE_SAFESEARCH'}{'on'} /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'block sites accessed by ip address'}:</td>
    <td><input type='checkbox' name='BLOCK_IP_ADDR' $checked{'BLOCK_IP_ADDR'}{'on'} /></td>
    <td class='base'>$Lang::tr{'block ads with empty window'}:</td>
    <td><input type='checkbox' name='ENABLE_EMPTY_ADS' $checked{'ENABLE_EMPTY_ADS'}{'on'} /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'block all urls not explicitly allowed'}:</td>
    <td><input type='checkbox' name='BLOCK_ALL' $checked{'BLOCK_ALL'}{'on'} /></td>
    <td class='base'>$Lang::tr{'allow custom whitelist for banned clients'}:</td>
    <td><input type='checkbox' name='ENABLE_GLOBAL_WHITELIST' $checked{'ENABLE_GLOBAL_WHITELIST'}{'on'} /></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment2buttons'><img src='/blob.gif' align='top' alt='*' />&nbsp;
    <font class='base'>$Lang::tr{'this field may be blank'}</font>
    </td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save and restart'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-urlfilter.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
    ;

    &Header::closebox();
    print "</form>\n";

    print "<form method='post' action='$ENV{'SCRIPT_NAME'}' enctype='multipart/form-data'>\n";
    &Header::openbox('100%', 'left', "$Lang::tr{'blacklist maintenance'}:");

    print <<END
<table width='100%'>
<tr>
    <td colspan='4' class='base'><b>$Lang::tr{'blacklist update'}</b>
END
;

    $updatesettings{'ENABLE_AUTOUPDATE'} = 'off';
    $updatesettings{'CHECKUPDATES'}      = 'off';
    $updatesettings{'CUSTOM_UPDATE_URL'} = '';

    if (-e "$updconffile") {
        &General::readhash("$updconffile", \%updatesettings);
    }

    $checked{'ENABLE_AUTOUPDATE'}{'off'}                                = '';
    $checked{'ENABLE_AUTOUPDATE'}{'on'}                                 = '';
    $checked{'ENABLE_AUTOUPDATE'}{$updatesettings{'ENABLE_AUTOUPDATE'}} = "checked='checked'";

    $checked{'CHECKUPDATES'}{'off'}                                = '';
    $checked{'CHECKUPDATES'}{'on'}                                 = '';
    $checked{'CHECKUPDATES'}{$updatesettings{'CHECKUPDATES'}} = "checked='checked'";

    print <<END
    </td>
<!--
</tr><tr>
    <td>$Lang::tr{'enable automatic update'}:</td>
    <td><input type='checkbox' name='ENABLE_AUTOUPDATE' $checked{'ENABLE_AUTOUPDATE'}{'on'} /></td>
    <td colspan='2'>&nbsp;</td>
-->
</tr><tr>
    <td width='25%' class='base'>$Lang::tr{'check for updates after connect'}:</td>
    <td width='25%' class='base'><input type='checkbox' name='CHECKUPDATES' $checked{'CHECKUPDATES'}{'on'} /></td>
    <td width='25%' class='base'>&nbsp;</td>
    <td width='25%' class='base'>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'blacklist source'}:</td>
    <td colspan='2'>
    <select name='UPDATE_SOURCE'>
END
    ;

    foreach (@source_urllist) {
        chomp;
        $source_name = substr($_, 0, rindex($_, ","));
        $source_url = substr($_, index($_, ",") + 1);
        my $selected = '';
        if (defined($updatesettings{'UPDATE_SOURCE'}) && $updatesettings{'UPDATE_SOURCE'} eq $source_url) {
            $selected = "selected='selected'";
        }
        print "\t<option value='$source_url' $selected>$source_name</option>\n";
    }

    my $selectedCustom = '';
    if (defined($updatesettings{'UPDATE_SOURCE'}) && $updatesettings{'UPDATE_SOURCE'} eq 'custom') {
        $selectedCustom = "selected='selected'";
    }

    print <<END
    <option value='custom' $selectedCustom>$Lang::tr{'custom blacklist url'}</option>
    </select>
    </td>
    <td>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'custom blacklist url'}:</td>
    <td colspan='3'><input type='text' name='CUSTOM_UPDATE_URL' value='$updatesettings{'CUSTOM_UPDATE_URL'}' size='40' /></td>
</tr>
</table>
<table width='100%'>
<tr>
    <td class='comment2buttons'>&nbsp;</td>
    <td class='button2buttons'>
END
    ;
    if (defined($updatesettings{'UPDATE_SOURCE'}) && $updatesettings{'UPDATE_SOURCE'} ne "") {
        print "<input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'instant update'}' />";
    }
    print <<END
    </td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /><input type='hidden' name='MODE' value='blacklist update' /></td>
    <td class='onlinehelp'>&nbsp;</td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td colspan='2'><b>$Lang::tr{'manually upload a blacklist'}</b></td>
</tr><tr>
    <td colspan='2'>$Lang::tr{'blacklist upload information'}</td>
</tr><tr>
    <td class='base'>$Lang::tr{'upload blacklist file'}:&nbsp;</td>
    <td><input type='file' name='UPDATEFILE' size='40' /><input type='submit' name='ACTION' value='$Lang::tr{'upload'}' /></td>
</tr>
</table>

<hr />
END
    ;

    print <<END

<table width='100%'>
<tr>
    <td class='base'><b>$Lang::tr{'blacklist editor'}</b></td>
</tr><tr>
    <td><input type='submit' name='ACTION' value='$Lang::tr{'blacklist editor'}' /></td>
</tr>
</table>
END
    ;

    &Header::closebox();
    print "</form>\n";
}
elsif ($tcsettings{'TCMODE'}) {

    #==========================================================
    #
    # Section: Set Time Constraints
    #
    #==========================================================

    print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

    $buttontext = $Lang::tr{'add'};
    if ($tcsettings{'ACTION'} eq $Lang::tr{'edit'}) {
        &Header::openbox('100%', 'left', $Lang::tr{'edit time constraint rule'} . ':');
        $buttontext = $Lang::tr{'update'};
    }
    else {
        &Header::openbox('100%', 'left', $Lang::tr{'add new time constraint rule'} . ':');
    }

    $selected{'DEFINITION'}{'within'}   = '';
    $selected{'DEFINITION'}{'outside'}   = '';
    $selected{'DEFINITION'}{$tcsettings{'DEFINITION'}}   = "selected='selected'";

    print <<END

<table width='100%'>
<tr>
	<td width='2%'>$Lang::tr{'definition'}</td>
	<td width='1%'>&nbsp;&nbsp;</td>
	<td width='2%' align='center'>$Lang::tr{'sunday short'}</td>
	<td width='2%' align='center'>$Lang::tr{'monday short'}</td>
	<td width='2%' align='center'>$Lang::tr{'tuesday short'}</td>
	<td width='2%' align='center'>$Lang::tr{'wednesday short'}</td>
	<td width='2%' align='center'>$Lang::tr{'thursday short'}</td>
	<td width='2%' align='center'>$Lang::tr{'friday short'}</td>
	<td width='2%' align='center'>$Lang::tr{'saturday short'}</td>
	<td width='1%'>&nbsp;&nbsp;</td>
	<td width='7%' colspan='3'>$Lang::tr{'from'}</td>
	<td width='1%'>&nbsp;</td>
	<td width='7%' colspan='3'>$Lang::tr{'to'}</td>
	<td>&nbsp;</td>
</tr>
<tr>
	<td class='base'>
	<select name='DEFINITION'>
        <option value='within' $selected{'DEFINITION'}{'within'}>$Lang::tr{'within'}</option>
        <option value='outside' $selected{'DEFINITION'}{'outside'}>$Lang::tr{'outside'}</option>
	</select>
	</td>
	<td>&nbsp;</td>
	<td class='base'><input type='checkbox' name='SUN' $checked{'SUN'}{'on'} /></td>
	<td class='base'><input type='checkbox' name='MON' $checked{'MON'}{'on'} /></td>
	<td class='base'><input type='checkbox' name='TUE' $checked{'TUE'}{'on'} /></td>
	<td class='base'><input type='checkbox' name='WED' $checked{'WED'}{'on'} /></td>
	<td class='base'><input type='checkbox' name='THU' $checked{'THU'}{'on'} /></td>
	<td class='base'><input type='checkbox' name='FRI' $checked{'FRI'}{'on'} /></td>
	<td class='base'><input type='checkbox' name='SAT' $checked{'SAT'}{'on'} /></td>
	<td>&nbsp;</td>
	<td class='base'>
	<select name='FROM_HOUR'>
END
;


    $selected{'FROM_HOUR'}{$tcsettings{'FROM_HOUR'}}     = "selected='selected'";
    $selected{'FROM_MINUTE'}{$tcsettings{'FROM_MINUTE'}} = "selected='selected'";
    $selected{'TO_HOUR'}{$tcsettings{'TO_HOUR'}}         = "selected='selected'";
    $selected{'TO_MINUTE'}{$tcsettings{'TO_MINUTE'}}     = "selected='selected'";

    for ($i = 0; $i <= 24; $i++) {
        my $hour = sprintf("%02s", $i);
        my $selected = '';
        if($hour eq $tcsettings{'FROM_HOUR'}) {
            $selected = "selected='selected'";
        }
        print "<option value='$hour' $selected>$hour</option>\n";
    }
    print <<END
	</select>
	</td>
	<td>:</td>
	<td class='base'>
	<select name='FROM_MINUTE'>
END
;

    for ($i = 0; $i <= 45; $i += 15) {
        my $minute = sprintf("%02s", $i);
        my $selected = '';
        if($minute eq $tcsettings{'FROM_MINUTE'}) {
            $selected = "selected='selected'";
        }
        print "<option value='$minute' $selected>$minute</option>\n";
    }
    print <<END
	</select>
	<td> - </td>
	<td class='base'>
	<select name='TO_HOUR'>
END
        ;
    for ($i = 0; $i <= 24; $i++) {
        my $hour = sprintf("%02s", $i);
        my $selected = '';
        if($hour eq $tcsettings{'TO_HOUR'}) {
            $selected = "selected='selected'";
        }
        print "<option value='$hour' $selected>$hour</option>\n";
    }
    print <<END
	</select>
	</td>
	<td>:</td>
	<td class='base'>
	<select name='TO_MINUTE'>
END
        ;
    for ($i = 0; $i <= 45; $i += 15) {
        my $minute = sprintf("%02s", $i);
        my $selected = '';
        if($minute eq $tcsettings{'TO_MINUTE'}) {
            $selected = "selected='selected'";
        }
        print "<option value='$minute' $selected>$minute</option>\n";
    }
    print <<END
	</select>
	</td>
	<td>&nbsp;</td>
</tr>
</table>

<br />

<table width='100%'>
	<tr>
		<td width='5%'>$Lang::tr{'source'}</td>
		<td width='1%'>&nbsp;&nbsp;</td>
		<td width='5%'>$Lang::tr{'destination'}&nbsp;<img src='/blob.gif' alt='*' /><img src='/blob.gif' alt='*' /></td>
		<td width='1%'>&nbsp;&nbsp;</td>
		<td width='5%'>$Lang::tr{'access'}</td>
		<td>&nbsp;</td>
	</tr>
	<tr>
        <td rowspan='2'><textarea name='SRC' cols='28' rows='5' wrap='off'>
END
        ;

    # transform from pre1.8 client definitions
    $tcsettings{'SRC'} =~ s/^\s+//g;
    $tcsettings{'SRC'} =~ s/\s+$//g;
    $tcsettings{'SRC'} =~ s/\s+-\s+/-/g;
    $tcsettings{'SRC'} =~ s/\s+/ /g;

    @clients = split(/ /, $tcsettings{'SRC'});
    undef $tcsettings{'SRC'};
    foreach (@clients) { $tcsettings{'SRC'} .= "$_\n"; }

    if(defined($tcsettings{'SRC'})) {
        print $tcsettings{'SRC'};
    }

    $selected{'DST'}{'any'} = '';
    $selected{'DST'}{'in-addr'} = '';
    $selected{'DST'}{'files'} = '';
    $selected{'DST'}{'custom-blocked'} = '';
    $selected{'DST'}{'custom-expressions'} = '';
    my @selectedcategories = split(/\|/, $tcsettings{'DST'});
    foreach (@selectedcategories) {
        $selected{'DST'}{$_} = "selected='selected'";
    }

    print <<END
</textarea></td>

		<td>&nbsp;</td>
		<td class='base' rowspan='2' valign='top'>
		<select name='DST' size='6' multiple>
            <option value='any' $selected{'DST'}{'any'}>$Lang::tr{'any'}</option>
            <option value='in-addr' $selected{'DST'}{'in-addr'}>in-addr</option>
END
;

    &readblockcategories;
    foreach my $category (@categories) {
        my $selected = '';
        if(defined($selected{'DST'}{$category})) {
            $selected = "selected='selected'";
        }
        print "<option value='$category' $selected>$category</option>\n";
    }

    print <<END
            <option value='files' $selected{'DST'}{'files'}>files</option>
            <option value='custom-blocked' $selected{'DST'}{'custom-blocked'}>custom-blocked</option>
            <option value='custom-expressions' $selected{'DST'}{'custom-expressions'}>custom-expressions</option>
		</select>
		</td>
		<td>&nbsp;</td>
		<td class='base' valign='top'>
		<select name='ACCESS'>
            <option value='block' $selected{'ACCESS'}{'block'}>$Lang::tr{'block'}</option>
            <option value='allow' $selected{'ACCESS'}{'allow'}>$Lang::tr{'allow'}</option>
		</select>
		</td>
		<td>&nbsp;</td>
	</tr>
	<tr>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
	</tr>
	<tr>
		<td>$Lang::tr{'remark'}&nbsp;<img src='/blob.gif' alt='*' /></td>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
	</tr>
	<tr>
		<td colspan='6'><input type='text' name='COMMENT' value='$tcsettings{'COMMENT'}' size='32' /></td>
	</tr>
</table>
<table width='100%'>
	<tr>
		<td width='5%' class='base'>$Lang::tr{'enabled'}:&nbsp;</td>
        <td><input type='checkbox' name='ENABLERULE' $checked{'ENABLERULE'}{'on'} /></td>
	</tr>
</table>

<table width='100%'>
<tr>
    <td class='comment2buttons'>
        <img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}
    </td>
    <td colspan='3'>&nbsp;</td>
</tr><tr>
    <td class='comment2buttons'>
        <img src='/blob.gif' alt='*' /><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'ctrl select multiple'}
    </td>
    <td class='button2buttons'>
        <input type='hidden' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' />
        <input type='hidden' class='commonbuttons' name='MODE' value='TIMECONSTRAINT' />
        <input type='submit' class='commonbuttons' name='SUBMIT' value='$buttontext' />
    </td>
    <td class='button2buttons'>
        <input type='reset' class='commonbuttons' name='ACTION' value='$Lang::tr{'reset'}' />
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-urlfilter.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/urlfilter.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
        ;

    if ($tcsettings{'ACTION'} eq $Lang::tr{'edit'}) {
        print "<input type='hidden' name='EDITING' value='$tcsettings{'ID'}' />\n";
    }
    else {
        print "<input type='hidden' name='EDITING' value='no' />\n";
    }

    &Header::closebox();
    print "</form>\n";

    &Header::openbox('100%', 'left', $Lang::tr{'current rules'});
    print <<END
<table width='100%'>
	<tr>
		<td width='25%' class='boldbase' align='center'><b>$Lang::tr{'definition'}</b></td>
		<td width='25%' class='boldbase' align='center'><b>$Lang::tr{'time space'}</b></td>
		<td width='25%' class='boldbase' align='center'><b>$Lang::tr{'source'}</b></td>
		<td width='25%' class='boldbase' align='center'><b>$Lang::tr{'destination'}</b></td>
		<td width='1%' class='boldbase' colspan='5' align='center'>&nbsp;</td>
	</tr>
END
        ;

    if ($tcsettings{'ACTION'} ne '' or $changed ne 'no') {
        open(FILE, $tcfile);
        @tclist = <FILE>;
        close(FILE);
    }

    $id = 0;
    foreach $line (@tclist) {
        $id++;
        chomp($line);
        @temp = split(/\,/, $line);

        $temp[16] = '' unless(defined($temp[16]));

        if ($tcsettings{'ACTION'} eq $Lang::tr{'edit'} && $tcsettings{'ID'} eq $id) {
            print "<tr class='selectcolour'>\n";
        }
        elsif ($id % 2) {
            print "<tr class='table1colour'>\n";
        }
        else {
            print "<tr class='table2colour'>\n";
        }

        if ($temp[0] eq 'within') {
            $temp[0] = $Lang::tr{'within'};
        }
        else {
            $temp[0] = $Lang::tr{'outside'};
        }

        if ($temp[13] eq 'any') {
            $temp[13] = $Lang::tr{'any'};
        }

        if ($temp[15] eq 'on') {
            $gif = 'on.gif';
            $toggle = 'off';
            $gdesc = $Lang::tr{'click to disable'};
        }
        else {
            $gif = 'off.gif';
            $toggle = 'on';
            $gdesc = $Lang::tr{'click to enable'};
        }

        if ($temp[14] eq 'block') {
            $led = 'led-red.gif';
            $ldesc = $Lang::tr{'block'};
        }
        else {
            $led = 'led-green.gif';
            $ldesc = $Lang::tr{'allow'};
        }

        undef $time;
        if ($temp[7] eq 'on') {
            $time .= $Lang::tr{'sunday very short'};
        }
        else {
            $time .= '=';
        }

        if ($temp[1] eq 'on') {
            $time .= $Lang::tr{'monday very short'};
        }
        else {
            $time .= '=';
        }

        if ($temp[2] eq 'on') {
            $time .= $Lang::tr{'tuesday very short'};
        }
        else {
            $time .= '=';
        }

        if ($temp[3] eq 'on') {
            $time .= $Lang::tr{'wednesday very short'};
        }
        else {
            $time .= '=';
        }

        if ($temp[4] eq 'on') {
            $time .= $Lang::tr{'thursday very short'};
        }
        else {
            $time .= '=';
        }

        if ($temp[5] eq 'on') {
            $time .= $Lang::tr{'friday very short'};
        }
        else {
            $time .= '=';
        }

        if ($temp[6] eq 'on') {
            $time .= $Lang::tr{'saturday very short'};
        }
        else {
            $time .= '=';
        }

        $time = $time . ' &nbsp; ' . $temp[8] . ':' . $temp[9] . ' to ' . $temp[10] . ':' . $temp[11];

        print <<END
		<td align='center'>$temp[0]</td>
		<td align='center' nowrap='nowrap'>$time</td>
		<td align='center'>$temp[12]</td>
		<td align='center'>$temp[13]</td>
		<td align='center'><img src='/images/$led' alt='$ldesc' /></td>

		<td align='center'>
		<form method='post' name='frma$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' title='$gdesc' alt='$gdesc' />
            <input type='hidden' name='MODE' value='TIMECONSTRAINT' />
            <input type='hidden' name='ID' value='$id' />
            <input type='hidden' name='ACTIVE' value='$toggle' />
            <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
		</form>
		</td>

		<td align='center'>
		<form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' title='$Lang::tr{'edit'}' alt='$Lang::tr{'edit'}' />
            <input type='hidden' name='MODE' value='TIMECONSTRAINT' />
            <input type='hidden' name='ID' value='$id' />
            <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
		</form>
		</td>

		<td align='center'>
		<form method='post' name='frmc$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='image' name='$Lang::tr{'copy rule'}' src='/images/copy.gif' title='$Lang::tr{'copy rule'}' alt='$Lang::tr{'copy rule'}' />
            <input type='hidden' name='MODE' value='TIMECONSTRAINT' />
            <input type='hidden' name='ID' value='$id' />
            <input type='hidden' name='ACTION' value='$Lang::tr{'copy rule'}' />
		</form>
		</td>

		<td align='center'>
		<form method='post' name='frmd$id' action='$ENV{'SCRIPT_NAME'}'>
		<input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' title='$Lang::tr{'remove'}' alt='$Lang::tr{'remove'}' />
		<input type='hidden' name='MODE' value='TIMECONSTRAINT' />
		<input type='hidden' name='ID' value='$id' />
		<input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
		</form>
		</td>

	</tr>
END
            ;
        if ($temp[16] ne "") {
            if ($tcsettings{'ACTION'} eq $Lang::tr{'edit'} && $tcsettings{'ID'} eq $id) {
                print "<tr class='selectcolour'>\n";
            }
            elsif ($id % 2) {
                print "<tr class='table1colour'>\n";
            }
            else {
                print "<tr class='table2colour'>\n";
            }
            print <<END
        <td align='center' colspan='4'>$temp[16]
        </td>
        <td align='center' colspan='5'>
        </td>
    </tr>
END
            ;
        }
    }

    print "</table>\n";

    # If the time constraint file contains entries, print entries and action icons
    if (!-z "$tcfile") {
        print <<END

<table>
	<tr>
		<td class='boldbase'>&nbsp; $Lang::tr{'legend'}:</td>
		<td align='right'>&nbsp;<img src='/images/led-green.gif' alt='$Lang::tr{'allow'}' /></td>
		<td class='base' align='left'>$Lang::tr{'allow'}</td>
		<td align='right'>&nbsp;<img src='/images/led-red.gif' alt='$Lang::tr{'block'}' /></td>
		<td class='base' align='left'>$Lang::tr{'block'}</td>
		<td align='right'>&nbsp;<img src='/images/on.gif' alt='$Lang::tr{'click to disable'}' /></td>
		<td class='base' align='left'>$Lang::tr{'click to disable'}</td>
		<td align='right'>&nbsp;<img src='/images/off.gif' alt='$Lang::tr{'click to enable'}' /></td>
		<td class='base' align='left'>$Lang::tr{'click to enable'}</td>
		<td align='right'>&nbsp;<img src='/images/edit.gif' alt='$Lang::tr{'edit'}' /></td>
		<td class='base' align='left'>$Lang::tr{'edit'}</td>
		<td align='right'>&nbsp;<img src='/images/copy.gif' alt='$Lang::tr{'copy rule'}' /></td>
		<td class='base' align='left'>$Lang::tr{'copy rule'}</td>
		<td align='right'>&nbsp;<img src='/images/delete.gif' alt='$Lang::tr{'remove'}' /></td>
		<td class='base' align='left'>$Lang::tr{'remove'}</td>
	</tr>
</table>
END
            ;
    }

    &Header::closebox();

}
elsif ($uqsettings{'UQMODE'}) {

    #==========================================================
    #
    # Section: Set User Quota
    #
    #==========================================================

    print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

    $buttontext = $Lang::tr{'add'};
    if ($uqsettings{'ACTION'} eq $Lang::tr{'edit'}) {
        &Header::openbox('100%', 'left', $Lang::tr{'edit user quota rule'} . ':');
        $buttontext = $Lang::tr{'update'};
    }
    else {
        &Header::openbox('100%', 'left', $Lang::tr{'add new user quota rule'} . ':');
    }
    print <<END

<table width='100%'>
<tr>
    <td width='25%'></td> <td width='25%'> </td><td width='25%'> </td><td width='25%'></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'time quota'}:</td>
    <td><input type='text' name='TIME_QUOTA' value='$uqsettings{'TIME_QUOTA'}' size='5' /></td>
    <td colspan='2' rowspan= '5' valign='top' class='base'>
        <table cellpadding='0' cellspacing='0'>
        <tr>
            <!-- intentionally left empty -->
        </tr><tr>
            <td>$Lang::tr{'assigned quota users'}:</td>
        </tr><tr>
            <!-- intentionally left empty -->
        </tr><tr>
            <!-- intentionally left empty -->
        </tr><tr>
            <td><textarea name='QUOTA_USERS' cols='32' rows='6' wrap='off'>
END
;

    if(defined($uqsettings{'QUOTA_USERS'})) {
        $uqsettings{'QUOTA_USERS'} =~ s/\|/\n/g;
        print $uqsettings{'QUOTA_USERS'};
    }

    $selected{'SPORADIC'}{'0'} = '';
    $selected{'SPORADIC'}{'300'} = '';
    $selected{'SPORADIC'}{'900'} = '';
    $selected{'SPORADIC'}{$uqsettings{'SPORADIC'}} = "selected='selected'";

    print <<END
</textarea></td>
        </tr>
        </table>
    </td>
</tr><tr>
    <td class='base'>$Lang::tr{'activity detection'}:</td>
    <td class='base'><select name='SPORADIC'>
            <option value='0'   $selected{'SPORADIC'}{'0'}>$Lang::tr{'disabled'}</option>
            <option value='300' $selected{'SPORADIC'}{'300'}>5 $Lang::tr{'minutes'}</option>
            <option value='900' $selected{'SPORADIC'}{'900'}>15 $Lang::tr{'minutes'}</option>
    </select></td>
</tr>
END
;

    $selected{'RENEWAL'}{'hourly'} = '';
    $selected{'RENEWAL'}{'daily'} = '';
    $selected{'RENEWAL'}{'weekly'} = '';
    $selected{'RENEWAL'}{$uqsettings{'RENEWAL'}} = "selected='selected'";

    print <<END
<tr>
    <td class='base'>$Lang::tr{'refresh'}:</td>
    <td class='base'><select name='RENEWAL'>
            <option value='hourly' $selected{'RENEWAL'}{'hourly'}>$Lang::tr{'hourly'}</option>
            <option value='daily'  $selected{'RENEWAL'}{'daily'}>$Lang::tr{'daily'}</option>
            <option value='weekly' $selected{'RENEWAL'}{'weekly'}>$Lang::tr{'weekly'}</option>
    </select></td>
</tr>
<tr>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'enabled'}:</td>
    <td class='base'><input type='checkbox' name='ENABLEQUOTA' $checked{'ENABLEQUOTA'}{'on'} /></td>
</tr>
</table>

<table width='100%'>
<!-- no blank fields visible, at present...
<tr>
    <td class='comment2buttons'>
        <img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}
    </td>
    <td colspan='3'>&nbsp;</td>
</tr>
  -->
<tr>
    <td class='comment2buttons'>
        &nbsp; <!-- no multiple categories to select, at present...
        <img src='/blob.gif' alt='*' /><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'ctrl select multiple'}
      -->
    </td>
    <td class='button2buttons'>
        <input type='hidden' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' />
        <input type='hidden' class='commonbuttons' name='MODE' value='USERQUOTA' />
        <input type='submit' class='commonbuttons' name='SUBMIT' value='$buttontext' />
    </td>
    <td class='button2buttons'>
        <input type='reset' class='commonbuttons' name='ACTION' value='$Lang::tr{'reset'}' />
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-urlfilter.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/urlfilter.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
        ;

    if ($uqsettings{'ACTION'} eq $Lang::tr{'edit'}) {
        print "<input type='hidden' name='EDITING' value='$uqsettings{'ID'}' />\n";
    }
    else {
        print "<input type='hidden' name='EDITING' value='no' />\n";
    }

    &Header::closebox();
    print "</form>\n";

    &Header::openbox('100%', 'left', $Lang::tr{'current rules'});
    print <<END
<table width='100%'>
	<tr>
		<td width='25%' class='boldbase' align='center'><b>$Lang::tr{'time quota'}</b></td>
		<td width='25%' class='boldbase' align='center'><b>$Lang::tr{'activity detection'}</b></td>
		<td width='25%' class='boldbase' align='center'><b>$Lang::tr{'refresh'}</b></td>
		<td class='boldbase' align='center'><b>$Lang::tr{'assigned users'}</b></td>
		<td width='1%' class='boldbase' colspan='4' align='center'>&nbsp;</td>
	</tr>
END
        ;

    if ($uqsettings{'ACTION'} ne '' or $changed ne 'no') {
        open(FILE, $uqfile);
        @uqlist = <FILE>;
        close(FILE);
    }

    $id = 0;
    foreach $line (@uqlist) {
        $id++;
        chomp($line);
        @temp = split(/\,/, $line);

        if ($uqsettings{'ACTION'} eq $Lang::tr{'edit'} && $uqsettings{'ID'} eq $id) {
            print "<tr class='selectcolour'>\n";
        }
        elsif ($id % 2) {
            print "<tr class='table1colour'>\n";
        }
        else {
            print "<tr class='table2colour'>\n";
        }

        if ($temp[4] eq 'on') {
            $gif = 'on.gif';
            $toggle = 'off';
            $gdesc = $Lang::tr{'click to disable'};
        }
        else {
            $gif = 'off.gif';
            $toggle = 'on';
            $gdesc = $Lang::tr{'click to enable'};
        }

        $temp[5] = $temp[1];

        if ($temp[1] eq '0') {
            $temp[5] = $Lang::tr{'disabled'}
        }
        else {
            $temp[5] = ($temp[5] / 60) . ' ' . $Lang::tr{'minutes'}
        }

        $_ = $temp[3];
        s/\|/, /g;
        s/%5c/\\/g;
        $temp[6] = $_;

        print <<END
		<td align='center'>$temp[0] $Lang::tr{'minutes'}</td>
		<td align='center'>$temp[5]</td>
		<td align='center'>$Lang::tr{$temp[2]}</td>
		<td align='center'>$temp[6]</td>

		<td align='center'>
		<form method='post' name='frma$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' title='$gdesc' alt='$gdesc' />
            <input type='hidden' name='MODE' value='USERQUOTA' />
            <input type='hidden' name='ID' value='$id' />
            <input type='hidden' name='ACTIVE' value='$toggle' />
            <input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
		</form>
		</td>

		<td align='center'>
		<form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' title='$Lang::tr{'edit'}' alt='$Lang::tr{'edit'}' />
            <input type='hidden' name='MODE' value='USERQUOTA' />
            <input type='hidden' name='ID' value='$id' />
            <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
		</form>
		</td>

		<td align='center'>
		<form method='post' name='frmc$id' action='$ENV{'SCRIPT_NAME'}'>
            <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' title='$Lang::tr{'remove'}' alt='$Lang::tr{'remove'}' />
            <input type='hidden' name='MODE' value='USERQUOTA' />
            <input type='hidden' name='ID' value='$id' />
            <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
		</form>
		</td>

	</tr>
END
            ;
    }

    print "</table>\n";

    # If the user quota file contains entries, print entries and action icons
    if (!-z "$uqfile") {
        print <<END

<table>
	<tr>
		<td class='boldbase'>&nbsp; <b>$Lang::tr{'legend'}:</b></td>
		<td>&nbsp; <img src='/images/on.gif' alt='$Lang::tr{'click to disable'}' /></td>
		<td class='base'>$Lang::tr{'click to disable'}</td>
		<td>&nbsp; &nbsp; <img src='/images/off.gif' alt='$Lang::tr{'click to enable'}' /></td>
		<td class='base'>$Lang::tr{'click to enable'}</td>
		<td>&nbsp; &nbsp; <img src='/images/edit.gif' alt='$Lang::tr{'edit'}' /></td>
		<td class='base'>$Lang::tr{'edit'}</td>
		<td>&nbsp; &nbsp; <img src='/images/delete.gif' alt='$Lang::tr{'remove'}' /></td>
		<td class='base'>$Lang::tr{'remove'}</td>
	</tr>
</table>
END
            ;
    }

    &Header::closebox();

}
else {

    #==========================================================
    #
    # Section: Blacklist editor
    #
    #==========================================================

    print "<form method='post' action='$ENV{'SCRIPT_NAME'}' enctype='multipart/form-data'>\n";

    &Header::openbox('100%', 'left', "$Lang::tr{'blacklist editor'}:");

    print <<END

<table width='100%'>
<tr>
	<td width='25%'></td> <td width='20%'> </td><td width='25%'> </td><td width='30%'></td>
</tr>
<tr>
       	<td class='base'><b>$Lang::tr{'blacklist name'}</b></td>
</tr>
<tr>
       	<td class='base'>$Lang::tr{'blacklist category name'}:</td>
	<td><input type='text' name='BE_NAME' value='$besettings{'BE_NAME'}' size='12' /></td>
</tr>
</table>
<hr size='1'>
<table width='100%'>
<tr>
	<td width='25%'></td> <td width='20%'> </td><td width='25%'> </td><td width='20%'></td>
</tr>
<tr>
       	<td class='base' colspan='4'><b>$Lang::tr{'edit domains urls expressions'}</b></td>
</tr>
<tr>
	<td colspan='2'>$Lang::tr{'domains'}</td>
	<td colspan='2'>$Lang::tr{'urls'}</td>
</tr>
<tr>
	<td colspan='2'><textarea name='BE_DOMAINS' cols='38' rows='10' wrap='off'>
END
        ;

    if(defined($besettings{'BE_DOMAINS'})) {
        print $besettings{'BE_DOMAINS'};
    }
    print <<END
</textarea></td>
	<td colspan='2'><textarea name='BE_URLS' cols='38' rows='10' wrap='off'>
END
        ;

    if(defined($besettings{'BE_URLS'})) {
        print $besettings{'BE_URLS'};
    }

    print <<END
</textarea></td>
</tr>
<tr>
	<td colspan='4'>$Lang::tr{'expressions'}</td>
</tr>
<tr>
	<td colspan='4'><textarea name='BE_EXPRESSIONS' cols='80' rows='3' wrap='off'>
END
        ;

    if(defined($besettings{'BE_EXPRESSIONS'})) {
        print $besettings{'BE_EXPRESSIONS'};
    }

    print <<END
</textarea></td>
</tr>
</table>
<hr size='1'>
<table width='100%'>
<tr>
       	<td class='base' colspan='4'><b>$Lang::tr{'load blacklist'}</b></td>
</tr>
<tr>
       	<td width='25%' class='base'>$Lang::tr{'select blacklist'}:</td>
	<td width='20%' class='base'>
	<select name='BE_BLACKLIST'>
END
;

    &readblockcategories;
    foreach my $category (@categories) {
        my $selected = '';
        if($category eq $besettings{'BE_BLACKLIST'}) {
            $selected = "selected='selected'";
        }
        print "<option value='$category' $selected>$category</option>\n";
    }

    print <<END
	</select>
	</td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
<tr>
	<td colpsan='4'><input type='submit' name='ACTION' value='$Lang::tr{'load blacklist'}' /></td>
</tr>
</tr>
</table>
<hr size='1'>
<table width='100%'>
<tr>
       	<td class='base' colspan='4'><b>$Lang::tr{'import blacklist'}</b></td>
</tr>
<tr>
	<td colspan='4'>$Lang::tr{'blacklist import text'}:</td>
</tr>
<tr>
	<td nowrap><input type='file' name='IMPORTFILE' size='40' /> &nbsp; <input type='submit' name='ACTION' value='$Lang::tr{'import blacklist'}' /></td>
	<td><input type='hidden' name='MODE' value='BLACKLIST_EDITOR' /></td>
</tr>
</table>
<hr size='1'>
<table width='100%'>
<tr>
       	<td class='base' colspan='4'><b>$Lang::tr{'export blacklist'}</b></td>
</tr>
<tr>
	<td><input type='submit' name='ACTION' value='$Lang::tr{'export blacklist'}' /></td>
</tr>
</table>
<hr size='1'>
<table width='100%'>
<tr>
       	<td class='base' colspan='4'><b>$Lang::tr{'install blacklist'}</b></td>
</tr>
END
;

    $checked{'NORESTART'}{'off'}                                = '';
    $checked{'NORESTART'}{'on'}                                 = '';
    $checked{'NORESTART'}{$besettings{'NORESTART'}} = "checked='checked'";

    print <<END
<tr>
	<td width='25%' class='base'>$Lang::tr{'urlfilter dont restart'}:</td>
	<td width='25%' class='base'><input type='checkbox' name='NORESTART' $checked{'NORESTART'}{'on'} /></td>
	<td width='50%'>&nbsp;</td>
</tr>

<tr>
	<td><input type='submit' name='ACTION' value='$Lang::tr{'install blacklist'}' /></td>
</tr>
<tr>
       	<td class='base' colspan='2'><br />$Lang::tr{'install blacklist information'}</td>
</tr>
</table>
<hr>
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'><input type='reset' class='commonbuttons' name='ACTION' value='$Lang::tr{'reset'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-urlfilter.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/urlfilter.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
    ;

    &Header::closebox();
    print "</form>\n";

}

&Header::closebigbox();

&Header::closepage();

# -------------------------------------------------------------------

sub savesettings
{

    # transform to pre1.8 client definitions
    @clients = split(/\n/, $filtersettings{'UNFILTERED_CLIENTS'});
    $filtersettings{'UNFILTERED_CLIENTS'} = '';
    foreach (@clients) {
        s/^\s+//g;
        s/\s+$//g;
        s/\s+-\s+/-/g;
        s/\s+/ /g;
        s/\n//g;
        $filtersettings{'UNFILTERED_CLIENTS'} .= "$_ ";
    }
    $filtersettings{'UNFILTERED_CLIENTS'} =~ s/\s+$//;

    # transform to pre1.8 client definitions
    @clients = split(/\n/, $filtersettings{'BANNED_CLIENTS'});
    $filtersettings{'BANNED_CLIENTS'} = '';
    foreach (@clients) {
        s/^\s+//g;
        s/\s+$//g;
        s/\s+-\s+/-/g;
        s/\s+/ /g;
        s/\n//g;
        $filtersettings{'BANNED_CLIENTS'} .= "$_ ";
    }
    $filtersettings{'BANNED_CLIENTS'} =~ s/\s+$//;

    &writeconfigfile;

    delete $filtersettings{'CUSTOM_BLACK_DOMAINS'};
    delete $filtersettings{'CUSTOM_BLACK_URLS'};
    delete $filtersettings{'CUSTOM_WHITE_DOMAINS'};
    delete $filtersettings{'CUSTOM_WHITE_URLS'};
    delete $filtersettings{'CUSTOM_EXPRESSIONS'};
    delete $filtersettings{'UPDATEFILE'};

    &General::writehash("/var/ofw/proxy/filtersettings", \%filtersettings);

    # write redirector config
    my %redirectorconf=();
    $redirectorconf{'NAME'} = $Lang::tr{'url filter'};
    $redirectorconf{'ORDER'} = 10;
    $redirectorconf{'CMD'} = '/usr/bin/squidGuard';
    $redirectorconf{'OPTION_CHAIN'} = '-f';
    $redirectorconf{'ENABLED'} = $filtersettings{'ENABLED'};

    &General::writehash("/var/ofw/proxy/redirector/urlfilter", \%redirectorconf);

    system('/usr/local/bin/restartsquid --config');
}

# -------------------------------------------------------------------

sub readblockcategories
{
    undef(@categories);

    &getblockcategory($dbdir);

    foreach (@categories) {
        $_ = substr($_, length($dbdir) + 1);
    }

    @filtergroups = @categories;

    foreach (@filtergroups) {
        s/\//_SLASH_/g;
        s/ /_SPACE_/g;
        tr/a-z/A-Z/;
        $_ = "FILTER_" . $_;
    }
}

# -------------------------------------------------------------------

sub getblockcategory
{
    foreach $category (<$_[0]/*>) {
        if (-d $category) {
            if ((-e "$category/domains") || (-e "$category/urls")) {
                unless ($category =~ /\bcustom\b/) { push(@categories, $category); }
            }
            $category =~ s/ /\\ /g;
            &getblockcategory($category);
        }
    }
}

# -------------------------------------------------------------------

sub readcustomlists
{
    if (-e "$dbdir/custom/blocked/domains") {
        open(FILE, "$dbdir/custom/blocked/domains");
        delete $filtersettings{'CUSTOM_BLACK_DOMAINS'};
        while (<FILE>) { $filtersettings{'CUSTOM_BLACK_DOMAINS'} .= $_ }
        close(FILE);
    }

    if (-e "$dbdir/custom/blocked/urls") {
        open(FILE, "$dbdir/custom/blocked/urls");
        delete $filtersettings{'CUSTOM_BLACK_URLS'};
        while (<FILE>) { $filtersettings{'CUSTOM_BLACK_URLS'} .= $_ }
        close(FILE);
    }

    if (-e "$dbdir/custom/blocked/expressions") {
        open(FILE, "$dbdir/custom/blocked/expressions");
        delete $filtersettings{'CUSTOM_EXPRESSIONS'};
        while (<FILE>) { $filtersettings{'CUSTOM_EXPRESSIONS'} .= $_ }
        close(FILE);
    }

    if (-e "$dbdir/custom/allowed/domains") {
        open(FILE, "$dbdir/custom/allowed/domains");
        delete $filtersettings{'CUSTOM_WHITE_DOMAINS'};
        while (<FILE>) { $filtersettings{'CUSTOM_WHITE_DOMAINS'} .= $_ }
        close(FILE);
    }
    if (-e "$dbdir/custom/allowed/urls") {
        open(FILE, "$dbdir/custom/allowed/urls");
        delete $filtersettings{'CUSTOM_WHITE_URLS'};
        while (<FILE>) { $filtersettings{'CUSTOM_WHITE_URLS'} .= $_ }
        close(FILE);
    }
}

# -------------------------------------------------------------------

sub aggregatedconstraints
{
    my $aggregated;
    my @old;
    my @new;
    my @tmp1;
    my @tmp2;
    my $x;

    if (-e $tcfile) {
        open(TC, $tcfile);
        @old = <TC>;
        close(TC);

        while (@old > 0) {
            $aggregated = 0;
            $x          = shift(@old);
            chomp($x);
            @tmp1 = split(/\,/, $x);
            $tmp1[16] = '';
            foreach (@new) {
                @tmp2 = split(/\,/);
                if (($tmp1[15] eq 'on') && ($tmp2[15] eq 'on')) {
                    if (   ($tmp1[0] eq $tmp2[0])
                        && ($tmp1[12] eq $tmp2[12])
                        && ($tmp1[13] eq $tmp2[13])
                        && ($tmp1[14] eq $tmp2[14]))
                    {
                        $aggregated = 1;
                        $tmp2[16] .= "    weekly ";
                        if ($tmp1[1] eq 'on') { $tmp2[16] .= "m"; }
                        if ($tmp1[2] eq 'on') { $tmp2[16] .= "t"; }
                        if ($tmp1[3] eq 'on') { $tmp2[16] .= "w"; }
                        if ($tmp1[4] eq 'on') { $tmp2[16] .= "h"; }
                        if ($tmp1[5] eq 'on') { $tmp2[16] .= "f"; }
                        if ($tmp1[6] eq 'on') { $tmp2[16] .= "a"; }
                        if ($tmp1[7] eq 'on') { $tmp2[16] .= "s"; }
                        $tmp2[16] .= " $tmp1[8]:$tmp1[9]-$tmp1[10]:$tmp1[11]\n";
                        $_ = join(",", @tmp2);
                    }

                }
            }
            if (!$aggregated) {
                $tmp1[16] .= "    weekly ";
                if ($tmp1[1] eq 'on') { $tmp1[16] .= "m"; }
                if ($tmp1[2] eq 'on') { $tmp1[16] .= "t"; }
                if ($tmp1[3] eq 'on') { $tmp1[16] .= "w"; }
                if ($tmp1[4] eq 'on') { $tmp1[16] .= "h"; }
                if ($tmp1[5] eq 'on') { $tmp1[16] .= "f"; }
                if ($tmp1[6] eq 'on') { $tmp1[16] .= "a"; }
                if ($tmp1[7] eq 'on') { $tmp1[16] .= "s"; }
                $tmp1[16] .= " $tmp1[8]:$tmp1[9]-$tmp1[10]:$tmp1[11]\n";
                $x = join(",", @tmp1);
                push(@new, $x);
            }
        }
    }

    return @new;

}

# -------------------------------------------------------------------

sub setpermissions
{
    my $bldir = $_[0];

    foreach $category (<$bldir/*>) {
        if (-d $category) {
            system("chmod 755 $category &> /dev/null");
            foreach $blacklist (<$category/*>) {
                if (-f $blacklist) { system("chmod 644 $blacklist &> /dev/null"); }
                if (-d $blacklist) { system("chmod 755 $blacklist &> /dev/null"); }
            }
            system("chmod 666 $category/*.db &> /dev/null");
            &setpermissions($category);
        }
    }
}

# -------------------------------------------------------------------

sub writeconfigfile
{
    my $executables =
"\\.\(ade|adp|asx|bas|bat|chm|com|cmd|cpl|crt|dll|eml|exe|hiv|hlp|hta|inc|inf|ins|isp|jse|jtd|lnk|msc|msh|msi|msp|mst|nws|ocx|oft|ops|pcd|pif|plx|reg|scr|sct|sha|shb|shm|shs|sys|tlb|tsp|url|vbe|vbs|vxd|wsc|wsf|wsh\)\$";
    my $audiovideo = "\\.\(aiff|asf|avi|dif|divx|flv|mov|movie|mp3|mpe?g?|mpv2|ogg|ra?m|snd|qt|wav|wma|wmf|wmv\)\$";
    my $archives   = "\\.\(bin|bz2|cab|cdr|dmg|gz|hqx|rar|smi|sit|sea|tar|tgz|zip\)\$";

    my $ident = " anonymous";

    my $defaultrule = '';
    my $tcrule      = '';
    my $redirect    = '';
    my $qredirect   = '';

    my $idx;

    my @ec = ();
    my @tc = ();
    my @uq = ();

    if (!(-d "$dbdir/custom"))         { mkdir("$dbdir/custom") }
    if (!(-d "$dbdir/custom/blocked")) { mkdir("$dbdir/custom/blocked") }
    if (!(-d "$dbdir/custom/allowed")) { mkdir("$dbdir/custom/allowed") }

    open(FILE, ">/$dbdir/custom/blocked/domains");
    if(defined($filtersettings{'CUSTOM_BLACK_DOMAINS'})) {
        @temp = split(/\n/, $filtersettings{'CUSTOM_BLACK_DOMAINS'});
        foreach (@temp) {
            s/^\s+//g;
            s/\s+$//g;
            s/\n//g;
            unless ($_ eq '') { print FILE "$_\n"; }
        }
    }
    close(FILE);

    open(FILE, ">/$dbdir/custom/blocked/urls");
    if(defined($filtersettings{'CUSTOM_BLACK_URLS'})) {
        @temp = split(/\n/, $filtersettings{'CUSTOM_BLACK_URLS'});
        foreach (@temp) {
            s/^\s+//g;
            s/\s+$//g;
            s/\n//g;
            unless ($_ eq '') { print FILE "$_\n"; }
        }
    }
    close(FILE);

    open(FILE, ">/$dbdir/custom/blocked/expressions");
    if(defined($filtersettings{'CUSTOM_EXPRESSIONS'})) {
        @temp = split(/\n/, $filtersettings{'CUSTOM_EXPRESSIONS'});
        foreach (@temp) {
            s/^\s+//g;
            s/\s+$//g;
            s/\n//g;
            unless ($_ eq '') { print FILE "$_\n"; }
        }
    }
    close(FILE);

    open(FILE, ">/$dbdir/custom/blocked/files");
    if ($filtersettings{'BLOCK_EXECUTABLES'} eq 'on') { print FILE "$executables\n"; }
    if ($filtersettings{'BLOCK_AUDIO-VIDEO'} eq 'on') { print FILE "$audiovideo\n"; }
    if ($filtersettings{'BLOCK_ARCHIVES'}    eq 'on') { print FILE "$archives\n"; }
    close(FILE);

    open(FILE, ">/$dbdir/custom/allowed/domains");
    if(defined($filtersettings{'CUSTOM_WHITE_DOMAINS'})) {
        @temp = split(/\n/, $filtersettings{'CUSTOM_WHITE_DOMAINS'});
        foreach (@temp) {
            s/^\s+//g;
            s/\s+$//g;
            s/\n//g;
            unless ($_ eq '') { print FILE "$_\n"; }
        }
    }
    close(FILE);

    open(FILE, ">/$dbdir/custom/allowed/urls");
    if(defined($filtersettings{'CUSTOM_WHITE_URLS'})) {
        @temp = split(/\n/, $filtersettings{'CUSTOM_WHITE_URLS'});
        foreach (@temp) {
            s/^\s+//g;
            s/\s+$//g;
            s/\n//g;
            unless ($_ eq '') { print FILE "$_\n"; }
        }
    }
    close(FILE);

    if ($filtersettings{'ENABLE_USERNAME_LOG'} eq 'on') {
        $ident = "";
    }

    if ($filtersettings{'ENABLE_DNSERROR'} eq 'on') {
        $redirect = "302:http://0.0.0.0";
    }
    elsif ($filtersettings{'REDIRECT_PAGE'} eq '') {
        if ($filtersettings{'SHOW_CATEGORY'} eq 'on') {
            $redirect .= '&category=%t';
        }
        if ($filtersettings{'SHOW_URL'} eq 'on') {
            $redirect .= '&url=%u';
        }
        if ($filtersettings{'SHOW_IP'} eq 'on') {
            $redirect .= '&ip=%a';
        }
        $redirect =~ s/^&/?/;
        $redirect = "http:\/\/$netsettings{'GREEN_1_ADDRESS'}:$http_port\/cgi-bin\/redirect.cgi" . $redirect;
    }
    else {
        $redirect = $filtersettings{'REDIRECT_PAGE'};
    }

    undef $defaultrule;

    if ($filtersettings{'ENABLE_CUSTOM_WHITELIST'} eq 'on') {
        $defaultrule .= "custom-allowed ";
    }
    if ($filtersettings{'BLOCK_ALL'} eq 'on') {
        $defaultrule .= "none";
    }
    else {
        if ($filtersettings{'BLOCK_IP_ADDR'} eq 'on') {
            $defaultrule .= "!in-addr ";
        }
        for ($i = 0; $i < @filtergroups; $i++) {
            if (defined($filtersettings{$filtergroups[$i]}) && $filtersettings{$filtergroups[$i]} eq 'on') {
                $defaultrule .= "!$categories[$i] ";
            }
        }
        if ($filtersettings{'ENABLE_CUSTOM_BLACKLIST'} eq 'on') {
            $defaultrule .= "!custom-blocked ";
        }
        if ($filtersettings{'ENABLE_CUSTOM_EXPRESSIONS'} eq 'on') {
            $defaultrule .= "!custom-expressions ";
        }
        if (   ($filtersettings{'BLOCK_EXECUTABLES'} eq 'on')
            || ($filtersettings{'BLOCK_AUDIO-VIDEO'} eq 'on')
            || ($filtersettings{'BLOCK_ARCHIVES'} eq 'on'))
        {
            $defaultrule .= "!files ";
        }
        $defaultrule .= "any";
    }

    $defaultrule =~ s/\//_/g;

    open(FILE, ">/var/ofw/proxy/squidGuard.conf") or die "Unable to write squidGuard.conf file";
    flock(FILE, 2);

    print FILE <<END
# Do not modify '/var/ofw/proxy/squidGuard.conf' directly since any changes
# you make will be overwritten whenever you resave URL filter settings using the
# web interface!

logdir /var/log/squidGuard
syslog enable
dbhome $dbdir

END
    ;
    if ($filtersettings{'ENABLE_SAFESEARCH'} eq 'on') {

# These 2 alternatives for Google safe search ar currently under investigation
#    s@(^http[s]?://[0-9a-z]+\.google\\.[a-z]+[-/%.0-9a-z]*/.*(\\?|q=).*)\@\\1&safe=vss\@i
#    s@(.*\\Wgoogle\\.\\w+/)(.*)\@forcesafesearch.google.com/\2\@i

        print FILE <<END
rewrite rew-rule-safesearch {
    # rewrite safesearch
    s@(.*\\Wgoogle\\.\\w+/(webhp|search|imghp|images|grphp|groups|frghp|froogle)\\?)(.*)(\\bsafe=\\w+)(.*)\@\\1\\3safe=strict\\5\@i
    s@(.*\\Wgoogle\\.\\w+/(webhp|search|imghp|images|grphp|groups|frghp|froogle)\\?)(.*)\@\\1safe=strict\\\&\\3\@i
    s@(.*\\Wbing\\.\\w+/)(.*)(\\badlt=\\w+)(.*)\@\\1\\2\\4&adlt=strict\@i
    s@(.*\\Wsearch\\.yahoo\\.\\w+/search\\W)(.*)(\\bvm=\\w+)(.*)\@\\1\\2vm=r\\4\@i
    s@(.*\\Wsearch\\.yahoo\\.\\w+/search\\W.*)\@\\1\\\&vm=r\@i
    s@(.*\\Walltheweb\\.com/customize\\?)(.*)(\\bcopt_offensive=\\w+)(.*)\@\\1\\2copt_offensive=on\\4\@i
}

END
    }

    if (!($filtersettings{'UNFILTERED_CLIENTS'} eq '')) {
        print FILE "src unfiltered {\n";
        print FILE "    ip $filtersettings{'UNFILTERED_CLIENTS'}\n";
        print FILE "}\n\n";
    }
    if (!($filtersettings{'BANNED_CLIENTS'} eq '')) {
        print FILE "src banned {\n";
        print FILE "    ip $filtersettings{'BANNED_CLIENTS'}\n";
        if ($filtersettings{'ENABLE_LOG'} eq 'on') {
            if ($filtersettings{'ENABLE_CATEGORY_LOG'} eq 'on') {
                print FILE "    logfile       " . $ident . " banned.log\n";
            }
            else {
                print FILE "    logfile       " . $ident . " urlfilter.log\n";
            }
        }
        print FILE "}\n\n";
    }

    if (-e $uqfile) {
        open(UQ, $uqfile);
        @uqlist = <UQ>;
        close(UQ);

        if (@uqlist > 0) {
            $idx = 0;
            foreach (@uqlist) {
                chomp;
                @uq = split(/\,/);
                if ($uq[4] eq 'on') {
                    $idx++;
                    $uq[0] = $uq[0] * 60;
                    if ($uq[1] eq '0') {
                        if ($uq[2] eq 'hourly') { $uq[1] = 3600 }
                        if ($uq[2] eq 'daily')  { $uq[1] = 86400 }
                        if ($uq[2] eq 'weekly') { $uq[1] = 604800 }
                    }
                    $uq[3] =~ s/\|/ /g;
                    $uq[3] =~ s/\\/%5c/g;
                    print FILE "src quota-$idx {\n";
                    print FILE "    user $uq[3]\n";
                    print FILE "    userquota $uq[0] $uq[1] $uq[2]\n";
                    print FILE "}\n\n";
                }
            }

        }
    }

    @tclist = &aggregatedconstraints;

    if (@tclist > 0) {
        $idx = 0;
        foreach (@tclist) {
            chomp;
            @tc = split(/\,/);
            if ($tc[15] eq 'on') {
                $idx++;
                print FILE "src network-$idx {\n";
                @clients = split(/ /, $tc[12]);
                @temp    = split(/-/, $clients[0]);
                if ((&General::validipormask($temp[0])) || (&General::validipandmask($temp[0]))) {
                    print FILE "    ip $tc[12]\n";
                }
                else {
                    print FILE "    user";
                    @clients = split(/ /, $tc[12]);
                    foreach $line (@clients) {
                        $line =~ s/(^\w+)\\(\w+$)/$1%5c$2/;
                        print FILE " $line";
                    }
                    print FILE "\n";
                }
                if (($filtersettings{'ENABLE_LOG'} eq 'on') && ($tc[14] eq 'block') && ($tc[13] eq 'any')) {
                    if ($filtersettings{'ENABLE_CATEGORY_LOG'} eq 'on') {
                        print FILE "    logfile       " . $ident . " timeconst.log\n";
                    }
                    else {
                        print FILE "    logfile       " . $ident . " urlfilter.log\n";
                    }
                }
                print FILE "}\n\n";
            }
        }

        $idx = 0;
        foreach (@tclist) {
            chomp;
            @tc = split(/\,/);
            if ($tc[15] eq 'on') {
                $idx++;
                print FILE "time constraint-$idx {\n";
                print FILE "$tc[16]\n";
                print FILE "}\n\n";
            }
        }
    }

    foreach $category (@categories) {
        $blacklist = $category;
        $category =~ s/\//_/g;
        print FILE "dest $category {\n";
        if (-e "$dbdir/$blacklist/domains") {
            print FILE "    domainlist     $blacklist\/domains\n";
        }
        if (-e "$dbdir/$blacklist/urls") {
            print FILE "    urllist        $blacklist\/urls\n";
        }
        if ((-e "$dbdir/$blacklist/expressions") && ($filtersettings{'ENABLE_EXPR_LISTS'} eq 'on')) {
            print FILE "    expressionlist $blacklist\/expressions\n";
        }
        if ((($category eq 'ads') || ($category eq 'adv')) && ($filtersettings{'ENABLE_EMPTY_ADS'} eq 'on')) {
            print FILE "    redirect       http:\/\/$netsettings{'GREEN_1_ADDRESS'}:$http_port\/images/null.gif\n";
        }
        if ($filtersettings{'ENABLE_LOG'} eq 'on') {
            if ($filtersettings{'ENABLE_CATEGORY_LOG'} eq 'on') {
                print FILE "    logfile       $ident $category.log\n";
            }
            else {
                print FILE "    logfile       $ident urlfilter.log\n";
            }
        }
        print FILE "}\n\n";
        $category = $blacklist;
    }

    print FILE "dest files {\n";
    print FILE "    expressionlist custom\/blocked\/files\n";
    if ($filtersettings{'ENABLE_LOG'} eq 'on') {
        if ($filtersettings{'ENABLE_CATEGORY_LOG'} eq 'on') {
            print FILE "    logfile       $ident files.log\n";
        }
        else {
            print FILE "    logfile       $ident urlfilter.log\n";
        }
    }
    print FILE "}\n\n";

    print FILE "dest custom-allowed {\n";
    print FILE "    domainlist     custom\/allowed\/domains\n";
    print FILE "    urllist        custom\/allowed\/urls\n";
    print FILE "}\n\n";

    print FILE "dest custom-blocked {\n";
    print FILE "    domainlist     custom\/blocked\/domains\n";
    print FILE "    urllist        custom\/blocked\/urls\n";
    if ($filtersettings{'ENABLE_LOG'} eq 'on') {
        if ($filtersettings{'ENABLE_CATEGORY_LOG'} eq 'on') {
            print FILE "    logfile       $ident custom.log\n";
        }
        else {
            print FILE "    logfile       $ident urlfilter.log\n";
        }
    }
    print FILE "}\n\n";

    print FILE "dest custom-expressions {\n";
    print FILE "    expressionlist custom\/blocked\/expressions\n";
    if ($filtersettings{'ENABLE_LOG'} eq 'on') {
        if ($filtersettings{'ENABLE_CATEGORY_LOG'} eq 'on') {
            print FILE "    logfile       $ident custom.log\n";
        }
        else {
            print FILE "    logfile       $ident urlfilter.log\n";
        }
    }
    print FILE "}\n\n";

    print FILE "acl {\n";
    if (!($filtersettings{'UNFILTERED_CLIENTS'} eq '')) {
        print FILE "    unfiltered {\n";
        print FILE "        pass all\n";
        print FILE "    }\n\n";
    }
    if (!($filtersettings{'BANNED_CLIENTS'} eq '')) {
        print FILE "    banned {\n";
        print FILE "        pass ";
        if (   ($filtersettings{'ENABLE_CUSTOM_WHITELIST'} eq 'on')
            && ($filtersettings{'ENABLE_GLOBAL_WHITELIST'} eq 'on'))
        {
            print FILE "custom-allowed ";
        }
        print FILE "none\n";
        print FILE "    }\n\n";
    }

    if (-s $uqfile) {
        open(UQ, $uqfile);
        @uqlist = <UQ>;
        close(UQ);

        $idx = 0;
        foreach (@uqlist) {
            chomp;
            @uq = split(/\,/);
            if ($uq[4] eq 'on') {
                $idx++;
                $qredirect = $redirect;
                $qredirect =~ s/\%t/\%q\%20-\%20\%i/;
                print FILE "    quota-$idx {\n";
                print FILE "        pass ";
                if (   ($filtersettings{'ENABLE_CUSTOM_WHITELIST'} eq 'on')
                    && ($filtersettings{'ENABLE_GLOBAL_WHITELIST'} eq 'on'))
                {
                    print FILE "custom-allowed ";
                }
                print FILE "none\n";
                unless ($redirect eq $qredirect) { print FILE "        redirect $qredirect\n"; }
                print FILE "    }\n\n";
            }
        }
    }

    if (@tclist > 0) {
        $idx = 0;
        foreach (@tclist) {
            chomp;
            @tc = split(/\,/);
            @ec = split(/\|/, $tc[13]);
            foreach (@ec) { s/\//_/g; }
            if ($tc[15] eq 'on') {
                $idx++;
                print FILE "    network-$idx $tc[0] constraint-$idx {\n";
                print FILE "        pass ";

                if ($filtersettings{'BLOCK_ALL'} eq 'on') {
                    if ($tc[14] eq 'block') {
                        if ((@ec == 1) && ($ec[0] eq 'any')) {
                            if (   ($filtersettings{'ENABLE_CUSTOM_WHITELIST'} eq 'on')
                                && ($filtersettings{'ENABLE_GLOBAL_WHITELIST'} eq 'on'))
                            {
                                print FILE "custom-allowed ";
                            }
                            print FILE "none";
                        }
                        else {
                            print FILE $defaultrule;
                        }
                    }
                    else {
                        foreach (@ec) {
                            print FILE "$_ ";
                        }
                        print FILE $defaultrule unless ((@ec == 1) && ($ec[0] eq 'any'));
                    }
                }
                else {
                    if ($tc[14] eq 'block') {
                        $tcrule = $defaultrule;
                        if ($filtersettings{'ENABLE_CUSTOM_WHITELIST'} eq 'on') {
                            $tcrule =~ s/custom-allowed //;
                            print FILE "custom-allowed "
                                unless ((@ec == 1)
                                && ($ec[0] eq 'any')
                                && ($filtersettings{'ENABLE_GLOBAL_WHITELIST'} eq 'off'));
                        }
                        if ((@ec == 1) && ($ec[0] eq 'any')) {
                            print FILE "none";
                        }
                        else {
                            foreach (@ec) {
                                print FILE "!$_ " unless (index($defaultrule, "!" . $_ . " ") ge 0);
                            }
                        }
                        print FILE $tcrule unless ((@ec == 1) && ($ec[0] eq 'any'));
                    }
                    else {
                        $tcrule = $defaultrule;
                        if ((@ec == 1) && ($ec[0] eq 'any')) {
                            print FILE "any";
                        }
                        else {
                            foreach (@ec) {
                                $tcrule = "$_ " . $tcrule unless (index($defaultrule, "!" . $_ . " ") ge 0);
                                $tcrule =~ s/!$_ //;
                            }
                            print FILE $tcrule;
                        }
                    }
                }

                print FILE "\n";

                print FILE "    }\n\n";
            }
        }
    }

    print FILE "    default {\n";
    print FILE "        pass $defaultrule\n";
    if (($filtersettings{'ENABLE_LOG'} eq 'on') && ($filtersettings{'BLOCK_ALL'} eq 'on')) {
        if ($filtersettings{'ENABLE_CATEGORY_LOG'} eq 'on') {
            print FILE "        logfile" . $ident . " default.log\n";
        }
        else {
            print FILE "        logfile" . $ident . " urlfilter.log\n";
        }
    }
    if ($filtersettings{'ENABLE_SAFESEARCH'} eq 'on') {
        print FILE "        rewrite rew-rule-safesearch\n";
    }
    print FILE "        redirect $redirect\n";
    print FILE "    }\n";
    print FILE "}\n";

    close FILE;
}

# -------------------------------------------------------------------

sub resetTcSettings
{
    $tcsettings{'DEFINITION'}   = 'within';
    $tcsettings{'FROM_HOUR'}    = 0;
    $tcsettings{'FROM_MINUTE'}  = 0;
    $tcsettings{'TO_HOUR'}      = 24;
    $tcsettings{'TO_MINUTE'}    = 0;
    $tcsettings{'ACCESS'}       = 'block';
    $tcsettings{'MON'}          = 'off';
    $tcsettings{'TUE'}          = 'off';
    $tcsettings{'WED'}          = 'off';
    $tcsettings{'THU'}          = 'off';
    $tcsettings{'FRI'}          = 'off';
    $tcsettings{'SAT'}          = 'off';
    $tcsettings{'SUN'}          = 'off';
    $tcsettings{'SRC'}          = '';
    $tcsettings{'DST'}          = '';
    $tcsettings{'COMMENT'}      = '';
    $tcsettings{'ACTION'}       = '';
    $tcsettings{'MODE'}         = '';
    $tcsettings{'CHANGED'}      = 'no';
}

sub resetUqSettings
{
    $uqsettings{'TIME_QUOTA'}   = '';
    $uqsettings{'SPORADIC'}     = '0';
    $uqsettings{'RENEWAL'}      = 'hourly';
    $uqsettings{'ENABLEQUOTA'}  = 'off';
    $uqsettings{'QUOTA_USERS'}  = '';
    $uqsettings{'ACTION'}       = '';
    $uqsettings{'MODE'}         = '';
    $uqsettings{'CHANGED'}      = 'no';
}


sub restartexit
{
    my $restart = shift;

    system('/usr/local/bin/restartsquid --waitpid >/dev/null &') if ($restart);
    &Header::page_show($Lang::tr{'urlfilter configuration'}, 'warning', $Lang::tr{'web proxy will now restart'}, "<meta http-equiv='refresh' content='5; URL=/cgi-bin/urlfilter.cgi' />");
    exit 0;
}
