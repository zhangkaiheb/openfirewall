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
# (c) 2004-2007 marco.s - http://www.urlfilter.net
# (c) 2012-2014 The Openfirewall Team
#
# $Id: blacklistupdate.pl 7506 2014-04-29 13:56:19Z owes $
#

use strict;
use warnings;

require '/usr/lib/ofw/general-functions.pl';
use Fcntl qw(:flock);   # import LOCK_* constants

# Debug level:
#	0 - no print
#	1 - print
my $debugLevel = 0;

my $make_clean = 1;

my $target = '/var/ofw/proxy/download';
my $dbdir  = '/var/lib/squidguard/db';

my $sourceurlfile = '/var/ofw/proxy/blacklistupdate/blacklistupdate.urls';
my $updconffile = '/var/ofw/proxy/blacklistupdate/blacklistupdate.conf';

my %updatesettings;
$updatesettings{'ENABLED'} = 'off';
$updatesettings{'ENABLE_AUTOUPDATE'} = 'off';
$updatesettings{'CHECKUPDATES'} = 'off';
my %proxysettings;
$proxysettings{'UPSTREAM_PROXY'} = '';
$proxysettings{'UPSTREAM_USER'} = '';
$proxysettings{'UPSTREAM_PASSWORD'} = '';

my @categories;
my $blacklist;

my $exitcode = 1;
my $doUpdate = 0;
my $doUpdateForce = 0;
my $doSetPermissions = 0;

if (-e "$updconffile") {
    &General::readhash("$updconffile", \%updatesettings);
}
if (-e '/var/ofw/proxy/settings') {
    &General::readhash('/var/ofw/proxy/settings', \%proxysettings);
}

while (@ARGV) {
    my $argument = shift;

    print "arg: $argument\n" if ($debugLevel > 0);

    if ($argument eq '--force') {
        # force/instant update
        $doUpdateForce = 1;
    }
    elsif ($argument eq '--red') {
        # check for update after red connect when URL filter enabled
        if (($updatesettings{'ENABLED'} eq 'on') && ($updatesettings{'CHECKUPDATES'} eq 'on')) {
            $doUpdate = 1;
        }
    }
    elsif ($argument eq '--perm') {
        # set permissions on prebuild blacklist
        $doSetPermissions = 1;
    }
    elsif ($argument eq '-v') {
        # verbose
        $debugLevel++;
    }
    else {
        # If we are here, a parameter was given to us that we do not know about.

        # TODO: error handling ?
        # rm -rf /
        # something else ?
    }
} # while (@ARGV)


if ($doUpdate || $doUpdateForce) {

    if (-e '/var/ofw/red/active') {
        if ($debugLevel > 0) {
            print "Updating...\n";
            system("logger -t installpackage[urlfilter] \"URL filter blacklist - Updating...\"");
        }
        &updateblacklist();
    }
    else {
        if ($debugLevel > 0) {
            print "RED connection is down, exit.\n";
            system("logger -t installpackage[urlfilter] \"URL filter blacklist - RED connection is down, exit.\"");
        }

        # silently exit
        $exitcode = 0;
    }
}

if($doSetPermissions) {
    &setpermissions ($dbdir);
    $exitcode = 0;
}

exit $exitcode;


sub updateblacklist
{
    # ENABLE_AUTOUPDATE is never set in current .cgi
    #if (($updatesettings{'ENABLE_AUTOUPDATE'} ne 'on') && !$doUpdateForce) {
    #    if ($debugLevel > 0) {
    #        print "Update not enabled, exit.\n";
    #        system("logger -t installpackage[urlfilter] \"URL filter blacklist - Update not enabled, exit.\"");
    #    }
    #    return;
    #}

    my $blacklist_url = '';
    my $blacklist_src = '';

    my $proxy_login = '';
    my $source_url = '';
    my $source_name = '';
    my @source_urllist = ();
    my $seconds = time();

    unless (open(LOCKFILE, ">${dbdir}/.lock")) {
        die "Could not open lockfile";
    }
    unless (flock(LOCKFILE, LOCK_EX | LOCK_NB)) {
        die "Could not lock lockfile";
    }

    # If enough space available, download and prepare in /tmp (uses tmpfs)
    # to decrease time needed for update
    $target = '/tmp/blacklistu' if (&General::getavailabledisk('/tmp') > 128);
    my $tempdb = "$target/blacklists";

    if (-e "$sourceurlfile") {
        open(FILE, $sourceurlfile);
        @source_urllist = <FILE>;
        close(FILE);
    }

    if ($updatesettings{'UPDATE_SOURCE'} eq 'custom') {
        $blacklist_url = $updatesettings{'CUSTOM_UPDATE_URL'};
    }
    else {
        $blacklist_url = $updatesettings{'UPDATE_SOURCE'};

        foreach my $source (@source_urllist)
        {
            chomp $source;
            $source_name = substr($source, 0, rindex($source,","));
            $source_url = substr($source, index($source,",")+1);
            if ($blacklist_url eq $source_url) {
                $blacklist_src = $source_name;
            }
        }
    }

    if ($blacklist_src eq '') {
        $blacklist_src = "custom source URL";
    }

    $blacklist_url =~ s/\&/\\\&/;

    my $blacklist = substr($blacklist_url, rindex($blacklist_url,"/")+1);

    if (($blacklist =~ /\?/) || (!($blacklist =~ /\.t(ar\.)?gz$/))) {
        $blacklist = 'blacklist.tar.gz';
    }
    $blacklist = $target.'/'.$blacklist;

    unless ($blacklist_url eq '') {
        if ($debugLevel > 0) {
            print "Using $blacklist_src\n";
            system("logger -t installpackage[urlfilter] \"URL filter blacklist - Using $blacklist_src\"");
        }

        if (-d $target) {
            system("rm -rf $target");
        }
        system("mkdir $target");

        if (($proxysettings{'UPSTREAM_PROXY'}) && ($proxysettings{'UPSTREAM_USER'})) {
            $proxy_login = "--proxy-user=\"$proxysettings{'UPSTREAM_USER'}\"";
            if ($proxysettings{'UPSTREAM_PASSWORD'}) {
                $proxy_login .= " --proxy-password=\"$proxysettings{'UPSTREAM_PASSWORD'}\"";
            }
        }

        $ENV{'http_proxy'} = $proxysettings{'UPSTREAM_PROXY'};
        system("/usr/bin/wget $proxy_login -o $target/wget.log -O $blacklist $blacklist_url");
        $ENV{'http_proxy'} = '';

        if (-e $blacklist) {
            system("/bin/tar --no-same-owner -xzf $blacklist -C $target");

            if (-d "$target/BL") {
                system ("mv $target/BL $target/blacklists");
            }

            if (-d "$tempdb") {
                undef(@categories);

                &getblockcategory ($tempdb);

                foreach (@categories) {
                    $_ = substr($_, length($tempdb)+1);
                }

                open(FILE, ">$target/update.conf");
                flock FILE, 2;
                print FILE "logdir $target\n";
                print FILE "dbhome $tempdb\n\n";

                foreach my $category (@categories) {
                    my $category_name = $category;
                    $category_name =~ s/\//_/g;
                    print FILE "dest $category_name {\n";
                    if (-s "$tempdb/$category/domains") {
                        print FILE "    domainlist     $category\/domains\n";
                    }
                    if (-s "$tempdb/$category/urls") {
                        print FILE "    urllist        $category\/urls\n";
                    }
                    print FILE "}\n\n";
                }

                print FILE "acl {\n";
                print FILE "    default {\n";
                print FILE "        pass none\n";
                print FILE "    }\n";
                print FILE "}\n";
                close FILE;

                system("/usr/bin/squidGuard -d -c $target/update.conf -C all");

                # remove old blacklists (except custom lists)
                system("rm -rf `find $dbdir/* -maxdepth 0 | grep -v $dbdir/custom` ");
                system("cp -r $target/blacklists/* $dbdir");

                &setpermissions ($dbdir);

                &General::touchupdate('blacklist.last');

                system("/usr/local/bin/restartsquid");

                print "Update from $blacklist_src completed\n" if ($debugLevel > 0);
                my $elapsed = time() - $seconds;
                &General::log("installpackage[urlfilter]", "URL filter blacklist - Update from $blacklist_src completed in $elapsed seconds.");
                $exitcode = 0;
            }
            else {
                print "ERROR: Not a valid URL filter blacklist\n" if ($debugLevel > 0);

                system("logger -t installpackage[urlfilter] \"URL filter blacklist - ERROR: Not a valid URL filter blacklist\"");
            }
        }
        else {
            print "ERROR: Unable to retrieve blacklist from $blacklist_src\n" if ($debugLevel > 0);

            system("logger -t installpackage[urlfilter] \"URL filter blacklist - ERROR: Unable to retrieve blacklist from $blacklist_src\"");
        }

    }
    else {
        system("logger -t installpackage[urlfilter] \"URL filter blacklist - ERROR: No update source defined\"");
    }

    if ((-d $target) && ($make_clean)) {
        system("rm -rf $target");
    }
    
    close(LOCKFILE);
    unlink("${dbdir}/.lock");
}


# -------------------------------------------------------------------

sub getblockcategory
{
    foreach my $category (<$_[0]/*>)
    {
        if (-d $category)
        {
            if ((-s "$category/domains") || (-s "$category/urls"))
            {
                unless ($category =~ /\bcustom\b/) {
                    push(@categories, $category);
                }
            }
            &getblockcategory ($category);
        }
    }
}

# -------------------------------------------------------------------

sub setpermissions
{
    my $bldir = $_[0];

    system("chown -R nobody.nobody $bldir");

    foreach my $category (<$bldir/*>)
    {
             if (-d $category){
            system("chmod 755 $category &> /dev/null");
            foreach my $blacklist (<$category/*>)
            {
                    if (-f $blacklist) { system("chmod 644 $blacklist &> /dev/null"); }
                    if (-d $blacklist) { system("chmod 755 $blacklist &> /dev/null"); }
            }
            system("chmod 666 $category/*.db &> /dev/null");

            &setpermissions ($category);
        }
     }
}

# -------------------------------------------------------------------
