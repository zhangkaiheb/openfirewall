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
# Copyright (c) 2009-2014 The IPCop Team
#
# $Id: ddns-lib.pl 7680 2014-10-28 13:06:25Z owes $
#

package DDNS;

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';

my $settingsfile = '/var/ipcop/ddns/settings';
my $datafile     = '/var/ipcop/ddns/config';

my $ddnsprefix = $Lang::tr{'ddns noip prefix'};
$ddnsprefix =~ s/%/$General::noipprefix/;

# Hash with all services we support and some specifics about them, which fiels are mandatory etc.
$DDNS::va{'all-inkl.com'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'cjb.net'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 0, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'dhs.org'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'dnsmadeeasy.com'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 0, PASSWORD => 1, LBNAME => '', HELP => $Lang::tr{'ddns help dnsmadeeasy'}};

#Note: HOSTNAME as ID may content a list but the comma is not allowed char ...!
$DDNS::va{'dnspark.com'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'dtdns.com'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'dyndns.org'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'dyndns-custom'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'dyndns-static'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'dyns.cx'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'dynu.ca'} = {
    LOGIN    => 1,
    HOSTNAME => 1,
    DOMAIN   => 1,
    PASSWORD => 1,
    LBNAME   => 'dynu.ca dyn.ee dynserv.(ca|org|net|com)',
    HELP     => ''
};
$DDNS::va{'easydns.com'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'editdns.net'} =
    {LOGIN => 0, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'enom.com'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'everydns.net'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'freedns.afraid.org'} = {
    LOGIN    => 1,
    HOSTNAME => 0,
    DOMAIN   => 0,
    PASSWORD => 0,
    LBNAME   => '',
    HELP     => $Lang::tr{'ddns help freedns'}
};    # connect string is in LOGIN field
$DDNS::va{'loopia.se'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => 'Help: https://support.loopia.se/wiki/LoopiaDNS_med_dynamisk_IP'};
$DDNS::va{'namecheap.com'} =
    {LOGIN => 0, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'no-ip.com'} = 
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => $ddnsprefix};
$DDNS::va{'nsupdate'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'ods.org'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'opendns.com'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 0, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'ovh.com'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'regfish.com'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 0, LBNAME => '', HELP => ''};
$DDNS::va{'registerfly.com'} =
    {LOGIN => 0, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'selfhost.de'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 0, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'sitelutions.com'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 0, PASSWORD => 1, LBNAME => '', HELP => 'Put record-id in hostname field'};
# Help is hard-coded in German for now
$DDNS::va{'spdns.de'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => 'Hostname ohne Domain'};
$DDNS::va{'strato.com'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'tiggerswelt.net'} =
    {LOGIN => 1, HOSTNAME => 1, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};
$DDNS::va{'yi.org'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 0, PASSWORD => 1, LBNAME => '', HELP => ''};

#$DDNS::va{'tzo.com'}     = { LOGIN=>1,   HOSTNAME=>1, DOMAIN=>1, PASSWORD=>1, LBNAME=>'', HELP=>'' };  # comment this service out until a working fix is developed
$DDNS::va{'zoneedit.com'} =
    {LOGIN => 1, HOSTNAME => 0, DOMAIN => 1, PASSWORD => 1, LBNAME => '', HELP => ''};


# Fetch the settings and list of DDNS host entries, this will write %DDNS::settings and @DDNS::hosts
&readSettings;
&readHosts;

1;


sub readSettings
{
    %DDNS::settings = ();

    $DDNS::settings{'BEHINDROUTER'}    = 'RED_IP';
    $DDNS::settings{'MINIMIZEUPDATES'} = '';
    &General::readhash($settingsfile, \%DDNS::settings);
}

sub writeSettings
{
    my $tmpsettings = shift;

    $DDNS::settings{'BEHINDROUTER'}    = $tmpsettings->{BEHINDROUTER};
    $DDNS::settings{'MINIMIZEUPDATES'} = $tmpsettings->{MINIMIZEUPDATES};
    &General::writehash($settingsfile, \%DDNS::settings);

    &readSettings;
}

sub readHosts
{
    @DDNS::hosts = ();

    return unless (open(FILE, "$datafile"));
    my @tmpfile = <FILE>;
    close(FILE);

    foreach my $line (@tmpfile) {
        chomp($line);    # remove newline
        my @tmp = split(/\,/, $line);

        $tmp[1] = '' unless defined $tmp[1];
        $tmp[2] = '' unless defined $tmp[2];
        $tmp[3] = '' unless defined $tmp[3];    # unused (PROXY) ? Keep for compat with older config files.
        $tmp[4] = '' unless defined $tmp[4];
        $tmp[5] = '' unless defined $tmp[5];
        $tmp[6] = '' unless defined $tmp[6];
        $tmp[7] = 'off' unless defined $tmp[7];

        push @DDNS::hosts, { ENABLED => $tmp[7],
            SERVICE => $tmp[0], HOSTNAME => $tmp[1], DOMAIN => $tmp[2],
            PROXY => $tmp[3], WILDCARDS => $tmp[4],
            LOGIN => $tmp[5], PASSWORD => $tmp[6]};
    }
}

sub writeHosts
{
    open(FILE, ">$datafile");
    for my $id (0 .. $#DDNS::hosts) {
        print FILE "$DDNS::hosts[$id]{'SERVICE'},$DDNS::hosts[$id]{'HOSTNAME'},";
        print FILE "$DDNS::hosts[$id]{'DOMAIN'},$DDNS::hosts[$id]{'PROXY'},";
        print FILE "$DDNS::hosts[$id]{'WILDCARDS'},$DDNS::hosts[$id]{'LOGIN'},";
        print FILE "$DDNS::hosts[$id]{'PASSWORD'},$DDNS::hosts[$id]{'ENABLED'}\n";
    }
    close FILE;

    &readHosts;
}
