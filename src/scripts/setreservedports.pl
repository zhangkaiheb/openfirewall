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
# $Id: setreservedports.pl 7523 2014-05-06 18:42:29Z owes $
# 
# Copyright (c) 2009-2014 The IPCop Team
#
#
# Just a note: existing connections will not be cut when changing ports.
#   ESTABLISHED, RELATED can be really amazing
#

use strict;

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/DataAccess.pl';


my $prototest = '';
my $porttest = 0;
my $portgui  = 0;
my $portssh  = 0;
my $nocheck  = 0;


if ($#ARGV == -1) {
    &cmdhelp();
}

while (@ARGV) {
    my $argument = shift;

    if (($argument eq '--test') && ($#ARGV >= 1)) {
        $porttest = shift;
        die "Invalid port: $porttest" unless (&General::validport($porttest));
        
        $prototest = shift;
    }
    elsif (($argument eq '--gui') && ($#ARGV >= 0)) {
        $portgui = shift;
        die "Invalid port: $portgui" unless (&General::validport($portgui));
    }
    elsif (($argument eq '--ssh') && ($#ARGV >= 0)) {
        $portssh = shift;
        die "Invalid port: $portssh" unless (&General::validport($portssh));
    }
    elsif ($argument eq '--nocheck') {
        $nocheck = 1;
    }
    else {
        &cmdhelp();
    }
}

if ($porttest) {
    # This is only a quick hack to do some testing

    if (&DATA::isReservedPort($prototest, $porttest)) {
        print "reserved\n";
    }
    else {
        print "not reserved\n";
    }
}

if ($portgui) {
    if (($nocheck == 0) && &DATA::isReservedPort("tcp", $portgui)) {
        print "Cannot change GUI port to $portgui, port is reserved\n";
    }
    else {
        &setgui();
    }
}

if ($portssh) {
    if (($nocheck == 0) && &DATA::isReservedPort("tcp", $portssh)) {
        print "Cannot change SSH port to $portssh, port is reserved\n";
    }
    else {
        &setssh();
    }
}


sub setgui()
{
    print "Changing GUI port to $portgui\n";

    my %mainsettings = ();
    &General::readhash('/var/ipcop/main/settings', \%mainsettings);
    $mainsettings{'GUIPORT'} = $portgui;
    &General::writehash('/var/ipcop/main/settings', \%mainsettings);

    # Change apache port
    print "Change httpd configuration ... \n";
    system("/bin/sed", "-i", "-e", "s+^Listen .*\$+Listen $portgui+",
                "-e", "s+^<VirtualHost _default_:.*\$+<VirtualHost _default_:$portgui>+",
                "/etc/httpd/conf/portgui.conf");
    # Not needed to start httpd during installation
    if (-e '/var/run/httpd.pid') {
        print 'Restarting httpd ... \n';
        system('/usr/local/bin/restarthttpd --restart');
    }

    # Inform squid
    print "Change proxy configuration ... \n";
    if (-e '/var/ipcop/proxy/squid.conf') {
        system("/bin/sed -i 's+acl IPCop_https port.*\$+acl IPCop_https port $portgui+' /var/ipcop/proxy/squid.conf");

        # Restart squid if enabled
        if (-e '/var/run/squid.pid') {
            my %proxysettings = ();
            &General::readhash("/var/ipcop/proxy/settings", \%proxysettings);
            if (($proxysettings{'ENABLED_GREEN_1'} eq 'on') || ($proxysettings{'ENABLED_BLUE_1'} eq 'on')) {
                print "Restarting proxy ... \n";
                system('/usr/local/bin/restartsquid');
            }
        }
    }

    # TODO: we may need a different test here to detect config change from restore during installation
    if (-e '/var/run/httpd.pid') {
        # Rewrite firewall rules
        system("/usr/local/bin/setfwrules --ipcop >/dev/null");
    }
    
    &General::log("GUI port changed to $portgui");
}


sub setssh()
{
    print "Changing SSH port to $portssh\n";

    my %mainsettings = ();
    &General::readhash('/var/ipcop/main/settings', \%mainsettings);
    $mainsettings{'SSHPORT'} = $portssh;
    &General::writehash('/var/ipcop/main/settings', \%mainsettings);

    # Change sshd port
    print "Change sshd configuration ... \n";
    system("/bin/sed", "-i", "-e", "s+Port .*\$+Port $portssh+", "/etc/ssh/sshd_config");

    # Not needed to start sshd during installation
    if (-e '/var/run/sshd.pid') {
        my %sshsettings = ();
        &General::readhash('/var/ipcop/remote/settings', \%sshsettings);
        if ($sshsettings{'ENABLE_SSH'} eq 'on') {
            print "Restarting SSHd ... \n";
            system('/usr/local/bin/restartssh');
        }
    }
    # Rewrite firewall rules
    system("/usr/local/bin/setfwrules --ipcop >/dev/null");

    &General::log("SSH port changed to $portssh");
}

sub cmdhelp()
{
    print <<END;
Usage is: [--gui portnumber] [--ssh portnumber] [--test portnumber proto] [--nocheck]

    --gui port              Change the IPCop GUI to tcp/port
    --ssh port              Change the IPCop SSH to tcp/port
    --test port proto       Run a quick test to see if proto/port is reserved
    --nocheck               Do not check if port is reserved, use in case of restore only

    To change GUI or SSH enter a portnumber between 1 and 65535. 
    Also be very sure that you know what you are doing!
END

    exit 0;
}
