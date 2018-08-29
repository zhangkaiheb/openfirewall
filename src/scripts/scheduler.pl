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
# (c) 2009-2015, the Openfirewall Team
#
# $Id: scheduler.pl 7884 2015-02-09 16:54:04Z owes $
#


use strict;
require '/usr/lib/ofw/scheduler-lib.pl';


my ($second, $minute, $hour, $day, $month ,$year, $weekday) = localtime(time);
# get the closest thing possible
$minute = int($minute / 5) * 5;


if ( ($ARGV[0] eq '--cron') || ($ARGV[0] eq 'cron')) {
    &fcron();
}
elsif (($ARGV[0] eq '--reconnect') || ($ARGV[0] eq 'reconnect')) {
    &reconnect();
}
elsif (($ARGV[0] eq '--dial') || ($ARGV[0] eq 'dial')) {
    &dial();
}
elsif (($ARGV[0] eq '--hangup') || ($ARGV[0] eq 'hangup')) {
    &hangup();
}
elsif (($ARGV[0] eq '--profile') || ($ARGV[0] eq 'profile')) {
    die "" unless (defined($ARGV[1]));
    &profile($ARGV[1]);
} else {
    print "Usage: $0 {--cron | --reconnect | --dial | --hangup | --profile #number}\n";
}

exit 0;



#   __                  _   _
#  / _|                | | (_)
# | |_ _   _ _ __   ___| |_ _  ___  _ __  ___
# |  _| | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | | | |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#

sub reconnect
{
    &General::log('Scheduler reconnect');

    if (-e '/var/ofw/red/active') {
        &hangup();
        # Some providers/connections exist that reconnect better after a small delay
        sleep 15;
    }
    &dial();
}

sub dial
{
    &General::log("Scheduler dial");
    &General::log('red', 'Scheduler dial');

    return if (-e '/var/ofw/red/active');

    unless (system('/etc/rc.d/rc.red', 'start') == 0) {
        &General::log("Scheduler dial failed: $?");
        return;
    }

    # wait maximum 60 seconds for red/active triggerfile
    my $counter = 60;
    until (-e '/var/ofw/red/active' || $counter == 0) {
        sleep 1;
        $counter--;
    }
}

sub hangup
{
    &General::log("Scheduler hangup");
    &General::log('red', 'Scheduler hangup');

    my $existPPP = -e '/var/run/ppp-ofw.pid';
    return unless (-e '/var/ofw/red/active' || $existPPP);
    
    my $ppppid = '-';
    if($existPPP) {
        $ppppid = `cat /var/run/ppp-ofw.pid | grep -v ppp`;
        chomp($ppppid);
    }

    unless (system('/etc/rc.d/rc.red', 'stop') == 0) {
        &General::log("Scheduler hangup failed: $?");
        return;
    }

    # now wait for red/active triggerfile and ppp daemon to disappear
    sleep 1;
    while (-e '/var/ofw/red/active' || ($existPPP && -d "/proc/$ppppid")) {
        sleep 1;
    }

    # Wait for rc.updatered to finish
    while (! system("/bin/ps ax | /bin/grep -q [r]c.updatered") ) {
        sleep 1;
    }
}

sub profile
{
    my $profilenr = shift;
    my $red_active = 0;         # are we connected?

    unless (-e "/var/ofw/ppp/settings-${profilenr}")
    {
        &General::log("Secheduler invalid profile: $profilenr");
        return;
    }
    &General::log("Scheduler select profile $profilenr");

    if (-e '/var/ofw/red/active') {
        # remember to restart red after changing profile
        $red_active = 1;
        &hangup();
    }

    &General::SelectProfile($profilenr);

    if ($red_active == 1) {
        &dial();
    }
}


sub blacklistupdate
{
    &General::log("Scheduler Blacklistupdate");

    system("/usr/local/bin/blacklistupdate.pl --force");
}

sub dyndns
{
    &General::log("Scheduler dynamic DNS");

    system("/usr/local/bin/setddns.pl --force");
}

sub update
{
    system("/usr/local/bin/updatelists.pl --cron");
}

sub reboot
{
    system("/usr/local/bin/ofwreboot --boot Scheduled reboot");
}

sub shutdown
{
    system("/usr/local/bin/ofwreboot --down Scheduled shutdown");
}

sub ipsec
{
    my $parameter = shift;

    &General::log("Scheduler IPsec ${parameter}");
    system("/usr/local/bin/ipsecctrl --${parameter}");
}

sub openvpn
{
    my $parameter = shift;

    &General::log("Scheduler OpenVPN ${parameter}");
    system("/usr/local/bin/restartopenvpn --${parameter}");
}

sub fcron
{
    for my $id (0 .. $#SCHEDULER::list) {
        next if ($SCHEDULER::list[$id]{'ACTIVE'} ne 'on');

        my $action_hour = substr($SCHEDULER::list[$id]{'TIME'},0,2);
        my $action_minute = substr($SCHEDULER::list[$id]{'TIME'},3,2);

        next if ($action_hour != $hour);
        next if ($action_minute != $minute);

        if ($SCHEDULER::list[$id]{'DAYSTYPE'} eq 'days') {
            my @temp = split(/-/,$SCHEDULER::list[$id]{'DAYS'},2);

            my $daystart = substr($temp[0], 0, -1);
            my $dayend = substr($temp[1], 1);

            next if (($day < $daystart) || ($day > $dayend));
        }
        else {
            next if (index($SCHEDULER::list[$id]{'WEEKDAYS'}, $General::weekDays[$weekday]) == -1);
        }

        if ($SCHEDULER::list[$id]{'ACTION'} eq 'reconnect') {
            &reconnect()
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'dial') {
            &dial();
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'hangup') {
            &hangup();
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'reboot') {
            &reboot();
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'shutdown') {
            &shutdown();
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'profile') {
            &profile($SCHEDULER::list[$id]{'OPTIONS'});
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'start ipsec') {
            &ipsec('start');
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'stop ipsec') {
            &ipsec('stop');
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'start openvpn server') {
            &openvpn('start');
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'stop openvpn server') {
            &openvpn('stop');
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'dyndns force') {
            &dyndns();
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'check for updates') {
            &update();
        }
        elsif ($SCHEDULER::list[$id]{'ACTION'} eq 'check for blacklist updates') {
            &blacklistupdate();
        }
    }
}
