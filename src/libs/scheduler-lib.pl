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
# Copyright (c) 2009-2012 The IPCop Team
#
# $Id: scheduler-lib.pl 6427 2012-02-27 18:20:25Z owes $
#


package SCHEDULER;

# enable only the following on debugging purpose
use warnings; no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';


@SCHEDULER::actions = (
    'reconnect', 'dial', 'hangup', 'reboot', 'shutdown',
    'start ipsec', 'stop ipsec', 'start openvpn server', 'stop openvpn server',
    'dyndns force', 'check for updates', 'check for blacklist updates'
);
# we also want these actions pulled in for translations
# $Lang::tr{'reconnect'} $Lang::tr{'dial'} $Lang::tr{'hangup'}
# $Lang::tr{'reboot'} $Lang::tr{'shutdown'}
# $Lang::tr{'start ipsec'} $Lang::tr{'stop ipsec'} $Lang::tr{'start openvpn server'} $Lang::tr{'stop openvpn server'}
# $Lang::tr{'dyndns force'} $Lang::tr{'check for updates'} $Lang::tr{'check for blacklist updates'}

$SCHEDULER::maxprofiles = 5;

&SCHEDULER::readSettings();

1;


#
# read the file with scheduled actions
#
sub readSettings
{
    @SCHEDULER::list = ();
    if (! -e '/var/ipcop/main/scheduler') {
        return;
    }

    open(FILE, '/var/ipcop/main/scheduler');
    my @tmpfile = <FILE>;
    close (FILE);

    my $newline = "";
    foreach $newline (@tmpfile) {
        my $l_weekdays = '';

        chomp($newline);
        my @tmp = split(/\,/, $newline);
        $tmp[5] = '' unless defined $tmp[5];
        $tmp[6] = '' unless defined $tmp[6];
        $tmp[7] = '' unless defined $tmp[7];

        if ($tmp[3] eq 'days') {
            my @daytmp = split(/ /, $tmp[4]);
            if ($daytmp[0] eq $daytmp[2]) {
                $formatted = "$Lang::tr{'day'}: $daytmp[0]";
            }
            else {
                $formatted = "$Lang::tr{'days'}: $tmp[4]";
            }
        }
        else {
            $formatted = "$Lang::tr{'days of the week'}: ";
            foreach my $d (@General::weekDays) {
                if (index($tmp[5], $d) != -1) {
                    $formatted .= $Lang::tr{$d}."&nbsp;";
                }
            }
        }
        $SCHEDULER::count++;
        push @SCHEDULER::list, { ACTIVE => $tmp[0], ACTION => $tmp[1],
            TIME => $tmp[2], DAYSTYPE => $tmp[3], DAYS => $tmp[4], WEEKDAYS => $tmp[5], DAYS_FORMATTED => $formatted,
            OPTIONS => $tmp[6], COMMENT => $tmp[7]};
    }
}


#
# write the actions to file
#
sub writeSettings
{
    open(FILE, '>/var/ipcop/main/scheduler') or die 'Unable to open scheduler settings file.';

    for my $id (0 .. $#SCHEDULER::list) {
        if ( ($SCHEDULER::list[$id]{'ACTIVE'} ne 'on') && ($SCHEDULER::list[$id]{'ACTIVE'} ne 'off') ) { next; }

        print FILE "$SCHEDULER::list[$id]{'ACTIVE'},$SCHEDULER::list[$id]{'ACTION'},";
        print FILE "$SCHEDULER::list[$id]{'TIME'},$SCHEDULER::list[$id]{'DAYSTYPE'},";
        print FILE "$SCHEDULER::list[$id]{'DAYS'},$SCHEDULER::list[$id]{'WEEKDAYS'},";
        print FILE "$SCHEDULER::list[$id]{'OPTIONS'},$SCHEDULER::list[$id]{'COMMENT'}\n";
    }
    close FILE;

    # Sort the action list on time, which is field 3
    system('/usr/bin/sort -t "," -k 3 -o /var/ipcop/main/scheduler /var/ipcop/main/scheduler');

    &readSettings();
}
