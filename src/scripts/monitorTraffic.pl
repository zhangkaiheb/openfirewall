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
# along with IPCop; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#
# $Id: monitorTraffic.pl 5834 2011-08-28 19:30:53Z dotzball $
#

use strict;

# enable only the following on debugging purpose
#use warnings;

require '/usr/lib/ipcop/general-functions.pl';
require "/usr/lib/ipcop/lang.pl";
require '/usr/lib/ipcop/traffic-lib.pl';

# Debug level:
#    0 - send email (if enabled), no print
#    1 - send email (if enabled), print
#    2 - only print
my $debugLevel = 0;
# Debug

my %log = ();
$log{'CALC_VOLUME_TOTAL'} = 0;
$log{'CALC_VOLUME_IN'} = 0;
$log{'CALC_VOLUME_OUT'} = 0;
$log{'CALC_WEEK_TOTAL'} = 0;
$log{'CALC_WEEK_IN'} = 0;
$log{'CALC_WEEK_OUT'} = 0;
$log{'CALC_LAST_RUN'} = 0;
$log{'CALC_PERCENT_TOTAL'} = 0;
$log{'CALC_PERCENT_IN'} = 0;
$log{'CALC_PERCENT_OUT'} = 0;
$log{'WARNMAIL_SEND'} = 'no';

# current time == endtime
my $currentTime = time;

# on force we don't load the log data
unless(defined($ARGV[0]) && $ARGV[0] eq '--force') {
    &TRAFFIC::readTrafficCounts(\%log);
}


# Only send email?
if(defined($ARGV[0]) && $ARGV[0] eq '--warnEmail') {
    print "Send warn email\n" if($debugLevel > 0);
    # send warn email
    my $return = &sendWarnEmail();
    print "return: $return\n";
    exit 0;
}


# should we recalculate?
# calc seconds for one interval
my $intervalTime = $TRAFFIC::settings{'CALC_INTERVAL'} * 60;
# next time, we have to calculate
my $nextRunTime = $log{'CALC_LAST_RUN'} + $intervalTime;

if ($debugLevel > 0) {
    my($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($log{'CALC_LAST_RUN'});
    my $lastRun = sprintf("%04d-%02d-%02d, %02d:%02d", 1900+$year, $mon+1, $mday, $hour, $min);
    print "last run: $lastRun\n";

    ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($nextRunTime);
    my $nextRun = sprintf("%04d-%02d-%02d, %02d:%02d", 1900+$year, $mon+1, $mday, $hour, $min);
    print "next run: $nextRun\n";

    ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($currentTime);
    my $current = sprintf("%04d-%02d-%02d, %02d:%02d", 1900+$year, $mon+1, $mday, $hour, $min);
    print "current time: $current\n";
}

# use a little time buffer in case the last run started some seconds earlier
if($currentTime < ($nextRunTime - 60) ) {
    # nothing to do
    if ($debugLevel > 0) {
        my $infoMsg = "Traffic monitor: nothing to do, do next calculation later.";
        print "$infoMsg\n";
        &General::log($infoMsg);
    }
    exit 0;
}
elsif($debugLevel > 0) {
    my $infoMsg = "Traffic monitor: Calc traffic now.";
    print "$infoMsg\n";
    &General::log($infoMsg);
}

####
# Calculate Traffic
#

$log{'CALC_LAST_RUN'} = $currentTime;
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($currentTime);

&TRAFFIC::calcTrafficCounts(\%log);

my $infoMsg = "Reached: $log{'CALC_VOLUME_TOTAL'} MB\n";
print "$infoMsg\n" if ($debugLevel > 0);

# monitor traffic volume?
if ($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on') {

    my $infoMsg = "Used (\%): \n";
    if($TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'} eq 'on') {
        $infoMsg .= "Total: $log{'CALC_PERCENT_TOTAL'} \% - Max.: $TRAFFIC::settings{'VOLUME_TOTAL'} MB ";
    }
    if($TRAFFIC::settings{'VOLUME_IN_ENABLED'} eq 'on') {
        $infoMsg .= "Input: $log{'CALC_PERCENT_IN'} \% - Max.: $TRAFFIC::settings{'VOLUME_IN'} MB ";
    }
    if($TRAFFIC::settings{'VOLUME_OUT_ENABLED'} eq 'on') {
         $infoMsg .= "Output: $log{'CALC_PERCENT_OUT'} \% - Max.: $TRAFFIC::settings{'VOLUME_OUT'} MB ";
    }

    print "$infoMsg\n" if ($debugLevel > 0);


    if($TRAFFIC::settings{'WARN_ENABLED'} eq 'on'
        && ($log{'CALC_PERCENT_TOTAL'} >= $TRAFFIC::settings{'WARN'}
            || $log{'CALC_PERCENT_TOTAL'} >= $TRAFFIC::settings{'WARN'}
            || $log{'CALC_PERCENT_TOTAL'} >= $TRAFFIC::settings{'WARN'}) )
    {
        # warnlevel is reached
        if ($debugLevel > 0) {
            my $warnMsg = "Traffic monitor warning: $infoMsg";
            print "$warnMsg\n";
            &General::log($warnMsg);
        }

        if($debugLevel < 2) {
            if($TRAFFIC::settings{'SEND_EMAIL_ENABLED'} eq 'on'
                && $log{'WARNMAIL_SEND'} ne 'yes')
            {
                # send warn email
                my $return = &sendWarnEmail('--warnEmail');

                if($return =~ /Email was sent successfully!/) {
                    $log{'WARNMAIL_SEND'} = 'yes';
                }
                else {
                    $log{'WARNMAIL_SEND'} = 'no';
                }
            }
        }

    }
    else {
        # warnlevel not reached, reset warnmail send
        $log{'WARNMAIL_SEND'} = 'no';
    }
}

&TRAFFIC::writeTrafficCounts(\%log);

exit 0;

sub sendWarnEmail
{
    my $template = "/var/ipcop/email/templates/warn-traffic";

    if(-e "$template.${Lang::language}.tpl") {
        $template .= ".${Lang::language}.tpl";
    }
    else {
        $template .= ".en.tpl";
    }

    # read template
    open(FILE, "$template");
    my @temp = <FILE>;
    close(FILE);

    my $date_lastrun = &TRAFFIC::getFormatedDate($log{'CALC_LAST_RUN'});

    my $messagefile ="/tmp/monitorTraffic.msg";

    open(FILE, ">$messagefile") or die 'Can not create temp messagefile';

    my $starttime = &TRAFFIC::getStarttimeMonth($TRAFFIC::settings{'PERIOD_TYPE'});

    $starttime =~ /^(\d\d\d\d)(\d\d)(\d\d)$/;

    my $startday = "$1-$2-$3";

    foreach my $line (@temp) {
        chomp($line);

        # remove lines from email which we don't need
        if($TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'} ne 'on') {
            if ($line =~ /__CALC_VOLUME_TOTAL__/ || $line =~ /__CALC_PERCENT_TOTAL__/ || $line =~ /__VOLUME_TOTAL__/) {
                next;
            }
        }
        if($TRAFFIC::settings{'VOLUME_IN_ENABLED'} ne 'on') {
            if ($line =~ /__CALC_VOLUME_IN__/ || $line =~ /__CALC_PERCENT_IN__/ || $line =~ /__VOLUME_IN__/) {
                next;
            }
        }
        if($TRAFFIC::settings{'VOLUME_OUT_ENABLED'} ne 'on') {
            if ($line =~ /__CALC_VOLUME_OUT__/ || $line =~ /__CALC_PERCENT_OUT__/ || $line =~ /__VOLUME_OUT__/) {
                next;
            }
        }

        $line =~ s/__CALC_VOLUME_TOTAL__/$log{'CALC_VOLUME_TOTAL'}/;
        $line =~ s/__CALC_VOLUME_IN__/$log{'CALC_VOLUME_IN'}/;
        $line =~ s/__CALC_VOLUME_OUT__/$log{'CALC_VOLUME_OUT'}/;

        $line =~ s/__CALC_PERCENT_TOTAL__/$log{'CALC_PERCENT_TOTAL'}/;
        $line =~ s/__CALC_PERCENT_IN__/$log{'CALC_PERCENT_IN'}/;
        $line =~ s/__CALC_PERCENT_OUT__/$log{'CALC_PERCENT_OUT'}/;

        $line =~ s/__VOLUME_TOTAL__/$TRAFFIC::settings{'VOLUME_TOTAL'}/;
        $line =~ s/__VOLUME_IN__/$TRAFFIC::settings{'VOLUME_IN'}/;
        $line =~ s/__VOLUME_OUT__/$TRAFFIC::settings{'VOLUME_OUT'}/;

        $line =~ s/__STARTDAY__/$startday/;
        $line =~ s/__LAST_RUN__/$date_lastrun/;

        print FILE "$line\n";
    }

    close(FILE);

    my $subject = $Lang::tr{'subject warn traffic'};

    unless($subject =~ /^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:\.\+,\ ]+$/) {
        # found some problematic characters, use english subject text
        &Lang::reload(2);
        $subject = $Lang::tr{'subject warn traffic'};
        print "Found problematic character, use english subject text \n" if ($debugLevel > 0);
    }

    my $cmd = "/usr/local/bin/emailhelper ";
    $cmd .= " -s \"$subject\" ";
    $cmd .= " -m \"$messagefile\" ";
    $cmd .= " -d ";

    print "cmd: $cmd \n" if ($debugLevel > 0);

    my $return = `$cmd`;

    return $return;
}


