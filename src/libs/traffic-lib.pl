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
# along with Openfirewall; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#

package TRAFFIC;

use DBI;
use strict;
# enable only the following on debugging purpose
#use warnings; no warnings 'once';
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/DataAccess.pl';

$|=1; # line buffering

%TRAFFIC::settings = ();


# enable(==1)/disable(==0) HTML Form debugging
$TRAFFIC::debugFormparams = 0;


$TRAFFIC::settingsfile = "/var/ofw/traffic/settings";
$TRAFFIC::logfile = "/var/log/traffic.log";
$TRAFFIC::colorOk 	 = '#00FF00';
$TRAFFIC::colorWarn = '#FF9900';
$TRAFFIC::colorMax  = '#FF0000';


@TRAFFIC::longmonths = ( $Lang::tr{'january'}, $Lang::tr{'february'}, $Lang::tr{'march'},
    $Lang::tr{'april'}, $Lang::tr{'may'}, $Lang::tr{'june'}, $Lang::tr{'july'}, $Lang::tr{'august'},
    $Lang::tr{'september'}, $Lang::tr{'october'}, $Lang::tr{'november'},
    $Lang::tr{'december'} );

@TRAFFIC::months = ( 0,1,2,3,4,5,6,7,8,9,10,11 );

@TRAFFIC::years=();

my @now = localtime(time);
$now[5] = $now[5]+1900;

for (my $year = 2001; $year<=($now[5]+2); $year++) {
    push(@TRAFFIC::years, $year);
}




# Init Settings
$TRAFFIC::settings{'ENABLED'}      = 'off';
$TRAFFIC::settings{'DETAIL_LEVEL'} = 'Low';
$TRAFFIC::settings{'SHOW_AT_HOME'} = 'off';
$TRAFFIC::settings{'TRAFFIC_VIEW_REVERSE'} = 'off';
$TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} = 'off';
$TRAFFIC::settings{'PERIOD_TYPE'} = 'monthly';
$TRAFFIC::settings{'STARTDAY'} = '1';
$TRAFFIC::settings{'ROLLING_WINDOW'} = '30';
$TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'} = 'off';
$TRAFFIC::settings{'VOLUME_TOTAL'} = '';
$TRAFFIC::settings{'VOLUME_IN_ENABLED'} = 'off';
$TRAFFIC::settings{'VOLUME_IN'} = '';
$TRAFFIC::settings{'VOLUME_OUT_ENABLED'} = 'off';
$TRAFFIC::settings{'VOLUME_OUT'} = '';
$TRAFFIC::settings{'WARN_ENABLED'} = 'off';
$TRAFFIC::settings{'WARN'} = '80';
$TRAFFIC::settings{'CALC_INTERVAL'} = '60';
$TRAFFIC::settings{'SEND_EMAIL_ENABLED'} = 'off';


&TRAFFIC::readSettings();

sub readSettings
{
    &General::readhash($TRAFFIC::settingsfile, \%TRAFFIC::settings);
}

sub getDeviceNames
{
    my $devices = shift;
    my $interfaces = shift;

    foreach my $name (keys %{$interfaces}) {
        if ($interfaces->{$name}{'ID'} ne '') {
            $devices->{$interfaces->{$name}{'ID'}} = $name;
        }
    }
}

sub writeTrafficCounts
{
    my $calc = shift;


    &General::writehash($TRAFFIC::logfile, \%{$calc});
}

sub readTrafficCounts
{
    my $calc = shift;

    $calc->{'CALC_VOLUME_TOTAL'} = 0;
    $calc->{'CALC_VOLUME_IN'} = 0;
    $calc->{'CALC_VOLUME_OUT'} = 0;
    $calc->{'CALC_WEEK_TOTAL'} = 0;
    $calc->{'CALC_WEEK_IN'} = 0;
    $calc->{'CALC_WEEK_OUT'} = 0;
    $calc->{'CALC_LAST_RUN'} = 0;
    $calc->{'CALC_PERCENT_TOTAL'} = 0;
    $calc->{'CALC_PERCENT_IN'} = 0;
    $calc->{'CALC_PERCENT_OUT'} = 0;

    &General::readhash($TRAFFIC::logfile, \%{$calc}) if(-e $TRAFFIC::logfile);
}


sub calcTrafficCounts
{
    my $calc = shift;

    $calc->{'CALC_VOLUME_TOTAL'} = 0;
    $calc->{'CALC_VOLUME_IN'} = 0;
    $calc->{'CALC_VOLUME_OUT'} = 0;
    $calc->{'CALC_WEEK_TOTAL'} = 0;
    $calc->{'CALC_WEEK_IN'} = 0;
    $calc->{'CALC_WEEK_OUT'} = 0;
    $calc->{'CALC_PERCENT_TOTAL'} = 0;
    $calc->{'CALC_PERCENT_IN'} = 0;
    $calc->{'CALC_PERCENT_OUT'} = 0;

    my $endtime   = &getEndtimeNow();
    #print "end: '$endtime'<br />";

    my $dbh = DBI->connect("dbi:SQLite:dbname=/var/log/traffic/aggregate.db", "", "", {RaiseError => 1});
eval {
    my $select = "SELECT oob_prefix, SUM(ip_totlen) ";
    $select .= " FROM daily ";
    $select .= " WHERE date>= ? AND date< $endtime ";
    $select .= "    AND oob_prefix like 'RED_%' ";
    $select .= " GROUP BY oob_prefix ;";

    my $sthSelect = $dbh->prepare($select);
    my $prefix = "";
    my $bytes = 0;
    $sthSelect->bind_columns(\$prefix, \$bytes);

    # this month
    my $starttime = &getStarttimeMonth($TRAFFIC::settings{'PERIOD_TYPE'});
    $sthSelect->execute($starttime);
    while ($sthSelect->fetch()) {
        $calc->{'CALC_VOLUME_TOTAL'} += $bytes;
        if ($prefix =~/_IN/) {
            $calc->{'CALC_VOLUME_IN'} += $bytes;
        }
        elsif ($prefix =~/_OUT/) {
            $calc->{'CALC_VOLUME_OUT'} += $bytes;
        }
    }

    #print "start month: '$starttime'<br />";

    # this week
    # We start on Monday, not on sunday
    if ($now[6] == 0) {
        # it is sunday
        $now[6] = 6;
    }
    else {
        $now[6]--;
    }

    # calculate the date of the monday this week
    my @weekStart = localtime( time() - ($now[6] * 86400));
    $weekStart[5] += 1900;
    my $startMonth = $weekStart[4] + 1;
    my $startDay = $weekStart[3];

    $startMonth = $startMonth < 10 ? $startMonth = "0".$startMonth : $startMonth;
    $startDay = $startDay < 10 ? $startDay = "0".$startDay : $startDay;

    $starttime = "$weekStart[5]$startMonth$startDay";
    $sthSelect->execute($starttime);
    while ($sthSelect->fetch()) {
        $calc->{'CALC_WEEK_TOTAL'} += $bytes;
        if($prefix =~/_IN/) {
            $calc->{'CALC_WEEK_IN'} += $bytes;
        }
        elsif($prefix =~/_OUT/) {
            $calc->{'CALC_WEEK_OUT'} += $bytes;
        }
    }
    #print "start week: '$starttime'<br />";

    $sthSelect->finish();
};
    if ($@) {
        warn "Transaction aborted because $@";
    }

    $calc->{'CALC_VOLUME_TOTAL'} = sprintf("%.2f", ($calc->{'CALC_VOLUME_TOTAL'}/1048576));
    $calc->{'CALC_VOLUME_IN'} = sprintf("%.2f", ($calc->{'CALC_VOLUME_IN'}/1048576));
    $calc->{'CALC_VOLUME_OUT'} = sprintf("%.2f", ($calc->{'CALC_VOLUME_OUT'}/1048576));
    $calc->{'CALC_WEEK_TOTAL'} =sprintf("%.2f", ($calc->{'CALC_WEEK_TOTAL'}/1048576));
    $calc->{'CALC_WEEK_IN'} = sprintf("%.2f", ($calc->{'CALC_WEEK_IN'}/1048576));
    $calc->{'CALC_WEEK_OUT'} = sprintf("%.2f", ($calc->{'CALC_WEEK_OUT'}/1048576));

    $dbh->disconnect() or warn $dbh->errstr;

    if ($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on') {
        if ($TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'} eq 'on') {
            $calc->{'CALC_PERCENT_TOTAL'} = sprintf("%d", ($calc->{'CALC_VOLUME_TOTAL'} / $TRAFFIC::settings{'VOLUME_TOTAL'} * 100));
        }
        if ($TRAFFIC::settings{'VOLUME_IN_ENABLED'} eq 'on') {
            $calc->{'CALC_PERCENT_IN'} = sprintf("%d", ($calc->{'CALC_VOLUME_IN'} / $TRAFFIC::settings{'VOLUME_IN'} * 100));
        }
        if ($TRAFFIC::settings{'VOLUME_OUT_ENABLED'} eq 'on') {
            $calc->{'CALC_PERCENT_OUT'} = sprintf("%d", ($calc->{'CALC_VOLUME_OUT'} / $TRAFFIC::settings{'VOLUME_OUT'} * 100));
        }
    }
}

sub getEndtimeNow
{
    my $currentTime = time();
    # as we always use date < $end, and we want to include today, use tomorrow as excluded end day
    my @now = localtime($currentTime + 86400);
    $now[5] += 1900;
    $now[4]++;
    my $day = $now[3];
    my $month =$now[4];
    $month = $month < 10 ? $month = "0".$month : $month;
    $day = $day < 10 ? $day = "0".$day : $day;

    return "$now[5]$month$day";
}

sub getStarttimeMonth
{
    my $periodType = shift;

    my $starttime = '';

    if ($periodType eq 'rollingWindow') {
        my @rollingStart = localtime( time() - (($TRAFFIC::settings{'ROLLING_WINDOW'} - 1) * 86400));
        $rollingStart[5] += 1900;
        my $startMonth = $rollingStart[4] + 1;
        my $startDay = $rollingStart[3];

        $startMonth = $startMonth < 10 ? $startMonth = "0".$startMonth : $startMonth;
        $startDay = $startDay < 10 ? $startDay = "0".$startDay : $startDay;

        $starttime = "$rollingStart[5]$startMonth$startDay";
    }
    else {
        my @now = localtime(time);
        $now[5] = $now[5] + 1900;

        my $startYear  = $now[5];
        my $startMonth = $now[4] + 1;

        my $startDay = 1;

        if ($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on') {
            $startDay = $TRAFFIC::settings{'STARTDAY'};
        }

        # this periode started last month
        if ($now[3] < $startDay) {
            $startMonth = $now[4];

            # when current month is january we start in last year december
            if ($now[4] == 0) {
                $startYear  = $now[5] - 1;
                $startMonth = 12;
            }
        }

        $startMonth = $startMonth < 10 ? $startMonth = "0".$startMonth : $startMonth;
        $startDay = $startDay < 10 ? $startDay = "0".$startDay : $startDay;

        $starttime = "$startYear$startMonth$startDay";
    }

    return $starttime;
}

sub calcTraffic
{
    my $allDaysBytes = shift;
    my $start = shift;
    my $end = shift;
    my $displayMode = shift;
    my $devices = shift;

    my $dbh = DBI->connect("dbi:SQLite:dbname=/var/log/traffic/aggregate.db", "", "", {RaiseError => 1});
eval {
    my $select = "SELECT date, oob_prefix, SUM(ip_totlen) ";
    $select .= " FROM daily ";
    $select .= " WHERE date>= $start AND date< $end ";
    $select .= " AND ( ";

    my $isFirst = 1;
    # TODO: may some errorhandling in case of no devices
    foreach my $device (keys %{$devices}) {
        if($isFirst) {
            $isFirst = 0;
        }
        else {
            $select .= " OR ";
        }
        $select .= " oob_prefix like '".$device."%' ";
    }
    $select .= " ) ";

    $select .= " GROUP BY date, oob_prefix ";
    $select .= " ORDER BY date, oob_prefix ;";

    ###
    # DEBUG
    ###
    if ($TRAFFIC::debugFormparams == 1) {
       print "DEBUG: $select<br />\n";
    }

    my $sthSelect = $dbh->prepare($select);
    my $date = 0;
    my $prefix = "";
    my $bytes = 0;
    $sthSelect->bind_columns(\$date, \$prefix, \$bytes);

    $sthSelect->execute();
    while ($sthSelect->fetch()) {
        $date =~ /(\d\d\d\d)(\d\d)(\d\d)/;
        my $displayDate = "$1-$2-$3";

        if($displayMode eq 'monthly') {
            $displayDate =  "$1-$2";
            $date = "$1$2";
        }

        if (!defined($allDaysBytes->{$date})) {
            $allDaysBytes->{$date} = ();
            $allDaysBytes->{$date}{'Day'} = $displayDate;
        }

        $prefix =~ /^(\w+_\d+)_.*(IN|OUT)/;
        my $rule = $1."_".$2;

        if (!defined($allDaysBytes->{$date}{$rule})) {
            $allDaysBytes->{$date}{$rule} = 0;
        }

        $allDaysBytes->{$date}{$rule} += $bytes;
    }

    $sthSelect->finish();
};
    if ($@) {
        warn "Transaction aborted because $@";
    }

    $dbh->disconnect() or warn $dbh->errstr;
}



sub traffPercentbar
{
    my $percent = $_[0];
    my $fg = '#a0a0a0';
    my $bg = '#e2e2e2';

    unless ($percent =~ m/^(\d+)%$/) {
        return;
    }

    print <<END;
<table width='100%' border='1' cellspacing='0' cellpadding='0' style='border-width:1px;border-style:solid;border-color:$fg;width:100%;height:10px;'>
<tr>
END

    if ($percent eq "100%" || $1 > 100) {
        $fg = $TRAFFIC::colorMax;
        print "<td width='100%' bgcolor='$fg' style='background-color:$fg;border-style:solid;border-width:1px;border-color:$bg'>"
    }
    elsif ($percent eq "0%") {
        print "<td width='100%' bgcolor='$bg' style='background-color:$bg;border-style:solid;border-width:1px;border-color:$bg'>"
    }
    else {
        if ($TRAFFIC::settings{'WARN_ENABLED'} eq 'on' && $1 >= $TRAFFIC::settings{'WARN'}) {
            $fg = $TRAFFIC::colorWarn;
        }

        print "<td width='$percent' bgcolor='$fg' style='background-color:$fg;border-style:solid;border-width:1px;border-color:$bg'></td><td width='" . (100-$1) . "%' bgcolor='$bg' style='background-color:$bg;border-style:solid;border-width:1px;border-color:$bg'>"
    }
    print <<END;
        <img src='/images/null.gif' width='1' height='1' alt='' />
    </td>
</tr>
</table>
END
}




sub getFormatedDate
{
	my $time = shift;
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($time);

	return sprintf("%04d-%02d-%02d, %02d:%02d", 1900+$year, $mon+1, $mday, $hour, $min);

}
# always return 1;
1;
# EOF
