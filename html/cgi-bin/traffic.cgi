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
# $Id: traffic.cgi 5433 2011-02-09 18:56:59Z eoberlander $
#

# Add entry in menu
# MENUENTRY status 060 "sstraffic" "sstraffic"

use strict;

# enable only the following on debugging purpose
use warnings;
no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require "/usr/lib/ipcop/lang.pl";
require "/usr/lib/ipcop/header.pl";
require "/usr/lib/ipcop/traffic-lib.pl";

my %cgiparams;
my %pppsettings;
my %netsettings;
my %settings;

&General::readhash("/var/ipcop/ppp/settings", \%pppsettings);

$cgiparams{'SHOW_PAGE'} = 'overview';

my @now = localtime(time);
$now[5] = $now[5] + 1900;

$cgiparams{'STARTYEAR'}  = $now[5];
$cgiparams{'STOPYEAR'}   = $now[5];
$cgiparams{'STARTMONTH'} = $now[4];

$cgiparams{'STARTDAY'} = 1;
$cgiparams{'STOPDAY'}  = 1;

if($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on')
{
    if($TRAFFIC::settings{'PERIOD_TYPE'} eq 'monthly') {
        $cgiparams{'STARTDAY'} = $TRAFFIC::settings{'STARTDAY'};
        $cgiparams{'STOPDAY'} = $TRAFFIC::settings{'STARTDAY'};
    }
}

# this periode started last month
if ($now[3] < $cgiparams{'STARTDAY'}) {
    $cgiparams{'STARTMONTH'} = $now[4] - 1;
    $cgiparams{'STOPMONTH'}  = $now[4];

    # when current month is january we start in last year december
    if ($cgiparams{'STOPMONTH'} == 0) {
        $cgiparams{'STARTYEAR'}  = $now[5] - 1;
        $cgiparams{'STARTMONTH'} = 11;
    }
}
else {
    $cgiparams{'STARTMONTH'} = $now[4];
    $cgiparams{'STOPMONTH'}  = $now[4] + 1;

    # when we are in december, this periode ends next year january
    if ($cgiparams{'STARTMONTH'} == 11) {
        $cgiparams{'STOPYEAR'}  = $now[5] + 1;
        $cgiparams{'STOPMONTH'} = 0;
    }
}

my $startMonthPreset = $cgiparams{'STARTMONTH'};

if($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on' && $TRAFFIC::settings{'PERIOD_TYPE'} eq 'rollingWindow')
{
    $cgiparams{'STARTMONTH'} = 'rollingWindow';
}


&General::getcgihash(\%cgiparams);

my $showAllTraff   = 0;
my $selectYearALL  = "";
my $selectMonthALL = "";

if ($cgiparams{'SHOW_PAGE'} ne 'detailed') {
    if ($cgiparams{'STARTYEAR'} eq '????') {
        $selectYearALL = 'selected=\'selected\'';
        $showAllTraff  = 1;
    }

    if ($cgiparams{'STARTMONTH'} eq '??') {
        $selectMonthALL = 'selected=\'selected\'';
        $showAllTraff   = 1;
    }
}

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'sstraffic'}, 1, '');

&Header::openbigbox('100%', 'left');

###############
# DEBUG DEBUG
if ($TRAFFIC::debugFormparams == 1) {
    &Header::openbox('100%', 'left', 'DEBUG');
    my $debugCount = 0;
    foreach my $line (sort keys %cgiparams) {
        print "$line = $cgiparams{$line}<br />\n";
        $debugCount++;
    }
    print "&nbsp;Count: $debugCount\n";
    &Header::closebox();
}

if ($cgiparams{'SHOW_PAGE'} ne 'detailed') {
    &Header::openbox('100%', 'left', "");

    my $firstDayTxt = '';

    if($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on')
    {
        if($TRAFFIC::settings{'PERIOD_TYPE'} eq 'monthly') {
            $firstDayTxt = " ($Lang::tr{'monthly volume start day short'}): $TRAFFIC::settings{'STARTDAY'}";
        }
        else {
            $firstDayTxt = " ($Lang::tr{'rolling window days'}: $TRAFFIC::settings{'ROLLING_WINDOW'}):";
        }
    }

    print <<END;
        <table width='100%' align='center'>
        <tr>
            <td width='90%' align='left' nowrap='nowrap'>
                <form method='post' action='/cgi-bin/traffic.cgi'>
                    $Lang::tr{'selecttraffic'}$firstDayTxt
                    <select name='STARTMONTH'>
END

    if($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on' && $TRAFFIC::settings{'PERIOD_TYPE'} eq 'rollingWindow')
    {
        print "\t<option ";
        if ("$cgiparams{'STARTMONTH'}" eq 'rollingWindow') {
            print 'selected=\'selected\' ';
        }
        print "value='rollingWindow'>$Lang::tr{'rolling window'}</option>\n";
    }

    foreach my $month (@TRAFFIC::months) {
        print "\t<option ";
        if ("$month" eq "$cgiparams{'STARTMONTH'}") {
            print 'selected=\'selected\' ';
        }
        print "value='$month'>$TRAFFIC::longmonths[$month]</option>\n";
    }

    print <<END;
                        <option $selectMonthALL value='??'>$Lang::tr{'allmsg'}</option>
                    </select>
                    <select name='STARTYEAR'>
END

    for (my $index = 0; $index <= $#TRAFFIC::years; $index++) {
        print "\t<option ";
        if ("$TRAFFIC::years[$index]" eq "$cgiparams{'STARTYEAR'}") {
            print 'selected=\'selected\' ';
        }
        print "value='$TRAFFIC::years[$index]'>$TRAFFIC::years[$index]</option>\n";
    }

    print <<END;
                        <option $selectYearALL value='????'>$Lang::tr{'allmsg'}</option>
                    </select>
                    <input type='hidden' name='SHOW_PAGE' value='overview' />
                    <input type='submit' name='ACTION' value='$Lang::tr{'update'}' />
                </form>
            </td>
            <td width='5%' align='center'>
                <form method='post' action='/cgi-bin/trafficadm.cgi'>
                <input type='submit' name='ACTION' value='$Lang::tr{'traffic configuration'}' />
                </form>
            </td>
            <td width='5%' align='center'>
              <form method='post' action='/cgi-bin/traffic.cgi'>
                    <input type='hidden' name='SHOW_PAGE' value='detailed' />
                    <input type='submit' name='ACTION' value='&gt;&gt;' />
                </form>
            </td>
        </tr>
        </table>
END

    &Header::closebox();
}    # 'normal' page / overview
else {
    &Header::openbox('100%', 'left', "");

    if($cgiparams{'STARTMONTH'} eq 'rollingWindow') {
        $cgiparams{'STARTMONTH'} = $startMonthPreset ;
    }

    print <<END;
    <table width='100%' align='center'>
    <tr>
        <td width='90%' class='base' align='center'>
            <form method='post' action='/cgi-bin/traffic.cgi'>
            $Lang::tr{'from'}
            <select name='STARTDAY'>
END

    my @days = (
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    );

    foreach my $day (@days) {
        print "\t<option ";
        if ($day == $cgiparams{'STARTDAY'}) {
            print 'selected=\'selected\' ';
        }
        print "value='$day'>$day</option>\n";
    }
    print <<END;
        </select>
        <select name='STARTMONTH'>
END

    foreach my $month (@TRAFFIC::months) {
        print "\t<option ";
        if ($month == $cgiparams{'STARTMONTH'}) {
            print 'selected=\'selected\' ';
        }
        print "value='$month'>$TRAFFIC::longmonths[$month]</option>\n";
    }

    print <<END;
        </select>
        <select name='STARTYEAR'>
END

    foreach my $year (@TRAFFIC::years) {
        print "\t<option ";
        if ($year == $cgiparams{'STARTYEAR'}) {
            print 'selected=\'selected\' ';
        }
        print "value='$year'>$year</option>\n";
    }

    print <<END;
        </select>
        $Lang::tr{'to'}
        <select name='STOPDAY'>
END

    foreach my $day (@days) {
        print "\t<option ";
        if ($day == $cgiparams{'STOPDAY'}) {
            print 'selected=\'selected\' ';
        }
        print "value='$day'>$day</option>\n";
    }

    print <<END;
        </select>
        <select name='STOPMONTH'>
END

    foreach my $month (@TRAFFIC::months) {
        print "\t<option ";
        if ($month == $cgiparams{'STOPMONTH'}) {
            print 'selected=\'selected\' ';
        }
        print "value='$month'>$TRAFFIC::longmonths[$month]</option>\n";
    }

    print <<END;
        </select>
        <select name='STOPYEAR'>
END

    foreach my $year (@TRAFFIC::years) {
        print "\t<option ";
        if ($year == $cgiparams{'STOPYEAR'}) {
            print 'selected=\'selected\' ';
        }
        print "value='$year'>$year</option>\n";
    }

    print <<END;
                </select>
               <input type='hidden' name='SHOW_PAGE' value='detailed' />
               <input type='submit' name='ACTION' value='$Lang::tr{'update'}' />
            </form>
        </td>
        <td width='5%' align='center'>
            <form method='post' action='/cgi-bin/traffic.cgi'>
                <input type='hidden' name='SHOW_PAGE' value='overview' />
                <input type='submit' name='ACTION' value='&lt;&lt;' />
            </form>
        </td>
        </tr>
        </table>
END

    &Header::closebox();

}    # detailed page

&Header::openbox('100%', 'left', "$Lang::tr{'traffics'}:");

my %devices     = ();
my %ifaceCounts = ();
my %interfaces  = ();
&DATA::setup_default_interfaces(\%interfaces, \%ifaceCounts);

&TRAFFIC::getDeviceNames(\%devices, \%interfaces);

# TODO: add rules for these and fix columnsize in case of more than 4 interfaces
delete($devices{'OPENVPN-RW'});
delete($devices{'IPSEC-RED'});
delete($devices{'IPSEC-BLUE'});

# columnsize for two networks
my $dateWidth    = '20%';
my $inOutWidth   = '17%';
my $monthlyWidth = '0%';

my $countDev = keys %devices;

# four networks
if ($countDev == 4) {
    $dateWidth  = '12%';
    $inOutWidth = '11%';

    if($showAllTraff && $TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on')
    {
        $dateWidth = '11%';
        $inOutWidth = '10%';
        $monthlyWidth = '10%';
    }
}

# three networks
elsif ($countDev == 3) {
    $dateWidth  = '16%';
    $inOutWidth = '14%';

    if($showAllTraff && $TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on')
    {
        $dateWidth = '14%';
        $inOutWidth = '12%';
        $monthlyWidth = '14%';
    }
}

elsif($showAllTraff && $TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on')
{
	# 2 networks but with show all
	$dateWidth = '18%';
	$inOutWidth = '16%';
	$monthlyWidth = '18%';
}

print <<END;
	<table width='100%'>
	<tr>
		<td width='$dateWidth' align='center' class='boldbase'></td>
END


my @sortedDeviceKeys = &getSortedDeviceKeys(\%devices, \%interfaces);

if($TRAFFIC::debugFormparams == 1) {
    foreach my $key (keys %devices) {
        print "key: $key<br />\n";
    }
    foreach my $key (@sortedDeviceKeys) {
        print "sorted: $key<br />\n";
    }
}

foreach my $device (@sortedDeviceKeys) {
    my $colspan = 2;

    if($showAllTraff==1) {
        if($interfaces{$devices{$device}}{'COLOR'} eq 'RED_COLOR'){
            $colspan = 3;
        }
    }

    print "<td align='center' class='boldbase' colspan='$colspan'><b>".&General::translateinterface($devices{$device})."</b></td>\n";
}

print <<END;
	</tr>
	<tr>
		<td width='$dateWidth' align='center' class='boldbase'><b>$Lang::tr{'date'}</b></td>
END

my %total_bytes = ();

my $redDevice = '';
foreach my $device (@sortedDeviceKeys) {
    my $color = '';

    my $txt_in = '';
    my $txt_out = '';

    if ($interfaces{$devices{$device}}{'COLOR'} eq 'RED_COLOR') {
        $color = 'ipcop_iface_red';
        $redDevice = $device;

        if($showAllTraff && $TRAFFIC::settings{'VOLUME_IN_ENABLED'} eq 'on') {
            $txt_in = "<br />($TRAFFIC::settings{'VOLUME_IN'} MB)";
        }
        if($showAllTraff && $TRAFFIC::settings{'VOLUME_OUT_ENABLED'} eq 'on') {
            $txt_out = "<br />($TRAFFIC::settings{'VOLUME_OUT'} MB)";
        }
    }
    elsif ($interfaces{$devices{$device}}{'COLOR'} eq 'ORANGE_COLOR') {
        $color = 'ipcop_iface_orange';
    }
    elsif ($interfaces{$devices{$device}}{'COLOR'} eq 'BLUE_COLOR') {
        $color = 'ipcop_iface_blue';
    }
    elsif ($interfaces{$devices{$device}}{'COLOR'} eq 'GREEN_COLOR') {
        $color = 'ipcop_iface_green';
    }

    print
"<td width='$inOutWidth' align='center' class='boldbase'><font class='$color'><b>$Lang::tr{'trafficin'} $txt_in</b></font></td>";
    print
"<td width='$inOutWidth' align='center' class='boldbase'><font class='$color'><b>$Lang::tr{'trafficout'} $txt_out</b></font></td>";

    # init total count
    $total_bytes{$device . "_TOTAL_IN"}  = 0;
    $total_bytes{$device . "_TOTAL_OUT"} = 0;
}

if($showAllTraff==1)
{
    my $vol_txt = '';
    if($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on' && $TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'} eq 'on') {
        $vol_txt = "<br />($TRAFFIC::settings{'VOLUME_TOTAL'} MB)";
    }
    print
"<td width='$inOutWidth' align='center' class='boldbase'><font class='ipcop_iface_red'><b>$Lang::tr{'trafficsum'} $vol_txt </b></font></td>";
}

print "</tr>\n";

my $startYear     = $cgiparams{'STARTYEAR'};
my $endYear       = $cgiparams{'STOPYEAR'};
my $startMonth    = $cgiparams{'STARTMONTH'};
my $endMonth      = $cgiparams{'STOPMONTH'};
my $displayMode   = "daily_multi";
my $startDay      = $cgiparams{'STARTDAY'};
my $endDay        = $cgiparams{'STOPDAY'};
my $selectedMonth = '0';

if($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on' && $cgiparams{'SHOW_PAGE'} ne 'detailed')
{
	$startDay = $TRAFFIC::settings{'STARTDAY'};
	$endDay = $TRAFFIC::settings{'STARTDAY'};
}

# "show All ?
if ($cgiparams{'STARTYEAR'} eq '????') {

    # 'show all month' + 'show all years'
    # OR <selected Month> + 'show all years'

    # if we have a <selected Month>, we read all traffic but display only the selected month
    if ($cgiparams{'STARTMONTH'} ne '??') {
        $selectedMonth = $cgiparams{'STARTMONTH'} + 1;
        $selectedMonth = $selectedMonth < 10 ? $selectedMonth = "0" . $selectedMonth : $selectedMonth;
    }

    $displayMode = "monthly";

    # start with 1970-01-01
    $startYear  = 1970;
    $startMonth = '1';
    $startDay   = '1';

    # end with next year: 20xx-01-01
    $endYear  = $now[5] + 1;
    $endMonth = '1';
    $endDay   = '1';
}
elsif ($cgiparams{'STARTMONTH'} eq '??') {

    # 'show all month' + 20xx
    $displayMode = "monthly";

    # start with 20xx-01-01
    $startMonth = '1';
    $startDay   = '1';

    # end with (20xx+1)-01-01
    $endYear  = $startYear + 1;
    $endMonth = '1';
    $endDay   = '1';
}
elsif ($cgiparams{'SHOW_PAGE'} eq 'detailed') {

    # detailed page
    # get real month instead of month index
    $startMonth++;
    $endMonth++;

    # we want to see the selected end day, so select everything smaller than endday+1
    $endDay++;
}
else {

    # no "Show All" (normal / overview page)
    $endYear  = $startYear;
    $endMonth = $startMonth;
    $endDay   = $startDay;

    $startMonth++;
    $endMonth = $endMonth + 2;

    # this periode started last month
    if ($now[3] < $startDay) {

        # when current month is january we start in last year december
        if ($endMonth == 13) {
            $endMonth = 1;
            $endYear++;
        }
    }
    else {

        # when we are in december, this periode ends next year january
        if ($startMonth == 12) {
            $endYear++;
            $endMonth = 1;
        }
    }
}

my $start = "";
my $end   = "";

if($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on'
    && $TRAFFIC::settings{'PERIOD_TYPE'} eq 'rollingWindow'
    && $cgiparams{'STARTMONTH'} eq 'rollingWindow'
    && $cgiparams{'SHOW_PAGE'} ne 'detailed')
{
    $end = &TRAFFIC::getEndtimeNow();
    $start = &TRAFFIC::getStarttimeMonth('rollingWindow');
}
else
{
    $startMonth = $startMonth < 10 ? $startMonth = "0" . $startMonth : $startMonth;
    $endMonth   = $endMonth < 10   ? $endMonth   = "0" . $endMonth   : $endMonth;
    $startDay   = $startDay < 10   ? $startDay   = "0" . $startDay   : $startDay;
    $endDay     = $endDay < 10     ? $endDay     = "0" . $endDay     : $endDay;

    $start = "$startYear$startMonth$startDay";
    $end   = "$endYear$endMonth$endDay";
}

my %allDaysBytes = ();
my @allDays = &TRAFFIC::calcTraffic(\%allDaysBytes, $start, $end, $displayMode, \%devices);

########
# DEBUG
########
#print "Start: $start <br /> End: $end <br /> \n";
########
# DEBUG
########

my $lines = 0;

my @days = sort keys %allDaysBytes;

if ($TRAFFIC::settings{'TRAFFIC_VIEW_REVERSE'} eq 'on') { @days = reverse @days; }

foreach (@days) {

    # special code for: <selected Month> + 'show all years'
    if (   $cgiparams{'STARTMONTH'} ne '??'
        && $cgiparams{'STARTYEAR'} eq '????'
        && $cgiparams{'SHOW_PAGE'} ne 'detailed')
    {

        # show only those traffic in the selected month
        if ($allDaysBytes{$_}{'Day'} !~ /^\d\d\d\d-$selectedMonth$/) {
            next;
        }
    }

    print "<tr class='table".int(($lines % 2) + 1)."colour'>";

    printf "<td align='center' nowrap='nowrap'>%s</td>\n", $allDaysBytes{$_}{'Day'};

    foreach my $device (@sortedDeviceKeys) {
        # init with 0 (bytes) in case we had no traffic on this interface for this day
        if (!defined($allDaysBytes{$_}{$device . "_IN"})) {
            $allDaysBytes{$_}{$device . "_IN"} = 0;
        }
        if (!defined($allDaysBytes{$_}{$device . "_OUT"})) {
            $allDaysBytes{$_}{$device . "_OUT"} = 0;
        }

        # init total count
        if (!defined($total_bytes{$device . "_TOTAL_IN"})) {
            $total_bytes{$device . "_TOTAL_IN"} = 0;
        }
        if (!defined($total_bytes{$device . "_TOTAL_OUT"})) {
            $total_bytes{$device . "_TOTAL_OUT"} = 0;
        }

        $total_bytes{$device . "_TOTAL_IN"}  += $allDaysBytes{$_}{$device . "_IN"};
        $total_bytes{$device . "_TOTAL_OUT"} += $allDaysBytes{$_}{$device . "_OUT"};

        my $vol_in = $allDaysBytes{$_}{$device . "_IN"} / 1048576;
        my $vol_out = $allDaysBytes{$_}{$device . "_OUT"} / 1048576;

        my $color_in = '';
        my $color_out = '';

        if($device eq $redDevice)
        {
            if($showAllTraff && $TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on' && $cgiparams{'SHOW_PAGE'} ne 'detailed')
            {
                if($TRAFFIC::settings{'VOLUME_IN_ENABLED'} eq 'on') {
                    $color_in = "bgcolor='".&getMonthlyVolumeColor($vol_in, $TRAFFIC::settings{'VOLUME_IN'} )."'";
                }
                if($TRAFFIC::settings{'VOLUME_OUT_ENABLED'} eq 'on') {
                    $color_out = "bgcolor='".&getMonthlyVolumeColor($vol_out, $TRAFFIC::settings{'VOLUME_OUT'} )."'";
                }
            }
        }

        printf "<td align='center' nowrap='nowrap' $color_in>%.3f</td>\n", $vol_in;
        printf "<td align='center' nowrap='nowrap' $color_out>%.3f</td>\n", $vol_out;
    }

    if($showAllTraff && $TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on' && $cgiparams{'SHOW_PAGE'} ne 'detailed')
    {
        my $total_red = ($allDaysBytes{$_}{$redDevice . "_IN"} + $allDaysBytes{$_}{$redDevice . "_OUT"})/1048576;
        my $color = '';

        if($TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'} eq 'on')
        {
            $color = "bgcolor='".&getMonthlyVolumeColor($total_red, $TRAFFIC::settings{'VOLUME_TOTAL'})."'";
        }

        printf("<td align='center' nowrap='nowrap' $color>%.2f</td>\n", $total_red);
    }
    print "</tr>\n";

    $lines++;
}

print "<tr class='table".int(($lines % 2) + 1)."colour'>";

my $txt = '';
my $total_red_in = sprintf("%.2f", ($total_bytes{$redDevice . "_TOTAL_IN"} / 1048576));
my $total_red_out = sprintf("%.2f", ($total_bytes{$redDevice . "_TOTAL_OUT"} / 1048576));
my $color_in = '';
my $color_out = '';


if($TRAFFIC::settings{'VOLUME_IN_ENABLED'} eq 'on') {
    $color_in = &getMonthlyVolumeColor($total_red_in, $TRAFFIC::settings{'VOLUME_IN'} );
    $txt = "$Lang::tr{'trafficin'} $TRAFFIC::settings{'VOLUME_IN'} MB";
}
if($TRAFFIC::settings{'VOLUME_OUT_ENABLED'} eq 'on') {
    $color_out = &getMonthlyVolumeColor($total_red_out, $TRAFFIC::settings{'VOLUME_OUT'} );
    if($txt ne '') {
        $txt .= ", ";
    }
    $txt .= "$Lang::tr{'trafficout'} $TRAFFIC::settings{'VOLUME_OUT'} MB";
}

print <<END;
	<td align='center' class='boldbase' height='20' nowrap='nowrap'><b>$Lang::tr{'trafficsum'}</b></td>
END

my $deviceColcount = 0;
foreach my $device (@sortedDeviceKeys) {
    $total_bytes{$device . "_TOTAL_IN"}  = sprintf("%.2f", ($total_bytes{$device . "_TOTAL_IN"} / 1048576));
    $total_bytes{$device . "_TOTAL_OUT"} = sprintf("%.2f", ($total_bytes{$device . "_TOTAL_OUT"} / 1048576));

    $deviceColcount += 2;

    if($device eq $redDevice
        && $TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on'
        && $cgiparams{'SHOW_PAGE'} ne 'detailed'
        && $showAllTraff==0)
    {
        print <<END;
	<td align='center' class='boldbase' nowrap='nowrap' bgcolor='$color_in'><b>$total_bytes{$device."_TOTAL_IN"} MB</b></td>
	<td align='center' class='boldbase' nowrap='nowrap' bgcolor='$color_out'><b>$total_bytes{$device."_TOTAL_OUT"} MB</b></td>
END
    }
    else {
        print <<END;
	<td align='center' class='boldbase' nowrap='nowrap'><b>$total_bytes{$device."_TOTAL_IN"} MB</b></td>
	<td align='center' class='boldbase' nowrap='nowrap'><b>$total_bytes{$device."_TOTAL_OUT"} MB</b></td>
END
    }

}

if($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on' && $cgiparams{'SHOW_PAGE'} ne 'detailed')
{
    my $total_red_all = sprintf("%.2f", ($total_bytes{$redDevice . "_TOTAL_IN"} + $total_bytes{$redDevice . "_TOTAL_OUT"}));

    if($showAllTraff==0)
    {
        my $colcount = 1 + $deviceColcount - 2;
        my $color_total = '';
        my $vol_total = '';
        if($TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'} eq 'on')
        {
            $color_total = &getMonthlyVolumeColor($total_red_all, $TRAFFIC::settings{'VOLUME_TOTAL'} );
            $vol_total = "<b>$total_red_all MB</b>";

            if($txt ne '') {
                $txt .= ", ";
            }
            $txt .= "$Lang::tr{'trafficsum'} $TRAFFIC::settings{'VOLUME_TOTAL'} MB";
        }

        print <<END;
        </tr>
        <tr>
            <td align='left' class='boldbase' height='20' nowrap='nowrap' colspan='$colcount'>
                <b>$Lang::tr{'monitor volume'} ($txt)</b>
            </td>
            <td align='center' class='boldbase' nowrap='nowrap' bgcolor='$color_total' colspan='2'>$vol_total</td>
END

    }
    else
    {
        print <<END;
            <td align='center' class='boldbase' nowrap='nowrap' ><b>$total_red_all MB</b></td>
END
    }

}
print "</tr>\n";

print <<END;
	</table>
END

&Header::closebox();

&Header::closebigbox();

&Header::closepage();


sub getSortedDeviceKeys
{
#&TRAFFIC::getDeviceNames(\%devices, \%interfaces);
    my $devices = shift;
    my $interfaces = shift;
    my @keysToSort =  ();

    my %sortOrder = ('GREEN_COLOR' => 0,
        'IPSEC_COLOR' => 1,
        'OVPN_COLOR' => 2,
        'BLUE_COLOR' => 3,
        'ORANGE_COLOR' => 4,
        'RED_COLOR' => 5);

    foreach my $key ( (keys %{$interfaces})) {
        #print " iface: $key <br />\n";
        if(defined($devices->{$interfaces->{$key}{'ID'}}) ) {
            push(@keysToSort, $key);
        }
    }

    my @sortedKeys = sort {
        #print " $a <=> $b : $sortOrder{$interfaces->{$a}{'COLOR'}} <=> $sortOrder{$interfaces->{$b}{'COLOR'}} <br />\n";
        #print " $a <=> $b : $interfaces->{$a}{'COLOR'} <=> $interfaces->{$b}{'COLOR'} <br />\n";
        $sortOrder{$interfaces->{$a}{'COLOR'}} <=> $sortOrder{$interfaces->{$b}{'COLOR'}}
        or $a cmp $b;
    } @keysToSort;

    my @sorted = ();
    foreach my $key (@sortedKeys) {
        push(@sorted, $interfaces->{$key}{'ID'});
    }

    return @sorted;
}


sub getMonthlyVolumeColor
{
    my $volume_red = shift;
    my $volume_allowed = shift;
    my $color = $TRAFFIC::colorOk;
    my $warnTraff = ($volume_allowed * $TRAFFIC::settings{'WARN'} / 100);

    if($TRAFFIC::settings{'WARN_ENABLED'} eq 'on'
        && $warnTraff < $volume_red)
    {
        $color = $TRAFFIC::colorWarn;
    }
    if($volume_allowed < $volume_red)
    {
        $color = $TRAFFIC::colorMax;
    }
    return $color;
}
