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
# (c) The SmoothWall Team
# Copyright (c) 2001-2016 The IPCop Team
#
# $Id: logsystem.cgi 8036 2016-01-04 08:03:32Z owes $
#

# Add entry in menu
# MENUENTRY logs 060 "system logs" "system log viewer"
#
# Make sure translation exists $Lang::tr{'system log viewer'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

use POSIX();

my %cgiparams    = ();
my %logsettings  = ();
my $errormessage = '';

my @now  = localtime();
my $dow  = $now[6];
my $doy  = $now[7];
my $tdoy = $now[7];
my $thisyear = $now[5] + 1900;

$cgiparams{'DAY'}     = $now[3];        # day. 0 (=all), 1, ... , 31
$cgiparams{'MONTH'}   = $now[4];        # month. 0 (=January), 1 (=February), ... , 11 (=December)
$cgiparams{'YEAR'}    = $now[5]+1900;   # year.
$cgiparams{'ACTION'}  = '';
$cgiparams{'SECTION'} = 'ipcop';

my %sections = (
    'ipcop' => '(ipcop|ipcopreboot\[\d+\]|sendEmail\[\d+\])',
    'red' =>
'(red|connectioncheck|kernel: usb.*|pppd\[\d+\]|chat\[\d+\]|pppoe\[\d+\]|pptp\[\d+\]|pppoa\[\d+\]|pppoa3\[\d+\]|pppoeci\[\d+\]|ipppd|ipppd\[\d+\]|kernel: ippp\d|kernel: isdn.*|ibod\[\d+\]|kernel: eth.*|dhcpcd\[\d*\]|modem_run\[\d+\])',
    'dns'            => '(dnsmasq\[\d+\])',
    'dhcp'           => '(dnsmasq-dhcp\[\d+\]|dhcpd)',
    'cron'           => '(fcron\[\d+\]|fcrontab\[\d+\])',
    'ntp'            => '(ntpd(?:ate)?\[\d+\])',
    'ssh'            => '(sshd(?:\(.*\))?\[\d+\])',
    'auth'           => '(\w+\(pam_unix\)\[\d+\]|login\\[\d+\])',
    'kernel'         => '(kernel)',
    'ipsec'          => '(vpn|ipsec|ipsec_[\w_]+|pluto\[\d+\]|vpn-watch)',
    'openvpn'        => '(vpn|openvpn|OVPN_.*|openvpnserver\[\d+\])',
    'squid'          => '(squid\[\d+\]|msnt_auth\[\d+\])',
    'squidguard'     => '(squidGuard\[\d+\])',
    'installpackage' => '(installpackage|installpackage\[urlfilter\])',
    'traffic'        => '(accountingctrl|aggregate|vnstatd\[\d+\])',
);

# Translations for the %sections array.
my %trsections = (
    'ipcop'          => 'IPCop',
    'red'            => 'RED',
    'dns'            => 'DNS',
    'dhcp'           => "$Lang::tr{'dhcp server'}",
    'cron'           => 'Cron',
    'ntp'            => 'NTP',
    'ssh'            => 'SSH',
    'auth'           => "$Lang::tr{'loginlogout'}",
    'kernel'         => "$Lang::tr{'kernel'}",
    'ipsec'          => 'IPsec',
    'openvpn'        => 'OpenVPN',
    'squid'          => "$Lang::tr{'proxy'}",
    'squidguard'     => "$Lang::tr{'url filter'}",
    'installpackage' => "$Lang::tr{'update transcript'}",
    'traffic'        => "$Lang::tr{'sstraffic'}",
);

&General::getcgihash(\%cgiparams);
$logsettings{'LOGVIEW_REVERSE'}  = 'off';
$logsettings{'LOGVIEW_VIEWSIZE'} = 150;
&General::readhash('/var/ipcop/logging/settings', \%logsettings);

my $start = ($logsettings{'LOGVIEW_REVERSE'} eq 'on') ? 0x7FFFF000 : 0;    #index of first line number to display

my @temp_then = ();
if ($ENV{'QUERY_STRING'} && $cgiparams{'ACTION'} ne $Lang::tr{'update'}) {
    @temp_then = split(',', $ENV{'QUERY_STRING'});
    $start                = $temp_then[0];
    $cgiparams{'YEAR'}    = $temp_then[1];
    $cgiparams{'MONTH'}   = $temp_then[2];
    $cgiparams{'DAY'}     = $temp_then[3];
    $cgiparams{'SECTION'} = $temp_then[4];
}

if (!($cgiparams{'MONTH'} =~ /^(0|1|2|3|4|5|6|7|8|9|10|11)$/)
    || !($cgiparams{'DAY'} =~
        /^(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)$/))
{
    $cgiparams{'YEAR'}  = $now[5]+1900;
    $cgiparams{'MONTH'} = $now[4];
    $cgiparams{'DAY'}   = $now[3];
}
elsif ($cgiparams{'ACTION'} eq '>>') {
    @temp_then = &General::calculatedate($cgiparams{'YEAR'}, $cgiparams{'MONTH'}, $cgiparams{'DAY'}, 1);
    $cgiparams{'YEAR'}  = $temp_then[5]+1900;
    $cgiparams{'MONTH'} = $temp_then[4];
    $cgiparams{'DAY'}   = $temp_then[3];
}
# There is a comma in FR button string
elsif (&Header::cleanhtml($cgiparams{'ACTION'},"y") eq $Lang::tr{'day today'}) {
    $cgiparams{'YEAR'}  = $now[5]+1900;
    $cgiparams{'MONTH'} = $now[4];
    $cgiparams{'DAY'}   = $now[3];
}
elsif ($cgiparams{'ACTION'} eq '<<') {
    @temp_then = &General::calculatedate($cgiparams{'YEAR'}, $cgiparams{'MONTH'}, $cgiparams{'DAY'}, -1);
    $cgiparams{'YEAR'}  = $temp_then[5]+1900;
    $cgiparams{'MONTH'} = $temp_then[4];
    $cgiparams{'DAY'}   = $temp_then[3];
}
else {
    @temp_then = &General::validatedate($cgiparams{'YEAR'}, $cgiparams{'MONTH'}, $cgiparams{'DAY'});
    $cgiparams{'YEAR'}  = $temp_then[5]+1900;
    $cgiparams{'MONTH'} = $temp_then[4];
    $cgiparams{'DAY'}   = $temp_then[3];
}

# Date to display
my $date = sprintf("%d-%02d-%02d", $cgiparams{'YEAR'}, $cgiparams{'MONTH'}+1, $cgiparams{'DAY'});

my $monthstr = $General::shortMonths[ $cgiparams{'MONTH'} ];
my $daystr   = $cgiparams{'DAY'} == 0 ? '..' : $cgiparams{'DAY'} <= 9 ? " $cgiparams{'DAY'}" : "$cgiparams{'DAY'}";
my $section  = $sections{$cgiparams{'SECTION'}};

my $lines = 0;
my @log   = ();

my $loop    = 1;
my $filestr = 0;
my $lastdatetime;    # for debug
my $search_for_end = 0;
my $day_extension = ($cgiparams{'DAY'} == 0 ? 1: $cgiparams{'DAY'});

while ($loop) {

    # calculate file name
    my $gzindex;
    if (($cgiparams{'MONTH'} eq $now[4]) && ($day_extension eq $now[3])) {
        $filestr = "/var/log/messages";
        $loop = 0;
    }
    else {
        $filestr = sprintf("/var/log/messages-%d%02d%02d", $cgiparams{'YEAR'}, $cgiparams{'MONTH'}+1, $day_extension);
        $filestr = "${filestr}.gz" if -f "${filestr}.gz";
    }

    # now read file if existing
    if (open(FILE, ($filestr =~ /.gz$/ ? "gzip -dc $filestr |" : $filestr))) {

        #&General::log("reading $filestr");
        READ: while (<FILE>) {
            my $line = $_;
            if ($line =~ /^${monthstr} ${daystr} ..:..:.. [\w\-]+ ${section}: (.*)/) {
                # when standard viewing, just keep in memory the correct slice
                # it starts a '$start' and size is $viewport
                # If export, then keep all lines...
                if ($cgiparams{'ACTION'} eq $Lang::tr{'export'}) {
                    $log[ $lines++ ] = "$line";
                }
                else {
                    if ($lines++ < ($start + $logsettings{'LOGVIEW_VIEWSIZE'})) {
                        push(@log, "$line");
                        if (@log > $logsettings{'LOGVIEW_VIEWSIZE'}) {
                            shift(@log);
                        }

                        #} else { dont do this optimisation, need to count lines !
                        #    $datetime = $maxtime; # we have read viewsize lines, stop main loop
                        #    last READ;           # exit read file
                    }
                }
                $search_for_end = 1;    # we find the start of slice, can look for end now
            }
            else {
                if ($search_for_end == 1) {

                    # finish read files when date is over (test month equality only)
                    $line =~ /^(...) (..) ..:..:..*$/;
                    $loop = 0 if (($1 ne $monthstr) || (($daystr ne '..') && ($daystr ne $2)));
                }
            }
        }
        close(FILE);
    }
    $day_extension++;
    if ($day_extension > 31) {
        $loop = 0;
    }
}   # while

#  $errormessage = "$Lang::tr{'date not in logs'}: $filestr $Lang::tr{'could not be opened'}";

if ($cgiparams{'ACTION'} eq $Lang::tr{'export'}) {
    print "Content-type: text/plain\n";
    # Use short identifier in filename instead of translation, so the filename is not broken.
    print "Content-Disposition: attachment; filename=\"ipcop-$cgiparams{'SECTION'}-$date.log\";\n";
    print "\n";
    print "IPCop diagnostics\r\n";
    print "$Lang::tr{'section'}: $trsections{$cgiparams{'SECTION'}}\n";
    print "$Lang::tr{'date'}: $date\r\n\r\n";

    # Do not reverse log when exporting
    # if ($logsettings{'LOGVIEW_REVERSE'} eq 'on') { @log = reverse @log; }

    foreach $_ (@log) {
        /^... (..) (..:..:..) [\w\-]+ ${section}: (.*)$/;
        my $day = $1;
        $day =~ tr / /0/;
        my $time = $cgiparams{'DAY'} ? "$2" : "$day/$2";
        print "$time $3 $4\r\n";
    }
    exit 0;
}

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'system logs'}, 1, '');

&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();
}

&Header::openbox('100%', 'left', "$Lang::tr{'settings'}:");

print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='50%' class='base' nowrap='nowrap'>$Lang::tr{'year'}:&nbsp;
    <select name='YEAR'>
END
    ;
for (my $year = $thisyear-2; $year <= $thisyear; $year++) {
    print "\t<option ";
    if ($year == $cgiparams{'YEAR'}) {
        print "selected='selected' ";
    }
    print "value='$year'>$year</option>\n";
}
print <<END
    </select>
    &nbsp;&nbsp;$Lang::tr{'month'}:&nbsp;
    <select name='MONTH'>
END
    ;
for (my $month = 0; $month < 12; $month++) {
    print "\t<option ";
    if ($month == $cgiparams{'MONTH'}) {
        print "selected='selected' ";
    }
    print "value='$month'>$Lang::tr{$General::longMonths[$month]}</option>\n";
}
print <<END
    </select>
    &nbsp;&nbsp;$Lang::tr{'day'}:&nbsp;
    <select name='DAY'>
END
    ;
print "<option value='0'>$Lang::tr{'all'}</option>\n";
for (my $day = 1; $day <= 31; $day++) {
    print "\t<option ";
    if ($day == $cgiparams{'DAY'}) {
        print "selected='selected' ";
    }
    print "value='$day'>$day</option>\n";
}
print <<END
    </select>
    </td>
    <td width='45%'  align='center'>
        <input type='submit' name='ACTION' title='$Lang::tr{'day before'}' value='&lt;&lt;' />
        <input type='submit' name='ACTION' value='$Lang::tr{'day today'}' />
        <input type='submit' name='ACTION' title='$Lang::tr{'day after'}' value='&gt;&gt;' />
        <input type='submit' name='ACTION' value='$Lang::tr{'update'}' />
        <input type='submit' name='ACTION' value='$Lang::tr{'export'}' />
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/logs-system.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
<hr />
<table>
<tr>
    <td class='base' nowrap='nowrap'>$Lang::tr{'section'}:&nbsp;
    <select name='SECTION' onchange='this.form.submit()'>
END
    ;
foreach $section (sort {$trsections{$a} cmp $trsections{$b}} keys %sections) {
    print "\t<option ";
    if ($section eq $cgiparams{'SECTION'}) {
        print "selected='selected' ";
    }
    print "value='$section'>$trsections{$section}</option>\n";
}
print <<END
    </select>
    </td>
</tr>
</table>
</form>
END
    ;

&Header::closebox();

&Header::openbox('100%', 'left', "$Lang::tr{'log'}:");
print "<p><b>$Lang::tr{'total hits for log section'} $trsections{$cgiparams{'SECTION'}}, $date: $lines</b></p>";

$start = $lines - $logsettings{'LOGVIEW_VIEWSIZE'} if ($start >= $lines - $logsettings{'LOGVIEW_VIEWSIZE'});
$start = 0 if ($start < 0);

my $prev;
if ($start == 0) {
    $prev = -1;
}
else {
    $prev = $start - $logsettings{'LOGVIEW_VIEWSIZE'};
    $prev = 0 if ($prev < 0);
}

my $next;
if ($start == $lines - $logsettings{'LOGVIEW_VIEWSIZE'}) {
    $next = -1;
}
else {
    $next = $start + $logsettings{'LOGVIEW_VIEWSIZE'};
    $next = $lines - $logsettings{'LOGVIEW_VIEWSIZE'} if ($next >= $lines - $logsettings{'LOGVIEW_VIEWSIZE'});
}

if ($logsettings{'LOGVIEW_REVERSE'} eq 'on') { @log = reverse @log; }
if ($lines != 0) { &oldernewer(); }

print <<END
<table width='100%'>
<tr>
    <td width='10%' align='center' class='boldbase'><b>$Lang::tr{'time'}</b></td>
    <td width='15%' align='center' class='boldbase'><b>$Lang::tr{'section'}</b></td>
    <td width='75%'>&nbsp;</td>
</tr>
END
    ;

$lines = 0;

#print '<tt>';
foreach $_ (@log) {
    /^... (..) (..:..:..) [\w\-]+ ${section}: (.*)$/;
    my $day = $1;
    $day =~ tr / /0/;
    my $time = $cgiparams{'DAY'} ? "$2" : "$day/$2";
    my $sec  = $3;
    my $data = $4;

    # correct the cut position, just when section=RED
    if (($cgiparams{'SECTION'} eq 'red') && ($sec =~ /(kernel:)(.*)/)) {
        $sec  = 'kernel';
        $data = $2 . ': ' . $data;
    }
    my $d = substr($data, 0, 80);
    while (length($data) > 80) {
        $data = substr($data, 80);
        # Insert a space if none found in last 25 characters to aid line breaking
        $d .= ' ' if (index(substr($d, -25), ' ') == -1);
        $d .= substr($data, 0, 80);
    }

    print "<tr class='table".int(($lines % 2) + 1)."colour'>";
    print "<td>$time</td><td>$sec</td><td>" . &Header::cleanhtml("$d", 'y') . "</td></tr>\n";
    $lines++;
}

#print '</tt>';
print "</table>";

&oldernewer();

&Header::closebox();

&Header::closebigbox();

&Header::closepage();

sub oldernewer {
    print <<END
<table width='100%'>
<tr>
    <td align='center' width='50%'>
END
;

    if ($prev != -1) {
        print "<a href='/cgi-bin/logsystem.cgi?$prev,$cgiparams{'YEAR'},$cgiparams{'MONTH'},$cgiparams{'DAY'},$cgiparams{'SECTION'}'>$Lang::tr{'older'}</a>";
    }
    else {
        print "$Lang::tr{'older'}";
    }
    print "</td>\n";

    print "<td align='center' width='50%'>";
    if ($next >= 0) {
        print "<a href='/cgi-bin/logsystem.cgi?$next,$cgiparams{'YEAR'},$cgiparams{'MONTH'},$cgiparams{'DAY'},$cgiparams{'SECTION'}'>$Lang::tr{'newer'}</a>";
    }
    else {
        print "$Lang::tr{'newer'}";
    }

    print <<END
    </td>
</tr>
</table>
END
;
}
