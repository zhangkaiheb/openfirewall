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
# Copyright (c) 2014-2018 The Openfirewall Team
#

# Add entry in menu
# MENUENTRY logs 040 "proxy logs" "proxy log viewer" haveProxy
#
# Make sure translation exists $Lang::tr{'proxy logs'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

use POSIX();

my %cgiparams    = ();
my %logsettings  = ();
my %ips          = ();
my %users        = ();
my %selected     = ();
my %checked      = ();
my @log          = ();
my $errormessage = '';

my @now  = localtime();
my $dow  = $now[6];          # day of week
my $doy  = $now[7];          # day of year (0..364)
my $tdoy = $now[7];
my $thisyear = $now[5] + 1900;

$cgiparams{'DAY'}     = $now[3];        # day. 0 (=all), 1, ... , 31
$cgiparams{'MONTH'}   = $now[4];        # month. 0 (=January), 1 (=February), ... , 11 (=December)
$cgiparams{'YEAR'}    = $now[5]+1900;   # year.
$cgiparams{'SOURCE_IP'}     = 'ALL';
$cgiparams{'USERNAME'}      = 'ALL';
$cgiparams{'FILTER'}        = "[.](gif|jpeg|jpg|png|css|js)\$";
$cgiparams{'ENABLE_FILTER'} = 'off';
$cgiparams{'ACTION'}        = '';

&General::getcgihash(\%cgiparams);
$logsettings{'LOGVIEW_REVERSE'}  = 'off';
$logsettings{'LOGVIEW_VIEWSIZE'} = 150;
&General::readhash('/var/ofw/logging/settings', \%logsettings);

if ($cgiparams{'ACTION'} eq '') {
    my %save = ();
    &General::readhash('/var/ofw/proxy/viewersettings', \%save)
        if (-e '/var/ofw/proxy/viewersettings');
    $cgiparams{'FILTER'}        = $save{'FILTER'}        if (exists($save{'FILTER'}));
    $cgiparams{'ENABLE_FILTER'} = $save{'ENABLE_FILTER'} if (exists($save{'ENABLE_FILTER'}));
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'restore defaults'}) {
    $cgiparams{'SOURCE_IP'}     = 'ALL';
    $cgiparams{'USERNAME'}      = 'ALL';
    $cgiparams{'FILTER'}        = "[.](gif|jpeg|jpg|png|css|js)\$";
    $cgiparams{'ENABLE_FILTER'} = 'off';
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'save'}) {
    my %save = ();
    $save{'FILTER'}        = $cgiparams{'FILTER'};
    $save{'ENABLE_FILTER'} = $cgiparams{'ENABLE_FILTER'};
    &General::writehash('/var/ofw/proxy/viewersettings', \%save);
}

my $start = ($logsettings{'LOGVIEW_REVERSE'} eq 'on') ? 0x7FFFF000 : 0;    #index of first line number to display

my @temp_then = ();
if ($ENV{'QUERY_STRING'} && $cgiparams{'ACTION'} ne $Lang::tr{'update'}) {
    @temp_then = split(',', $ENV{'QUERY_STRING'});
    $start                  = $temp_then[0];
    $cgiparams{'YEAR'}      = $temp_then[1];
    $cgiparams{'MONTH'}     = $temp_then[2];
    $cgiparams{'DAY'}       = $temp_then[3];
    $cgiparams{'SECTION'}   = $temp_then[4];
    $cgiparams{'SOURCE_IP'} = $temp_then[5];
    $cgiparams{'USERNAME'}  = $temp_then[6];
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

my $filter    = $cgiparams{'ENABLE_FILTER'} eq 'on' ? $cgiparams{'FILTER'} : '';
my $sourceip  = $cgiparams{'SOURCE_IP'};
my $sourceall = $cgiparams{'SOURCE_IP'} eq 'ALL' ? 1 : 0;
my $username  = $cgiparams{'USERNAME'};
my $usersall  = $cgiparams{'USERNAME'} eq 'ALL' ? 1 : 0;

my $lines    = 0;
my $temp     = ();
my $thiscode = '$temp =~ /$filter/;';
eval($thiscode);
if ($@ ne '') {
    $errormessage = "$Lang::tr{'bad ignore filter'}:.$@<P>";
    $filter       = '';
}
else {
    my $loop    = 1;
    my $filestr = 0;
    my $lastdatetime;    # for debug
    my $day_extension = ($cgiparams{'DAY'} == 0 ? 1: $cgiparams{'DAY'});

    while ($loop) {

        my $gzindex;
        if (($cgiparams{'MONTH'} eq $now[4]) && ($day_extension eq $now[3])) {
            $filestr = "/var/log/squid/access.log";
            $loop = 0;
        }
        else {
            $filestr = sprintf("/var/log/squid/access.log-%d%02d%02d", $cgiparams{'YEAR'}, $cgiparams{'MONTH'}+1, $day_extension);
            $filestr = "${filestr}.gz" if -f "${filestr}.gz";
        }

        # now read file if existing
        if (open(FILE, ($filestr =~ /.gz$/ ? "gzip -dc $filestr |" : $filestr))) {

            #&General::log("reading $filestr");
            my @temp_now = localtime(time);
            $temp_now[4] = $cgiparams{'MONTH'};
            $temp_now[3] = $cgiparams{'DAY'};
            if (   ($cgiparams{'MONTH'} eq $now[4]) && ($cgiparams{'DAY'} > $now[3])
                || ($cgiparams{'MONTH'} > $now[4]))
            {
                $temp_now[5]--;    # past year
            }

            $temp_now[2] = $temp_now[1] = $temp_now[0] = 0;    # start at 00:00:00
            $temp_now[3] = 1 if ($cgiparams{'DAY'} == 0);      # All days selected, start at '1'
            my $mintime = POSIX::mktime(@temp_now);
            my $maxtime;
            if ($cgiparams{'DAY'} == 0) {                      # full month
                if ($temp_now[4]++ == 12) {
                    $temp_now[4] = 0;
                    $temp_now[5]++;
                }
                $maxtime = POSIX::mktime(@temp_now);
            }
            else {
                $maxtime = $mintime + 86400;                   # full day
            }
        READ: while (<FILE>) {
                my ($datetime, $do, $ip, $ray, $me, $far, $url, $so) = split;
                $ips{$ip}++;
                $users{$so}++;

                # for debug
                #$lastdatetime = $datetime;

                # collect lines between date && filter
                if (   (($datetime > $mintime) && ($datetime < $maxtime))
                    && !($url =~ /$filter/)
                    && ((($ip eq $sourceip) || $sourceall))
                    && ((($so eq $username) || $usersall)))
                {

                    # when standard viewing, just keep in memory the correct slices
                    # it starts a '$start' and size is $viewport
                    # If export, then keep all lines...
                    if ($cgiparams{'ACTION'} eq $Lang::tr{'export'}) {
                        $log[ $lines++ ] = "$datetime $ip $so $url";
                    }
                    else {
                        if ($lines++ < ($start + $logsettings{'LOGVIEW_VIEWSIZE'})) {
                            push(@log, "$datetime $ip $so $url");
                            if (@log > $logsettings{'LOGVIEW_VIEWSIZE'}) {
                                shift(@log);
                            }

                            #} else { dont do this optimisation, need to count lines !
                            #    $datetime = $maxtime; # we have read viewsize lines, stop main loop
                            #    last READ;		  # exit read file
                        }
                    }
                }

                # finish loop when date of lines are past maxtime
                $loop = ($datetime < $maxtime);
            }
            close(FILE);
        }
        $day_extension++;
        if ($day_extension > 31) {
            $loop = 0;
        }
    }

    #$errormessage="$errormessage$Lang::tr{'date not in logs'}: $filestr $Lang::tr{'could not be opened'}";
    if (0) {           # print last date record read
        my ($SECdt, $MINdt, $HOURdt, $DAYdt, $MONTHdt, $YEARdt) = localtime($lastdatetime);
        $SECdt   = sprintf("%.02d", $SECdt);
        $MINdt   = sprintf("%.02d", $MINdt);
        $HOURdt  = sprintf("%.02d", $HOURdt);
        $DAYdt   = sprintf("%.02d", $DAYdt);
        $MONTHdt = sprintf("%.02d", $MONTHdt + 1);
        $YEARdt  = sprintf("%.04d", $YEARdt + 1900);
        &General::log("$HOURdt:$MINdt:$SECdt, $DAYdt/$MONTHdt/$YEARdt--");
    }
}

if ($cgiparams{'ACTION'} eq $Lang::tr{'export'}) {
    print "Content-type: text/plain\n";
    print "Content-Disposition: attachment; filename=\"ipcop-proxy-$date.log\";\n";
    print "\n";
    print "Openfirewall proxy log\r\n";
    print "$Lang::tr{'date'}: $date\r\n";
    print "$Lang::tr{'source ip'}: $cgiparams{'SOURCE_IP'}\r\n";
    print "$Lang::tr{'username'}: $cgiparams{'USERNAME'}\r\n";
    if ($cgiparams{'ENABLE_FILTER'} eq 'on') {
        print "Ignore filter: $cgiparams{'FILTER'}\r\n";
    }
    print "\r\n";

    # Do not reverse log when exporting
    #if ($logsettings{'LOGVIEW_REVERSE'} eq 'on') { @log = reverse @log; }

    foreach $_ (@log) {
        my ($datetime, $ip, $so, $url) = split;
        my ($SECdt, $MINdt, $HOURdt, $DAYdt, $MONTHdt, $YEARdt) = localtime($datetime);
        $SECdt  = sprintf("%.02d", $SECdt);
        $MINdt  = sprintf("%.02d", $MINdt);
        $HOURdt = sprintf("%.02d", $HOURdt);
        if ($cgiparams{'DAY'} == 0) {    # full month
            $DAYdt = sprintf("%.02d", $DAYdt);
            print "$DAYdt/$HOURdt:$MINdt:$SECdt $ip $so $url\n";
        }
        else {
            print "$HOURdt:$MINdt:$SECdt $ip $so $url\n";
        }
    }
    exit;
}

$selected{'SOURCE_IP'}{$cgiparams{'SOURCE_IP'}} = "selected='selected'";
$selected{'USERNAME'}{$cgiparams{'USERNAME'}} = "selected='selected'";

$checked{'ENABLE_FILTER'}{'off'}                       = '';
$checked{'ENABLE_FILTER'}{'on'}                        = '';
$checked{'ENABLE_FILTER'}{$cgiparams{'ENABLE_FILTER'}} = "checked='checked'";

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'proxy log viewer'}, 1, '');

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
        <a href='${General::adminmanualurl}/logs-proxy.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td width='25%' class='base'>$Lang::tr{'source ip'}:</td>
    <td width='25%' class='base'>
    <select name='SOURCE_IP'>
    <option value='ALL' $selected{'SOURCE_IP'}{'ALL'}>$Lang::tr{'caps all'}</option>
END
;
foreach my $ip (keys %ips) {
    print "<option value='$ip' $selected{'SOURCE_IP'}{$ip}>$ip</option>\n";
}
print <<END
    </select>
    </td>
    <td width='25%' class='base'>$Lang::tr{'username'}:</td>
    <td width='25%' class='base'>
    <select name='USERNAME'>
    <option value='ALL' $selected{'USERNAME'}{'ALL'}>$Lang::tr{'caps all'}</option>
END
;
foreach my $so (sort keys %users) {
    print "<option value='$so' $selected{'USERNAME'}{$so}>$so</option>\n";
}
print <<END
    </select>
    </td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'enable ignore filter'}:</td>
    <td colspan='3'><input type='checkbox' name='ENABLE_FILTER' value='on' $checked{'ENABLE_FILTER'}{'on'} /></td>
</tr>
<tr>
	<td width='25%' class='base'>$Lang::tr{'ignore filter'}:</td>
	<td><input type='text' name='FILTER' value='$cgiparams{'FILTER'}' size='40' /></td>
	<td colspan='2' align='center'>
		<input type='submit' name='ACTION' value='$Lang::tr{'restore defaults'}' />&nbsp;
		<input type='submit' name='ACTION' value='$Lang::tr{'save'}' />
	</td>
</tr>
</table>
</form>
END
    ;

&Header::closebox();
&Header::openbox('100%', 'left', "$Lang::tr{'log'}:");

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

print "<p><b>$Lang::tr{'web hits'} $date: $lines</b></p>";
if ($lines != 0) { &oldernewer(); }
print <<END
<table width='100%'>
<tr>
<td width='10%' align='center' class='boldbase'><b>$Lang::tr{'time'}</b></td>
<td width='15%' align='center' class='boldbase'><b>$Lang::tr{'source ip'}</b></td>
<td width='15%' align='center' class='boldbase'><b>$Lang::tr{'username'}</b></td>
<td width='60%' align='center' class='boldbase'><b>$Lang::tr{'website'}</b></td>
</tr>
END
    ;
my $ll = 0;
foreach $_ (@log) {
    print "<tr class='table".int(($ll % 2) + 1)."colour'>";
    my ($datetime, $ip, $so, $url) = split;
    my ($SECdt, $MINdt, $HOURdt, $DAYdt, $MONTHdt, $YEARdt) = localtime($datetime);
    $SECdt  = sprintf("%.02d", $SECdt);
    $MINdt  = sprintf("%.02d", $MINdt);
    $HOURdt = sprintf("%.02d", $HOURdt);

    $url =~ /(^.{0,90})/;
    my $part = $1;
    unless (length($part) < 90) { $part = "${part}..."; }
    $url  = &Header::cleanhtml($url,  "y");
    $part = &Header::cleanhtml($part, "y");
    if ($cgiparams{'DAY'} == 0) {    # full month
        $DAYdt = sprintf("%.02d/", $DAYdt);
    }
    else {
        $DAYdt = '';
    }
    print <<END
    <td align='center'>$DAYdt$HOURdt:$MINdt:$SECdt</td>
    <td align='center'>$ip</td>
    <td align='center'>$so</td>
    <td align='left'><a href='$url' title='$url' target='_blank'>$part</a></td>
</tr>
END
    ;
    $ll++;
}

print "</table>";

&oldernewer();

&Header::closebox();

&Header::closebigbox();

&Header::closepage();

sub oldernewer {
    print <<END
<table width='100%'>
<tr>
END
        ;

    print "<td align='center' width='50%'>";
    if ($prev != -1) {
        print
"<a href='/cgi-bin/logproxy.cgi?$prev,$cgiparams{'YEAR'},$cgiparams{'MONTH'},$cgiparams{'DAY'},$cgiparams{'SOURCE_IP'},$cgiparams{'USERNAME'}'>$Lang::tr{'older'}</a>";
    }
    else {
        print "$Lang::tr{'older'}";
    }
    print "</td>\n";

    print "<td align='center' width='50%'>";
    if ($next >= 0) {
        print
"<a href='/cgi-bin/logproxy.cgi?$next,$cgiparams{'YEAR'},$cgiparams{'MONTH'},$cgiparams{'DAY'},$cgiparams{'SOURCE_IP'},$cgiparams{'USERNAME'}'>$Lang::tr{'newer'}</a>";
    }
    else {
        print "$Lang::tr{'newer'}";
    }
    print "</td>\n";

    print <<END
</tr>
</table>
END
        ;
}

