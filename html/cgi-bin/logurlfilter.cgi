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
# (c) 2018-2019 The Openfirewall Team
#
#

# Add entry in menu
# MENUENTRY logs 050 "urlfilter logs" "urlfilter log viewer" haveProxy
#
# Make sure translation exists $Lang::tr{'urlfilter logs'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

use POSIX();

my $logdir = "/var/log/squidGuard";

my %cgiparams=();
my %logsettings=();
my %filtersettings=();

my $errormessage='';

my @ip=();
my %ips=();
my @category=();
my %categories=();
my %usernames=();

my @now  = localtime();
my $thisyear = $now[5] + 1900;

$cgiparams{'ACTION'} = '';

$cgiparams{'DAY'}     = $now[3];        # day. 0 (=all), 1, ... , 31
$cgiparams{'MONTH'}   = $now[4];        # month. 0 (=January), 1 (=February), ... , 11 (=December)
$cgiparams{'YEAR'}    = $now[5]+1900;   # year.
$cgiparams{'CATEGORY'} = 'ALL';
$cgiparams{'SOURCE_IP'} = 'ALL';
$cgiparams{'USERNAME'} = 'ALL';

&General::getcgihash(\%cgiparams);
$logsettings{'LOGVIEW_REVERSE'} = 'off';
$logsettings{'LOGVIEW_VIEWSIZE'} = 150;
&General::readhash("/var/ofw/logging/settings", \%logsettings);

if (-e "/var/ofw/proxy/filtersettings") {
    &General::readhash("/var/ofw/proxy/filtersettings", \%filtersettings);
}

my $start = 0;

my @temp_then = ();
if ($ENV{'QUERY_STRING'} && $cgiparams{'ACTION'} ne $Lang::tr{'update'}) {
    @temp_then = split(',', $ENV{'QUERY_STRING'});
    @temp_then = split(',', $ENV{'QUERY_STRING'});
    $start                  = $temp_then[0];
    $cgiparams{'YEAR'}      = $temp_then[1];
    $cgiparams{'MONTH'}     = $temp_then[2];
    $cgiparams{'DAY'}       = $temp_then[3];
    $cgiparams{'CATEGORY'}  = $temp_then[4];
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

my $monthstr = $General::shortMonths[ $cgiparams{'MONTH'} ];
my $daystr   = $cgiparams{'DAY'} == 0 ? '..' : $cgiparams{'DAY'} <= 9 ? " $cgiparams{'DAY'}" : "$cgiparams{'DAY'}";

my @log   = ();

&processevent;

if ($cgiparams{'ACTION'} eq $Lang::tr{'export'}) {
    print "Content-type: text/plain\n";
    print "Content-Disposition: attachment; filename=\"ofw-urlfilter-$date.log\";\n";
    print "\n";
    print "Openfirewall URL filter log\r\n";
    print "$Lang::tr{'date'}: $date\r\n\r\n";
    print "Category: $cgiparams{'CATEGORY'}\r\n";
    print "Client: $cgiparams{'SOURCE_IP'}\r\n";
    if ($filtersettings{'ENABLE_USERNAME_LOG'} eq 'on') {
        print "Username: $cgiparams{'USERNAME'}\r\n";
    }

    print "\r\n";

    # Do not reverse log when exporting
    # if ($logsettings{'LOGVIEW_REVERSE'} eq 'on') { @log = reverse @log; }

    foreach $_ (@log) {
        my ($date,$time,$pid,@loginfo) = split(/ /);
        chomp(@loginfo);
        @ip = split(/\//,$loginfo[2]);
        @category = split(/\//,$loginfo[0]);
        my $dsturl = $loginfo[1];
        $loginfo[3] =~ s/\%5c/\\/;
        if ((($cgiparams{'CATEGORY'}  eq 'ALL') || ($category[1] eq $cgiparams{'CATEGORY'})) &&
            (($cgiparams{'SOURCE_IP'} eq 'ALL') || ($ip[0] eq $cgiparams{'SOURCE_IP'})) &&
            (($cgiparams{'USERNAME'}  eq 'ALL') || ($loginfo[3] eq $cgiparams{'USERNAME'})))
        {
            print "$date ";
            print "$time ";
            print "$category[1] ";
            print "$ip[0] ";
            if ($filtersettings{'ENABLE_USERNAME_LOG'} eq 'on') {
                print "$loginfo[3] ";
            }
            print "$dsturl";
            print "\n";

        }
    }

    exit;
}

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'urlfilter log viewer'}, 1, '');

&Header::openbigbox('100%', 'left', '');

if ($errormessage) {
    &Header::openbox('100%', 'left', $Lang::tr{'error messages'}, 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();
}

&Header::openbox('100%', 'left', "$Lang::tr{'settings'}:");

print <<END
<form method='post' action="$ENV{'SCRIPT_NAME'}">
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
    <td width='45%'>
        <input type='submit' name='ACTION' title='$Lang::tr{'day before'}' value='&lt;&lt;' />
        <input type='submit' name='ACTION' value='$Lang::tr{'day today'}' />
        <input type='submit' name='ACTION' title='$Lang::tr{'day after'}' value='&gt;&gt;' />
        <input type='submit' name='ACTION' value='$Lang::tr{'update'}' />&nbsp;
        <input type='submit' name='ACTION' value='$Lang::tr{'export'}' />
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/logs-urlfilter.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
<hr />
<table>
END
;

my $selectedAllCat = '';
if($cgiparams{'CATEGORY'} eq 'ALL') {
    $selectedAllCat = "selected='selected'";
}

print <<END
<tr>
    <td width='25%' class='base' nowrap='nowrap'>$Lang::tr{'category'}:&nbsp;</td>
    <td width='25%' class='base'>
        <select name='CATEGORY'>
            <option value='ALL' $selectedAllCat>$Lang::tr{'caps all'}</option>
END
;
foreach my $cat (sort(keys %categories)) {
    my $selected = '';
    if($cat eq $cgiparams{'CATEGORY'}) {
        $selected = "selected='selected'";
    }
    print "<option value='$cat' $selected>$cat</option>\n";
}
print <<END
        </select>
    </td>
    <td width='25%' class='base' nowrap='nowrap'>$Lang::tr{'client'}:&nbsp;</td>
    <td width='25%' class='base'>
END
;

my $selectedAllSrcIp = '';
if($cgiparams{'SOURCE_IP'} eq 'ALL') {
    $selectedAllSrcIp = "selected='selected'";
}

print <<END
    <select name='SOURCE_IP'>
    <option value='ALL' $selectedAllSrcIp>$Lang::tr{'caps all'}</option>
END
;
foreach my $ipaddr (sort(keys %ips)) {
    my $selected = '';
    if($ipaddr eq $cgiparams{'SOURCE_IP'}) {
        $selected = "selected='selected'";
    }

print "<option value='$ipaddr' $selected>$ipaddr</option>\n"; }
print <<END
    </select>
    </td>
    <td class='base' nowrap='nowrap'>
END
;

if ($filtersettings{'ENABLE_USERNAME_LOG'} eq 'on') {
    print "$Lang::tr{'username'}:&nbsp;\n";
}

print <<END
    </td>
    <td width='30%'>
END
;
if ($filtersettings{'ENABLE_USERNAME_LOG'} eq 'on') {
    my $selectedAllUser = '';
    if($cgiparams{'USERNAME'} eq 'ALL') {
        $selectedAllUser = "selected='selected'";
    }
     print <<END
   <select name='USERNAME'>
        <option value='ALL' $selectedAllUser>$Lang::tr{'caps all'}</option>
END
;
    foreach my $user (sort(keys %usernames)) {
        my $selected = '';
        if($user eq $cgiparams{'USERNAME'}) {
            $selected = "selected='selected'";
        }

        print "<option value='$user' $selected>$user</option>\n";
    }
    print "</select>\n";
}


print <<END
        </td>
    </tr>
</table>
</form>
END
;

&Header::closebox();

&Header::openbox('100%', 'left', $Lang::tr{'log'});

my $lines = @log;
my $offset = $logsettings{'LOGVIEW_VIEWSIZE'};

if(($start + $offset) > $lines) {
    $offset = $lines - $start;
}

my $prev;
if ($start == 0) {
    $prev = -1;
}
else {
    $prev = $start - $logsettings{'LOGVIEW_VIEWSIZE'};
    $prev = 0 if ($prev < 0);
}

my $next;
if ($start >= $lines - $logsettings{'LOGVIEW_VIEWSIZE'}) {
    $next = -1;
}
else {
    $next = $start + $logsettings{'LOGVIEW_VIEWSIZE'};
}


if ($logsettings{'LOGVIEW_REVERSE'} eq 'on') {
    my $tmp = $prev;
    $prev = $next;
    $next = $tmp;
    @log = reverse @log;
}

if ($lines != 0) {
    &oldernewer();
}

print "<p><b>$Lang::tr{'web hits'} $date: $lines</b></p>\n";

my @slice = splice(@log, $start, $offset);

if ($lines)
{
    $lines = 0;

    print "<table width='100%'>\n";
    print <<END

        <tr>
            <td align='center'><b>$Lang::tr{'time'}</b></td>
            <td align='center'><b>$Lang::tr{'category'}</b></td>
            <td align='center'><b>$Lang::tr{'client'}</b></td>
END
;
    if ($filtersettings{'ENABLE_USERNAME_LOG'} eq 'on') {
        print "<td align='center'><b>$Lang::tr{'username'}</b></td>\n";
    }
    print <<END
            <td align='center'><b>$Lang::tr{'destination'}</b></td>
        </tr>
END
;


    foreach $_ (@slice)
    {
        my $attr1 = '';
        my $attr2 = '';
        my ($date,$time,$pid,@loginfo) = split(/ /);
        @ip = split(/\//, $loginfo[2]);
        @category = split(/\//, $loginfo[0]);
        my $dsturl = $loginfo[1];
        if(defined($loginfo[3])) {
            $loginfo[3] =~ s/\%5c/\\/;
        }
        if ((($cgiparams{'CATEGORY'}  eq 'ALL') || ($category[1] eq $cgiparams{'CATEGORY'})) &&
            (($cgiparams{'SOURCE_IP'} eq 'ALL') || ($ip[0] eq $cgiparams{'SOURCE_IP'})) &&
            (($cgiparams{'USERNAME'}  eq 'ALL') || ($loginfo[3] eq $cgiparams{'USERNAME'})))
        {
            $lines++;

            if ($lines % 2) {
                print "<tr class='table1colour'>\n";
            }
            else {
                print "<tr class='table2colour'>\n";
            }


            print "<td width='10%' align='center'>$time</td>\n";
            print "<td width='11%' align='center'>$category[1]</td>\n";
            print "<td width='15%' align='center'>$ip[0]</td>\n";
            my $site = '';
            if ($filtersettings{'ENABLE_USERNAME_LOG'} eq 'on')
            {
                print "<td width='12%' align='center'>$loginfo[3]</td>\n";
                $site = substr($dsturl,0,55);
                if (length($dsturl) > 55) { $site .= "..."; }
            }
            else {
                $site = substr($dsturl,0,69);
                if (length($dsturl) > 69) {
                    $site .= "...";
                }
            }
            print "<td><a href='$dsturl' title='$dsturl' target='_blank'>$site</a></td>\n";

            print "</tr>\n";
        }
    }

    print "</table>\n";

}

&oldernewer();

&Header::closebox();

&Header::closebigbox();

&Header::closepage();

# -------------------------------------------------------------------

sub processevent
{
    my $filestr='';

    undef @log;

    foreach my $logarch (<$logdir/*>)
    {
        if ($logarch !~ /squidGuard\.log/) {
            if($logarch =~ /\.gz$/) {
                open (LOG, "gzip -dc $logarch |");
            }
            else {
                open (LOG, $logarch);
            }
            foreach (<LOG>) {
                my ($date,$time,$pid,@loginfo) = split(/ /);
                my ($logyear,$logmonth,$logday) = split(/-/,$date);
                @category = split(/\//,$loginfo[0]);
                $categories{$category[1]}++;
                @ip = split(/\//,$loginfo[2]);
                $ips{$ip[0]}++;
                $loginfo[3] =~ s/\%5c/\\/;
                $usernames{$loginfo[3]}++;

                if (($logyear == $cgiparams{'YEAR'})
                    && ($logmonth == $cgiparams{'MONTH'}+1)
                    && ($logday == $cgiparams{'DAY'})) {
                        push(@log,$_)
                }
            }
            close(LOG);
        }
    }

    my @temp = ();
    foreach (@log)
    {
        my ($date,$time,$pid,@loginfo) = split(/ /);
        @ip = split(/\//,$loginfo[2]);
        @category = split(/\//,$loginfo[0]);
        $loginfo[3] =~ s/\%5c/\\/;
        if ((($cgiparams{'CATEGORY'}  eq 'ALL') || ($category[1] eq $cgiparams{'CATEGORY'}))
            && (($cgiparams{'SOURCE_IP'} eq 'ALL') || ($ip[0] eq $cgiparams{'SOURCE_IP'}))
            && (($cgiparams{'USERNAME'}  eq 'ALL') || ($loginfo[3] eq $cgiparams{'USERNAME'})))
        {
            push(@temp,$_);
        }
    }
    @log = @temp;
    @log = sort { substr($a,11,8) cmp substr($b,11,8) } @log;

}

# -------------------------------------------------------------------

sub oldernewer {
    print <<END
<table width='100%'>
<tr>
    <td align='center' width='50%'>
END
;

    if ($prev != -1) {
        print "<a href='$ENV{'SCRIPT_NAME'}?$prev,$cgiparams{'YEAR'},$cgiparams{'MONTH'},$cgiparams{'DAY'},$cgiparams{'CATEGORY'},$cgiparams{'SOURCE_IP'},$cgiparams{'USERNAME'}'>$Lang::tr{'older'}</a>";
    }
    else {
        print "$Lang::tr{'older'}";
    }
    print "</td>\n";

    print "<td align='center' width='50%'>";
    if ($next >= 0) {
        print "<a href='$ENV{'SCRIPT_NAME'}?$next,$cgiparams{'YEAR'},$cgiparams{'MONTH'},$cgiparams{'DAY'},$cgiparams{'CATEGORY'},$cgiparams{'SOURCE_IP'},$cgiparams{'USERNAME'}'>$Lang::tr{'newer'}</a>";
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
