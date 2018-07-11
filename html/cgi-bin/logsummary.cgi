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
# $Id: logsummary.cgi 8037 2016-01-04 08:06:53Z owes $
#

# Add entry in menu
# MENUENTRY logs 020 "log summary" "log summary"

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

# $Lang::tr{'ls_dhcpd'}      # Dummy string variables included here
# $Lang::tr{'ls_disk space'} # or gen_strings script will miss them
# $Lang::tr{'ls_free/swan'}
# $Lang::tr{'ls_httpd'}
# $Lang::tr{'ls_init'}
# $Lang::tr{'ls_modprobe'}
# $Lang::tr{'ls_pam_unix'}
# $Lang::tr{'ls_sshd'}
# $Lang::tr{'ls_syslogd'}
# Hack for Firewall, no point to add 'iptables firewall' as text
# $Lang::tr{'firewall'}
# Hack for Kernel, old text combined kernel and firewall
# $Lang::tr{'kernel'}

use POSIX();

my %cgiparams    = ();
my $errormessage = '';

my @now  = localtime();
my $thisyear = $now[5] + 1900;

$cgiparams{'DAY'}     = '';             # day. 0 (=all), 1, ... , 31
$cgiparams{'MONTH'}   = '';             # month. 0 (=January), 1 (=February), ... , 11 (=December)
$cgiparams{'YEAR'}    = '';             # year.
$cgiparams{'ACTION'}  = '';

&General::getcgihash(\%cgiparams);

my @temp_then = ();
if ($ENV{'QUERY_STRING'} && $cgiparams{'ACTION'} ne $Lang::tr{'update'}) {
    @temp_then = split(',', $ENV{'QUERY_STRING'});
    $cgiparams{'YEAR'}  = $temp_then[1];
    $cgiparams{'MONTH'} = $temp_then[2];
    $cgiparams{'DAY'}   = $temp_then[3];
}

if (   !($cgiparams{'MONTH'} =~ /^(0|1|2|3|4|5|6|7|8|9|10|11)$/)
    || !($cgiparams{'DAY'} =~ /^(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)$/)
    )
{
    # Reports are generated at the end of the day, so if nothing is selected
    # we need to display yesterdays (todays won't have been generated yet)
    @temp_then = &General::calculatedate($now[5]+1900, $now[4], $now[3], -1);
    $cgiparams{'YEAR'}  = $temp_then[5]+1900;
    $cgiparams{'MONTH'} = $temp_then[4];
    $cgiparams{'DAY'}   = $temp_then[3];
}
elsif ($cgiparams{'ACTION'} eq '>>') {
    @temp_then = &General::calculatedate($cgiparams{'YEAR'}, $cgiparams{'MONTH'}, $cgiparams{'DAY'}, 1);
    $cgiparams{'YEAR'}  = $temp_then[5]+1900;
    $cgiparams{'MONTH'} = $temp_then[4];
    $cgiparams{'DAY'}   = $temp_then[3];
}
# There may be a comma in button string
elsif (&Header::cleanhtml($cgiparams{'ACTION'},"y") eq $Lang::tr{'day yesterday'}) {
    @temp_then = &General::calculatedate($now[5]+1900, $now[4], $now[3], -1);
    $cgiparams{'YEAR'}  = $temp_then[5]+1900;
    $cgiparams{'MONTH'} = $temp_then[4];
    $cgiparams{'DAY'}   = $temp_then[3];
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

my $monthnum     = $cgiparams{'MONTH'} + 1;
my $monthstr     = $monthnum <= 9 ? "0$monthnum" : "$monthnum";
my $longmonthstr = $Lang::tr{$General::longMonths[$cgiparams{'MONTH'}]};
my $daystr       = $cgiparams{'DAY'} <= 9 ? "0$cgiparams{'DAY'}" : "$cgiparams{'DAY'}";

my $skip    = 0;
my $filestr = "/var/log/logwatch/$cgiparams{'YEAR'}-$monthstr-$daystr";

if (!(open(FILE, $filestr))) {
    $errormessage = "$Lang::tr{'date not in logs'}: $filestr $Lang::tr{'could not be opened'}";
    $skip         = 1;

    # Note: This is in case the log does not exist for that date
}

if (!$skip && $cgiparams{'ACTION'} eq $Lang::tr{'export'}) {
    print "Content-type: text/plain\n\n";

    while (<FILE>) {
        print "$_\r\n";
    }
    close(FILE);
    exit 0;
}

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'log summary'}, 1, '');

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
        <input type='submit' name='ACTION' value='$Lang::tr{'day yesterday'}' />
        <input type='submit' name='ACTION' title='$Lang::tr{'day after'}' value='&gt;&gt;' />
        <input type='submit' name='ACTION' value='$Lang::tr{'update'}' />
        <input type='submit' name='ACTION' value='$Lang::tr{'export'}' />
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/logs-summary.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END
    ;

&Header::closebox();

my $header  = 0;
my @content = ();

if (!$skip) {
    while (<FILE>) {
        if (/^\s*--+ ([^-]+) Begin --+\s*$/) {

            # New Section. open box
            @content = ();
            my $boxtitle = $Lang::tr{"ls_\L$1"} ? $Lang::tr{"ls_\L$1"} . ":" : "$1:";
            # Hack for Firewall and Kernel, to avoid need to add/modify language texts
            $boxtitle = $Lang::tr{'firewall'}.":" if ("\L$1" eq 'iptables firewall');
            $boxtitle = $Lang::tr{'kernel'}.":" if ("\L$1" eq 'kernel');
            &Header::openbox('100%', 'left', $boxtitle);
            print "<pre>";
        }
        elsif (/^\s*--+ ([^-]+) End --+\s*$/) {

            # End of Section, kill leading and trailing blanks, print info, close
            # box
            while ($content[0]         =~ /^\s*$/) { shift @content; }
            while ($content[$#content] =~ /^\s*$/) { pop @content; }
            foreach $_ (@content) { $_ =~ s/\s*$//; print &Header::cleanhtml($_, "y") . "\n"; }
            print "\n</pre>";
            &Header::closebox();
        }
        elsif (/^\s*#+ LogWatch [^#]+[)] #+\s*$/) {

            # Start of logwatch header, skip it
            $header = 1;
        }
        elsif (/^\s*#+\s*$/) {

            # End of logwatch header
            $header = 0;
        }
        elsif (/^\s*#+ LogWatch End #+\s*$/) {

            # End of report
        }
        elsif ($header eq 0) {
            push(@content, $_);
        }
    }
    close(FILE);
}

&Header::closebigbox();

&Header::closepage();
