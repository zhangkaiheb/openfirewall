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
#

# Add entry in menu
# MENUENTRY status 010 "alt home" "alt home"
#
# Make sure translation exists $Lang::tr{'alt home'}

use strict;

# enable only the following on debugging purpose
use warnings; no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/traffic-lib.pl';

my %mainsettings  = ();
my %cgiparams     = ();
my %pppsettings   = ();
my %modemsettings = ();
my %netsettings   = ();

my $warnmessage = '';
my $refresh     = '';

&Header::showhttpheaders();

$cgiparams{'ACTION'} = '';
&General::getcgihash(\%cgiparams);
$pppsettings{'VALID'}       = '';
$pppsettings{'PROFILENAME'} = 'None';
&General::readhash('/var/ofw/main/settings',     \%mainsettings);
&General::readhash('/var/ofw/ppp/settings',      \%pppsettings);
&General::readhash('/var/ofw/modem/settings',    \%modemsettings);
&General::readhash('/var/ofw/ethernet/settings', \%netsettings);

my $connstate = &General::connectionstatus();
if ($connstate =~ /$Lang::tr{'dod waiting'}/) {
    $refresh = "<meta http-equiv='refresh' content='30;' />";
}
elsif ($connstate =~ /$Lang::tr{'connecting'}/) {
    $refresh = "<meta http-equiv='refresh' content='5;' />";
}
elsif ($connstate =~ /$Lang::tr{'disconnecting'}/) {
    $refresh = "<meta http-equiv='refresh' content='5;' />";
}
elsif ($mainsettings{'REFRESHINDEX'} eq 'on') {
    $refresh = "<meta http-equiv='refresh' content='600;' />";
}

&Header::openpage($Lang::tr{'main page'}, 1, $refresh);
&Header::openbigbox('', 'center');

print "<div align='center'>";
&Header::openbox('50%', 'center', &Header::cleanhtml(`/bin/uname -n`, "y"), '', '#69C');

# hide buttons only when pppsettings mandatory used and not valid
if (   ($pppsettings{'VALID'} eq 'yes')
    || (($netsettings{'RED_COUNT'} >= 1) && $netsettings{'RED_1_TYPE'} =~ /^(DHCP|STATIC)$/))
{
    print <<END
<table border='0'>
<tr>
    <td align='center'><form method='post' action='/cgi-bin/dial.cgi'>
        <input type='submit' name='ACTION' value='$Lang::tr{'dial'}' />
    </form></td>
    <td>&nbsp;&nbsp;</td>
    <td align='center'><form method='post' action='/cgi-bin/dial.cgi'>
        <input type='submit' name='ACTION' value='$Lang::tr{'hangup'}' />
    </form></td>
    <td>&nbsp;&nbsp;</td>
    <td align='center'><form method='post' action="$ENV{'SCRIPT_NAME'}">
        <input type='submit' name='ACTION' value='$Lang::tr{'refresh'}' />
    </form></td>
</tr></table><br />
END
        ;
}

print "<font face='Helvetica' size='4'><b>";
if (!(($netsettings{'RED_COUNT'} >= 1) && $netsettings{'RED_1_TYPE'} =~ /^(DHCP|STATIC)$/)) {
    print "<u>$Lang::tr{'current profile'}: $pppsettings{'PROFILENAME'}</u><br />\n";
}

if (   ($pppsettings{'VALID'} eq 'yes' && $modemsettings{'VALID'} eq 'yes')
    || (($netsettings{'RED_COUNT'} >= 1) && $netsettings{'RED_1_TYPE'} =~ /^(DHCP|STATIC)$/))
{
    print $connstate;
    print "</b></font>\n";
    if ($connstate =~ /$Lang::tr{'connected'}/) {

        # display our public internet IP
        my $fetch_ip = &General::GetDyndnsRedIP;
        my $host_name;
        if (defined($host_name) && ($host_name ne 'unavailable')) {
            $host_name = (gethostbyaddr(pack("C4", split(/\./, $fetch_ip)), 2))[0];
        }
        else {
            $host_name = $fetch_ip;
        }
        print
"<br />$Lang::tr{'ip address'} ($Lang::tr{'internet'}): $fetch_ip <br /> $Lang::tr{'openfirewalls hostname'} ($Lang::tr{'internet'}): $host_name";

        # and also the the real red IP if it is different from public IP
        if (open(IPADDR, "/var/ofw/red/local-ipaddress")) {
            my $ipaddr = <IPADDR>;
            close IPADDR;
            chomp($ipaddr);
            if ($ipaddr ne $fetch_ip) {    #do not show info twice
                my $host_name = (gethostbyaddr(pack("C4", split(/\./, $ipaddr)), 2))[0];
                $host_name = $ipaddr if ($host_name eq '');
                print
"<br />$Lang::tr{'ip address'} ($Lang::tr{'red'}): $ipaddr <br /> $Lang::tr{'openfirewalls hostname'} ($Lang::tr{'red'}): $host_name";
            }
        }
    }

}
elsif ($modemsettings{'VALID'} eq 'no') {
    print "$Lang::tr{'modem settings have errors'}\n </b></font>\n";
}
else {
    print "$Lang::tr{'profile has errors'}\n </b></font>\n";
}

print "<br />\n";

# Reboot required flagfile
if (-e '/rebootrequired') {
    $warnmessage .= "<li><b>$Lang::tr{'reboot required'}</b></li>\n";
}
# Memory usage warning
my @free = `/bin/free`;
$free[1] =~ m/(\d+)/;
my $mem = $1;
$free[2] =~ m/(\d+)/;
my $used = $1;
if ($mem) {
    my $pct = int 100 * ($mem - $used) / $mem;
    if ($used / $mem > 90) {
        $warnmessage .= "<li> $Lang::tr{'high memory usage'}: $pct% !</li>\n";
    }
}
else {
    $warnmessage .= "<li> $Lang::tr{'high memory usage'}: 100% ! $Lang::tr{'memory'}=0M</li>\n";
}

# Diskspace usage warning
my $free = &General::getavailabledisk('/root');
if ($free < 15) {

    # available:plain value in MB, and not %used as 10% is too much to waste on small disk
    # and root size should not vary during time
    $warnmessage .= "<li> $Lang::tr{'filesystem full'}: /root <b>$Lang::tr{'free'}=${free}M</b> !</li>\n";
}
my $percent = &General::getavailabledisk('/var/log', 'use');
if ($percent > 90) {
    my $freepercent = int(100 - $percent);
    $warnmessage .=
        "<li> $Lang::tr{'filesystem full'}: /var/log <b>$Lang::tr{'free'}=${freepercent}%</b> !</li>\n";
}

# Patches warning
my $patchmessage = &General::ispatchavailable();
if ($patchmessage ne "") {
    $warnmessage .= "<li><b>$patchmessage</b></li>\n";
}

# If an AddOn wants to insert an info/warn message, than this is the spot to do it.
# Add text to $warnmessage and you're done.
# Markerwarnmessage


if ($warnmessage) {
    print "<ol style='width:500px;'>$warnmessage</ol>";
}
else {
   print "<br />\n";
}

print "<a href='${General::adminmanualurl}/homepage.html' target='_blank'>
    <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>";

if($TRAFFIC::settings{'SHOW_AT_HOME'} eq 'on') {
    my %calc = ();

    &TRAFFIC::calcTrafficCounts(\%calc);

    print <<END;
<hr />
<table width='100%'>
END

#~ 	my $calctime = &TRAFFIC::getFormatedDate($calc{'CALC_LAST_RUN'});

#~     print <<END;
#~     <tr>
#~     <td align='left' colspan="3">
#~         $Lang::tr{'traffic monitor'} ($Lang::tr{'traffic calc time'} $calctime):

#~     </td>
#~  </tr>
#~ END

    print <<END;
<tr>
    <td align='left' width='10%'>&nbsp;</td>
    <td align='left' width='80%' nowrap='nowrap' >
    <table width='100%'>
    <tr>
        <td align='left' width='25%' nowrap='nowrap' >&nbsp;</td>
        <td align='center' width='25%' nowrap='nowrap' class='boldbase'>
            <font class='ofw_iface_red'><b>$Lang::tr{'trafficin'}</b></font>
        </td>
        <td align='center' width='25%' nowrap='nowrap' class='boldbase'>
            <font class='ofw_iface_red'><b>$Lang::tr{'trafficout'}</b></font>
        </td>
        <td align='center' width='25%' nowrap='nowrap' class='boldbase'>
            <font class='ofw_iface_red'><b>$Lang::tr{'trafficsum'}</b></font>
        </td>
    </tr><tr>
        <td align='left' nowrap='nowrap' >$Lang::tr{'this weeks volume'} (MB):</td>
        <td align='center' nowrap='nowrap' class='boldbase'>$calc{'CALC_WEEK_IN'}</td>
        <td align='center' nowrap='nowrap' class='boldbase'>$calc{'CALC_WEEK_OUT'}</td>
        <td align='center' nowrap='nowrap' class='boldbase'>$calc{'CALC_WEEK_TOTAL'}</td>
    </tr><tr>
        <td align='left' nowrap='nowrap' >$Lang::tr{'this months volume'} (MB):</td>
        <td align='center' nowrap='nowrap' class='boldbase'>$calc{'CALC_VOLUME_IN'}</td>
        <td align='center' nowrap='nowrap' class='boldbase'>$calc{'CALC_VOLUME_OUT'}</td>
        <td align='center' nowrap='nowrap' class='boldbase'>$calc{'CALC_VOLUME_TOTAL'}</td>
    </tr>
END

    if ($TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'} eq 'on') {
        if ($TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'} eq 'on') {
            print <<END;
    <tr>
        <td align='left'>$Lang::tr{'monitor volume'} $TRAFFIC::settings{'VOLUME_TOTAL'} MB</td>
        <td align='left' colspan="3" nowrap='nowrap'>
END

            &TRAFFIC::traffPercentbar("$calc{'CALC_PERCENT_TOTAL'}%");

            print <<END;
        </td>
        <td align='left' nowrap='nowrap'>&nbsp; $calc{'CALC_PERCENT_TOTAL'}%</td>
    </tr>
END
        }

        if ($TRAFFIC::settings{'VOLUME_IN_ENABLED'} eq 'on') {
            print <<END;
    <tr>
        <td align='center'>$Lang::tr{'trafficin'} max. $TRAFFIC::settings{'VOLUME_IN'} MB</td>
        <td align='left' colspan="3" nowrap='nowrap'>
END

            &TRAFFIC::traffPercentbar("$calc{'CALC_PERCENT_IN'}%");

            print <<END;
        </td>
        <td align='left' nowrap='nowrap'>&nbsp; $calc{'CALC_PERCENT_IN'}%</td>
    </tr>
END
        }

        if ($TRAFFIC::settings{'VOLUME_OUT_ENABLED'} eq 'on') {
            print <<END;
    <tr>
        <td align='center'>$Lang::tr{'trafficout'} max. $TRAFFIC::settings{'VOLUME_OUT'} MB</td>
        <td align='left' colspan="3" nowrap='nowrap'>
END

            &TRAFFIC::traffPercentbar("$calc{'CALC_PERCENT_OUT'}%");

            print <<END;
        </td>
        <td align='left' nowrap='nowrap'>&nbsp; $calc{'CALC_PERCENT_OUT'}%</td>
    </tr>
END
        }

    }

    print <<END;
    </table>
    </td>
    <td align='left' width='10%' nowrap='nowrap' >&nbsp;</td>
    </tr>
    </table>
END

}

&Header::closebox();

print "</div>";
print "<div style='float:left; margin-right:5px'>";

print "<a name='memory'/>\n";
&Header::openbox('50%', 'left', "$Lang::tr{'memory'}:", '', '#69C');
print "<table>";
my $mem_size=0;
my $mem_used=0;
my $mem_free=0;
my $mem_shared=0;
my $mem_buffers=0;
my $mem_cached=0;
my $buffers_used=0;
my $buffers_free=0;
my $swap_size=0;
my $swap_used=0;
my $swap_free=0;

my $percent=0;

open(FREE,'/bin/free |');
while (<FREE>) {
    if ($_ =~ m/^Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/) {
        ($mem_size,$mem_used,$mem_free,$mem_shared,$mem_buffers,$mem_cached) = ($1,$2,$3,$4,$5,$6);
    }
    elsif ($_ =~ m/^Swap:\s+(\d+)\s+(\d+)\s+(\d+)$/) {
        ($swap_size,$swap_used,$swap_free) = ($1,$2,$3);
    }
    elsif ($_ =~ m/^-\/\+ buffers\/cache:\s+(\d+)\s+(\d+)$/ ) {
        ($buffers_used,$buffers_free) = ($1,$2);
    }
}
close FREE;

print <<END
<tr>
    <td>&nbsp;</td>
    <td align='center' class='boldbase'>$Lang::tr{'size'}</td>
    <td align='center' class='boldbase'>$Lang::tr{'used'}</td>
    <td align='center' class='boldbase'>$Lang::tr{'free'}</td>
    <td align='left' class='boldbase' colspan='2'>$Lang::tr{'percentage'}</td>
</tr><tr>
    <td class='boldbase'>$Lang::tr{'ram'}</td>
    <td align='right'>$mem_size</td>
    <td align='right'>$mem_used</td>
    <td align='right'>$mem_free</td>
    <td>
END
;
($percent = ($mem_used/$mem_size)*100) =~ s/^(\d+)(\.\d+)?$/$1%/;
&Header::percentbar($percent);
print <<END
    </td>
    <td align='right'>$percent</td>
</tr>
END
;
print "<tr><td colspan='2' class='boldbase'>$Lang::tr{'buffers'}</td><td align='right'>$mem_buffers</td><td>&nbsp;</td><td>";
($percent = ($mem_buffers/$mem_size)*100) =~ s/^(\d+)(\.\d+)?$/$1%/;
&Header::percentbar($percent);
print "</td><td align='right'>$percent</td></tr>";
print "<tr><td colspan='2' class='boldbase'>$Lang::tr{'cached'}</td><td align='right'>$mem_cached</td><td>&nbsp;</td><td>";
($percent = ($mem_cached/$mem_size)*100) =~ s/^(\d+)(\.\d+)?$/$1%/;
&Header::percentbar($percent);
print "</td><td align='right'>$percent</td></tr>";
print "<tr><td colspan='2' class='boldbase'>$Lang::tr{'excluding buffers and cache'}</td><td align='right'>$buffers_used</td><td>&nbsp;</td><td>";
($percent = ($buffers_used/$mem_size)*100) =~ s/^(\d+)(\.\d+)?$/$1%/;
&Header::percentbar($percent);
print "</td><td align='right'>$percent</td></tr>";
print "<tr><td class='boldbase'>$Lang::tr{'swap'}</td><td align='right'>$swap_size</td><td align='right'>$swap_used</td><td align='right'>$swap_free</td><td>";
if ($swap_size != 0) {
    ($percent = ($swap_used/$swap_size)*100) =~ s/^(\d+)(\.\d+)?$/$1%/;
}
else {
    $percent = '';
}
&Header::percentbar($percent);
print "</td><td align='right'>$percent</td></tr>";
print "</table>";
&Header::closebox();
print "</div>";
#print "<div align='left'>";


print "<div style='float:right; margin-left:5px'>";

print "<a name='disk'/>\n";
&Header::openbox('50%', 'left', "$Lang::tr{'disk usage'}:", '', '#69C');
print "<table>\n";

print <<END
<tr>
<td align='left' class='boldbase'>$Lang::tr{'device'}</td>
<td align='left' class='boldbase'>$Lang::tr{'mounted on'}</td>
<td align='center' class='boldbase'>$Lang::tr{'size'}</td>
<td align='center' class='boldbase'>$Lang::tr{'used'}</td>
<td align='center' class='boldbase'>$Lang::tr{'free'}</td>
<td align='left' class='boldbase' colspan='2'>$Lang::tr{'percentage'}</td>
</tr>
END
;

open(DF,'/bin/df -h -x rootfs|');
my @df = <DF>;
close DF;

# skip first line:
# Filesystem            Size  Used Avail Use% Mounted on
shift(@df);
chomp(@df);
# merge all lines to one single line separated by spaces
my $all_inOneLine=join(' ',@df);

# now get all entries in an array
my @all_entries=split(' ',$all_inOneLine);

# loop over all entries. Six entries belong together.
while (@all_entries > 0) {
    my $device=shift(@all_entries);
    if ($device eq "/dev/disk/by-label/root") {
        $device = `/bin/readlink -f /dev/disk/by-label/root`;
    }
    my $size=shift(@all_entries);
    my $used=shift(@all_entries);
    my $free=shift(@all_entries);
    my $percent=shift(@all_entries);
    my $mount=shift(@all_entries);
    next if ($mount eq "/dev");
    print <<END
<tr>
<td>$device</td>
<td>$mount</td>
<td align='right'>$size</td>
<td align='right'>$used</td>
<td align='right'>$free</td>
<td>
END
;
    &Header::percentbar($percent);
    print <<END
</td>
<td align='right'>$percent</td>
</tr>
END
;

}
print "<tr><td>1</td></tr>";
print "</table>\n";
&Header::closebox();

print "</div>";

# If an AddOn wants to insert own box, than this is the spot to do it.
# Add code and html below this line.
# Markeraddonbox


&Header::closebigbox();

&Header::closepage();
