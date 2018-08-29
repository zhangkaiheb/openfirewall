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
# status.cgi originally (2001) from the Smoothwall project
# (c) The SmoothWall Team
#
# Many changes since 2001
# (c) 2001-2014, the Openfirewall Team
#
# $Id: status.cgi 7203 2014-01-08 06:04:23Z owes $
#

# Add entry in menu
# MENUENTRY status 010 "sssystem status" "system status information"
#
# Make sure translation exists $Lang::tr{'sssystem status'} $Lang::tr{'system status information'}

use strict;

# enable only the following on debugging purpose
use warnings; no warnings 'once';# 'redefine', 'uninitialized';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my %netsettings=();
&General::readhash('/var/ofw/ethernet/settings', \%netsettings);

# Maps a nice printable name to the changing part of the pid file, which
# is also the name of the program
my %servicenames =
(
    $Lang::tr{'dhcp server'} => 'dhcpd',
    $Lang::tr{'dns proxy server'} => 'dnsmasq/dnsmasq',
    $Lang::tr{'web server'} => 'httpd',
    $Lang::tr{'cron server'} => 'fcron',
    $Lang::tr{'logging server'} => 'rsyslogd',
    $Lang::tr{'ntp server'} => 'ntpd',
    $Lang::tr{'secure shell server'} => 'sshd',
    $Lang::tr{'ipsec server'} => 'pluto/pluto',
    $Lang::tr{'openvpn server'}  => 'openvpn',
    $Lang::tr{'url filter'} => 'squidguard',
    $Lang::tr{'web proxy'} => 'squid'
);

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'status information'}, 1, '');

&Header::openbigbox('100%', 'left');

my $araid = '';
$araid = "<a href='#raid'>$Lang::tr{'RAID status'}</a> |" if (-e "/proc/mdstat");

print <<END
<table width='100%' cellspacing='0' cellpadding='5' border='0'>
<tr><td style="background-color: #FFFFFF;" align='left'>
    <a href='#services'>$Lang::tr{'services'}</a> |
    <a href='#memory'>$Lang::tr{'memory'}</a> |
    <a href='#disk'>$Lang::tr{'disk usage'}</a> |
    <a href='#inodes'>$Lang::tr{'inodes usage'}</a> |
    $araid    
    <a href='#uptime'>$Lang::tr{'uptime and users'}</a> |
    <a href='#kernel'>$Lang::tr{'kernel version'}</a>
</td></tr></table>
END
;

print "<a name='services'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'services'}:");

print <<END
<div align='center'>
<table width='60%' cellspacing='1' cellpadding='2' border='0'>
END
;

my $lines = 0;
my $key = '';
foreach $key (sort keys %servicenames)
{
    my $tid = ($lines % 2) + 1;
    print "<tr class='table${tid}colour'>\n"; 
    print "<td align='left'>$key</td>\n";
    my $shortname = $servicenames{$key};
    my $status = &General::isrunning($shortname);
    print "$status\n";
    print "</tr>\n";
    $lines++;
}


print "</table></div>\n";

&Header::closebox();

print "<a name='memory'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'memory'}:");
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

open(FREE,'/usr/bin/free |');
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

print "<a name='disk'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'disk usage'}:");
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
print "</table>\n";
&Header::closebox();

print "<a name='inodes'/>\n";
&Header::openbox('100%', 'left', $Lang::tr{'inodes usage'}.':');
print "<table>\n";

print <<END
<tr>
<td align='left' class='boldbase'>$Lang::tr{'device'}</td>
<td align='left' class='boldbase'>$Lang::tr{'mounted on'}</td>
<td align='center' class='boldbase'>Inodes</td>
<td align='center' class='boldbase'>$Lang::tr{'used'}</td>
<td align='center' class='boldbase'>$Lang::tr{'free'}</td>
<td align='left' class='boldbase' colspan='2'>$Lang::tr{'percentage'}</td>
</tr>
END
;

open(DF,'/bin/df -i -x rootfs|');
@df = <DF>;
close DF;

# skip first line:
# Filesystem            Inodes  IUsed IFree IUse% Mounted on
shift(@df);
chomp(@df);
# merge all lines to one single line seperated by spaces
$all_inOneLine=join(' ',@df);

# now get all entries in an array
@all_entries=split(' ',$all_inOneLine);

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
print "</table>\n";
&Header::closebox();

if (-e "/etc/mdadm/mdadm.conf") {
    print "<a name='raid'/>\n";
    &Header::openbox('100%', 'left', "$Lang::tr{'RAID status'}:");
    print <<END
<table cellspacing='1' cellpadding='2' border='0'><tr>
    <td align='left' class='boldbase'>$Lang::tr{'device'}</td>
    <td align='left' class='boldbase'>$Lang::tr{'status'}</td>
    <td align='center' class='boldbase'>Active</td>
    <td align='center' class='boldbase'>Working</td>
    <td align='center' class='boldbase'>Failed</td>
</tr>
END
;
    for (my $i=0; $i < 2; $i++) {
        my $state = "";
        my $rowtext = "<td align='center'>md$i</td>";

        open(MDADM, "/usr/local/bin/sysinfo --raid=md$i |");
        while(<MDADM>) {
            if ($_ =~ m/^\s+State\s+:\s+(.*?)\s*$/) {
                my $field = &Header::cleanhtml($1,"y");
                $rowtext .= "<td>$field</td>";
                $state = "class='ofw_error'" if (($field ne 'clean') && ($field ne 'active'));
            }
            elsif ($_ =~ m/^\s*Active Devices\s+:\s+(\d+).*$/) {
                $rowtext .= "<td align='center'>$1</td>";
            }
            elsif ($_ =~ m/^\s*Working Devices\s+:\s+(\d+).*$/) {
                $rowtext .= "<td align='center'>$1</td>";
            }
            elsif ($_ =~ m/^\s*Failed Devices\s+:\s+(\d+).*$/) {
                $rowtext .= "<td align='center'>$1</td>";
            }
        }
        close MDADM;

        print "<tr $state>$rowtext</tr>";
    }
    print "</table>\n";
    &Header::closebox();
}

print "<a name='uptime'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'uptime and users'}:");
my $output = `/usr/bin/w`;
$output = &Header::cleanhtml($output,"y");
print "<table>";
foreach my $line (split(/\n/, $output))
{
    if (index($line, 'load average') != -1) {
        # Line containing uptime and load average is the first line, put it in a seperate table
        print "<tr><td>$line</td></tr></table><br /><table>\n"
    }
    elsif ($line =~ m/^(\S*)\s+(\S*)\s+(\S*)\s+(\S*)\s+(\S*)\s+(\S*)\s+(.*)$/) {
        my $classbold = '';
        $classbold = "class='boldbase'" if(index($line, 'LOGIN@') != -1);
        print "<tr $classbold><td>$1</td><td>$2</td><td>$3</td><td>$4</td><td>$5</td><td>$6</td><td>$7</td></tr>\n";
    } else {
        print "<tr><td colspan='7'>$line</td></tr>\n"
    }
}
print "</table>";
&Header::closebox();

print "<a name='kernel'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'kernel version'}:");
print `/bin/uname -o`." ".`/bin/uname -r`."<br />";
print `/bin/uname -v`."<br />";
print `/bin/uname -m`." ".`/bin/uname -p`." ".`/bin/uname -i`;
&Header::closebox();

&Header::closebigbox();

&Header::closepage();

