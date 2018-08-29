#!/usr/bin/perl
#
################################################################################
#
# openfirewall SysInfo Web-Iface
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
################################################################################
#
# Based on Openfirewall http://www.openfirewall.cn, hddgraph (C) by weizen_42
# 2007-02-13 modified by wintermute for SysInfo
# Copyright (C) 2007-2008 Tom 'wintermute' Eichstaedt <wintermute@tom-e.de>
#
# $Id: sysinfo.cgi 7717 2014-12-01 18:20:17Z owes $
#

# Add entry in menu
# MENUENTRY status 020 "system info" "system info"

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

use LWP::UserAgent;

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my %cgiparams=();
my @lines;
my $i;
my $output;


&Header::showhttpheaders();

&Header::openpage($Lang::tr{'system info'}, 1, '');

&Header::openbigbox('100%', 'left');

my $acobalt = '';
$acobalt = "<a href='#cobalt'>$Lang::tr{'system info cobalt'}</a> |" if (-e "/proc/cobalt");

print <<END
<table width='100%' cellspacing='0' cellpadding='5'border='0'>
<tr><td style="background-color: #FFFFFF;" align='left'>
    <a href='#cpu'>$Lang::tr{'system info cpu'}</a> |
    $acobalt
    <a href='#hdd'>$Lang::tr{'system info hdd'}</a> |
    <a href='#pci'>$Lang::tr{'system info pci'}</a> |
    <a href='#nic'>$Lang::tr{'system info nic'}</a> |
    <a href='#link'>$Lang::tr{'system info link'}</a> |
    <a href='#usb'>$Lang::tr{'system info usb'}</a> |
    <a href='#irq'>$Lang::tr{'system info irq'}</a> |
    <a href='#ps'>$Lang::tr{'system info ps'}</a> |
    <a href='#modules'>$Lang::tr{'loaded modules'}</a>
</td></tr></table>
END
;

print "<a name='cpu'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'system info cpu'}:");

my $outputcpu = `/bin/cat /proc/cpuinfo`;
my $cpumhz;
my $bogomips;
my $bogoeff;
$outputcpu = &Header::cleanhtml($outputcpu);
chomp($outputcpu);

my $outputcpuleft;
my $outputcpumid;
my $outputcpuright;
(@lines) = split(/\n/, $outputcpu);
$outputcpu = '';

foreach my $line (@lines) {
    unless ( $line =~ /(.*?)\s*:\s*(.*)/ ) {
        $outputcpuleft .= "\n";
        $outputcpumid .= "\n";
        $outputcpuright .= "\n";
        next;
    }

    my $left = $1;
    my $right = $2;
    $outputcpuleft .= "$left\n";
    $outputcpumid .= " : \n";
    if (length($right) > 100) {
        $outputcpuleft .= "\n";
        $outputcpumid .= "\n";
        $outputcpuright .= substr($right, 0, rindex($right, ' ', 100)) . "\n" . substr($right, rindex($right, ' ', 100)) . "\n";
    }
    else {
        $outputcpuright .= "$right\n";
    }
    $cpumhz = $1 if ($line =~ /cpu MHz.*: (.*)/);
    if ($line =~ /bogomips.*: (.*)/) {
        $bogomips = $1;
        $bogoeff = $bogomips / $cpumhz * 50;
        $outputcpuleft .= "bogomips eff.\n";
        $outputcpumid .= " : \n";
        $outputcpuright .= sprintf("%.4f %%\n", $bogoeff);
    }
}
print <<END
<table cellspacing='0' cellpadding='0' border='0'><tr>
    <td valign='top'><pre>$outputcpuleft</pre></td>
    <td valign='top'><pre>$outputcpumid</pre></td>
    <td valign='top'><pre>$outputcpuright</pre></td>
</tr></table>
END
;
&Header::closebox();


#
# This is where platform specific information will be shown.
#
if (-e "/proc/cobalt") {
    print "<a name='cobalt'/>\n";
    &Header::openbox('100%', 'left', "$Lang::tr{'system info cobalt'}:");
    
    my $outputsystype = `/bin/cat /proc/cobalt/systype`;
    my $outputserialnumber = `/bin/cat /proc/cobalt/serialnumber`;
    my $outputfan = `/bin/cat /proc/cobalt/faninfo`;
    my $outputvoltage = `/bin/cat /proc/cobalt/sensors/voltage`;
    my $outputthermal = `/bin/cat /proc/cobalt/sensors/thermal`;
    my $outputraminfo = `/bin/cat /proc/cobalt/raminfo`;

    $outputsystype = &Header::cleanhtml($outputsystype);
    $outputserialnumber = &Header::cleanhtml($outputserialnumber);
    $outputfan = &Header::cleanhtml($outputfan);
    if (index($outputsystype, 'Alpine') != -1) {
        (@lines) = split(/\n/, $outputfan);
        $outputfan = "";
        foreach my $line (@lines) {
            next if ($line =~ /fan 0|fan 4/);
            $outputfan .= $line."\n";
        }
    }
    $outputthermal = &Header::cleanhtml($outputthermal);
    $outputvoltage = &Header::cleanhtml($outputvoltage);
    $outputraminfo = &Header::cleanhtml($outputraminfo);
    
    print "<pre>Cobalt System Type:\n$outputsystype \n";
    print "Cobalt System Serial Number:\n$outputserialnumber \n";
    if (index($outputsystype, 'Alpine') != -1) {
        print "Fan Info:\n$outputfan \n";
        print "Voltage:\n$outputvoltage \n";
    }
    else {
        print "Cpu Temperature In Degrees Celsius:\n$outputthermal \n";
    }
    print "Ram Slot Information:\n$outputraminfo<\/pre>";

    &Header::closebox();
}


print "<a name='hdd'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'system info hdd'}:");
if (-e "/etc/mdadm/mdadm.conf") {
    $i = 0;
    open(MDADM, "/usr/local/bin/sysinfo --raid=md0 |");
    while(<MDADM>) {
        if ($_ =~ m/^\s+(\d+).*\/dev\/(.*)\d$/) {
            if ($i) {
                print "<br /><hr />";
            }
            print "<b>$2</b><br />";
            &diskinfo($2);
            $i++;
        }
    }
    close MDADM;
}
elsif (! -e "/proc/scsi/scsi") {
    my $systemdisk = `ls -la /dev/disk/by-label/root`;
    $systemdisk =~ m/\.\.\/\.\.\/(.*)\d/;
    &diskinfo($1);
}
else {
    my $outputscsi = `/bin/cat /proc/scsi/scsi`;
    $outputscsi = &Header::cleanhtml($outputscsi);
    print "<pre>$outputscsi</pre>\n";
}
&Header::closebox();

print "<a name='pci'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'system info pci'}:");
my $outputpci = `/usr/sbin/lspci -nn`;
$outputpci = &Header::cleanhtml($outputpci);
print "<pre>$outputpci</pre>\n";
&Header::closebox();

print "<a name='nic'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'system info nic'}:");
my $outputnic = `/usr/sbin/lspci -nn`;
$outputnic = &Header::cleanhtml($outputnic);

print "<pre>";
(@lines) = split(/\n/, $outputnic);
foreach my $line (@lines) {
    next if ($line !~ /Ethernet|Network/);
    print $line."\r";
    (my $slot) = split(/ /, $line);
    $outputnic = `/usr/local/bin/sysinfo --pci=$slot`;
    $outputnic =~ s/$slot/       /;
    $outputnic = &Header::cleanhtml($outputnic);
    print $outputnic;
}
print "</pre>";
&Header::closebox();

print "<a name='link'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'system info link'}:");
print "<table cellspacing='0' cellpadding='0'border='0'><tr>";
print "<td colspan='2'><pre style='font: 12px; margin: 0px;'>$Lang::tr{'system info linkmii'}:</pre></td>";
print "</tr><tr>";
print "<td><pre style='font: 12px; margin: 0px;'>    </pre></td>";
print "<td><pre>";

(@lines) = split(/\n/, `/bin/cat /proc/net/dev`);
foreach my $line (@lines) {
    $line =~ /\s*(.*):(.*)/;
    my $iface = $1;
    next if (($iface eq "") || ($iface eq "lo") || ($iface =~ /ipsec|mast0|ppp|tun/));

    $output = `/usr/local/bin/sysinfo --mii=$iface`;
    if (length ($output) < 5) {
        $output = "$iface: link status: unknown (MII not supported)\n";
    }
    $output = &General::color_devices($output);
    print $output;
}

print "</pre></td>";
print "</tr></table>";

print "<table cellspacing='0' cellpadding='0'border='0'><tr>";
print "<td colspan='2'><pre style='font: 12px; margin: 0px;'>$Lang::tr{'system info linketh'}:</pre></td>";
print "</tr><tr>";
print "<td><pre style='font: 12px; margin: 0px;'>    </pre></td>";
print "<td>";

(@lines) = split(/\n/, `/bin/cat /proc/net/dev`);
foreach my $line (@lines) {
    $line =~ /\s*(.*):(.*)/;
    my $iface = $1;
    next if (($iface eq "") || ($iface eq "lo") || ($iface =~ /ipsec|mast0|ppp|tun/));

    $output = `/usr/local/bin/sysinfo --link=$iface | /bin/grep Settings`;
    my $outputethtoolspd = `/usr/local/bin/sysinfo --link=$iface | /bin/grep Speed`;
    my $outputethtooldup = `/usr/local/bin/sysinfo --link=$iface | /bin/grep Duplex`;
    my $outputethtoollnk = `/usr/local/bin/sysinfo --link=$iface | /bin/grep Link`;
    $output = &General::color_devices($output);
    $outputethtoolspd = &Header::cleanhtml($outputethtoolspd);
    $outputethtooldup = &Header::cleanhtml($outputethtooldup);
    $outputethtoollnk = &Header::cleanhtml($outputethtoollnk);
    print "<pre>$output $outputethtoolspd $outputethtooldup $outputethtoollnk</pre>";
}   

print "</td>";
print "</tr></table>";
&Header::closebox();

print "<a name='usb'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'system info usb'}:");
my $outputusb = `/usr/local/bin/sysinfo --usb`;
$outputusb = &Header::cleanhtml($outputusb);
print "<pre>$outputusb</pre>\n";
&Header::closebox();

print "<a name='irq'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'system info irq'}:");
$output = `/bin/cat /proc/interrupts`;
$output = &General::color_devices($output);
print "<pre>$output</pre>\n";
&Header::closebox();

print "<a name='ps'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'system info ps'}:");
my $outputps = `ps fax -o user,pid,ppid,%cpu,%mem,vsz,rss,tty,stat,start,time,command --cols 128`;
$outputps = &Header::cleanhtml($outputps);
print "<pre>$outputps</pre>\n";
&Header::closebox();

print "<a name='modules'></a>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'loaded modules'}:");
my @lsmod = qx+/bin/lsmod+;

my $boldclass = "class='boldbase'";
print "<table width='100%'>";
foreach my $line (@lsmod) {
    chomp($line);
    ($line = &Header::cleanhtml($line,"y")) =~ s/\[.*\]//g;
    my @split = split(/\s+/, $line);

    my @usedby=split(/,/,$split[3]);
    my $printusedby='';
    my $i=1;
    foreach my $module (@usedby) {
        if ($i % 5 != 1) {
            $printusedby.=',';
        }
        $printusedby.=$module;
        if ($i % 5 == 0) {
            $printusedby.="<br />";
        }
        $i++;
    }

    printf <<END
<tr valign='top'>
  <td width='12%' $boldclass>$split[0]&nbsp;</td>
  <td width='5%' align='right' $boldclass>$split[1]&nbsp;</td>
  <td width='5%' align='right' $boldclass>$split[2]&nbsp;</td>
  <td width='78%' $boldclass>$printusedby</td>
</tr>
END
;
    $boldclass = '';
}
print "</table>\n";
&Header::closebox();

&Header::closebigbox();

&Header::closepage();

##
## Output Diskinfo for 1 disk
##
sub diskinfo 
{
    my $dev = shift;
    my $outputhdd = `/usr/local/bin/sysinfo --disk=$dev`;
    $outputhdd = &Header::cleanhtml($outputhdd);
    
    print "<pre>";
    (@lines) = split(/\n/, $outputhdd);
    my $counter = 0;
    foreach my $line (@lines) {
        print $line."\r" if ($counter++ > 2);
    }
    print "</pre>\n";
}
