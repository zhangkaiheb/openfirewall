#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL
#
# (c) The SmoothWall Team
#
# $Id: netstatus.cgi 4476 2010-04-15 18:33:40Z eoberlander $
#

# Add entry in menu
# MENUENTRY status 030 "ssnetwork status" "network status information"
#
# Make sure translation exists $Lang::tr{'ssnetwork status'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

my %dhcpsettings=();
my %netsettings=();
my %dhcpinfo=();
my %pppsettings=();
my $output='';
$dhcpinfo{'DOMAIN'}=''; # because it may not be defined in the answer
my $dhcpserver = 0;

&General::readhash('/var/ipcop/dhcp/settings', \%dhcpsettings);
&General::readhash('/var/ipcop/ethernet/settings', \%netsettings);
&General::readhash('/var/ipcop/ppp/settings', \%pppsettings);
&Header::showhttpheaders();
&Header::openpage($Lang::tr{'network status information'}, 1, '');

my @DHCPINTERFACEs=('GREEN','BLUE');
foreach my $interface (@DHCPINTERFACEs) {
    for (my $counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
        if ( $dhcpsettings{"ENABLED_${interface}_${counter}"} eq 'on' ) {
            $dhcpserver++;
        }
    }
}

&Header::openbigbox('100%', 'left');

print "<table width='100%' cellspacing='0' cellpadding='5' border='0'>\n";
print "<tr><td style='background-color: #FFFFFF;' align='left'>\n";
print "<a href='#interfaces'>$Lang::tr{'interfaces'}</a> |\n";
print "<a href='#reddns'>$Lang::tr{'red'} $Lang::tr{'dns configuration'}</a> |\n";
if ( ($netsettings{'RED_COUNT'} >= 1) && $netsettings{'RED_1_TYPE'} eq "DHCP") {
    print "<a href='#reddhcp'>$Lang::tr{'red'} $Lang::tr{'dhcp configuration'}</a> |\n";
}
if ($dhcpserver > 0) {
    print "<a href='#leases'>$Lang::tr{'current dynamic leases'}</a> |\n";
}
if ($pppsettings{'TYPE'} =~ /^(bewanadsl|alcatelusb|conexantpciadsl|eagleusbadsl|wanpipe)$/) {
    print "<a href='#adsl'>$Lang::tr{'adsl settings'}</a> |\n";
}
print "<a href='#routing'>$Lang::tr{'routing table entries'}</a> |\n";
print "<a href='#arp'> $Lang::tr{'arp table entries'}</a>\n";
print "</td></tr></table>\n";

print "<a name='interfaces'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'interfaces'}:");

my %addrs = {};
my $intid = "";

$output = `/sbin/ip addr list`;
$output = &Header::cleanhtml($output,"y");
foreach my $line (split(/\n/, $output))
{
  if ($line =~ m/^([0-9]+): ([^ ]+): (.*)$/) {
    $intid = "$1: $2:";
    $addrs{$intid}  = " <tr class='table1colour'><td colspan='2'>".&General::color_devices($2)."</td></tr><tr><td width='5%'>&nbsp;</td><td>".$3."</td></tr>\n";
  } else {
    $addrs{$intid} .= " <tr><td>&nbsp;</td><td>$line</td></tr>\n"
  }
}

$output = `/sbin/ip -s link list`;
$output = &Header::cleanhtml($output,"y");
$intid = "";
print "<table width='100%'>\n";
foreach my $line (split(/\n/, $output))
{
  if ($line =~ m/^([0-9]+): ([^ ]+): (.*)$/) {
    print " </table></td></tr><tr><td colspan='2'>&nbsp;</td></tr>\n" unless ($intid eq "");
    $intid = "$1: $2:";
    print $addrs{$intid};
    print " <tr><td>&nbsp;</td><td><table width='90%'>\n";
  } elsif ($line =~ m/^\s+([TR]X:)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/) {
    print "  <tr class='table1colour'><td><b>$1</b></td><td>$2</td><td>$3</td><td>$4</td><td>$5</td><td>$6</td><td>$7</td></tr>\n";
  } elsif ($line =~ m/^\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/) {
    print "  <tr><td>&nbsp;</td><td>$1</td><td>$2</td><td>$3</td><td>$4</td><td>$5</td><td>$6</td></tr>\n";
  }
}
print "</table></td></tr></table>\n";

&Header::closebox();

print "<a name='reddns'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'red'} $Lang::tr{'dns configuration'}:");
if (-e "/var/ipcop/red/active") {
    my $dns1 = `/bin/cat /var/ipcop/red/dns1`;
    chomp($dns1);
    my $dns2 = `/bin/cat /var/ipcop/red/dns2`;
    chomp($dns2);

    print <<END
<table width='100%'>
    <tr><td width='30%'>$Lang::tr{'primary dns'}:</td><td>$dns1</td></tr>
    <tr><td width='30%'>$Lang::tr{'secondary dns'}:</td><td>$dns2</td></tr>
</table>
END
    ;
}
else {
    print "$Lang::tr{'connection is down'}";
}    
&Header::closebox();

if ( ($netsettings{'RED_COUNT'} >= 1)  && $netsettings{'RED_1_TYPE'} eq "DHCP") {

    print "<a name='reddhcp'/>\n";
    &Header::openbox('100%', 'left', "$Lang::tr{'red'} $Lang::tr{'dhcp configuration'}:");
    if (-s "/var/log/dhcpclient.info") {

        &General::readhash("/var/log/dhcpclient.info", \%dhcpinfo);

        my $lsetme=0;
        my $leasetime="";
        if ($dhcpinfo{'DHCLIENT_LEASETIME'} ne "") {
            $lsetme=$dhcpinfo{'DHCLIENT_LEASETIME'};
            $lsetme=($lsetme/60);
            if ($lsetme > 59) {
                $lsetme=($lsetme/60); $leasetime=$lsetme." Hour";
            } 
            else {
                $leasetime=$lsetme." Minute";
            }
            if ($lsetme > 1) {
                $leasetime=$leasetime."s";
            }
        }
        my $leaseexpires = localtime($dhcpinfo{'DHCLIENT_EXPIRY'});

        print "<table width='100%'>";
        if ($dhcpinfo{'DHCLIENT_HOSTNAME'}) {
            print "<tr><td width='30%'>$Lang::tr{'hostname'}:</td><td>$dhcpinfo{'DHCLIENT_HOSTNAME'}.$dhcpinfo{'DHCLIENT_DOMAIN'}</td></tr>\n";
        } 
        else {
            print "<tr><td width='30%'>$Lang::tr{'domain'}:</td><td>$dhcpinfo{'DHCLIENT_DOMAIN'}</td></tr>\n";
        }
        print <<END
    <tr><td>$Lang::tr{'gateway'}:</td><td>$dhcpinfo{'DHCLIENT_GATEWAY'}</td></tr>
    <tr><td>$Lang::tr{'primary dns'}:</td><td>$dhcpinfo{'DHCLIENT_DNS1'}</td></tr>
    <tr><td>$Lang::tr{'secondary dns'}:</td><td>$dhcpinfo{'DHCLIENT_DNS2'}</td></tr>
    <tr><td>$Lang::tr{'dhcp server'}:</td><td>$dhcpinfo{'DHCLIENT_SIADDR'}</td></tr>
    <tr><td>$Lang::tr{'def lease time'}:</td><td>$leasetime</td></tr>
    <tr><td>$Lang::tr{'lease expires'}:</td><td>$leaseexpires</td></tr>
</table>
END
    ;
    }
    else {
        print "$Lang::tr{'no dhcp lease'}";
    }
    &Header::closebox();
}

if ($dhcpserver > 0) {
    print "<a name='leases'/>";
    &General::CheckSortOrder;
    &General::PrintActualLeases;
}

if ( ($netsettings{'RED_COUNT'} == 0)  && (exists($pppsettings{'TYPE'})) ) {
    my $output1='';
    my $output2='';
    if ($pppsettings{'TYPE'} eq 'bewanadsl') {
        print "<a name='adsl'/>\n";
        &Header::openbox('100%', 'left', "$Lang::tr{'adsl settings'}:");
        $output1 = `/usr/bin/unicorn_status`;
        $output1 = &Header::cleanhtml($output1,"y");
        $output2 = `/bin/cat /proc/net/atm/UNICORN:*`;
        $output2 = &Header::cleanhtml($output2,"y");
        print "<pre>$output1$output2</pre>\n";
        &Header::closebox();
    }
    if ($pppsettings{'TYPE'} eq 'alcatelusb') {
        print "<a name='adsl'/>\n";
        &Header::openbox('100%', 'left', "$Lang::tr{'adsl settings'}:");
        $output = `/bin/cat /proc/net/atm/speedtch:*`;
        $output = &Header::cleanhtml($output,"y");
        print "<pre>$output</pre>\n";
        &Header::closebox();
    }
    if ($pppsettings{'TYPE'} eq 'conexantpciadsl') {
        print "<a name='adsl'/>\n";
        &Header::openbox('100%', 'left', "$Lang::tr{'adsl settings'}:");
        $output = `/bin/cat /proc/net/atm/CnxAdsl:*`;
        $output = &Header::cleanhtml($output,"y");
        print "<pre>$output</pre>\n";
        &Header::closebox();
    }
    if ($pppsettings{'TYPE'} eq 'eagleusbadsl') {
        print "<a name='adsl'/>\n";
        &Header::openbox('100%', 'left', "$Lang::tr{'adsl settings'}:");
        $output = `/usr/sbin/eaglestat`;
        $output = &Header::cleanhtml($output,"y");
        print "<pre>$output</pre>\n";
        &Header::closebox();
    }
    if ($pppsettings{'TYPE'} eq 'wanpipe') {
        print "<a name='adsl'/>\n";
        &Header::openbox('100%', 'left', "$Lang::tr{'adsl settings'}:");
        $output = `/bin/cat /proc/net/wanrouter/config | /usr/bin/sort`;
        $output = &Header::cleanhtml($output,"y");
        print "<pre>$output</pre>\n";
        &Header::closebox();
    }
}

print "<a name='routing'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'routing table entries'}:");
$output = `/sbin/ip route list`;
$output = &Header::cleanhtml($output,"y");
print <<END
<table width='100%'>
<tr>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'destination ip or net'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'gateway ip'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'interface'}</td>
    <td width='25%' class='boldbase'>$Lang::tr{'remark'}</td>
</tr>
END
;
my $count = 0;
foreach my $line (split(/\n/, $output))
{
    print "<tr class='table".int(($count % 2) + 1)."colour'>";
    if ($line =~ m/^(.*) dev ([^ ]+) (.*) src (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>$4</td>";
        print "<td align='center'>".&General::color_devices($2)."</td><td>$3</td></tr>";
    }
    elsif ($line =~ m/^(.*) via (.*) dev (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>$2</td>";
        print "<td align='center'>".&General::color_devices($3)."</td><td>&nbsp;</td></tr>";
    }
    elsif ($line =~ m/^(.*) dev ipsec(\d*)  (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>&nbsp;</td>";
        print "<td align='center'>".&General::color_devices("ipsec$2")."</td><td>$3</td></tr>";
    }
    else {
        print "<td colspan='4'>$line</td></tr>";
    }
    
    $count++;
}
print "</table>";
&Header::closebox();

print "<a name='arp'/>\n";
&Header::openbox('100%', 'left', "$Lang::tr{'arp table entries'}:");
$output = `/sbin/ip neigh list`;
$output = &Header::cleanhtml($output,"y");
print <<END
<table width='100%'>
<tr>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'ip address'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'interface'}</td>
    <td width='25%' align='center' class='boldbase'>$Lang::tr{'mac address'}</td>
    <td width='25%' class='boldbase'>$Lang::tr{'status'}</td>
</tr>
END
;
my $count = 0;
foreach my $line (split(/\n/, $output))
{
    print "<tr class='table".int(($count % 2) + 1)."colour'>";
    if ($line =~ m/^(.*) dev ([^ ]+) lladdr ([0-9a-f:]*) (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>".&General::color_devices($2)."</td>";
        print "<td align='center'>$3</td><td>$4</td></tr>";
    }
    elsif ($line =~ m/^(.*) dev ([^ ]+)  (.*)$/) {
        print "<td align='center'>$1</td><td align='center'>".&General::color_devices($2)."</td>";
        print "<td align='center'>-</td><td>$3</td></tr>";
    }
    else {
        print "<td colspan='4'>$line</td></tr>";
    }
    
    $count++;
}
print "</table>";
&Header::closebox();

&Header::closebigbox();

&Header::closepage();
