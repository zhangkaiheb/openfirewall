#!/usr/bin/perl
#
#
# This code is distributed under the terms of the GPL
#
#

# Add entry in menu
# MENUENTRY status 040 "ssnetwork status" "network status information"
#
# Make sure translation exists $Lang::tr{'ssnetwork status'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/widget-lib.pl';

my %dhcpsettings=();
my %netsettings=();
my %dhcpinfo=();
my %pppsettings=();
my $output='';
$dhcpinfo{'DOMAIN'}=''; # because it may not be defined in the answer
my $dhcpserver = 0;

&General::readhash('/var/ofw/dhcp/settings', \%dhcpsettings);
&General::readhash('/var/ofw/ethernet/settings', \%netsettings);
&General::readhash('/var/ofw/ppp/settings', \%pppsettings);
&Header::showhttpheaders();

my $extrahead = Widget::widget_css();
&Header::openpage($Lang::tr{'network status information'}, 1, $extrahead);

my %icons = Widget::widget_icons();
my $closeIcon = $icons{'close'};
my $expandIcon = $icons{'expand'};

my @DHCPINTERFACEs=('GREEN','BLUE');
foreach my $interface (@DHCPINTERFACEs) {
    for (my $counter = 1; $counter <= $netsettings{"${interface}_COUNT"}; $counter++) {
        if ( $dhcpsettings{"ENABLED_${interface}_${counter}"} eq 'on' ) {
            $dhcpserver++;
        }
    }
}

print Widget::widget_add_button();
print "<div class='status-widget-grid'>\n";

# Interfaces - each interface as a separate widget
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
my $current_iface = "";
my $iface_content = "";

# Collect all interfaces and their content
my @interfaces = ();
my %iface_data = ();

foreach my $line (split(/\n/, $output))
{
  if ($line =~ m/^([0-9]+): ([^ ]+): (.*)$/) {
    if ($current_iface ne "") {
        # Save previous interface data
        $iface_data{$current_iface} = $iface_content;
    }
    $current_iface = $2;
    push(@interfaces, $current_iface) unless grep { $_ eq $current_iface } @interfaces;
    $iface_content = "";
    $intid = "$1: $2:";
    $iface_content .= $addrs{$intid} if exists $addrs{$intid};
    $iface_content .= " <tr><td>&nbsp;</td><td><table width='90%'>\n";
  } elsif ($line =~ m/^\s+([TR]X:)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)\s+([^ ]+)/) {
    $iface_content .= "  <tr class='table1colour'><td><b>$1</b></td><td>$2</td><td>$3</td><td>$4</td><td>$5</td><td>$6</td><td>$7</td></tr>\n";
  } elsif ($line =~ m/^\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/) {
    $iface_content .= "  <tr><td>&nbsp;</td><td>$1</td><td>$2</td><td>$3</td><td>$4</td><td>$5</td><td>$6</td></tr>\n";
  }
}
# Save last interface
if ($current_iface ne "") {
    $iface_data{$current_iface} = $iface_content;
}

# Output each interface as a separate widget card
foreach my $iface (@interfaces) {
    print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$iface</span>
END
;
print Widget::widget_header_buttons($closeIcon, $expandIcon);
print <<END
    </div>
    <div class="widget-body">
        <table width='100%'>
END
;
    print $iface_data{$iface};
    print "</table></td></tr></table>\n";
    print <<END
    </div>
</div>
END
;
}

# Red DNS Configuration widget
print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$Lang::tr{'red'} $Lang::tr{'dns configuration'}</span>
END
;
print Widget::widget_header_buttons($closeIcon, $expandIcon);
print <<END
    </div>
    <div class="widget-body">
END
;
if (-e "/var/ofw/red/active") {
    my $dns1 = `/bin/cat /var/ofw/red/dns1`;
    chomp($dns1);
    my $dns2 = `/bin/cat /var/ofw/red/dns2`;
    chomp($dns2);

    print <<END
<table class="widget-table">
    <tr><td width='30%'>$Lang::tr{'primary dns'}:</td><td>$dns1</td></tr>
    <tr><td width='30%'>$Lang::tr{'secondary dns'}:</td><td>$dns2</td></tr>
</table>
END
    ;
}
else {
    print "$Lang::tr{'connection is down'}";
}
print <<END
    </div>
</div>
END
;

# Red DHCP Configuration widget (conditional)
if ( ($netsettings{'RED_COUNT'} >= 1)  && $netsettings{'RED_1_TYPE'} eq "DHCP") {
    print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$Lang::tr{'red'} $Lang::tr{'dhcp configuration'}</span>
END
;
    print Widget::widget_header_buttons($closeIcon, $expandIcon);
    print <<END
    </div>
    <div class="widget-body">
END
;
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

        print "<table class='widget-table'>";
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
    print <<END
    </div>
</div>
END
;
}

# Current Dynamic Leases widget (conditional)
if ($dhcpserver > 0) {
    &General::CheckSortOrder;
    &General::PrintActualLeases;
}

# ADSL Settings widget (conditional)
if ( ($netsettings{'RED_COUNT'} == 0)  && (exists($pppsettings{'TYPE'})) ) {
    my $output1='';
    my $output2='';
    if ($pppsettings{'TYPE'} eq 'bewanadsl') {
        $output1 = `/usr/bin/unicorn_status`;
        $output1 = &Header::cleanhtml($output1,"y");
        $output2 = `/bin/cat /proc/net/atm/UNICORN:*`;
        $output2 = &Header::cleanhtml($output2,"y");
        print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$Lang::tr{'adsl settings'}</span>
END
;
        print Widget::widget_header_buttons($closeIcon, $expandIcon);
        print <<END
    </div>
    <div class="widget-body">
        <pre>$output1$output2</pre>
    </div>
</div>
END
;
    }
    if ($pppsettings{'TYPE'} eq 'alcatelusb') {
        $output = `/bin/cat /proc/net/atm/speedtch:*`;
        $output = &Header::cleanhtml($output,"y");
        print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$Lang::tr{'adsl settings'}</span>
END
;
        print Widget::widget_header_buttons($closeIcon, $expandIcon);
        print <<END
    </div>
    <div class="widget-body">
        <pre>$output</pre>
    </div>
</div>
END
;
    }
    if ($pppsettings{'TYPE'} eq 'conexantpciadsl') {
        $output = `/bin/cat /proc/net/atm/CnxAdsl:*`;
        $output = &Header::cleanhtml($output,"y");
        print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$Lang::tr{'adsl settings'}</span>
END
;
        print Widget::widget_header_buttons($closeIcon, $expandIcon);
        print <<END
    </div>
    <div class="widget-body">
        <pre>$output</pre>
    </div>
</div>
END
;
    }
    if ($pppsettings{'TYPE'} eq 'eagleusbadsl') {
        $output = `/usr/sbin/eaglestat`;
        $output = &Header::cleanhtml($output,"y");
        print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$Lang::tr{'adsl settings'}</span>
END
;
        print Widget::widget_header_buttons($closeIcon, $expandIcon);
        print <<END
    </div>
    <div class="widget-body">
        <pre>$output</pre>
    </div>
</div>
END
;
    }
    if ($pppsettings{'TYPE'} eq 'wanpipe') {
        $output = `/bin/cat /proc/net/wanrouter/config | /usr/bin/sort`;
        $output = &Header::cleanhtml($output,"y");
        print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$Lang::tr{'adsl settings'}</span>
END
;
        print Widget::widget_header_buttons($closeIcon, $expandIcon);
        print <<END
    </div>
    <div class="widget-body">
        <pre>$output</pre>
    </div>
</div>
END
;
    }
}

print "</div>\n";

print Widget::widget_add_dialog($Lang::tr{'cancel'}, $Lang::tr{'add'});
print Widget::widget_js();

&Header::closepage();
