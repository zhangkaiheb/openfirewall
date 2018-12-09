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
# (c) 2001 Jack Beglinger <jackb_guppy@yahoo.com>
#
# (c) 2003 Dave Roberts <countzerouk@hotmail.com> - colour coded netfilter/iptables rewrite for 1.3
#
# (c) 2006 Franck - add sorting+filtering capability
#
# (c) 2008 Olaf for the Openfirewall Team - use conntrack with XML output from conntrack-tools
# (c) 2008 - 2011, the Openfirewall Team
#
# $Id: connections.cgi 7065 2013-06-08 20:21:14Z dotzball $
#

# Add entry in menu
# MENUENTRY status 080 "connections" "connections"

use strict;


# network will hold all known 'networks' in address/mask format. If mask is missing /32 is assumed.
my @network = ();
my @routes  = ();
my @colour  = ();
# since we want to show the OpenVPN Tunnel 'colored' we also check for protocol/port
# default setting is udp/1194 for OpenVPN
my @ports=();
my @protocols=();

# enable only the following on debugging purpose
use warnings; no warnings 'once';
use CGI::Carp 'fatalsToBrowser';
my $debug = 0;

use NetAddr::IP;
use XML::Simple;
use XML::Parser::Style::Tree;

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my $icount = 0;

# Read various files

my %netsettings = ();
&General::readhash('/var/ofw/ethernet/settings', \%netsettings);
my %mainsettings = ();
$mainsettings{'DISPLAY_CONNECTIONS'} = 'TRAFFIC';
&General::readhash('/var/ofw/main/settings', \%mainsettings);

my %cgiparams = ();
$cgiparams{'ACTION'} = '';
#Establish simple filtering&sorting boxes on top of table
$cgiparams{'SEE_PROTO'} = '';
$cgiparams{'SEE_STATE'} = '';
$cgiparams{'SEE_MARK'}  = '';
$cgiparams{'SEE_SRC'}   = '';
$cgiparams{'SEE_DEST'}  = '';
$cgiparams{'SEE_SORT'}  = '';
&General::getcgihash(\%cgiparams);


&Header::showhttpheaders();
&Header::openpage($Lang::tr{'connections'}, 1, '');
&Header::openbigbox('100%', 'left');


if ($cgiparams{'ACTION'} eq 'SAVE') {
    $mainsettings{'DISPLAY_CONNECTIONS'} = $cgiparams{'DISPLAY_CONNECTIONS'};
    &General::writehash('/var/ofw/main/settings', \%mainsettings);
}
if ( $cgiparams{'ACTION'} eq $Lang::tr{'refresh'} ) {
}


my $aliasfile = '/var/ofw/ethernet/aliases';
open(ALIASES, $aliasfile) or die 'Unable to open aliases file.';
my @aliases = <ALIASES>;
close(ALIASES);

# Add limited broadcast
push(@network, "255.255.255.255");
push(@colour,  'ofw_iface_bg_fw');
push(@ports, '0');
push(@protocols, '');

# Add IPsec remote networks
if (-e '/var/ofw/ipsec/config') {
    my %confighash=();
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);

    foreach my $key (keys(%confighash)) {
        # Only enabled and net-net configlines
        next unless ($confighash{$key}[0] eq 'on');
        next unless ($confighash{$key}[3] eq 'net');

        push(@network, $confighash{$key}[11]);
        push(@colour,  'ofw_iface_bg_ipsec');
        push(@ports, '0');
        push(@protocols, '');
    }
}

# Add Firewall Localhost 127.0.0.1
push(@network, '127.0.0.1');
push(@colour,  'ofw_iface_bg_fw');
push(@ports, '0');
push(@protocols, '');

# Add IGMP Multicast 224.0.0.0/4
push(@network, '224.0.0.1/4');
push(@colour,  'ofw_iface_bg_fw');
push(@ports, '0');
push(@protocols, '');


# Add OpenVPN net and RED/BLUE/ORANGE entry (when appropriate)
if (-e '/var/ofw/openvpn/settings') {
    my %ovpnsettings = ();
    # defaults for some OpenVPN parameters to avoid "Use of uninit value" warnings
    $ovpnsettings{'DOVPN_SUBNET'} = '';
    $ovpnsettings{'ENABLED_RED_1'} = '';
    $ovpnsettings{'ENABLED_BLUE_1'} = '';
    $ovpnsettings{'ENABLED_ORANGE_1'} = '';
    &General::readhash('/var/ofw/openvpn/settings', \%ovpnsettings);

    if ($ovpnsettings{'DOVPN_SUBNET'} ne '') {
        # add OpenVPN net
        push(@network, $ovpnsettings{'DOVPN_SUBNET'});
        push(@colour, 'ofw_iface_bg_ovpn');
        push(@ports, '0');
        push(@protocols, '');
    }
    
    if (open(IP, '/var/ofw/red/local-ipaddress') && ($ovpnsettings{'ENABLED_RED_1'} eq 'on')) {
        # add RED:port / proto
        my $redip = <IP>;
        close(IP);
        chomp $redip;
        push(@network, $redip);
        push(@colour, 'ofw_iface_bg_ovpn');
        push(@ports, $ovpnsettings{'DDEST_PORT'});
        push(@protocols, $ovpnsettings{'DPROTOCOL'});
    }
    if ( ($netsettings{'BLUE_COUNT'} > 0) && ($ovpnsettings{'ENABLED_BLUE_1'} eq 'on')) {
        # add BLUE:port / proto
        push(@network, $netsettings{'BLUE_1_ADDRESS'});
        push(@colour, 'ofw_iface_bg_ovpn');
        push(@ports, $ovpnsettings{'DDEST_PORT'});
        push(@protocols, $ovpnsettings{'DPROTOCOL'});
    }
    if ( ($netsettings{'ORANGE_COUNT'} > 0) && ($ovpnsettings{'ENABLED_ORANGE_1'} eq 'on')) {
      # add ORANGE:port / proto
        push(@network, $netsettings{'ORANGE_1_ADDRESS'});
        push(@colour, 'ofw_iface_bg_ovpn');
        push(@ports, $ovpnsettings{'DDEST_PORT'});
        push(@protocols, $ovpnsettings{'DPROTOCOL'});
    }
}

# Add Green, Blue, Orange Network
foreach my $interface ("GREEN","ORANGE","BLUE") {
    $icount = $netsettings{"${interface}_COUNT"};
    while ($icount > 0) {

        if(my $ip = new NetAddr::IP($netsettings{"${interface}_${icount}_ADDRESS"}, $netsettings{"${interface}_${icount}_NETMASK"})) {
            my $lc_colour = "ipcop_iface_bg_".lc(${interface});

            # Add Firewall Interface
            push(@network, $ip->addr());
            push(@colour,  'ofw_iface_bg_fw');
            push(@ports, '0');
            push(@protocols, '');

            # Add Broadcast address
            push(@network, $ip->broadcast()->addr());
            push(@colour,  'ofw_iface_bg_fw');
            push(@ports, '0');
            push(@protocols, '');

            # Add Network
            push(@network, $ip->network());
            push(@colour,  $lc_colour);
            push(@ports, '0');
            push(@protocols, '');

            # Add Routes
            @routes = `/sbin/ip route list | /bin/grep 'via.*$netsettings{"${interface}_${icount}_DEV"}'`;
            foreach my $route (@routes) {
                chomp($route);
                my @temp = split(/[\t ]+/, $route);
                push(@network, $temp[0]);
                push(@colour,  'ofw_iface_bg_green');
                push(@ports, '0');
                push(@protocols, '');
            }
        }
        $icount--;
    }
}

# Add STATIC RED aliases
$icount = $netsettings{'RED_COUNT'};
while ($icount > 0) {
    # We have a RED eth iface
    if ($netsettings{"RED_${icount}_TYPE"} eq 'STATIC') {
        # We have a STATIC RED eth iface
        foreach my $line (@aliases) {
            chomp($line);
            my @temp = split(/\,/, $line);
            if ($temp[0]) {
                push(@network, $temp[0]);
                push(@colour,  'ofw_iface_bg_fw');
                push(@ports, '0');
                push(@protocols, '');
            }
        }
    }
    $icount--;
}

if (open(IP, '/var/ofw/red/local-ipaddress')) {
    my $redip = <IP>;
    close(IP);
    chomp $redip;
    push(@network, $redip);
    push(@colour,  'ofw_iface_bg_fw');
    push(@ports, '0');
    push(@protocols, '');
}


my @list_proto = ($Lang::tr{'all'}, 'icmp', 'udp', 'tcp');
my @list_state = (
    $Lang::tr{'all'}, 'SYN_SENT',  'SYN_RECV', 'ESTABLISHED', 'FIN_WAIT', 'CLOSE_WAIT',
    'LAST_ACK',       'TIME_WAIT', 'CLOSE',    'LISTEN'
);
my @list_mark = ($Lang::tr{'all'}, '[ASSURED]', '[UNREPLIED]');
my @list_sort = (
    'orgsip', 'protocol', 'expires', 'status', 'orgdip', 'orgsp',
    'orgdp',  'repsip',   'repdip',  'repsp',  'repdp',  'marked'
);

# init or silently correct unknown value...
if (!grep (/^$cgiparams{'SEE_PROTO'}$/, @list_proto)) {
    $cgiparams{'SEE_PROTO'} = $list_proto[0];
}
if (!grep (/^$cgiparams{'SEE_STATE'}$/, @list_state)) {
    $cgiparams{'SEE_STATE'} = $list_state[0];
}
if (
    ($cgiparams{'SEE_MARK'} ne $Lang::tr{'all'}) &&    # ok the grep should work but it doesn't because of
    ($cgiparams{'SEE_MARK'} ne '[ASSURED]') &&         # the '[' & ']' interpreted as list separator.
    ($cgiparams{'SEE_MARK'} ne '[UNREPLIED]')          # So, explicitly enumerate items.
    )
{
    $cgiparams{'SEE_MARK'} = $list_mark[0];
}
if (!grep (/^$cgiparams{'SEE_SORT'}$/, @list_sort)) {
    $cgiparams{'SEE_SORT'} = $list_sort[0];
}

# *.*.*.* or a valid IP
if ($cgiparams{'SEE_SRC'} !~ /^(\*\.\*\.\*\.\*\.|\d+\.\d+\.\d+\.\d+)$/) {
    $cgiparams{'SEE_SRC'} = '*.*.*.*';
}
if ($cgiparams{'SEE_DEST'} !~ /^(\*\.\*\.\*\.\*\.|\d+\.\d+\.\d+\.\d+)$/) {
    $cgiparams{'SEE_DEST'} = '*.*.*.*';
}

our %entries = ();    # will hold the lines analyzed correctly
my $unknownlines = '';    # should be empty all the time...
my $index        = 0;     # just a counter to make unique entryies in entries

# Fetch connection tracking info in XML format
my $lines = `/usr/local/bin/conntrack_helper`;
my $xml  = new XML::Simple;
my $active = eval { $xml->XMLin($lines) };

foreach my $data (@{$active->{flow}}) {

    foreach my $elt (@{$data->{meta}}) {
        if ($elt->{direction} eq 'original') {
            if ($elt->{layer4}->{protoname} eq 'unknown') {
                if ($elt->{layer4}->{protonum} == 50) {
                    $entries{$index}->{protocol} = "esp";
                }
                elsif ($elt->{layer4}->{protonum} == 2) {
                    $entries{$index}->{protocol} = "igmp";
                }
                else {
                    $entries{$index}->{protocol} = "($elt->{layer4}->{protonum})";
                }
            }
            else {
                $entries{$index}->{protocol} = $elt->{layer4}->{protoname};
            }
            $entries{$index}->{orgsip}   = $elt->{layer3}->{src};
            $entries{$index}->{orgdip}   = $elt->{layer3}->{dst};
            $entries{$index}->{orgsp}    = $elt->{layer4}->{sport};
            $entries{$index}->{orgdp}    = $elt->{layer4}->{dport};
            $entries{$index}->{orgtraf}  = $elt->{counters}->{packets} . " / " . $elt->{counters}->{bytes};
        }
        elsif ($elt->{direction} eq 'reply') {
            $entries{$index}->{repsip}  = $elt->{layer3}->{src};
            $entries{$index}->{repdip}  = $elt->{layer3}->{dst};
            $entries{$index}->{repsp}   = $elt->{layer4}->{sport};
            $entries{$index}->{repdp}   = $elt->{layer4}->{dport};
            $entries{$index}->{reptraf} = $elt->{counters}->{packets} . " / " . $elt->{counters}->{bytes};
        }
        elsif ($elt->{direction} eq 'independent') {
            for my $key (keys %{$elt}) {
                if ($key eq 'timeout') {
                    $entries{$index}->{expires} = ${$elt}{$key};
                }
                elsif ($key eq 'mark') {
                    $entries{$index}->{marked} = ${$elt}{$key};
                }
                elsif ($key eq 'use') {
                    $entries{$index}->{use} = ${$elt}{$key};
                }
                elsif ($key eq 'state') {
                    $entries{$index}->{state} = ${$elt}{$key};
                }
                elsif (($key eq 'id') || ($key eq 'direction')) {
                }
                else {
                    $entries{$index}->{status} = $key;
                }
            }
        }
    }

    if ($entries{$index}->{protocol} eq "esp") {
        $entries{$index}->{orgsp} = '';
        $entries{$index}->{orgdp} = '';
        $entries{$index}->{repsp} = '';
        $entries{$index}->{repdp} = '';
    }
    $index++;
}

# Build listbox objects
my $menu_proto = &make_select('SEE_PROTO', $cgiparams{'SEE_PROTO'}, @list_proto);
my $menu_state = &make_select('SEE_STATE', $cgiparams{'SEE_STATE'}, @list_state);
my $menu_src   = &make_select('SEE_SRC',   $cgiparams{'SEE_SRC'},   &get_known_ips('orgsip'));
my $menu_dest  = &make_select('SEE_DEST',  $cgiparams{'SEE_DEST'},  &get_known_ips('orgdip'));
my $menu_mark  = &make_select('SEE_MARK',  $cgiparams{'SEE_MARK'},  @list_mark);
my $menu_sort  = &make_select('SEE_SORT',  $cgiparams{'SEE_SORT'},  @list_sort);


if ($debug > 0) {
    my $id = 0;
    my $line;
    &Header::openbox('100%', 'left', $Lang::tr{'connection tracking'});
    print "<table width='100%'>";
    print "<tr><th>Address</th><th>Port</th><th>Protocol</th><th>Colour</th></tr>\n";
    foreach $line (@network) {
        print "<tr><td>$network[$id]</td><td>$ports[$id]</td><td>$protocols[$id]</td><td class='$colour[$id]'>$colour[$id]</td></tr>";
        $id++;
    }
    print "</table>";
    &Header::closebox();
}


&Header::openbox('100%', 'left', $Lang::tr{'connection tracking'});

my %selected = ();
$selected{'TRAFFIC'}                            = '';
$selected{'STATUS'}                             = '';
$selected{$mainsettings{'DISPLAY_CONNECTIONS'}} = "selected='selected'";

print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'><tr>
    <td width='25%' class='base'>$Lang::tr{'display'}:</td>
    <td width='25%'><select name='DISPLAY_CONNECTIONS'><option value='TRAFFIC' $selected{'TRAFFIC'}>$Lang::tr{'traffic'}</option><option value='STATUS' $selected{'STATUS'}>$Lang::tr{'status'}</option></select></td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr></table><table width='100%'><tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'><input type='hidden' name='ACTION' value='SAVE' /><input type='submit' name='SUBMIT' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/status-connections.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr></table>
</form>
<hr />
END
    ;

if ($mainsettings{'DISPLAY_CONNECTIONS'} eq 'TRAFFIC') {
    print <<END
<table cellpadding='2'>
<tr><td align='center'><b>$Lang::tr{'protocol'}</b></td>
    <td align='center'><b>$Lang::tr{'original'}<br />$Lang::tr{'source ip and port'}</b></td>
    <td align='center'><b>$Lang::tr{'original'}<br />$Lang::tr{'dest ip and port'}</b></td>
    <td align='center'><b>$Lang::tr{'packets'} / $Lang::tr{'bytes'}</b></td>
    <td align='center'><b>$Lang::tr{'reply'}<br />$Lang::tr{'source ip and port'}</b></td>
    <td align='center'><b>$Lang::tr{'reply'}<br />$Lang::tr{'dest ip and port'}</b></td>
    <td align='center'><b>$Lang::tr{'packets'} / $Lang::tr{'bytes'}</b></td>
</tr>
END
    ;
}
else {
    print <<END
<table cellpadding='2'>
<tr><td align='center'><b>$Lang::tr{'protocol'}</b></td>
    <td align='center'><b>$Lang::tr{'original'}<br />$Lang::tr{'source ip and port'}</b></td>
    <td align='center'><b>$Lang::tr{'original'}<br />$Lang::tr{'dest ip and port'}</b></td>
    <td align='center'><b>$Lang::tr{'reply'}<br />$Lang::tr{'source ip and port'}</b></td>
    <td align='center'><b>$Lang::tr{'reply'}<br />$Lang::tr{'dest ip and port'}</b></td>
    <td align='center'><b>$Lang::tr{'expires'}<br />($Lang::tr{'seconds'})</b></td>
    <td align='center' colspan='2'><b>$Lang::tr{'connection'}<br />$Lang::tr{'status'}</b></td>
    <td align='center'><b>$Lang::tr{'marked'}</b></td>
    <td align='center'><b>$Lang::tr{'use'}</b></td>
</tr>
END
    ;
}    

foreach my $entry (sort sort_entries keys %entries) {
    my $orgsipcolour = &ipcolour($entries{$entry}->{orgsip}, $entries{$entry}->{orgsp}, $entries{$entry}->{protocol});
    my $orgdipcolour = &ipcolour($entries{$entry}->{orgdip}, $entries{$entry}->{orgdp}, $entries{$entry}->{protocol});
    my $repsipcolour = &ipcolour($entries{$entry}->{repsip}, $entries{$entry}->{repsp}, $entries{$entry}->{protocol});
    my $repdipcolour = &ipcolour($entries{$entry}->{repdip}, $entries{$entry}->{repdp}, $entries{$entry}->{protocol});
    
    my $trafficoriginal = "";
    $trafficoriginal = "<td align='center'>$entries{$entry}->{orgtraf}</td>" if ($mainsettings{'DISPLAY_CONNECTIONS'} eq 'TRAFFIC');
    my $trafficreply = "";
    $trafficreply = "<td align='center'>$entries{$entry}->{reptraf}</td>" if ($mainsettings{'DISPLAY_CONNECTIONS'} eq 'TRAFFIC');
    
    print <<END
<tr class='table1colour'>
    <td align='center'>$entries{$entry}->{protocol}</td>
    <td align='center' class='$orgsipcolour'>
        <a href='/cgi-bin/ipinfo.cgi?ip=$entries{$entry}->{orgsip}' class='$orgsipcolour'>
        $entries{$entry}->{orgsip}
        </a>:$entries{$entry}->{orgsp}</td>
    <td align='center' class='$orgdipcolour'>
        <a href='/cgi-bin/ipinfo.cgi?ip=$entries{$entry}->{orgdip}' class='$orgdipcolour'>
        $entries{$entry}->{orgdip}
        </a>:$entries{$entry}->{orgdp}</td>
    $trafficoriginal	
    <td align='center' class='$repsipcolour'>
        <a href='/cgi-bin/ipinfo.cgi?ip=$entries{$entry}->{repsip}' class='$repsipcolour'>
        $entries{$entry}->{repsip}
        </a>:$entries{$entry}->{repsp}</td>
    <td align='center' class='$repdipcolour'>
        <a href='/cgi-bin/ipinfo.cgi?ip=$entries{$entry}->{repdip}' class='$repdipcolour'>
        $entries{$entry}->{repdip}
        </a>:$entries{$entry}->{repdp}</td>
    $trafficreply
END
    ;

    if ($mainsettings{'DISPLAY_CONNECTIONS'} ne 'TRAFFIC') {
        print <<END
    <td align='center'>$entries{$entry}->{expires}</td>
    <td align='center'>$entries{$entry}->{state}</td>
    <td align='center'>$entries{$entry}->{status}</td>
    <td align='center'>$entries{$entry}->{marked}</td>
    <td align='center'>$entries{$entry}->{use}</td>
END
       ;
    }
    print "</tr>\n";    
}

print <<END
</table>
<hr />
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'><tr>
    <td class='comment1button'><table width='100%'><tr>
        <td align='center'><b>$Lang::tr{'legend'}: </b></td>
        <td align='center' class='ofw_iface_bg_green'><b>$Lang::tr{'lan'}</b></td>
        <td align='center' class='ofw_iface_bg_red'><b>$Lang::tr{'internet'}</b></td>
        <td align='center' class='ofw_iface_bg_blue'><b>$Lang::tr{'wireless'}</b></td>
        <td align='center' class='ofw_iface_bg_orange'><b>$Lang::tr{'dmz'}</b></td>
        <td align='center' class='ofw_iface_bg_fw'><b>Openfirewall</b></td>
        <td align='center' class='ofw_iface_bg_ipsec'><b>IPsec</b></td>
        <td align='center' class='ofw_iface_bg_ovpn'><b>OpenVPN</b></td>
    </tr></table></td>
    <td class='button1button'><input type='submit' name='ACTION' value='$Lang::tr{'refresh'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/status-connections.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr></table>
</form>
END
;

&Header::closebox();
&Header::closebigbox();
&Header::closepage();

sub ipcolour($) {
    my $id = 0;
    my $line;
    my $colour = 'ofw_iface_bg_red';
    my $ip = new NetAddr::IP($_[0]);
    my ($port) = $_[1];
    my ($protocol) = substr $_[2], 0, 3;
    foreach $line (@network) {
        my $range = new NetAddr::IP($network[$id]);
        if ($range->contains($ip)
                && (($ports[$id] eq $port) || ($ports[$id] eq '0'))
                && (($protocols[$id] eq $protocol) || ($protocols[$id] eq ''))) {
            return $colour[$id];
        }
        $id++;
    }
    return $colour;
}

# Create a string containing a complete SELECT html object
# param1: name
# param2: current value selected
# param3: field list
sub make_select () {
    my $select_name = shift;
    my $selected    = shift;
    my $select      = "<select name='$select_name'>";

    foreach my $value (@_) {
        my $check = $selected eq $value ? "selected='selected'" : '';
        $select .= "<option $check value='$value'>$value</option>";
    }
    $select .= "</select>";
    return $select;
}

# Build a list of IP obtained from the %entries hash
# param1: IP field name
sub get_known_ips ($) {
    my $field = shift;
    my $qs    = $cgiparams{'SEE_SORT'};    # switch the sort order
    $cgiparams{'SEE_SORT'} = $field;

    my @liste = ('*.*.*.*');
    foreach my $entry (sort sort_entries keys %entries) {
        push(@liste, $entries{$entry}->{$field}) if (!grep (/^$entries{$entry}->{$field}$/, @liste));
    }

    $cgiparams{'SEE_SORT'} = $qs;          #restore sort order
    return @liste;
}

# Used to sort the table containing the lines displayed.
sub sort_entries {                         #Reverse is not implemented
    my $qs = $cgiparams{'SEE_SORT'};
    if ($qs =~ /orgsip|orgdip|repsip|repdip/) {
        my @a = split(/\./, $entries{$a}->{$qs});
        my @b = split(/\./, $entries{$b}->{$qs});
               ($a[0] <=> $b[0])
            || ($a[1] <=> $b[1])
            || ($a[2] <=> $b[2])
            || ($a[3] <=> $b[3]);
    }
    elsif ($qs =~ /expire|orgsp|orgdp|repsp|repdp/) {
        $entries{$a}->{$qs} <=> $entries{$b}->{$qs};
    }
    else {
        $entries{$a}->{$qs} cmp $entries{$b}->{$qs};
    }
}

1;
