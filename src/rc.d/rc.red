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
# (c) The SmoothWall Team
# Copyright (c) 2001-2015 The Openfirewall Team
#
# $Id: rc.red 7871 2015-02-06 14:23:18Z owes $

# Clean up our environment (we're running SUID!)
delete @ENV{qw(IFS CDPATH ENV BASH_ENV PATH)};
$< = $>;

use strict;

#use warnings;
require '/usr/lib/ofw/general-functions.pl';

my %pppsettings;
my %isdnsettings;
my %netsettings;
my %dhcpsettings;
my $iface;

# read vars back from file.
&General::readhash("/var/ofw/ppp/settings",      \%pppsettings);
&General::readhash("/var/ofw/ethernet/isdn",     \%isdnsettings);
&General::readhash("/var/ofw/ethernet/settings", \%netsettings);
&General::readhash("/var/ofw/dhcp/settings",     \%dhcpsettings);

sub myexit
{
    my $retcode = shift;

    unlink('/var/ofw/red/connecting');
    unlink('/var/ofw/red/disconnecting');

    &General::log("ERROR ($retcode) in rc.red") if ($retcode);

    exit $retcode;
}

sub dodhcpdial($;$) {
    my ($iface, $dhcp_name) = @_;

    system('/sbin/iptables', '-A', 'REDINPUT', '-p', 'udp', '--source-port', '67', '--destination-port', '68', '-i',
        $iface, '-j', 'ACCEPT');

    unlink "/var/log/dhcpclient.info" if (-e "/var/log/dhcpclient.info");
    my @dhcpcommand = ('/usr/sbin/dhcpcd');

    push(@dhcpcommand, '--debug') if ($pppsettings{'DEBUG'} eq 'on');
    push(@dhcpcommand, ("--hostname=$dhcp_name")) if ($dhcp_name ne '');
    push(@dhcpcommand, '--nogateway') if ($netsettings{'RED_TYPE'} eq 'PPTP');
    push(@dhcpcommand, "$iface");

    if (system(@dhcpcommand)) {
        &General::log('red', 'dhcp client fail');
        myexit(1);
    }
    else {
        &General::log('red', 'dhcp client success');
    }
}

sub doupdatesettings {

    # complete cleanup only if settings were changed or clear is ordered
    system('/sbin/modprobe', '-r', 'pppoatm');
    system('/sbin/modprobe', '-r', 'pppoe');
    system('/usr/bin/killall /usr/sbin/br2684ctl 2>/dev/null');
    system('/sbin/modprobe', '-r', 'br2684');
    system('/sbin/modprobe', '-r', 'clip');

    # TODO: readd modules once we can compile them, or find a better mechanism
    #if ($pppsettings{'TYPE'} ne 'conexantpciadsl') { system('/sbin/modprobe', '-r', 'CnxADSL'); }
    #if ($pppsettings{'TYPE'} ne 'eagleusbadsl')    { system('/sbin/modprobe', '-r', 'eagle-usb');}
    #if ($pppsettings{'TYPE'} ne 'fritzdsl')    {
    #   system('/sbin/modprobe', '-r', 'fcdsl', 'fcdsl2', 'fcdslsl');}
    if ($pppsettings{'TYPE'} ne 'pulsardsl') { system('/sbin/modprobe -r pulsar 2>/dev/null'); }
    if ($pppsettings{'TYPE'} ne 'solosdsl')  { system('/sbin/modprobe -r solos_pci 2>/dev/null'); }
    sleep 1;
    if ($pppsettings{'TYPE'} !~ /^(alcatelusb|conexantpciadsl|pulsardsl|solos_pci)$/) {
        system('/sbin/modprobe', '-r', 'atm');
    }

    # remove existing default route (for static address) if it was been changed from setup or web interface SF1175052
    system('/sbin/ip route del default 2>/dev/null');

    # erase in case it was created once with 'persistent' selected but rc.red stop never used : SF1171610
    unlink("/var/ofw/red/iface");
}

# No output should be sent to the webclient
open STDIN,  '</dev/zero' or die "Can't read from /dev/zero";
open STDOUT, '>/dev/null' or die "Can't write to /dev/null";

if ($ARGV[0] eq 'start') {
    if (   -e "/var/ofw/red/active"
        || -e '/var/run/ppp-ofw.pid')
    {
        &General::log("ERROR: Can't start RED when it's still active");
        exit 1;
    }
    if (! system("/bin/ps ax | /bin/grep -q [r]c.updatered") ) {
        &General::log("ERROR: Can't start RED when rc.updatered is still active");
        exit 1;
    }

    system('/usr/bin/touch /var/ofw/red/connecting');
    unlink '/var/ofw/red/disconnecting';
    if (
        (
            (($netsettings{'RED_1_TYPE'} =~ /^(PPPOE|PPTP)$/) && ($netsettings{'RED_COUNT'} > 0))
            || (   (($pppsettings{'METHOD'} =~ /^(PPPOE|PPPOE_PLUGIN)$/) || ($pppsettings{'PROTOCOL'} eq 'RFC2364'))
                && ($netsettings{'RED_COUNT'} == 0))
        )
        && ($pppsettings{'RECONNECTION'} ne 'manual')
        )
    {
        system('/etc/rc.d/rc.connectioncheck start &');
    }

    ###
    ### Red device is ethernet
    ###
    if ($netsettings{'RED_COUNT'} > 0) {
        if ($netsettings{'RED_1_DEV'} ne '') {
            &General::log("red", "Starting RED device $netsettings{'RED_1_DEV'} type $netsettings{'RED_1_TYPE'}.");

            if ($netsettings{'RED_1_TYPE'} eq 'DHCP') {
                if (open(FILE, ">/var/ofw/red/iface")) { print FILE $netsettings{'RED_1_DEV'}; close FILE; }
                dodhcpdial($netsettings{'RED_1_DEV'}, $netsettings{'RED_DHCP_HOSTNAME'});
                exit 0;
            }
            elsif (($netsettings{'RED_1_TYPE'} eq 'PPTP') && ($pppsettings{'METHOD'} eq 'DHCP')) {
                if (open(FILE, ">/var/ofw/red/device")) { print FILE $netsettings{'RED_1_DEV'}; close FILE; }
                unlink("/var/ofw/red/iface");
                dodhcpdial($netsettings{'RED_1_DEV'}, $netsettings{'RED_DHCP_HOSTNAME'});
            }
            elsif (($netsettings{'RED_1_TYPE'} eq 'STATIC')
                || (($netsettings{'RED_1_TYPE'} eq 'PPTP') && ($pppsettings{'METHOD'} ne 'DHCP')))
            {
                system("/sbin/ip", "addr", "flush", "dev", $netsettings{'RED_1_DEV'});
                system("/sbin/ip", "addr", "add", "$netsettings{'RED_1_ADDRESS'}/$netsettings{'RED_1_NETMASK'}", "dev", $netsettings{'RED_1_DEV'});
                system("/sbin/ip", "link", "set", $netsettings{'RED_1_DEV'}, "up" );
                if ($netsettings{'RED_1_TYPE'} eq 'STATIC') {
                    system("echo $netsettings{'DNS1'}    > /var/ofw/red/dns1");
                    system("echo $netsettings{'DNS2'}    > /var/ofw/red/dns2");
                    system("echo $netsettings{'RED_1_ADDRESS'} > /var/ofw/red/local-ipaddress");
                    system("echo $netsettings{'DEFAULT_GATEWAY'} > /var/ofw/red/remote-ipaddress");
                }
                elsif ($netsettings{'RED_1_TYPE'} eq 'PPTP') {
                    if (open(FILE, ">/var/ofw/red/device")) { print FILE $netsettings{'RED_1_DEV'}; close FILE; }
                    unlink("/var/ofw/red/iface");
                }
                if ($netsettings{'DEFAULT_GATEWAY'} ne '') {
                    system("/sbin/ip", "route", "add", "default", "via", $netsettings{'DEFAULT_GATEWAY'});
                }
            }
            else {
                # PPPoE
                system("/sbin/ip", "addr", "flush", "dev", $netsettings{'RED_1_DEV'});
                system("/sbin/ip", "addr", "add", "$netsettings{'RED_1_ADDRESS'}/$netsettings{'RED_1_NETMASK'}", "dev", $netsettings{'RED_1_DEV'});
                system("/sbin/ip", "link", "set", $netsettings{'RED_1_DEV'}, "up");

                # VDSL using VLAN tag
                if ($pppsettings{'VDSL_TAG'}) {
                    if (! -d '/sys/module/8021q') {
                        system('/sbin/modprobe 8021q');
                    }

                    system("/sbin/ip link add link $netsettings{'RED_1_DEV'} name $netsettings{'RED_1_DEV'}.$pppsettings{'VDSL_TAG'} type vlan id $pppsettings{'VDSL_TAG'}");
                    system("/sbin/ip link set $netsettings{'RED_1_DEV'}.$pppsettings{'VDSL_TAG'} up");
                }
            }

            if ($netsettings{'RED_1_TYPE'} eq 'STATIC') {
                if (open(FILE, ">/var/ofw/red/iface")) { print FILE $netsettings{'RED_1_DEV'}; close FILE; }
                system("/usr/bin/touch", "/var/ofw/red/active");
                system("/etc/rc.d/rc.updatered red up");
                exit 0;
            }
        }
        else {
            &General::log('red', "ERROR: Can't start RED when RED device not set!");
            myexit(1);
        }
    }

    if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
        system('/usr/bin/touch', "/var/ofw/red/dial-on-demand");
    }

    if ($pppsettings{'VALID'} ne 'yes') {
        &General::log('red', 'ERROR: Profile has errors.');
        myexit(1);
    }

    if (-e "/var/ofw/ppp/updatesettings") {
        &doupdatesettings;
    }

    if (($pppsettings{'METHOD'} eq 'STATIC') && ($pppsettings{'DNS'} eq 'Manual')) {
        if (open(FILE, ">/var/ofw/red/dns1"))             { print FILE $pppsettings{'DNS1'};    close FILE; }
        if (open(FILE, ">/var/ofw/red/dns2"))             { print FILE $pppsettings{'DNS2'};    close FILE; }
        if (open(FILE, ">/var/ofw/red/local-ipaddress"))  { print FILE $pppsettings{'IP'};      close FILE; }
        if (open(FILE, ">/var/ofw/red/remote-ipaddress")) { print FILE $pppsettings{'GATEWAY'}; close FILE; }
    }
    if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
        &General::log("red", "Dial-on-Demand waiting to dial $pppsettings{'PROFILENAME'}.");
    }
    else {
        &General::log("red", "Dialling $pppsettings{'PROFILENAME'}.");
    }

    # ppp device node is not present after boot, create it
    if (! -e "/dev/ppp") {
        &General::log("red", "ppp device node created");
        system("mknod /dev/ppp c 108 0");
    }
    
    if    ($pppsettings{'TYPE'} eq 'modem')           { &domodemdial(); }
    elsif ($pppsettings{'TYPE'} eq 'serial')          { &doserialdial(); }
    elsif ($pppsettings{'TYPE'} eq 'isdn')            { &doisdndial(); }
    elsif ($pppsettings{'TYPE'} eq 'pppoe')           { &dopppoedial(); }
    elsif ($pppsettings{'TYPE'} eq 'pptp')            { &dopptpdial(); }
    elsif ($pppsettings{'TYPE'} eq 'alcatelusb')      { &doatmdial(); }
    elsif ($pppsettings{'TYPE'} eq 'pulsardsl')       { &doatmprepare($pppsettings{'TYPE'}); }
    elsif ($pppsettings{'TYPE'} eq 'solosdsl')        { &doatmprepare($pppsettings{'TYPE'}); }
    elsif ($pppsettings{'TYPE'} eq 'eciadsl')         { &doeciadsldial(); }
    elsif ($pppsettings{'TYPE'} eq 'fritzdsl')        { &dofritzdsldial(); }
    elsif ($pppsettings{'TYPE'} eq 'eagleusbadsl')    { &doeagleusbadsldial(); }
    elsif ($pppsettings{'TYPE'} eq 'conexantpciadsl') { &doconexantpciadsldial(); }
    elsif ($pppsettings{'TYPE'} eq 'wanpipe-adsl')    { &doatmprepare($pppsettings{'TYPE'}); }
    elsif ($pppsettings{'TYPE'} eq 'wanpipe-serial')  { &dowanpipeserialdial(); }

    if (-e "/var/ofw/ppp/updatesettings") {

        # erase update mark only after specific script had run, allowing specific script to treat the update
        unlink("/var/ofw/ppp/updatesettings");
    }
    if (($pppsettings{'RECONNECTION'} eq 'dialondemand') || ($pppsettings{'METHOD'} eq 'STATIC')) {
        system("/etc/rc.d/rc.updatered red up");
    }
}
elsif ($ARGV[0] eq 'stop') {
    $iface = &General::getredinterface();
    my $device = &General::getinterfacefromfile("/var/ofw/red/device");

    if (-e "/var/ofw/red/active") {
        system('/usr/bin/touch /var/ofw/red/disconnecting');
    }
    unlink "/var/ofw/red/dial-on-demand";
    unlink "/var/ofw/red/active";
    unlink "/var/ofw/red/connecting";
    unlink "/var/ofw/red/local-ipaddress";
    unlink "/var/ofw/red/remote-ipaddress";
    unlink "/var/ofw/red/dns1";
    unlink "/var/ofw/red/dns2";
    unlink "/var/ofw/red/resolv.conf";
    unlink "/var/ofw/red/device";

    # stay with keepconnected during transitional rc.red stop ordered by rc.connectioncheck
    if (!-e "/var/ofw/red/redial") {
        unlink "/var/ofw/red/keepconnected";
    }
    unlink "/var/ofw/red/redial";

    # Kill PPPD
    if (open(FILE, "/var/run/ppp-ofw.pid")) {
        my $pid = <FILE>;
        close FILE;
        chomp($pid);
        $pid =~ /(\d*)/;
        $pid = $1;
        system('/bin/kill', $pid);
    }

    # Bring down Ethernet interfaces & Kill DHCP client daemon
    if (($netsettings{'RED_COUNT'} > 0) && ($netsettings{'RED_1_TYPE'} eq 'PPPOE') && $iface) {
        system("/sbin/ip", "link", "set", $iface, "down");
    }
    if ($device) {
        system("/sbin/ip", "link", "set", $device, "down");
    }

    # VDSL using VLAN tag
    # VLAN tag can be set in profile even when not using PPPoE, so check for dev exists to avoid error messages
    if ($pppsettings{'VDSL_TAG'} && -e "/sys/class/net/$netsettings{'RED_1_DEV'}.$pppsettings{'VDSL_TAG'}") {
        system("/sbin/ip link set $netsettings{'RED_1_DEV'}.$pppsettings{'VDSL_TAG'} down");
        system("/sbin/ip link delete $netsettings{'RED_1_DEV'} name $netsettings{'RED_1_DEV'}.$pppsettings{'VDSL_TAG'}");
    }

    if (-e "/var/run/dhcpcd-$iface.pid") {
        my $pidfile = "/var/run/dhcpcd-$iface.pid";

        # release lease and stop daemon nicely
        system("/usr/sbin/dhcpcd --quiet -k $iface");

        # leave some time
        sleep 1;
        if (open(FILE, $pidfile)) {

            # still there, okay try killing
            my $pid = <FILE>;
            close FILE;
            chomp($pid);
            $pid =~ /(\d*)/;
            $pid = $1;
            system('/bin/kill', $pid);
            unlink "$pidfile";
        }
    }

    if (!system('/bin/ps -ef | /bin/grep -q [a]tmarpd')) {
        if ($pppsettings{'GATEWAY'} ne '') {
            system("/usr/sbin/atmarp -d $pppsettings{'GATEWAY'} 2>/dev/null");
        }
        system('/usr/bin/killall /usr/sbin/atmarpd 2>/dev/null');
        system('/sbin/ip', 'link', 'set', 'atm0', 'down');
    }

    if ($netsettings{'RED_COUNT'} == 0) {
        if ($pppsettings{'TYPE'} eq 'isdn')            { system('/etc/rc.d/rc.isdn',            'stop'); }
        if ($pppsettings{'TYPE'} eq 'eciadsl')         { system('/etc/rc.d/rc.eciadsl',         'stop'); }
        if ($pppsettings{'TYPE'} eq 'conexantpciadsl') { system('/etc/rc.d/rc.conexantpciadsl', 'stop'); }
        if ($pppsettings{'TYPE'} eq 'eagleusbadsl')    { system('/etc/rc.d/rc.eagleusbadsl',    'stop'); }
        if ($pppsettings{'TYPE'} eq 'fritzdsl')        { system('/etc/rc.d/rc.fritzdsl',        'stop'); }
        if ($pppsettings{'TYPE'} eq 'pulsardsl')       { system('/etc/rc.d/rc.pulsardsl',       'stop'); }
        if ($pppsettings{'TYPE'} eq 'solosdsl')        { system('/etc/rc.d/rc.solosdsl',        'stop'); }
        if ($pppsettings{'TYPE'} =~ /wanpipe/) { system('/etc/rc.d/rc.wanpipe', 'stop'); }
    }

    if (
        (($netsettings{'RED_COUNT'} > 0) && $netsettings{'RED_1_TYPE'} eq 'STATIC')
        || (   ($netsettings{'RED_COUNT'} == 0)
            && $pppsettings{'PROTOCOL'} eq 'RFC1483'
            && $pppsettings{'METHOD'}   eq 'STATIC')
        )
    {
        system("/etc/rc.d/rc.updatered red down");
    }
}
elsif ($ARGV[0] eq 'clear') {
    &doupdatesettings();
    &docleanup();

    # Remove possible leftover files
    unlink '/var/ofw/red/active';
    unlink '/var/ofw/red/connecting';
    unlink '/var/ofw/red/device';
    unlink '/var/ofw/red/disconnecting';
    unlink '/var/ofw/red/dial-on-demand';
    unlink '/var/ofw/red/dns1';
    unlink '/var/ofw/red/dns2';
    unlink '/var/ofw/red/eciadsl-synch-done';
    unlink '/var/ofw/red/local-ipaddress';
    unlink '/var/ofw/red/remote-ipaddress';
}
else {
    &General::log("ERROR: rc.red bad argument (start|stop|clear)");
    exit 1;
}

exit 0;

sub docleanup {
    if ($pppsettings{'TYPE'} eq 'eciadsl')         { system('/etc/rc.d/rc.eciadsl',         'cleanup'); }
    if ($pppsettings{'TYPE'} eq 'pulsardsl')       { system('/etc/rc.d/rc.pulsardsl',       'cleanup'); }
    if ($pppsettings{'TYPE'} eq 'fritzdsl')        { system('/etc/rc.d/rc.fritzdsl',        'cleanup'); }
    if ($pppsettings{'TYPE'} eq 'eagleusbadsl')    { system('/etc/rc.d/rc.eagleusbadsl',    'cleanup'); }
    if ($pppsettings{'TYPE'} eq 'conexantpciadsl') { system('/etc/rc.d/rc.conexantpciadsl', 'cleanup'); }
    if ($pppsettings{'TYPE'} eq 'solosdsl')        { system('/etc/rc.d/rc.solosdsl',        'cleanup'); }
}

sub domodemdial {
    my @pppcommand  = ('/usr/sbin/pppd');
    my $loginscript = '';

    if ($pppsettings{'COMPORT'} =~ /ttyACM/) {
        system('/sbin/rmmod acm');
        sleep 1;
        system('/sbin/modprobe acm');
    }

    my $device = "/dev/${pppsettings{'COMPORT'}}";

    if ($pppsettings{'DNS'} eq 'Automatic') {
        push(@pppcommand, ('usepeerdns'));
    }

    if ($pppsettings{'AUTH'} eq 'pap') {
        push(@pppcommand, ('-chap'));
    }
    elsif ($pppsettings{'AUTH'} eq 'chap') {
        push(@pppcommand, ('-pap'));
    }
    elsif ($pppsettings{'AUTH'} eq 'standard-login-script') {
        $loginscript = 'standardloginscript';
    }
    elsif ($pppsettings{'AUTH'} eq 'demon-login-script') {
        $loginscript = 'demonloginscript';
    }
    else {
        $loginscript = $pppsettings{'LOGINSCRIPT'};
    }

    if ($pppsettings{'RECONNECTION'} ne 'persistent') {
        if ($pppsettings{'TIMEOUT'} != 0) {
            my $seconds = $pppsettings{'TIMEOUT'} * 60;
            push(@pppcommand, ('idle', $seconds));
        }
        if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
            push(@pppcommand, ('demand', 'nopersist'));
        }
        push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
    }

    push(@pppcommand, ('novj', 'novjccomp'));

    push(
        @pppcommand,
        (
            'lock',                   'modem',       'crtscts',                  $device,
            $pppsettings{'DTERATE'},  'noipdefault', 'defaultroute',             'user',
            $pppsettings{'USERNAME'}, 'maxfail',     $pppsettings{'MAXRETRIES'}, 'connect',
            '/etc/ppp/dialer'
        )
    );
    if ($pppsettings{'DEBUG'} eq 'on') {
        push(@pppcommand, ('debug'));
    }

    system @pppcommand;
}

sub doserialdial {
    my @pppcommand  = ('/usr/sbin/pppd');
    my $loginscript = '';

    if ($pppsettings{'COMPORT'} =~ /ttyACM/) {
        system('/sbin/rmmod acm');
        sleep 1;
        system('/sbin/modprobe acm');
    }

    my $device = "/dev/${pppsettings{'COMPORT'}}";

    if ($pppsettings{'DNS'} eq 'Automatic') {
        push(@pppcommand, ('usepeerdns'));
    }

    if ($pppsettings{'AUTH'} eq 'pap') {
        push(@pppcommand, ('-chap'));
    }
    elsif ($pppsettings{'AUTH'} eq 'chap') {
        push(@pppcommand, ('-pap'));
    }

    if ($pppsettings{'RECONNECTION'} ne 'persistent') {
        if ($pppsettings{'TIMEOUT'} != 0) {
            my $seconds = $pppsettings{'TIMEOUT'} * 60;
            push(@pppcommand, ('idle', $seconds));
        }
        if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
            push(@pppcommand, ('demand', 'nopersist'));
        }
        push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
    }

    push(@pppcommand, ('novj', 'novjccomp'));

    push(
        @pppcommand,
        (
            'lock',                   'modem',       'crtscts',                  $device,
            $pppsettings{'DTERATE'},  'noipdefault', 'defaultroute',             'user',
            $pppsettings{'USERNAME'}, 'maxfail',     $pppsettings{'MAXRETRIES'}, 'connect',
            '/bin/true'
        )
    );
    if ($pppsettings{'DEBUG'} eq 'on') {
        push(@pppcommand, ('debug'));
    }

    system @pppcommand;
}

sub doisdndial {
    my $pppoptions;
    my $seconds;
    my $phone;

    if (system('/etc/rc.d/rc.isdn', 'start')) {
        &General::log('red', 'ERROR: ISDN module failed to load');
        myexit(1);
    }

    $seconds = $pppsettings{'TIMEOUT'} * 60;
    if ($pppsettings{'USEDOV'} eq 'on') {
        $phone = 'v' . $pppsettings{'TELEPHONE'};
    }
    else {
        $phone = $pppsettings{'TELEPHONE'};
    }

    if ($pppsettings{'COMPORT'} eq 'isdn2') {
        system('/usr/sbin/isdnctrl', 'addif',    'ippp0');
        system('/usr/sbin/isdnctrl', 'addslave', 'ippp0', 'ippp1');
        system('/usr/sbin/isdnctrl', 'l2_prot',  'ippp0', 'hdlc');
        system('/usr/sbin/isdnctrl', 'l3_prot',  'ippp0', 'trans');
        system('/usr/sbin/isdnctrl', 'encap',    'ippp0', 'syncppp');
        system('/usr/sbin/isdnctrl', 'dialmax',  'ippp0', $pppsettings{'MAXRETRIES'});
        system('/usr/sbin/isdnctrl', 'eaz',      'ippp0', $isdnsettings{'MSN'});
        system('/usr/sbin/isdnctrl', 'addphone', 'ippp0', 'out', $phone);
        system('/usr/sbin/isdnctrl', 'huptimeout', 'ippp0', $seconds);
        system('/usr/sbin/isdnctrl', 'l2_prot',    'ippp1', 'hdlc');
        system('/usr/sbin/isdnctrl', 'l3_prot',    'ippp1', 'trans');
        system('/usr/sbin/isdnctrl', 'encap',      'ippp1', 'syncppp');
        system('/usr/sbin/isdnctrl', 'dialmax',    'ippp1', $pppsettings{'MAXRETRIES'});
        system('/usr/sbin/isdnctrl', 'eaz',        'ippp0', $isdnsettings{'MSN'});
        system('/usr/sbin/isdnctrl', 'addphone',   'ippp1', 'out', $phone);
        system('/usr/sbin/isdnctrl', 'huptimeout', 'ippp1', $seconds);
        system('/usr/sbin/isdnctrl', 'dialmode',   'ippp1', 'auto');

        my @pppcommand = (
            '/usr/sbin/ipppd', 'ms-get-dns',
            'noipdefault',     '+mp', 'defaultroute',
            'user',            $pppsettings{'USERNAME'},
            'name',            $pppsettings{'USERNAME'},
            'active-filter',   'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0',
            'pidfile',         '/var/run/ppp-ofw.pid',
            '/dev/ippp0',      '/dev/ippp1'
        );

        if ($pppsettings{'DEBUG'} eq 'on') {
            push(@pppcommand, ('debug'));
        }
        if ($pppsettings{'AUTH'} eq 'pap') {
            push(@pppcommand, ('-chap'));
        }
        elsif ($pppsettings{'AUTH'} eq 'chap') {
            push(@pppcommand, ('-pap'));
        }
        system(@pppcommand);
    }
    else {
        system('/usr/sbin/isdnctrl', 'addif',    'ippp0');
        system('/usr/sbin/isdnctrl', 'l2_prot',  'ippp0', 'hdlc');
        system('/usr/sbin/isdnctrl', 'l3_prot',  'ippp0', 'trans');
        system('/usr/sbin/isdnctrl', 'encap',    'ippp0', 'syncppp');
        system('/usr/sbin/isdnctrl', 'dialmax',  'ippp0', $pppsettings{'MAXRETRIES'});
        system('/usr/sbin/isdnctrl', 'eaz',      'ippp0', $isdnsettings{'MSN'});
        system('/usr/sbin/isdnctrl', 'addphone', 'ippp0', 'out', $phone);
        system('/usr/sbin/isdnctrl', 'huptimeout', 'ippp0', $seconds);

        my @pppcommand = (
            '/usr/sbin/ipppd', 'ms-get-dns',
            'noipdefault',     'defaultroute',
            'user',            $pppsettings{'USERNAME'},
            'name',            $pppsettings{'USERNAME'},
            'active-filter',   'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0',
            'pidfile',         '/var/run/ppp-ofw.pid',
            '/dev/ippp0'
        );

        if ($pppsettings{'DEBUG'} eq 'on') {
            push(@pppcommand, ('debug'));
        }
        if ($pppsettings{'AUTH'} eq 'pap') {
            push(@pppcommand, ('-chap'));
        }
        elsif ($pppsettings{'AUTH'} eq 'chap') {
            push(@pppcommand, ('-pap'));
        }
        system(@pppcommand);
    }

    sleep 1;

    if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
        system('/usr/sbin/isdnctrl', 'dialmode', 'ippp0',          'auto');
        system('/sbin/ifconfig',     'ippp0',    '10.112.112.112', 'pointopoint', '10.112.112.113');
        system('/sbin/ip', 'link', 'set', 'ippp0', 'arp', 'off');
        system('/sbin/ip', 'route', 'add', 'default', 'dev', 'ippp0');
    }
    else {
        system('/usr/sbin/isdnctrl', 'dial', 'ippp0');
    }

    system('/usr/bin/killall', 'ibod');
    if ($pppsettings{'COMPORT'} eq 'isdn2') {
        if ($pppsettings{'USEIBOD'} eq 'on') {
            system("/usr/sbin/ibod &");
        }
        else {
            system('/usr/sbin/isdnctrl', 'addlink', 'ippp0');
        }
    }
}

sub dopppoedial {

    my $red_device = $netsettings{'RED_1_DEV'};
    $red_device = "$red_device.$pppsettings{'VDSL_TAG'}" if ($pppsettings{'VDSL_TAG'});
    if ($pppsettings{'METHOD'} ne 'PPPOE_PLUGIN') {
        my @pppcommand = ('/usr/sbin/pppd', 'pty');
        my @pppoecommand = (
            '/usr/sbin/pppoe', '-p', '/var/run/pppoe.pid', '-I', $red_device, '-T',
            '80',              '-U', '-m',                 '1412'
        );

        if ($pppsettings{'SERVICENAME'}) {
            push(@pppoecommand, ('-S', $pppsettings{'SERVICENAME'}));
        }
        if ($pppsettings{'CONCENTRATORNAME'}) {
            push(@pppoecommand, ('-C', $pppsettings{'CONCENTRATORNAME'}));
        }

        push(@pppcommand, "@pppoecommand");

        if ($pppsettings{'DNS'} eq 'Automatic') {
            push(@pppcommand, ('usepeerdns'));
        }

        if ($pppsettings{'AUTH'} eq 'pap') {
            push(@pppcommand, ('-chap'));
        }
        elsif ($pppsettings{'AUTH'} eq 'chap') {
            push(@pppcommand, ('-pap'));
        }

        if ($pppsettings{'RECONNECTION'} ne 'persistent') {
            if ($pppsettings{'TIMEOUT'} != 0) {
                my $seconds = $pppsettings{'TIMEOUT'} * 60;
                push(@pppcommand, ('idle', "$seconds"));
            }
            if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
                push(@pppcommand, ('demand', 'nopersist', 'connect', '/bin/true'));
            }
            push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
        }

        push(
            @pppcommand,
            (
                'noipdefault',       'default-asyncmap',
                'defaultroute',      'hide-password',
                'local',
                'mtu',               '1492',
                'mru',               '1492',
                'noaccomp',          'noccp',
                'nobsdcomp',         'nodeflate',
                'nopcomp',           'novj',    
                'novjccomp',
                'user',              $pppsettings{'USERNAME'}, 
                'lcp-echo-interval', '20',
                'lcp-echo-failure',  '3',
                'lcp-max-configure', '50',
                'maxfail',           $pppsettings{'MAXRETRIES'}
            )
        );
        if ($pppsettings{'DEBUG'} eq 'on') {
            push(@pppcommand, ('debug'));
        }

        system(@pppcommand);
    }
    else {

        # PPPoE plugin
        system('/sbin/modprobe pppoe');
        my @pppcommand = ('/usr/sbin/pppd');
        push(@pppcommand, 'plugin', 'rp-pppoe.so', "nic-$red_device");
        if ($pppsettings{'DNS'} eq 'Automatic') {
            push(@pppcommand, ('usepeerdns'));
        }
        if ($pppsettings{'AUTH'} eq 'pap') {
            push(@pppcommand, ('-chap'));
        }
        elsif ($pppsettings{'AUTH'} eq 'chap') {
            push(@pppcommand, ('-pap'));
        }
        if ($pppsettings{'RECONNECTION'} ne 'persistent') {
            if ($pppsettings{'TIMEOUT'} != 0) {
                my $seconds = $pppsettings{'TIMEOUT'} * 60;
                push(@pppcommand, ('idle', "$seconds"));
            }
            if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
                push(@pppcommand, ('demand', 'nopersist'));
            }
            push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
        }
        push(
            @pppcommand,
            (
                'noipdefault',        'defaultroute',
                'hide-password',      'ipcp-accept-local',
                'ipcp-accept-remote', 'passive',
                'noccp',              'nopcomp',
                'novjccomp',
                'user',               $pppsettings{'USERNAME'},
                'lcp-echo-interval',  '20',
                'lcp-echo-failure',   '3',
                'lcp-max-configure',  '50',
                'maxfail',            $pppsettings{'MAXRETRIES'}
            )
        );
        if ($pppsettings{'DEBUG'} eq 'on') {
            push(@pppcommand, ('debug'));
        }

        system(@pppcommand);
    }
}

sub dopptpdial {
    my %pptpdhcpc;
    my $routerip = $pppsettings{'ROUTERIP'} ? $pppsettings{'ROUTERIP'} : "10.0.0.138";
    if ($pppsettings{'METHOD'} eq 'DHCP' && -e "/var/ofw/red/device") {
        my $device = &General::getinterfacefromfile("/var/ofw/red/device");

        # TODO: verify the fixes from SF #2978513
        if (&General::readhash("/var/log/dhcpclient.info", \%pptpdhcpc)) {
            system("/sbin/ip", "route", "add", $routerip, "via", $pptpdhcpc{'DHCLIENT_GATEWAY'});
        }
        else {
            system("/sbin/ip", "route", "add", $routerip, "dev", $device);
        }
    }

    my @pppcommand = ('/usr/sbin/pppd', 'pty');
    my @pptpcommand = ('/usr/sbin/pptp', $routerip, '--nobuffer', '--nolaunchpppd', '--sync');
    if ($pppsettings{'PHONEBOOK'}) {
        push(@pptpcommand, ('--phone ', $pppsettings{'PHONEBOOK'}));
    }

    push(@pppcommand, "@pptpcommand");

    if ($pppsettings{'DNS'} eq 'Automatic') {
        push(@pppcommand, ('usepeerdns'));
    }
    if ($pppsettings{'AUTH'} eq 'pap') {
        push(@pppcommand, ('-chap'));
    }
    elsif ($pppsettings{'AUTH'} eq 'chap') {
        push(@pppcommand, ('-pap'));
    }

    if ($pppsettings{'RECONNECTION'} ne 'persistent') {
        if ($pppsettings{'TIMEOUT'} != 0) {
            my $seconds = $pppsettings{'TIMEOUT'} * 60;
            push(@pppcommand, ('idle', "$seconds"));
        }
        if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
            push(@pppcommand, ('demand', 'nopersist', 'connect', '/bin/true'));
        }
        push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
    }

    push(
        @pppcommand,
        (
            'noipdefault',       'default-asyncmap',
            'defaultroute',      'hide-password',
            'local',             'noaccomp',
            'noccp',             'nobsdcomp',
            'nodeflate',         'nopcomp',
            'novj',              'novjccomp',
            'user',              $pppsettings{'USERNAME'},
            'lcp-echo-interval', '20',
            'lcp-echo-failure',  '3',
            'lcp-max-configure', '50',
            'maxfail',           $pppsettings{'MAXRETRIES'},
            'sync'
        )
    );
    if ($pppsettings{'DEBUG'} eq 'on') {
        push(@pppcommand, ('debug'));
    }

    system(@pppcommand);
}

sub doeciadsldial {
    if (system('/etc/rc.d/rc.eciadsl', 'start')) {
        &General::log('red', 'ERROR: ECI ADSL failed to start');
        myexit(1);
    }
    if ($pppsettings{'PROTOCOL'} eq 'RFC1483') {
        if ($pppsettings{'ENCAP'} =~ /^(0|1)$/) {
            $iface = "tap0";
        }
        else {
            $iface = "tun0";
        }

        if (open(FILE, ">/var/ofw/red/iface")) { print FILE $iface; close FILE; }

        if ($pppsettings{'METHOD'} =~ /^(PPPOE|PPPOE_PLUGIN)$/) {
            if (open(FILE, ">/var/ofw/red/device")) { print FILE $iface; close FILE; }
            $netsettings{'RED_1_DEV'} = $iface;
            &dopppoedial();
        }
        elsif ($pppsettings{'METHOD'} eq 'STATIC') {
            system("/sbin/ip", "addr", "flush", "dev", $iface);
            system("/sbin/ip", "addr", "add", "$pppsettings{'IP'}/$pppsettings{'NETMASK'}", "dev", $iface);
            system("/sbin/ip", "route", "add", "default", "via", $pppsettings{'GATEWAY'});
            system("/usr/bin/touch", "/var/ofw/red/active");
            if (open(FILE, ">/var/ofw/red/iface")) { print FILE $iface; close FILE; }
        }
        elsif ($pppsettings{'METHOD'} eq 'DHCP') {

            # FIXME dhcp does not support tun0 interface (routed IP)
            dodhcpdial($iface, $pppsettings{'DHCP_HOSTNAME'});
        }
    }
    else {

        # PPPoA
        my ($VID2, $PID2, $CHIP, $ALTP, $ECIMODE);
        open(MODEMS, "/etc/eciadsl/modems.db") or die 'Unable to open modems database.';
        while (my $line = <MODEMS>) {
            $line =~ s/\s*\t+\s*/|/g;
            $line =~ /^(.+)\|(.+)\|(.+)\|(.+)\|(.+)\|(.+)\|(.+)\|(.+)$/;
            if ($1 eq $pppsettings{'MODEM'}) {
                $VID2 = $4;
                $PID2 = $5;
                $CHIP = $6;
                $ALTP = $8;
            }
        }
        close(MODEMS);
        if ($VID2 eq '') {
            &General::log('red', "$pppsettings{'MODEM'} not found in modems.db");
            myexit(1);
        }
        if ($CHIP eq '') {
            &General::log('red', "error in modems.db reading for $pppsettings{'MODEM'}");
            myexit(1);
        }
        if ($pppsettings{'ENCAP'} eq '1') {
            $ECIMODE = "LLC_RFC2364";
        }
        else {
            $ECIMODE = "VCM_RFC2364";
        }

        my @pppcommand = ('/usr/sbin/pppd', 'pty');
        my @pppoecicommand = (
            "/usr/sbin/eciadsl-pppoeci", '-alt',     "$ALTP",             '-vpi',
            $pppsettings{'VPI'},         '-vci',     $pppsettings{'VCI'}, '-vendor',
            "0x$VID2",                   '-product', "0x$PID2",           '-mode',
            $ECIMODE
        );
        push(@pppcommand, "@pppoecicommand");

        if ($pppsettings{'DNS'} eq 'Automatic') {
            push(@pppcommand, ('usepeerdns'));
        }
        if ($pppsettings{'AUTH'} eq 'pap') {
            push(@pppcommand, ('-chap'));
        }
        elsif ($pppsettings{'AUTH'} eq 'chap') {
            push(@pppcommand, ('-pap'));
        }

        if ($pppsettings{'RECONNECTION'} ne 'persistent') {
            if ($pppsettings{'TIMEOUT'} != 0) {
                my $seconds = $pppsettings{'TIMEOUT'} * 60;
                push(@pppcommand, ('idle', "$seconds"));
            }
            if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
                push(@pppcommand, ('demand', 'nopersist', 'connect', '/bin/true'));
            }
            push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
        }

        push(
            @pppcommand,
            (
                'noipdefault',        'defaultroute',
                'sync',               'ipcp-accept-local',
                'ipcp-accept-remote', 'passive',
                'noaccomp',           'nopcomp',
                'noccp',              'novj',
                'nobsdcomp',          'nodeflate',
                'user',               $pppsettings{'USERNAME'},
                'lcp-echo-interval',  '20',
                'lcp-echo-failure',   '3',
                'lcp-max-configure',  '50',
                'maxfail',            $pppsettings{'MAXRETRIES'}
            )
        );
        if ($pppsettings{'DEBUG'} eq 'on') {
            push(@pppcommand, ('debug'));
        }

        system(@pppcommand);
    }
}

sub dofritzdsldial {
    my $controller;

    if (system('/etc/rc.d/rc.fritzdsl', 'start')) {
        &General::log('red', 'ERROR: Fritz DSL module failed to load');
        myexit(1);
    }

# TODO: find device IDs, /proc/pci is gone

    # controller number
    if ($pppsettings{'TYPE'} eq 'fritzdsl') {
        if (!system('/bin/grep', '1244:2700', '/proc/pci')) {
            $controller = 1;    # fcdslsl
        }
        elsif (!system('/bin/grep', '1244:2900', '/proc/pci')) {
            $controller = 2;    # fcdsl2
        }
        elsif (!system('/bin/grep', '1131:5402', '/proc/pci')) {
            $controller = 2;    # fdsl
        }
        elsif (!system('/bin/grep', 'Vendor=057c ProdID=2300', '/proc/bus/usb/devices')) {
            $controller = 1;    # fcdslusb
        }
        elsif (!system('/bin/grep', 'Vendor=057c ProdID=3500', '/proc/bus/usb/devices')) {
            $controller = 1;    # fcdslslusb
        }
    }
    my @pppcommand = ('/usr/sbin/pppd');
    my @capiplugin;

    if ($pppsettings{'DNS'} eq 'Automatic') {
        push(@pppcommand, ('usepeerdns'));
    }

    if ($pppsettings{'AUTH'} eq 'pap') {
        push(@pppcommand, ('-chap'));
    }
    elsif ($pppsettings{'AUTH'} eq 'chap') {
        push(@pppcommand, ('-pap'));
    }

    if ($pppsettings{'RECONNECTION'} ne 'persistent') {
        if ($pppsettings{'TIMEOUT'} != 0) {
            my $seconds = $pppsettings{'TIMEOUT'} * 60;
            push(@pppcommand, ('idle', "$seconds"));
        }
        if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
            push(@pppcommand, ('demand', 'nopersist', 'connect', '/bin/true'));
        }
        push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
    }

    push(
        @pppcommand,
        (
            'noipdefault',        'defaultroute',
            'sync',               'ipcp-accept-local',
            'ipcp-accept-remote', 'passive',
            'noaccomp',           'nopcomp',
            'noccp',              'novj',
            'nobsdcomp',          'nodeflate',
            'user',               $pppsettings{'USERNAME'}, 
            'lcp-echo-interval',  '20',
            'lcp-echo-failure',   '3',
            'lcp-max-configure',  '50',
            'maxfail',            $pppsettings{'MAXRETRIES'}
        )
    );

    if ($pppsettings{'DEBUG'} eq 'on') {
        push(@pppcommand, ('debug'));
    }

    if ($pppsettings{'PROTOCOL'} eq 'RFC1483') {
        @capiplugin = (
            'plugin', 'capiplugin.so',     'protocol', 'adslpppoe', 'controller', $controller,
            'vpi',    $pppsettings{'VPI'}, 'vci',      $pppsettings{'VCI'}
        );
    }
    else {
        if ($pppsettings{'ENCAP'} eq '1') {
            @capiplugin = (
                'plugin',     'capiplugin.so', 'protocol', 'adslpppoallc',
                'controller', $controller,     'vpi',      $pppsettings{'VPI'},
                'vci',        $pppsettings{'VCI'}
            );
        }
        else {
            @capiplugin = (
                'plugin',     'capiplugin.so', 'protocol', 'adslpppoa',
                'controller', $controller,     'vpi',      $pppsettings{'VPI'},
                'vci',        $pppsettings{'VCI'}
            );
        }
    }
    push(@pppcommand, @capiplugin);
    push(@pppcommand, '/dev/null');

    system(@pppcommand);
}

sub doeagleusbadsldial {
    if (system('/etc/rc.d/rc.eagleusbadsl', 'start')) {
        &General::log('red', 'ERROR: EAGLE-USB ADSL MODEM failed to start');
        myexit(1);
    }

    # I'm guessing here, but documentation suggests to use br2684ctl etc.
    # pretty much looks similar to what we do in doatmdial
    # http://atm.eagle-usb.org/wakka.php?wiki=UeagleAtmDoc
    doatmdial();
    return;

    # TODO: the OLD stuff, probably no longer needed
    $iface = `/usr/sbin/eaglectrl -i 2>/dev/null | /usr/bin/tr -d '\012'`;
    $iface = &General::getinterface($iface);

    if ($pppsettings{'PROTOCOL'} eq 'RFC1483') {
        if (open(FILE, ">/var/ofw/red/iface")) { print FILE $iface; close FILE; }
        if ($pppsettings{'METHOD'} =~ /^(PPPOE|PPPOE_PLUGIN)$/) {
            if (open(FILE, ">/var/ofw/red/device")) { print FILE $iface; close FILE; }
            $netsettings{'RED_1_DEV'} = $iface;
            &dopppoedial();
        }
        elsif ($pppsettings{'METHOD'} eq 'STATIC') {
            system("/sbin/ip", "addr", "flush", "dev", $iface);
            system("/sbin/ip", "addr", "add", "$pppsettings{'IP'}/$pppsettings{'NETMASK'}", "dev", $iface);
            system("/sbin/ip", "route", "add", "default", "via", $pppsettings{'GATEWAY'});
            system("/usr/bin/touch", "/var/ofw/red/active");
        }
        elsif ($pppsettings{'METHOD'} eq 'DHCP') {
            dodhcpdial($iface, $pppsettings{'DHCP_HOSTNAME'});
        }
    }
    else {

        # PPPoA
        if (open(FILE, ">/var/ofw/red/device")) { print FILE $iface; close FILE; }
        $netsettings{'RED_1_DEV'} = $iface;
        my @pppcommand = ('/usr/sbin/pppd', 'pty');
        push(@pppcommand, "/usr/sbin/pppoa -I $iface ");

        if ($pppsettings{'DNS'} eq 'Automatic') { push(@pppcommand, ('usepeerdns')); }

        if ($pppsettings{'AUTH'} eq 'pap') {
            push(@pppcommand, ('-chap'));
        }
        elsif ($pppsettings{'AUTH'} eq 'chap') {
            push(@pppcommand, ('-pap'));
        }

        if ($pppsettings{'RECONNECTION'} ne 'persistent') {
            if ($pppsettings{'TIMEOUT'} != 0) {
                my $seconds = $pppsettings{'TIMEOUT'} * 60;
                push(@pppcommand, ('idle', "$seconds"));
            }
            if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
                push(@pppcommand, ('demand', 'nopersist', 'connect', '/bin/true'));
            }
            push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
        }
        push(
            @pppcommand,
            (
                'noipdefault',       'defaultroute',
                'ipcp-accept-local', 'ipcp-accept-remote',
                'passive',           'noaccomp',
                'nopcomp',           'noccp',
                'novj',              'nobsdcomp',
                'nodeflate',
                'user',              $pppsettings{'USERNAME'},
                'lcp-echo-interval', '20',
                'lcp-echo-failure',  '3',
                'lcp-max-configure', '50',
                'maxfail',           $pppsettings{'MAXRETRIES'}
            )
        );

        if ($pppsettings{'DEBUG'} eq 'on') {
            push(@pppcommand, ('debug'));
        }

        system(@pppcommand);
    }
}


sub doatmprepare {
    my $type = shift;
    my $script = "/etc/rc.d/rc.${type}";
    my $error;

    if ($type eq 'conexantpciadsl') {
        $error = 'ERROR: Conexant PCI ADSL modem failed to start';
    }
    elsif ($type eq 'pulsardsl') {
        $error = 'ERROR: PULSAR ADSL modem failed to start';
    }
    elsif ($type eq 'solosdsl') {
        $error = 'ERROR: Solos PCI modem failed to start';
    }
    elsif ($type eq 'wanpipe-adsl') {
        $script = '/etc/rc.d/rc.wanpipe';
        $error = 'ERROR: wanpipe adsl failed to start';
    }
    else {
        &General::log('red', 'ERROR: Called ATM prepare with unsupported type');
        myexit(1);
    }

    if (! -e $script) {
        &General::log('red', "ERROR: missing script $script");
        myexit(1);
    }
    if (system($script, 'start')) {
        &General::log('red', $error);
        myexit(1);
    }
    doatmdial();
}


sub doatmdial {
    my $ENCAP;
    if ($pppsettings{'PROTOCOL'} eq 'RFC2364') {
        system('/sbin/modprobe pppoatm');
        my @pppcommand = ('/usr/sbin/pppd');
        if   ($pppsettings{'ENCAP'} eq '0') { $ENCAP = 'vc-encaps'; }
        else                                { $ENCAP = 'llc-encaps'; }
        push(@pppcommand, 'plugin', 'pppoatm.so', $pppsettings{'VPI'} . "." . $pppsettings{'VCI'}, "$ENCAP");
        if ($pppsettings{'DNS'} eq 'Automatic') { push(@pppcommand, ('usepeerdns')); }
        if ($pppsettings{'AUTH'} eq 'pap') {
            push(@pppcommand, ('-chap'));
        }
        elsif ($pppsettings{'AUTH'} eq 'chap') {
            push(@pppcommand, ('-pap'));
        }
        if ($pppsettings{'RECONNECTION'} ne 'persistent') {
            if ($pppsettings{'TIMEOUT'} != 0) {
                my $seconds = $pppsettings{'TIMEOUT'} * 60;
                push(@pppcommand, ('idle', "$seconds"));
            }
            if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
                push(@pppcommand, ('demand', 'nopersist'));
            }
            push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
        }
        push(
            @pppcommand,
            (
                'noipdefault',       'defaultroute',
                'ipcp-accept-local', 'ipcp-accept-remote',
                'passive',           'nopcomp',
                'noccp',             'novj',
                'nobsdcomp',         'nodeflate',
                'user',              $pppsettings{'USERNAME'},
                'lcp-echo-interval', '20',
                'lcp-echo-failure',  '3',
                'lcp-max-configure', '50',
                'maxfail',           $pppsettings{'MAXRETRIES'}
            )
        );

        if ($pppsettings{'DEBUG'} eq 'on') {
            push(@pppcommand, ('debug'));
        }

        system(@pppcommand);
    }
    elsif ($pppsettings{'PROTOCOL'} eq 'RFC1483') {
        if ($pppsettings{'METHOD'} =~ /^(PPPOE|PPPOE_PLUGIN)$/) {
            my $itf    = '0';
            my $device = "nas$itf";
            if (open(FILE, ">/var/ofw/red/device")) { print FILE $device; close FILE; }
            $netsettings{'RED_1_DEV'} = $device;
            if (system('/bin/ps -ef | /bin/grep -q [b]r2684ctl')) {
                system('/sbin/modprobe br2684');
                system('/usr/sbin/br2684ctl', '-b', '-c', "$itf", '-e', $pppsettings{'ENCAP'}, '-a',
                    "$itf.$pppsettings{'VPI'}.$pppsettings{'VCI'}");
                sleep 3;
            }
            system('/sbin/ip', 'link', 'set', "$device", 'up');
            &dopppoedial();
        }
        elsif ($pppsettings{'ENCAP'} =~ /^(0|1)$/) {
            my $itf = '0';
            $iface = "nas$itf";
            if (open(FILE, ">/var/ofw/red/iface")) { print FILE $iface; close FILE; }
            if (system('/bin/ps -ef | /bin/grep -q [b]r2684ctl')) {
                system('/sbin/modprobe br2684');
                system('/usr/sbin/br2684ctl', '-b', '-c', "$itf", '-e', $pppsettings{'ENCAP'}, '-a',
                    "$itf.$pppsettings{'VPI'}.$pppsettings{'VCI'}");
                sleep 3;
            }
            system('/sbin/ip', 'link', 'set', "$iface", 'up');

            if ($pppsettings{'METHOD'} eq 'STATIC') {
                system("/sbin/ip", "addr", "flush", "dev", $iface);
                system("/sbin/ip", "addr", "add", "$pppsettings{'IP'}/$pppsettings{'NETMASK'}", "dev", $iface);
                system("/sbin/ip", "route", "add", "default", "via", $pppsettings{'GATEWAY'});
                system("/usr/bin/touch", "/var/ofw/red/active");
                system("/etc/rc.d/rc.updatered red up");
            }
            elsif ($pppsettings{'METHOD'} eq 'DHCP') {
                dodhcpdial($iface, $pppsettings{'DHCP_HOSTNAME'});
            }
        }
        elsif ($pppsettings{'ENCAP'} =~ /^(2|3)$/) {
            my $itf = '0';
            $iface = "atm$itf";
            if (open(FILE, ">/var/ofw/red/iface")) { print FILE $iface; close FILE; }
            if (system('/bin/ps -ef | /bin/grep -q [a]tmarpd')) {
                if (system('/usr/sbin/atmarpd -b -l syslog')) {
                    &General::log('red', 'atmarpd fail');
                    myexit(1);
                }

                # it will fail on all attempt after the first because interface still exist
                system("/usr/sbin/atmarp -c $iface 2>/dev/null");

                if ($pppsettings{'METHOD'} eq 'STATIC') {
                    system("/sbin/ip", "addr", "flush", "dev", $iface);
                    system("/sbin/ip", "addr", "add", "$pppsettings{'IP'}/$pppsettings{'NETMASK'}", "dev", $iface);
                    system("/sbin/ip", "link", "set", $iface, "up");

                    # we have to wait a bit before launching atmarp -s
                    sleep 2;
                    my @atmarp = (
                        '/usr/sbin/atmarp', '-s', $pppsettings{'GATEWAY'},
                        "$itf.$pppsettings{'VPI'}.$pppsettings{'VCI'}"
                    );
                    if ($pppsettings{'ENCAP'} eq '3') {
                        push(@atmarp, 'null');    # routed ip vc encap
                    }
                    system(@atmarp);
                    system("/sbin/ip", "route", "add", "default", "via", $pppsettings{'GATEWAY'});
                    system("/usr/bin/touch", "/var/ofw/red/active");
                }
            }
        }
    }
    else {
        &General::log('red', 'atm, no RFC2364 and no RFC1483');
        myexit(1);
    }
}

sub dowanpipeserialdial {
    if (system('/etc/rc.d/rc.wanpipe', 'start')) {
        &General::log('red', 'ERROR: Sangoma Wanpipe serial interface failed to start');
        myexit(1);
    }

    my @pppcommand = ('/usr/sbin/pppd');
    my $device     = "/dev/${pppsettings{'COMPORT'}}";

    if ($pppsettings{'DNS'} eq 'Automatic') {
        push(@pppcommand, ('usepeerdns'));
    }

    #   if ($pppsettings{'AUTH'} eq 'pap') {
    #       push(@pppcommand, ('-chap'));
    #   } elsif ($pppsettings{'AUTH'} eq 'chap') {
    #       push(@pppcommand, ('-pap'));
    #   }

    if ($pppsettings{'RECONNECTION'} ne 'persistent') {
        if ($pppsettings{'TIMEOUT'} != 0) {
            my $seconds = $pppsettings{'TIMEOUT'} * 60;
            push(@pppcommand, ('idle', $seconds));
        }
        if ($pppsettings{'RECONNECTION'} eq 'dialondemand') {
            push(@pppcommand, ('demand', 'nopersist'));
        }
        push(@pppcommand, ('active-filter', 'outbound and not icmp[0] == 3 and not tcp[13] & 4 != 0 '));
    }

    if ($pppsettings{'METHOD'} eq 'STATIC') {
        my $pppstaticip = ("$pppsettings{'IP'}:$pppsettings{'GATEWAY'}");
        push(@pppcommand, ($pppstaticip));
    }

    push(@pppcommand, ('novj', 'novjccomp'));
    push(
        @pppcommand,
        (
            'lock',                     $device,   $pppsettings{'DTERATE'},  'noipdefault',
            'defaultroute',             'user',    $pppsettings{'USERNAME'}, 'maxfail',
            $pppsettings{'MAXRETRIES'}, 'connect', '/bin/true'
        )
    );
    if ($pppsettings{'DEBUG'} eq 'on') {
        push(@pppcommand, ('debug'));
    }
    system @pppcommand;

    # Uncomment to debug pppd option string
    # &General::log ("STATUS: @pppcommand" );
}
