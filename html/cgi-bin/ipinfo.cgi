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
# (c) 2002 Josh Grubman <jg@false.net> - Multiple registry IP lookup code
# (c) 2014, the IPCop team
#
# $Id: ipinfo.cgi 7386 2014-03-31 04:35:39Z owes $
#

use IO::Socket;
use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

my %cgiparams=();

&Header::showhttpheaders();

&General::getcgihash(\%cgiparams);

$ENV{'QUERY_STRING'} =~s/&//g;
my @addrs = split(/ip=/,$ENV{'QUERY_STRING'});

my %whois_servers = (
    "AfriNIC" => "whois.afrinic.net",
    "APNIC"   => "whois.apnic.net",
    "LACNIC"  => "whois.lacnic.net",
    "RIPE"    => "whois.ripe.net",
);

&Header::openpage($Lang::tr{'ip info'}, 1, '');

&Header::openbigbox('100%', 'left');
my @lines=();
my $extraquery='';
foreach my $addr (@addrs) {
    next if $addr eq "";

    $extraquery='';
    @lines=();
    my $iaddr = inet_aton($addr);
    if (! defined($iaddr) ) {
        &Header::openbox('100%', 'left', $Lang::tr{'lookup failed'}, 'error');
        print $Lang::tr{'invalid address'} . ": ". &Header::cleanhtml($addr) . "<br />";
        &add_back();
        &Header::closebox();
        next;
    }
    my $whoisname = "whois.arin.net";
    my $hostname = gethostbyaddr($iaddr, AF_INET);

    if (!$hostname) {
        &Header::openbox('100%', 'left', $Lang::tr{'lookup failed'}, 'warning');
        print $Lang::tr{'lookup failed'} . ": ". &Header::cleanhtml($addr) . "<br /><hr />";
    }
    else {
        &Header::openbox('100%', 'left', $addr . ' (' . $hostname . ') : '.$whoisname);
    }

    my $sock = new IO::Socket::INET ( PeerAddr => $whoisname, PeerPort => 43, Proto => 'tcp');
    if ($sock) {
        print $sock "$addr\n";
        while (<$sock>) {
            $extraquery = $1 if (/NetType:\s+Allocated to (\S+)\s+/);
            $extraquery = $1 if (/NetType:\s+Transferred to (\S+)\s+/);
            push(@lines,$_);
        }
        close($sock);

        if ($extraquery) {
            undef (@lines);
            $whoisname = $whois_servers{$extraquery};
            my $sock = new IO::Socket::INET ( PeerAddr => $whoisname, PeerPort => 43, Proto => 'tcp');
            if ($sock) {
                print $sock "$addr\n";
                while (<$sock>) {
                    push(@lines,$_);
                }
            }
            else {
                @lines = ( "$Lang::tr{'unable to contact'} $whoisname" );
            }
        }
    }
    else {
        @lines = ( "$Lang::tr{'unable to contact'} $whoisname" );
    }

    print "<pre>\n";
    foreach my $line (@lines) {
        print &Header::cleanhtml($line,"y");
    }
    print "</pre>\n";

    &add_back();
    &Header::closebox();
}

&Header::closebigbox();

&Header::closepage();

sub add_back {

    if (defined($ENV{'HTTP_REFERER'})) {
        # Offer 'back' if there is a referer
        print "<hr /><div align='left'>";
        print "<a href='$ENV{'HTTP_REFERER'}'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a>";
        print "</div>";
    }
}
