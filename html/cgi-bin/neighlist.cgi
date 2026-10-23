#!/usr/bin/perl
#
# This code is distributed under the terms of the GPL
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

# Add entry in menu
# MENUTHRDLVL "neigh table" 020 "arp table entries" "arp table entries
#
# Make sure translation exists $Lang::tr{'arp table entries'}

use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/firewall-lib.pl';

my $output='';
&Header::showhttpheaders();

my %cgiparams    = ();
my $errormessage = '';
my $error        = '';
$cgiparams{'ACTION'}     = '';
$cgiparams{'USED_COUNT'} = 0;
&General::getcgihash(\%cgiparams);

# vars for setting up sort order
my $sort_col  = '1';
my $sort_type = 'a';
my $sort_dir  = 'asc';
my $junk;

if ($ENV{'QUERY_STRING'} ne '') {
    my ($item1, $item2, $item3) = split(/\&/, $ENV{'QUERY_STRING'});
    if ($item1 ne '') {
        ($junk, $sort_col) = split(/\=/, $item1);
    }
    if ($item2 ne '') {
        ($junk, $sort_type) = split(/\=/, $item2);
    }
    if ($item3 ne '') {
        ($junk, $sort_dir) = split(/\=/, $item3);
    }
}

&Header::openpage($Lang::tr{'network status information'}, 1, '');

print "<a name='arp'/>\n";

# Get ARP table entries
my $arpOutput = `/sbin/ip neigh list`;
$arpOutput = &Header::cleanhtml($arpOutput, "y");

# Convert to JavaScript format
my @jsData;
my $idx = 1;
foreach my $line (split(/\n/, $arpOutput)) {
    if ($line =~ m/^(.*) dev ([^ ]+) lladdr ([0-9a-f:]*) (.*)$/) {
        push @jsData, sprintf(
            "{id:'%d',ip:'%s',iface:'%s',mac:'%s',status:'%s'}",
            $idx, $1, $2, $3, $4
        );
        $idx++;
    }
    elsif ($line =~ m/^(.*) dev ([^ ]+)  (.*)$/) {
        push @jsData, sprintf(
            "{id:'%d',ip:'%s',iface:'%s',mac:'-',status:'%s'}",
            $idx, $1, $2, $3
        );
        $idx++;
    }
}
my $jsDataStr = join(",\n", @jsData);

print <<END;
<script src="/include/datatable.js"></script>
<script>
const arpData = [
$jsDataStr
];

document.addEventListener('DOMContentLoaded', function() {
    const table = new DataTable('#arpTable', {
        data: arpData,
        columns: [
            { key: 'id', title: '$Lang::tr{'sequence'}', sortable: true },
            { key: 'ip', title: '$Lang::tr{'ip address'}', sortable: true },
            { key: 'iface', title: '$Lang::tr{'interface'}', sortable: true },
            { key: 'mac', title: '$Lang::tr{'mac address'}', sortable: true },
            { key: 'status', title: '$Lang::tr{'status'}', sortable: true }
        ],
        defaultSort: { key: 'id', order: 'asc' },
        pageSize: 20,
        selectable: false,
        actions: [],
        disabledActions: []
    });
    table.render();
});
</script>
<div id="arpTable"></div>
END

&Header::closepage();
