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
# MENUTHRDLVL "routing table" 020 "routing table entries" "routing table entries"
#
# Make sure translation exists $Lang::tr{'routing table entries'}
#

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
&General::getcgihash(\%cgiparams);

# vars for setting up sort order
my $sort_col  = '1';
my $sort_type = 'a';
my $sort_dir  = 'asc';
my $junk;
my $lineNumber = 0;

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


$cgiparams{'ADDRESS'}  = '';
$cgiparams{'NETMASK'}  = '';
$cgiparams{'GATEWAY'}  = '';
$cgiparams{'IFACE'}    = '';
&General::getcgihash(\%cgiparams);


&Header::openpage($Lang::tr{'network status information'}, 1, '');

print "<a name='routing'/>\n";

# Get routing table entries
my $routeOutput = `/sbin/ip route list`;
$routeOutput = &Header::cleanhtml($routeOutput, "y");

# Convert to JavaScript format
my @jsData;
my $idx = 1;
foreach my $line (split(/\n/, $routeOutput)) {
    my ($dest, $gateway, $iface, $remark);
    if ($line =~ m/^(.*) dev ([^ ]+) (.*) src (.*)$/) {
        $dest = $1;
        $iface = $2;
        $gateway = $4;
        $remark = $3;
    }
    elsif ($line =~ m/^(.*) via (.*) dev (.*)$/) {
        $dest = $1;
        $gateway = $2;
        $iface = $3;
        $remark = '';
    }
    elsif ($line =~ m/^(.*) dev ipsec(\d*)  (.*)$/) {
        $dest = $1;
        $iface = "ipsec$2";
        $gateway = '';
        $remark = $3;
    }
    else {
        next;
    }
    
    push @jsData, sprintf(
        "{id:'%d',dest:'%s',gateway:'%s',iface:'%s',remark:'%s'}",
        $idx, $dest, $gateway, $iface, $remark
    );
    $idx++;
}
my $jsDataStr = join(",\n", @jsData);

print <<END;
<script src="/include/datatable.js"></script>
<script>
const routeData = [
$jsDataStr
];

document.addEventListener('DOMContentLoaded', function() {
    const table = new DataTable('#routeTable', {
        data: routeData,
        columns: [
            { key: 'id', title: '$Lang::tr{'sequence'}', sortable: true },
            { key: 'dest', title: '$Lang::tr{'destination ip or net'}', sortable: true },
            { key: 'gateway', title: '$Lang::tr{'gateway ip'}', sortable: true },
            { key: 'iface', title: '$Lang::tr{'interface'}', sortable: true },
            { key: 'remark', title: '$Lang::tr{'remark'}', sortable: true }
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
<div id="routeTable"></div>
END

&Header::closepage();
