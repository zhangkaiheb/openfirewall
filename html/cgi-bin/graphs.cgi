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
# along with IPCop. If not, see <http://www.gnu.org/licenses/>.
#
# (c) The SmoothWall Team
# Copyright (c) 2001-2011 The IPCop Team
#
# $Id: graphs.cgi 5799 2011-08-17 19:42:44Z owes $
#

# Add entries in menu
# MENUENTRY status 040 "system graphs" "system graphs"
# MENUENTRY status 050 "sstraffic graphs" "network traffic graphs" "?graph=network"
#
# Make sure translation exists $Lang::tr{'sstraffic graphs'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

my %cgiparams=();
my %pppsettings=();
my %netsettings=();
my @cgigraphs=();
my @graphs=();
my $iface='';

&Header::showhttpheaders();

my $graphdir = '/home/httpd/html/graphs';
&General::readhash('/var/ipcop/ethernet/settings', \%netsettings);

$ENV{'QUERY_STRING'} =~ s/&//g;
@cgigraphs = split(/graph=/,$ENV{'QUERY_STRING'});
$cgigraphs[1] = '' unless defined $cgigraphs[1];

if ($cgigraphs[1] =~ /(network|GREEN|BLUE|ORANGE|RED)/) {
    &Header::openpage($Lang::tr{'network traffic graphs'}, 1, '');
}
else {
    &Header::openpage($Lang::tr{'system graphs'}, 1, '');
}
&Header::openbigbox('100%', 'left');

if ($cgigraphs[1] =~ /(GREEN|BLUE|ORANGE|RED|cpu|memory|diskuse|disk)/) {
    # Display 1 specific graph

    my $graph = $cgigraphs[1];
    my ($graphname, $count) = split('_', lc($graph));
    my $back = '';
    my $title = '';
    if ($graph =~ /(GREEN|BLUE|ORANGE|RED)/) {
        $title = ($count >= 2) ? $Lang::tr{$graphname}." ".$count : $Lang::tr{$graphname};
        $back = "<a href='/cgi-bin/graphs.cgi?graph=network'>";
    } 
    else {
        $title = $Lang::tr{'cpu usage'} if ($graph eq 'cpu');
        $title = $Lang::tr{'memory usage'} if ($graph eq 'memory');
        $title = $Lang::tr{'disk usage'} if ($graph eq 'diskuse');
        $title = $Lang::tr{'disk access'} if ($graph eq 'disk');
        $back = "<a href='/cgi-bin/graphs.cgi'>";
    }

    &Header::openbox('100%', 'center', "$title $Lang::tr{'graph'}");

    if (-e "$graphdir/${graph}-day.png") {
        print <<END
<table width='100%'><tr>
    <td width='10%'>$back<img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
<hr />
<img src='/graphs/${graph}-day.png' border='0' alt='${graph}-$Lang::tr{'day'}' /><hr />
<img src='/graphs/${graph}-week.png' border='0' alt='${graph}-$Lang::tr{'week'}' /><hr />
<img src='/graphs/${graph}-month.png' border='0' alt='${graph}-$Lang::tr{'month'}' /><hr />
<img src='/graphs/${graph}-year.png' border='0' alt='${graph}-$Lang::tr{'year'}' />
END
        ;
    } 
    else {
        print $Lang::tr{'no information available'};
    }

    print <<END
<hr />
<table width='100%'><tr>
    <td width='10%'>$back<img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
    ;
    &Header::closebox();
}
elsif ($cgigraphs[1] =~ /network/) {
    # Display network graphs

    for my $color ('GREEN', 'ORANGE', 'BLUE') {
        my $icount = $netsettings{"${color}_COUNT"};
        while($icount > 0) {
            push (@graphs, ("${color}_${icount}"));
            $icount--;
        }
    }
    # RED_1 will always be there even in case of RED_COUNT==0 
    # as makegraphs will create RED_1 for MODEM/ISDN type connections
    push (@graphs, ("RED_1"));

    foreach my $graphname (@graphs) {
        my ($title, $count) = split('_', $graphname);
        $title = $Lang::tr{(lc($title))};
        $title = $title." ".$count if ( $count >= 2 );
        &Header::openbox('100%', 'center', "$title $Lang::tr{'graph'}");

        if (-e "$graphdir/${graphname}-day.png") {
            print "<a href='/cgi-bin/graphs.cgi?graph=$graphname'>";
            print "<img src='/graphs/${graphname}-day.png' alt='${graphname}-$Lang::tr{'day'}' border='0' />";
            print "</a><br />";
        } 
        else {
            print $Lang::tr{'no information available'};
        }
        if ( $graphname eq 'GREEN_1' ) {
            print<<END
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'>&nbsp;</td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/status-traffic-graphs.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
            ;
        }
        &Header::closebox();
    }
}
else {
    # Display system graphs

    &disp_graph("$Lang::tr{'cpu usage'} $Lang::tr{'graph'}", "cpu", "cpu-$Lang::tr{'day'}");
    &disp_graph("$Lang::tr{'memory usage'} $Lang::tr{'graph'}", "memory", "$Lang::tr{'memory'}-$Lang::tr{'day'}");
    &disp_graph("$Lang::tr{'disk usage'} $Lang::tr{'graph'}", "diskuse", "$Lang::tr{'disk usage'}-$Lang::tr{'day'}");
    &disp_graph("$Lang::tr{'disk access'} $Lang::tr{'graph'}", "disk", "disk-$Lang::tr{'day'}");
}

&Header::closebigbox();
&Header::closepage();


sub disp_graph
{
    my $title = shift;
    my $file  = shift;
    my $alt   = shift;

    &Header::openbox('100%', 'center', $title);
    if (-e "$graphdir/$file-day.png") {
        print "<a href='/cgi-bin/graphs.cgi?graph=$file'>";
        print "<img src='/graphs/$file-day.png' alt='$alt' border='0' />";
        print "</a><br />";
    } else {
        print $Lang::tr{'no information available'};
    }

    if ( $file eq 'cpu' ) {
        print<<END
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'>&nbsp;</td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/status-graphs.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
        ;
    }
    &Header::closebox();
}
