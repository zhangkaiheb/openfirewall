#!/usr/bin/perl
#
# (c) 2002 Robert Wood <rob@empathymp3.co.uk>
#
# $Id: proxygraphs.cgi 7496 2014-04-22 16:41:58Z owes $
#

# Add entry in menu
# MENUENTRY status 060 "ssproxy graphs" "proxy access graphs" haveProxy
#
# Make sure translation exists $Lang::tr{'ssproxy graphs'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my %cgiparams=();
my @cgigraphs=();
my @graphs = ();
my $graphdir = '/usr/local/apache/html/graphs';

&Header::showhttpheaders();

$ENV{'QUERY_STRING'} =~ s/&//g;
@cgigraphs = split(/graph=/,$ENV{'QUERY_STRING'});
$cgigraphs[1] = '' unless defined $cgigraphs[1];

&Header::openpage($Lang::tr{'proxy access graphs'}, 1, '');

&Header::openbigbox('100%', 'left');

if ($cgigraphs[1] =~ /(squid-requests|squid-hits)/) {
    # Display 1 specific graph

    my $graph = $cgigraphs[1];
    my ($graphname, $count) = split('_', lc($graph));
    my $back = '';
    my $title = '';
    $title = $Lang::tr{'proxy requests'} if ($graph eq 'squid-requests');
    $title = $Lang::tr{'proxy hits percentage'} if ($graph eq 'squid-hits');

    &Header::openbox('100%', 'center', "$title $Lang::tr{'graph'}");

    if (-e "$graphdir/${graph}-day.png") {
        print <<END
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/proxygraphs.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
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
    <td width='10%'><a href='/cgi-bin/proxygraphs.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
    ;
    &Header::closebox();
}
else {
    &disp_graph("$Lang::tr{'proxy access graphs'}", "squid-requests", "squid-requests-$Lang::tr{'day'}");
    &disp_graph("$Lang::tr{'proxy access graphs'}", "squid-hits", "squid-hits-$Lang::tr{'day'}");
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
        print "<a href='/cgi-bin/proxygraphs.cgi?graph=$file'>";
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
        <a href='${General::adminmanualurl}/status-proxy-graphs.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
END
        ;
    }
    &Header::closebox();
}
