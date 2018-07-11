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
# $Id: proxystatus.cgi 7418 2014-04-05 19:57:44Z owes $
#

# Add entry in menu
# MENUENTRY status 035 "proxy" "proxy"
#
# Make sure translation exists $Lang::tr{'proxy'}

use strict;

use warnings; no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

&Header::showhttpheaders();
&Header::openpage($Lang::tr{'proxy'}, 1, '');
&Header::openbigbox('100%', 'left');
&Header::openbox('100%', 'left', $Lang::tr{'proxy'});

my $sactive = &General::isrunning('squid', 'nosize');

print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='25%'>$Lang::tr{'web proxy'}:</td>
    $sactive
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'><input type='submit' name='ACTION' value='$Lang::tr{'refresh'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/status-proxy.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table></form>
<hr />
END
;

if (open(IPACHTML, '/var/log/squid/info')) {
    my $skip = 1;
    print "<pre>";
    while (<IPACHTML>) {
        $skip = 0 if (/Squid Object Cache/);
        print unless ($skip);
    }
    print "</pre>";
    close(IPACHTML);
}
else {
    print $Lang::tr{'no information available'};
}

&Header::closebox();
&Header::closebigbox();
&Header::closepage();
