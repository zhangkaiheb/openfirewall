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
# Copyright (c) 2018-2019 The Openfirewall Team
#
#

# Add entry in menu
# MENU-delete-ENTRY system 100 "credits" "credits"

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'credits'}, 1, '');

&Header::openbigbox('100%', 'left');

&Header::openbox('100%', 'left', $Lang::tr{'credits'});

print <<END

<table width='100%'>
<tr>
    <td align='left' width='20%'><img src='/openfirewall_small.gif' alt=''/></td>
    <td align='center' width='60%'><b><span style='font-size:14px'>Openfirewall - The Bad Packets Stop Here</span><br />
    <br />Visit us at <a href='http://www.openfirewall.cn/' target='_blank'>www.openfirewall.cn</a></b></td>
    <td align='left' width='20%'>&nbsp;</td>
</tr>
</table>
<hr />
<p><b>Main credits</b><br />
Release coordinator - Olaf Westrik
(<a href='mailto:'>&nbsp;</a>)<br />
Developer - Achim Weber
(<a href='mailto:'>&nbsp;</a>)<br />
Graphics - Tom Eichstaedt
(<a href='mailto:info\@cobin.de'>info\@cobin.de</a>)<br />
</p>

<p><b>Openfirewall 1.x developers</b><br />
Project Member - Mark Wormgoor
(<a href='mailto:mark\@wormgoor.com'>mark\@wormgoor.com</a>)<br />
Developer - Alan Hourihane
(<a href='mailto:alanh\@fairlite.demon.co.uk'>alanh\@fairlite.demon.co.uk</a>)<br />
Release coordinator - Gilles Espinasse
(<a href='mailto:g.esp.ipcop\@free.fr'>g.esp.ipcop\@free.fr</a>)<br />
Perl Developer - Franck Bourdonnec
(<a href='mailto:fbourdonnec\@chez.com'>fbourdonnec\@chez.com</a>)<br />
Testing - Dave Roberts
(<a href='mailto:dave\@daver.demon.co.uk'>dave\@daver.demon.co.uk</a>)<br />
Website Design + Graphics - Seth Bareiss
(<a href='mailto:seth\@fureai-ch.ne.jp'>seth\@fureai-ch.ne.jp</a>)<br />
Documentation - Harry Goldschmitt
(<a href='mailto:harry\@hgac.com'>harry\@hgac.com</a>)<br />
Red IP Aliasing - Steve Bootes
(<a href='mailto:Steve\@computingdynamics.co.uk'>Steve\@computingdynamics.co.uk</a>)<br />
Static DHCP Addresses - Graham Smith
(<a href='mailto:grhm\@grhm.co.uk'>grhm\@grhm.co.uk</a>)<br />
Squid graphs - Robert Wood
(<a href='rob\@empathymp3.co.uk'>rob\@empathymp3.co.uk</a>)<br />
Time Synchronization - Eric Oberlander
(<a href='mailto:eric\@oberlander.co.uk'>eric\@oberlander.co.uk</a>)<br />
Backup - Tim Butterfield
(<a href='mailto:timbutterfield\@mindspring.com'>timbutterfield\@mindspring.com</a>)<br />
DOV Support and Improved Dual ISDN Support - Traverse Technologies
(<a href='http://www.traverse.com.au/'>http://www.traverse.com.au/</a>)<br />
Traffic Shaping - David Kilpatrick
(<a href='mailto:dave\@thunder.com.au'>dave\@thunder.com.au</a>)<br />
Improved VPN Documentation - Christiaan Theron
(<a href='mailto:christiaan.theron\@virgin.net'>christiaan.theron\@virgin.net</a>)<br />
</p>

<p><b>Linux From Scratch</b><br />
For building openfirewall information from the Linux From Scratch (LFS) books is used.
The <a href='http://www.linuxfromscratch.org/index.html'>LFS books</a> are highly
recommended to anyone who wants to get some insight into what makes Linux systems tick.
</p>

<p><b>IPCop</b><br />
Openfirewall is partially based on the <a href='http://www.ipcop.org'>IPCop</a> GPL
version, v2.1.9.  We are grateful to them for both inspiring this product and
giving us the codebase to work with.
</p>
<br />
END
    ;

&Header::closebox();

&Header::closebigbox();

&Header::closepage();
