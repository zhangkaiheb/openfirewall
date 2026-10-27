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
#

# Add entry in menu
# MENUENTRY status 045 "proxy status" "proxy status"
#
# Make sure translation exists $Lang::tr{'proxy status'}

use strict;

use warnings; no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/widget-lib.pl';

&Header::showhttpheaders();

my $extrahead = Widget::widget_css();
&Header::openpage($Lang::tr{'proxy'}, 1, $extrahead);

my %icons = Widget::widget_icons();
my $closeIcon = $icons{'close'};
my $expandIcon = $icons{'expand'};

print Widget::widget_add_button();
print "<div class='status-widget-grid'>\n";

# Proxy Status widget
print <<END
<div class="widget-card">
    <div class="widget-header">
        <span class="widget-title">$Lang::tr{'proxy'}</span>
END
;
print Widget::widget_header_buttons($closeIcon, $expandIcon);
print <<END
    </div>
    <div class="widget-body">
END
;

my $sactive = &General::isrunning('squid', 'nosize');

print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table class="widget-table">
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
    <td class='button1button'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'refresh'}' /></td>
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

print <<END
    </div>
</div>
END
;

print "</div>\n";

print Widget::widget_add_dialog($Lang::tr{'cancel'}, $Lang::tr{'add'});
print Widget::widget_js();

&Header::closepage();
