#
# header.pl: various helper functions for the web GUI
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
# Copyright (c) 2004-2018 The Openfirewall Team
#

package Header;
require '/usr/lib/ofw/menu.pl';

use strict;
use Time::Local;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

$Header::boxcolour    = '#E0E0E0';    # used in makegraphs, use css whereever possible
$Header::boxframe     = '';           # retain frametype for closebox

# Make sure these make it into translations even though some of them may not be in use.
# $Lang::tr{'green'}    $Lang::tr{'green interface'}
# $Lang::tr{'blue'}     $Lang::tr{'blue interface'}
# $Lang::tr{'orange'}   $Lang::tr{'orange interface'}
# $Lang::tr{'red'}      $Lang::tr{'red interface'}
# $Lang::tr{'ipsec-red'}
# $Lang::tr{'ipsec-blue'}
# $Lang::tr{'openvpn-rw'}
# $Lang::tr{'any'}
#
# Same procedure for some top-level menu names
# $Lang::tr{'alt system'}
# $Lang::tr{'status'}
# $Lang::tr{'network'}
# $Lang::tr{'services'}
# $Lang::tr{'firewall'}
# $Lang::tr{'alt vpn'}
# $Lang::tr{'alt logs'}

my %menu = ();
our $javascript = 1;
our $httpheaders = 0;

# Define visual sort indicators for column headings
$Header::sortup = "<img src='/images/triangle_up.png' alt='a-z' />";      # sort small to large
$Header::sortdn = "<img src='/images/triangle_down.png' alt='z-a' />";    # sort large to small

### Initialize menu
sub genmenu
{
    ### Initialize environment
    my %menuconfig = ();
    my %ethsettings = ();
    &General::readhash('/var/ofw/ethernet/settings', \%ethsettings);
    my %proxysettings = ();
    &General::readhash('/var/ofw/proxy/settings', \%proxysettings);

    $menuconfig{'haveBlue'} = $ethsettings{'BLUE_COUNT'};
    $menuconfig{'haveProxy'} = 0;

    for (my $i = 1; $i <= $ethsettings{'GREEN_COUNT'}; $i++) {
        $menuconfig{'haveProxy'}++ if ($proxysettings{"ENABLED_GREEN_${i}"} eq 'on');
    }
    for (my $i = 1; $i <= $ethsettings{'BLUE_COUNT'}; $i++) {
        $menuconfig{'haveProxy'}++ if ($proxysettings{"ENABLED_BLUE_${i}"} eq 'on');
    }
    $menuconfig{'haveProxy'}++ if ($proxysettings{"ENABLED_OVPN"} eq 'on');


    &Menu::buildmenu(\%menuconfig);
    %menu = %Menu::menu;
}

sub showhttpheaders
{
    ### Make sure this is an SSL request
    if ($ENV{'SERVER_ADDR'} && $ENV{'HTTPS'} ne 'on') {
        my %mainsettings = ();

        # TODO: remove this. Need this for some limited time only: doing a restore may leave us without GUIPORT
        $mainsettings{'GUIPORT'} = 8443;

        &General::readhash('/var/ofw/main/settings', \%mainsettings);
        print "Status: 302 Moved\r\n";
        print "Location: https://$ENV{'SERVER_ADDR'}:$mainsettings{'GUIPORT'}/$ENV{'PATH_INFO'}\r\n\r\n";
        exit 0;
    }
    else {
        print "Pragma: no-cache\n";
        print "Cache-control: no-cache\n";
        print "Connection: close\n";
        print "Content-type: text/html\n\n";
    }
    $httpheaders = 1;
}

sub showjsmenu
{
    my $c1 = 1;

    print "    <script type='text/javascript'>\n";
    print "    domMenu_data.set('domMenu_main', new Hash(\n";

    foreach my $k1 (sort keys %menu) {
        my $c2 = 1;
        if ($c1 > 1) {
            print "    ),\n";
        }
        print "    $c1, new Hash(\n";
        print "\t'contents', '" . &cleanhtml($menu{$k1}{'contents'}) . "',\n";
        print "\t'uri', '$menu{$k1}{'uri'}',\n";
        $menu{$k1}{'statusText'} =~ s/'/\\\'/g;
        print "\t'statusText', '$menu{$k1}{'statusText'}',\n";
        foreach my $k2 (@{$menu{$k1}{'subMenu'}}) {
            print "\t    $c2, new Hash(\n";
            print "\t\t'contents', '" . &cleanhtml(@{$k2}[0]) . "',\n";
            print "\t\t'uri', '@{$k2}[1]',\n";
            @{$k2}[2] =~ s/'/\\\'/g;
            print "\t\t'statusText', '@{$k2}[2]'\n";
            if ($c2 <= $#{$menu{$k1}{'subMenu'}}) {
                print "\t    ),\n";
            }
            else {
                print "\t    )\n";
            }
            $c2++;
        }
        $c1++;
    }
    print "    )\n";
    print "    ));\n\n";

    print <<EOF
    domMenu_settings.set('domMenu_main', new Hash(
    'menuBarWidth', '0%',
    'menuBarClass', 'ofw_menuBar',
    'menuElementClass', 'ofw_menuElement',
    'menuElementHoverClass', 'ofw_menuElementHover',
    'menuElementActiveClass', 'ofw_menuElementHover',
    'subMenuBarClass', 'ofw_subMenuBar',
    'subMenuElementClass', 'ofw_subMenuElement',
    'subMenuElementHoverClass', 'ofw_subMenuElementHover',
    'subMenuElementActiveClass', 'ofw_subMenuElementHover',
    'subMenuMinWidth', 'auto',
    'distributeSpace', false,
    'openMouseoverMenuDelay', 0,
    'openMousedownMenuDelay', 0,
    'closeClickMenuDelay', 0,
    'closeMouseoutMenuDelay', 800
    ));
    </script>
EOF
        ;
}

sub showmenu
{
    if ($javascript) { print "<noscript>"; }
    print "<table cellpadding='0' cellspacing='0' border='0'>\n";
    print "<tr>\n";

    foreach my $k1 (sort keys %menu) {
        print "<td class='ofw_menuElementTD'><a href='"
            . @{@{$menu{$k1}{'subMenu'}}[0]}[1]
            . "' class='ofw_menuElementNoJS'>";
        print $menu{$k1}{'contents'} . "</a></td>\n";
    }
    print "</tr></table>\n";
    if ($javascript) { print "</noscript>"; }
}

sub showsubsection
{
    my $location = $_[0];
    my $c1       = 0;

    if ($javascript) { print "<noscript>"; }
    print "<table width='100%' cellspacing='0' cellpadding='5' border='0'>\n";
    print "<tr><td width='64'><img src='/images/null.gif' width='54' height='1' alt='' /></td>\n";
    print "<td align='left' width='100%'>";
    my @URI = split('\?', $ENV{'REQUEST_URI'});
    $URI[1] = '' unless (defined($URI[1]));

    foreach my $k1 (keys %menu) {

        if ($menu{$k1}{'contents'} eq $location) {
            foreach my $k2 (@{$menu{$k1}{'subMenu'}}) {
                if ($c1 > 0) {
                    print " | ";
                }
                if (@{$k2}[1] eq "$URI[0]\?$URI[1]" || (@{$k2}[1] eq $URI[0] && length($URI[1]) == 0)) {

                    #if (@{$k2}[1] eq "$URI[0]") {
                    print "<a href='@{$k2}[1]'><b>@{$k2}[0]</b></a>";
                }
                else {
                    print "<a href='@{$k2}[1]'>@{$k2}[0]</a>";
                }
                $c1++;
            }
        }
    }
    print "</td></tr></table>\n";
    if ($javascript) { print "</noscript>"; }
}

sub openpage
{
    my $title     = $_[0];
    my $menu      = $_[1];
    my $extrahead = $_[2];

    my $full_title = '';
    my $onload_menu = '';
    ### Initialize environment
    my %settings = ();
    &General::readhash('/var/ofw/main/settings', \%settings);

    if ($settings{'JAVASCRIPT'} eq 'off') {
        $javascript = 0;
    }
    else {
        $javascript = 1;
    }

    if ($settings{'WINDOWWITHHOSTNAME'} eq 'on') {
        $full_title = "$settings{'HOSTNAME'}.$settings{'DOMAINNAME'} - $title";
    }
    else {
        $full_title = "Openfirewall - $title";
    }

    $onload_menu = "onload=\"domMenu_activate('domMenu_main');\"" if ($menu == 1);

    print <<END
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html><head>
    <title>$full_title</title>
    $extrahead
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <link rel="shortcut icon" href="/favicon.ico" />
    <style type="text/css">\@import url(/include/openfirewall.css);</style>
END
    ;
    if ($javascript) {
        print "<script type='text/javascript' src='/include/domLib.js'></script>\n";
        print "<script type='text/javascript' src='/include/domMenu.js'></script>\n";
        &genmenu();
        &showjsmenu();
    }
    else {
        &genmenu();
    }

    my $location    = '';
    my $sublocation = '';
    my @URI         = split('\?', $ENV{'REQUEST_URI'});
    foreach my $k1 (keys %menu) {
        my $temp = $menu{$k1}{'contents'};
        foreach my $k2 (@{$menu{$k1}{'subMenu'}}) {
            if (@{$k2}[1] eq $URI[0]) {
                $location    = $temp;
                $sublocation = @{$k2}[0];
            }
        }
    }

    my @cgigraphs = split(/graph=/, $ENV{'QUERY_STRING'});
    if (defined($cgigraphs[1])) {
        if ($cgigraphs[1] =~ /(GREEN|BLUE|ORANGE|RED|network)/) {
            $location    = $Lang::tr{'status'};
            $sublocation = $Lang::tr{'sstraffic graphs'};
        }
        if ($cgigraphs[1] =~ /(cpu|memory|swap|disk)/) {
            $location    = $Lang::tr{'status'};
            $sublocation = $Lang::tr{'system graphs'};
        }
    }
    if ($ENV{'QUERY_STRING'} =~ /(ip)/) {
        $location    = $Lang::tr{'alt logs'};
        $sublocation = "WHOIS";
    }

    if ($javascript) {
        print <<END
<script type="text/javascript">
document.onmouseup = function()
{
    domMenu_deactivate('domMenu_main');
}
</script>
</head>
<body $onload_menu>
END
            ;
    }
    else {
        print "</head>\n\n<body>\n";
    }

    print <<END
<!-- OPENFIREWALL HEADER -->
<table width='100%' border='0' cellpadding='0' cellspacing='0'>
<col width='719' /><col /><col width='32' />
<tr><td style='background: url(/images/header_left.png); background-repeat:no-repeat;'>
    <table width='100%' border='0' cellpadding='0' cellspacing='0' style='table-layout:fixed;'>
    <col width='75' /><col width='182' /><col />
    <tr valign='bottom'><td></td>
        <td class='ofw_menuLocationMain' colspan='2' height='25'><img src='/images/null.gif' width='8' height='1' alt='' />$location
        <img src='/images/null.gif' width='16' height='1' alt='' /><img src='/images/header_arrow.gif' width='20' height='12' alt='' /><img src='/images/null.gif' width='24' height='1' alt='' /><font style='font-size: 12px;'>$sublocation</font></td>
    </tr>
    <tr valign='bottom'><td colspan='3' height='3'></td></tr>
    <tr valign='bottom'><td height='27'></td>
        <td colspan='2'>
END
        ;
    if ($menu == 1) {
        if ($javascript) {
            print "<div id='domMenu_main'></div>\n";
        }
        &showmenu();
    }
    print "    </td></tr></table>\n";
    &showsubsection($location);
    print <<END
</td>
<td valign='top' style='background: url(/images/header_dyn.png);background-repeat:repeat-x;'>&nbsp;</td>
<td style='background: url(/images/header_right.png); background-repeat:no-repeat;'>&nbsp;</td>
</tr>
</table>
<!-- OPENFIREWALL CONTENT -->
END
        ;
}

#
# Close GUI page. Use 'skip_connected' as parameter when connection information should not be displayed.
#
sub closepage
{
    my $connected = shift;
    my $extraversion = '';
    $extraversion = '| ' . `cat /etc/svn-install` . ' ' if (! -e '/var/log/updates/update.check');
    my $status = "<small>Openfirewall v${General::version} $extraversion &copy; 2001-2016 The Openfirewall Team</small>";

    $status = &General::connectionstatus() . "<br />" . `/bin/date "+%Y-%m-%d %H:%M:%S"`. "<br /><br />$status" if ($connected ne 'skip_connected');

    print <<END
<!-- OPENFIREWALL FOOTER -->
    <table width='100%' border='0'><tr>
    <td align='center' valign='middle'>$status</td>
    </tr></table>
</body></html>
END
        ;
}

sub openbigbox
{
    my $width   = $_[0];
    my $align   = $_[1];
    my $sideimg = $_[2];

    my $tablewidth = '';
    $tablewidth = "width='$width'" if ($width);

    print "<table width='100%' border='0'>\n";
    if ($sideimg) {
        print "<tr><td valign='top'><img src='/images/$sideimg' width='65' height='345' alt='' /></td>\n";
    }
    else {
        print "<tr>\n";
    }
    print "<td valign='top' align='center'><table $tablewidth cellspacing='0' cellpadding='10' border='0'>\n";
    print "<tr><td align='$align' valign='top'>\n";
}

sub closebigbox
{
    print "</td></tr></table></td></tr></table>\n";
}

sub openbox
{
    my $width   = $_[0];
    my $align   = $_[1];
    my $caption = $_[2];
    $Header::boxframe = '';

    $Header::boxframe = $_[3] if (defined($_[3]));

    my $tablewidth = "width='100%'";
    if ($width eq '100%') {
        $width = 500;
    }
    else {
        $tablewidth = "";
    }
    my $tdwidth = $width - 18 - 12 - 145 - 18;

    print <<END
<table cellspacing='0' cellpadding='0' $tablewidth border='0'>
    <tr>
        <td style='width:18px' ><img src='/images/null.gif' width='18'  height='1' alt='' /></td>
        <td style='width:12px' ><img src='/images/null.gif' width='12'  height='1' alt='' /></td>
        <td><img src='/images/null.gif' width='$tdwidth' height='1' alt='' /></td>
        <td style='width:145px' ><img src='/images/null.gif' width='145' height='1' alt='' /></td>
        <td style='width:18px' ><img src='/images/null.gif' width='18'  height='1' alt='' /></td>
    </tr><tr>
        <td colspan='2' ><img src='/images/${Header::boxframe}boxtop1.png' width='30' height='53' alt='' /></td>
        <td style='background: url(/images/${Header::boxframe}boxtop2.png);'>
END
        ;
    if   ($caption) { print "<b>$caption</b>\n"; }
    else            { print "&nbsp;"; }
    print <<END
        </td>
        <td colspan='2'><img src='/images/${Header::boxframe}boxtop3.png' width='163' height='53' alt='' /></td>
    </tr>
    <tr>
        <td style='background: url(/images/${Header::boxframe}boxleft.png);'><img src='/images/null.gif' width='18' height='1' alt='' /></td>
        <td colspan='3' style='background-color: $Header::boxcolour;'>
            <table width='100%' cellpadding='5'><tr><td align='$align' valign='top'>
END
        ;
}

# removed from above, store here
#    <col width='18' />
#    <col width='12' />
#    <col width='100%' />
#    <col width='145' />
#    <col width='18' />
#</table><table cellspacing='0' cellpadding='0' width='$width' border='0'>

sub closebox
{
    print <<END
            </td></tr></table>
        </td>
        <td style='background: url(/images/${Header::boxframe}boxright.png);'><img src='/images/null.gif' width='18' height='1' alt='' /></td>
    </tr><tr>
        <td style='background: url(/images/${Header::boxframe}boxbottom1.png);background-repeat:no-repeat;'><img src='/images/null.gif' width='18' height='18' alt='' /></td>
        <td style='background: url(/images/${Header::boxframe}boxbottom2.png);background-repeat:repeat-x;' colspan='3'><img src='/images/null.gif' width='1' height='18' alt='' /></td>
        <td style='background: url(/images/${Header::boxframe}boxbottom3.png);background-repeat:no-repeat;'><img src='/images/null.gif' width='18' height='18' alt='' /></td>
    </tr><tr>
        <td colspan='5'><img src='/images/null.gif' width='1' height='5' alt='' /></td>
    </tr>
</table>
END
        ;
}

sub cleanhtml
{
    my $outstring = $_[0];
    $outstring =~ tr/,/ / if not defined $_[1] or $_[1] ne 'y';
    $outstring =~ s/&/&amp;/g;
    $outstring =~ s/\'/&#039;/g;
    $outstring =~ s/\"/&quot;/g;
    $outstring =~ s/</&lt;/g;
    $outstring =~ s/>/&gt;/g;
    return $outstring;
}

sub cleanConfNames
{
    my $name = shift;
    $name =~ s/&//g;
    $name =~ s/\'//g;
    $name =~ s/\"//g;
    $name =~ s/<//g;
    $name =~ s/>//g;

    return $name;
}

sub percentbar
{
    my $percent = $_[0];

    if ($percent =~ m/^(\d+)%$/ )
    {
        print <<END
<table class='percentbar'>
<tr>
END
;
        if ($percent eq "100%") {
            print "<td width='100%' class='percent1'>"
        }
        elsif ($percent eq "0%") {
            print "<td width='100%' class='percent0'>"
        }
        else {
            print "<td width='$percent' class='percent1'></td><td width='" . (100-$1) . "%' class='percent0'>";
        }
        print <<END
<img src='/images/null.gif' width='1' height='1' alt='' /></td></tr></table>
END
;
    }
}

# Show page with Openfirewall logo and a single text. Optional refresh.
#   Parameters:
#   - page title
#   - boxtype: error = red boxframe, warning = yellow boxframe
#   - message
#   - refresh. Use full meta refresh like so: "<meta http-equiv='refresh' content='5; URL=/cgi-bin/index.cgi' />"
sub page_show
{
    my $title = shift;
    my $boxtype = shift;
    my $message = shift;
    my $refresh = shift;

    showhttpheaders() unless($httpheaders);
    openpage($title, 0, $refresh);
    openbigbox('100%', 'center');
    openbox('100%', 'left', '', $boxtype);
    print <<END
<div align='center'>
<table width='100%'>
<tr><td align='center'>
<br /><br /><img src='/openfirewall_big.gif' alt='openfirewall' /><br /><br /><br />
</td></tr>
</table>
<br />
<font size='6'>$message</font>
</div>
END
        ;
    closebox();
    closebigbox();
    closepage();
}

1;
