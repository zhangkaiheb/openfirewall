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
# (c) place a name here
#
# $Id: template.cgi 7795 2015-01-08 08:24:04Z owes $
#
# TODO: explanation of how this stuff works
#
# Notes:
# ======
# Run updatemenu.pl on IPCop to rebuild the menu after GUI modifications.
# Make sure the .CGI file has proper mode and owner
#       chown root.root /home/httpd/cgi-bin/base.cgi
#       chmod 755 /home/httpd/cgi-bin/base.cgi
# Look at /var/log/httpd/error_log for troubleshoothing


# Add entry in menu
# MENUENTRY services 001 "GUI page" "great stuff"
#
# Make sure translation exists $Lang::tr{'GUI page'} $Lang::tr{'great stuff'}

use strict;

# to troubleshoot your code, uncomment use warnings and CGI::Carp 'fatalsToBrowser'
#use warnings;
no warnings 'once';
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/lang.pl';
require '/usr/lib/ipcop/header.pl';

# Language texts. This should be handled differently.
# TODO: further explanation
$Lang::tr{'GUI page'} = 'GUI page';
$Lang::tr{'great stuff'} = 'great stuff';

my %settings = ();

# Global settings
$settings{'NAME'}  = '';       # a text field whose content will be checked to be 'foo' or 'bar' later
$settings{'ITF'}   = '';       # an option field to select color interface
$settings{'TURBO'} = 'off';    # a checkbox field to enable something

# Error handling
my $errormessage = '';
my $warnmessage  = '';

&Header::showhttpheaders();

# Read needed IPCop settings (example)
my %mainsettings = ();
&General::readhash('/var/ipcop/main/settings', \%mainsettings);

# Get GUI values
&General::getcgihash(\%settings);

&Header::openpage($Lang::tr{'GUI page'}, 1, '');
&Header::openbigbox('100%', 'left', '');
my %checked = ();

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}

&Header::closebigbox();
&Header::closepage();
