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
# (c) 2004-2007 marco.s - http://www.urlfilter.net
# (c) 2011 The IPCop Team
#
# $Id: redirect.cgi 6296 2012-01-30 18:07:51Z dotzball $
#

use CGI qw(param);
use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';

my $http_port      = '81';
my %netsettings;
my %filtersettings;

&General::readhash("/var/ipcop/ethernet/settings", \%netsettings);
&General::readhash("/var/ipcop/proxy/filtersettings", \%filtersettings);

my $category=param("category");
my $url=param("url");
my $ip=param("ip");

my $msgtext1 = '';
my $msgtext2 = '';
my $msgtext3 = '';

if ($filtersettings{'MSG_TEXT_1'} eq '') {
    $msgtext1 = "ACCESS DENIED";
}
else {
    $msgtext1 = $filtersettings{'MSG_TEXT_1'};
}

if ($filtersettings{'MSG_TEXT_2'} eq '') {
    $msgtext2 = "Access to the requested page has been denied.";
}
else {
    $msgtext2 = $filtersettings{'MSG_TEXT_2'};
}

if ($filtersettings{'MSG_TEXT_3'} eq '') {
    $msgtext3 = "Please contact the Network Administrator if you think there has been an error.";
}
else {
    $msgtext3 = $filtersettings{'MSG_TEXT_3'};
}

if ( (!defined($category)) || $category eq '') {
    $category = '&nbsp;';
}
else {
    $category = '['.$category.']';
}

print "Pragma: no-cache\n";
print "Cache-control: no-cache\n";
print "Connection: close\n";
print "Content-type: text/html\n\n";

print <<END
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title></title>
</head>

END
;

my $image = '';
if ($filtersettings{'ENABLE_BG_IMAGE'} eq 'on') {
    $image = "background-image: url('http://$netsettings{'GREEN_1_ADDRESS'}:$http_port/images/";

    if (-e "/home/httpd/html/images/custom-redirect-background.png") {
         $image .= "custom-redirect-background.png";
    }
    else {
         $image .= "redirect-background.png";
    }
    $image .= "');";
}

print <<END
    <body style="$image background-color:#FFFFFF; font-family:verdana, arial, 'sans serif';">
END
;

print <<END
<div style="width:80%; margin:20px auto;">
    <div style="padding:5px; background-color:#C0C0C0; text-align:right; font-weight:bold; font-family:verdana,arial,'sans serif'; color:#000000; font-size:60%;">
        $category
    </div>
    <div style="background-color:#F4F4F4; text-align:center; padding:20px;">
    <div style="letter-spacing:0.5em; word-spacing:1em; padding:20px; background-color:#FF0000; text-align:center; color:#FFFFFF; font-size:200%; font-weight: bold;">
      $msgtext1
    </div>
    <div style="padding:20px; margin-top:20px; background-color:#E2E2E2; text-align:center; color:#000000; font-family:verdana, arial, 'sans serif'; font-size:80%;">
      <p style="font-weight:bold; font-size:150%;">$msgtext2</p>
END
;

if (defined($url) && (!($url eq "")))
{
    print <<END
          <p>URL: <a href="$url">$url</a></p>
END
    ;
}

if(defined($ip) && (!($ip eq "")))
{
    print <<END
          <p>Client IP address: <span style="font-style:italic;">$ip</span></p>
END
    ;
}

print <<END
      <p>$msgtext3</p>
    </div>
    </div>
    <div style="padding:5px; background-color:#C0C0C0; text-align:right; color:#FFFFFF; font-size:60%; font-family:verdana,arial,'sans serif';">
        Web Filtering by <a style="color:#FFFFFF;" href="http://www.ipcop.org"><b>IPCop</b></a> and
        <a style="color:#FFFFFF;" href="http://www.squidguard.org"><b>SquidGuard</b></a>
    </div>
</div>
</body>
</html>
END
;

