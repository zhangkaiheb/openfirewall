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
# (c) 2018-2019 The Openfirewall Team
#
#

# Add entry in menu
# MENUENTRY services 040 "dynamic dns" "dynamic dns client"
#
# Make sure translation exists $Lang::tr{'dynamic dns client'}

use strict;

# enable only the following on debugging purpose
#use warnings; no warnings 'once';# 'redefine', 'uninitialized';
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/ddns-lib.pl';

my $addhost = 0;

# Files used
our $datafile = '/var/ofw/ddns/config';
my $logDirName = '/var/log/dyndns';

my %settings = ();
$settings{'HOSTNAME'}  = '';
$settings{'DOMAIN'}    = '';
$settings{'LOGIN'}     = '';
$settings{'PASSWORD'}  = '';
$settings{'ENABLED'}   = '';
$settings{'PROXY'}     = '';
$settings{'WILDCARDS'} = '';
$settings{'SERVICE'}   = 'freedns.afraid.org';

$settings{'ACTION'} = '';    # add/edit/remove
$settings{'KEY'}    = '';
$settings{'FIELD'}  = '';

my $errormessage = '';
my $error        = '';


&Header::showhttpheaders();

#Get GUI values
&General::getcgihash(\%settings);
my $key_id = $settings{'KEY'};
my $key_field = $settings{'FIELD'};


#
# Save global settings
#
if ($settings{'ACTION'} eq $Lang::tr{'save'}) {
    # No user input to check as we only have a radiobutton and a checkbox
    my %tmpsettings = ();
    $tmpsettings{'BEHINDROUTER'}    = $settings{'BEHINDROUTER'};
    $tmpsettings{'MINIMIZEUPDATES'} = $settings{'MINIMIZEUPDATES'};
    &DDNS::writeSettings(\%tmpsettings);

    # $logDirName/fetchIpState file is not writable from webgui,
    # but if I change the settings I would do a [Force Update] anyway.
    # So don't init the fetchIpState file, if it is already there, it will be re-written
    # in next 5-15 minutes.
}

# Toggle enable/disable FIELD.
if ($settings{'ACTION'} eq $Lang::tr{'toggle enable disable'}) {
    $DDNS::hosts[$key_id]{$key_field} = ($DDNS::hosts[$key_id]{$key_field} eq 'on') ? 'off' : 'on';
    &General::log($Lang::tr{'ddns hostname modified'});
    &DDNS::writeHosts;

    $settings{'KEY'} = '';
}

# Delete a DDNS host
if ($settings{'ACTION'} eq $Lang::tr{'remove'}) {
    splice(@DDNS::hosts, $key_id, 1);
    &General::log($Lang::tr{'ddns hostname removed'});
    &DDNS::writeHosts;

    $settings{'KEY'} = '';
}

# Want to add a DDNS host, set our 'add' flag. Service is selected in settings{'SERVICE'} and passed along
if ($settings{'ACTION'} eq 'ADD_HOST') {
    $addhost = 1;
}

# Add/Update, validate input and write host list in case everything OK
if ($settings{'ACTION'} eq $Lang::tr{'add'}) {        # Validate inputs

    # list box returns 'service optional synonyms'
    # keep only first name
    $settings{'SERVICE'} =~ s/ .*$//;

    # check HOSTNAME field
    $errormessage = $Lang::tr{'hostname not set'}
        if ($DDNS::va{$settings{'SERVICE'}}{HOSTNAME} && $settings{'HOSTNAME'} eq '');
    unless ($settings{'HOSTNAME'} =~ /^(|[a-zA-Z_;0-9-]+)$/) {
        $errormessage .= '<br />' . $Lang::tr{'invalid hostname'};
    }

    # check DOMAIN field; must contain at least one point followed by letters (.com => ok; com. => bad)
    $errormessage .= '<br />' . $Lang::tr{'domain not set'}
        if ($DDNS::va{$settings{'SERVICE'}}{DOMAIN} && $settings{'DOMAIN'} eq '');
    unless ($settings{'DOMAIN'} =~ /^(|[a-zA-Z_0-9.-]*\.[a-zA-Z_0-9.-]+)$/) {
        $errormessage .= '<br />' . $Lang::tr{'invalid domain name'};
    }

    # check LOGIN field
    $errormessage .= '<br />' . $Lang::tr{'username not set'}
        if ($DDNS::va{$settings{'SERVICE'}}{LOGIN} && $settings{'LOGIN'} eq '');

    # check PASSWORD field
    $errormessage .= '<br />' . $Lang::tr{'password not set'}
        if ($DDNS::va{$settings{'SERVICE'}}{PASSWORD} && $settings{'PASSWORD'} eq '');

    # PASSWORD cannot contain a comma, it breaks the csv config file.
    $errormessage .= '<br />' . $Lang::tr{'password contains illegal characters'} . ': [,]'
        if ($settings{'PASSWORD'} =~ /,/);

    if ($errormessage) {
        # Error, re-display the box with add fields
        $addhost = 1;
    }
    else {
        if ($settings{'KEY'} eq '') {
            # Add
            push @DDNS::hosts, { ENABLED => $settings{'ENABLED'},
                SERVICE => $settings{'SERVICE'}, HOSTNAME => $settings{'HOSTNAME'}, DOMAIN => $settings{'DOMAIN'},
                PROXY => $settings{'PROXY'}, WILDCARDS => $settings{'WILDCARDS'},
                LOGIN => $settings{'LOGIN'}, PASSWORD => $settings{'PASSWORD'}};

            &General::log($Lang::tr{'ddns hostname added'});
        }
        else {
            $DDNS::hosts[$key_id]{'SERVICE'}   = $settings{'SERVICE'};
            $DDNS::hosts[$key_id]{'HOSTNAME'}  = $settings{'HOSTNAME'};
            $DDNS::hosts[$key_id]{'DOMAIN'}    = $settings{'DOMAIN'};
            $DDNS::hosts[$key_id]{'PROXY'}     = $settings{'PROXY'};
            $DDNS::hosts[$key_id]{'WILDCARDS'} = $settings{'WILDCARDS'};
            $DDNS::hosts[$key_id]{'LOGIN'}     = $settings{'LOGIN'};
            $DDNS::hosts[$key_id]{'PASSWORD'}  = $settings{'PASSWORD'};
            $DDNS::hosts[$key_id]{'ENABLED'}   = $settings{'ENABLED'};

            &General::log($Lang::tr{'ddns hostname modified'});
            $settings{'KEY'} = '';    # End edit mode
        }
        &DDNS::writeHosts;
    }
}

if ($settings{'ACTION'} eq $Lang::tr{'edit'}) {
    $addhost = 1;

    $settings{'SERVICE'}   = $DDNS::hosts[$key_id]{'SERVICE'};
    $settings{'HOSTNAME'}  = $DDNS::hosts[$key_id]{'HOSTNAME'};
    $settings{'DOMAIN'}    = $DDNS::hosts[$key_id]{'DOMAIN'};
    $settings{'PROXY'}     = $DDNS::hosts[$key_id]{'PROXY'};
    $settings{'WILDCARDS'} = $DDNS::hosts[$key_id]{'WILDCARDS'};
    $settings{'LOGIN'}     = $DDNS::hosts[$key_id]{'LOGIN'};
    $settings{'PASSWORD'}  = $DDNS::hosts[$key_id]{'PASSWORD'};
    $settings{'ENABLED'}   = $DDNS::hosts[$key_id]{'ENABLED'};
}

if ($settings{'ACTION'} eq $Lang::tr{'instant update'}) {
    system('/usr/local/bin/setddns.pl', '--force');
}


&Header::openpage($Lang::tr{'dynamic dns'}, 1, '');
&Header::openbigbox('100%', 'left', '');

my %checked = ();    # Checkbox manipulations
$checked{'BEHINDROUTER'}{'RED_IP'}   = '';
$checked{'BEHINDROUTER'}{'FETCH_IP'} = '';
$checked{'BEHINDROUTER'}{$DDNS::settings{'BEHINDROUTER'}} = "checked='checked'";
$checked{'MINIMIZEUPDATES'} = ($DDNS::settings{'MINIMIZEUPDATES'} eq '') ? '' : "checked='checked'";

if ($settings{'ACTION'} eq 'ADD_HOST') {
    $settings{'ENABLED'} = 'on';    # Enable as default on first run only.
}
$checked{'ENABLED'}{'on'}   = ($settings{'ENABLED'}   ne 'on') ? '' : "checked='checked'";
$checked{'WILDCARDS'}{'on'} = ($settings{'WILDCARDS'} ne 'on') ? '' : "checked='checked'";

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='bold'>$errormessage&nbsp;</font>";
    &Header::closebox();

    $error = 'error';
}


#
# Config box, do not display if we add DDNS host
#
if (! $addhost) {
    &Header::openbox('100%', 'left', $Lang::tr{'settings'});
    print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>";
    print <<END
<table width='100%'>
<tr>
    <td class='base'>$Lang::tr{'dyn dns source choice'}:</td>
</tr><tr>
    <td class='base'><input type='radio' name='BEHINDROUTER' value='RED_IP' $checked{'BEHINDROUTER'}{'RED_IP'} />
    $Lang::tr{'use openfirewall red ip'}</td>
</tr><tr>
    <td class='base'><input type='radio' name='BEHINDROUTER' value='FETCH_IP' $checked{'BEHINDROUTER'}{'FETCH_IP'} />
    $Lang::tr{'fetch ip from'} <img src='/blob.gif' alt='*' /></td>
</tr><tr>
    <td class='base'><input type='checkbox' name='MINIMIZEUPDATES' $checked{'MINIMIZEUPDATES'} />
    $Lang::tr{'ddns minimize updates'}</td>
</tr>
</table>
<br /><hr />
END
    ;

    print <<END
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'avoid dod'}</td>
    <td class='button1button'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-dyndns.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END
    ;
    &Header::closebox();    # end of Settings1
}


my $buttontext = $Lang::tr{'add'};
if ($settings{'KEY'} ne '') {
    $buttontext = $Lang::tr{'update'};
    &Header::openbox('100%', 'left', $Lang::tr{'edit an existing ddns name'}, $error);
}
else {
    &Header::openbox('100%', 'left', "$Lang::tr{'add a ddns name'}:", $error);
}

# Build indicators for the optional fields
my $fhostname = $DDNS::va{$settings{'SERVICE'}}{'HOSTNAME'} ? '' : "&nbsp;<img src='/blob.gif' alt='*' />";
my $fdomain   = $DDNS::va{$settings{'SERVICE'}}{'DOMAIN'}   ? '' : "&nbsp;<img src='/blob.gif' alt='*' />";
my $flogin    = $DDNS::va{$settings{'SERVICE'}}{'LOGIN'}    ? '' : "&nbsp;<img src='/blob.gif' alt='*' />";
my $fpassword = $DDNS::va{$settings{'SERVICE'}}{'PASSWORD'} ? '' : "&nbsp;<img src='/blob.gif' alt='*' />";

my $fblobhelp = '';
if ($fhostname || $fdomain || $flogin || $fpassword) {
    $fblobhelp .= "<img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}";
}

# Additional help text
my $fhelp = '';
if ($DDNS::va{$settings{'SERVICE'}}{'HELP'} ne '') {
    $fhelp .= "<tr><td class='comment1button'>$DDNS::va{$settings{'SERVICE'}}{'HELP'}</td>";
    $fhelp .= "<td colspan='2'>&nbsp;</td></tr>";
}

# Build the listbox with service names
my $listboxcontent = '';
if ($addhost) {
    $listboxcontent = "<input type='hidden' name='SERVICE' value='$settings{'SERVICE'}' />";
    $listboxcontent .= "<b>$settings{'SERVICE'}</b>";
}
else {
    $listboxcontent = "<select size='1' name='SERVICE'>";
    foreach my $key (sort keys %DDNS::va) {
        $listboxcontent .= '<option ' . ($settings{'SERVICE'} eq $key ? "selected='selected'>" : '>');
        $listboxcontent .= $DDNS::va{$key}{'LBNAME'} ? $DDNS::va{$key}{'LBNAME'} : $key;
        $listboxcontent .= '</option>';
    }
    $listboxcontent .= '</select>';
}

if ($addhost) {
    print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='KEY' value='$settings{'KEY'}' />
<table width='100%' border='0'>
<tr>
    <td width='25%' class='base'>$Lang::tr{'service'}:</td>
    <td colspan='3'>$listboxcontent</td>
</tr><tr>
    <td colspan='4'>&nbsp;</td>
</tr><tr>
    <td class='base' width='25%'>$Lang::tr{'enabled'}:</td>
    <td width='25%'><input type='checkbox' name='ENABLED' value='on' $checked{'ENABLED'}{'on'} /></td>
    <td class='base' width='25%'>$Lang::tr{'enable wildcards'}:</td>
    <td width='25%'><input type='checkbox' name='WILDCARDS' value='on' $checked{'WILDCARDS'}{'on'} /></td>
</tr><tr>
    <td>$Lang::tr{'hostname'}:$fhostname</td>
    <td><input type='text' name='HOSTNAME' value='$settings{'HOSTNAME'}' /></td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'domain'}:$fdomain</td>
    <td><input type='text' name='DOMAIN' value='$settings{'DOMAIN'}' /></td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'username'}:$flogin</td>
    <td><input type='text' name='LOGIN' value='$settings{'LOGIN'}' /></td>
    <td colspan='2'>&nbsp;</td>
</tr><tr>
    <td>$Lang::tr{'password'}:$fpassword</td>
    <td><input type='password' name='PASSWORD' value='$settings{'PASSWORD'}' /></td>
    <td colspan='2'>&nbsp;</td>
</tr>
</table>
<hr />
<table width='100%'>
$fhelp
<tr>
    <td class='comment1button'>$fblobhelp</td>
    <td class='button1button'>
    <input type='hidden' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' />
    <input type='submit' class='commonbuttons' name='SUBMIT' value='$buttontext' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-dyndns.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END
    ;
}
else {
    print <<END
<form method='post' name='frm_add' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='25%'>$Lang::tr{'service'}:</td>
    <td>$listboxcontent</td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'>
        <input type='hidden' name='ACTION' class='commonbuttons'  value='ADD_HOST' />
        <input type='submit' name='SUBMIT' class='commonbuttons' value='$Lang::tr{'add'}' />
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-dyndns.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END
    ;
}
&Header::closebox();

#
# Third box shows the list, in columns
#
&Header::openbox('100%', 'left', "$Lang::tr{'current ddns names'}:");

print <<END
<table width='100%'>
<tr>
    <td width='20%' align='center' class='boldbase'>$Lang::tr{'service'}</td>
    <td width='30%' align='center' class='boldbase'>$Lang::tr{'hostname'}</td>
    <td width='30%' align='center' class='boldbase'>$Lang::tr{'domain'}</td>
    <td width='10%' align='center' class='boldbase'>$Lang::tr{'wildcards'}</td>
    <td width='10%' colspan='3' class='boldbase' align='center'>$Lang::tr{'action'}</td>
</tr>
END
    ;
my $ip  = &General::GetDyndnsRedIP;
my $key = 0;

for my $id (0 .. $#DDNS::hosts) {

    # Choose icon for checkbox
    my $gifwildcard  = '';
    my $descwildcard = '';
    if ($DDNS::hosts[$id]{'WILDCARDS'} eq "on") {
        $gifwildcard  = 'on.gif';
        $descwildcard = $Lang::tr{'click to disable'};
    }
    else {
        $gifwildcard  = 'off.gif';
        $descwildcard = $Lang::tr{'click to enable'};
    }

    my $sync  = "blue";
    my $gif   = '';
    my $gdesc = '';
    if ($DDNS::hosts[$id]{'ENABLED'} eq "on") {
        $gif   = 'on.gif';
        $gdesc = $Lang::tr{'click to disable'};
        my $ipCacheFile = "$logDirName/$DDNS::hosts[$id]{'SERVICE'}.$DDNS::hosts[$id]{'HOSTNAME'}.$DDNS::hosts[$id]{'DOMAIN'}";
        $sync = (-e $ipCacheFile && ($ip eq `cat $ipCacheFile`) ? "green" : "red");
    }
    else {
        $gif   = 'off.gif';
        $gdesc = $Lang::tr{'click to enable'};
    }

    # Colorize each line
    if ($settings{'KEY'} eq $id) {
        print "<tr class='selectcolour'>";
    }
    else {
        print "<tr class='table".int(($id % 2) + 1)."colour'>";
    }

    # If a field is empty, replace it with a '---' to see colorized info!
    $DDNS::hosts[$id]{'HOSTNAME'} = '---' if ($DDNS::hosts[$id]{'HOSTNAME'} eq '');
    $DDNS::hosts[$id]{'DOMAIN'} = '---' if ($DDNS::hosts[$id]{'DOMAIN'} eq '');

    print <<END
<td align='center'><a href='http://$DDNS::hosts[$id]{'SERVICE'}' target='_blank'>$DDNS::hosts[$id]{'SERVICE'}</a></td>
<td align='center'><font color='$sync'>$DDNS::hosts[$id]{'HOSTNAME'}</font></td>
<td align='center'><font color='$sync'>$DDNS::hosts[$id]{'DOMAIN'}</font></td>

<td align='center'>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
<input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gifwildcard' alt='$descwildcard' title='$descwildcard' />
<input type='hidden' name='KEY' value='$id' />
<input type='hidden' name='FIELD' value='WILDCARDS' />
</form>
</td>

<td align='center'>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
<input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' alt='$gdesc' title='$gdesc' />
<input type='hidden' name='KEY' value='$id' />
<input type='hidden' name='FIELD' value='ENABLED' />
</form>
</td>

<td align='center'>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
<input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
<input type='hidden' name='KEY' value='$id' />
</form>
</td>

<td align='center'>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
<input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
<input type='hidden' name='KEY' value='$id' />
</form>
</td>
</tr>
END
        ;
    $key++;
}
print "</table>";

# If table contains entries, print 'Key to action icons'
if ($key) {
    print <<END
<table width='100%'>
<tr>
    <td class='boldbase'>&nbsp;<b>$Lang::tr{'legend'}:&nbsp;</b></td>
    <td><img src='/images/on.gif' alt='$Lang::tr{'click to disable'}' /></td>
    <td class='base'>$Lang::tr{'click to disable'}</td>
    <td>&nbsp;&nbsp;</td>
    <td><img src='/images/off.gif' alt='$Lang::tr{'click to enable'}' /></td>
    <td class='base'>$Lang::tr{'click to enable'}</td>
    <td>&nbsp;&nbsp;</td>
    <td><img src='/images/edit.gif' alt='$Lang::tr{'edit'}' /></td>
    <td class='base'>$Lang::tr{'edit'}</td>
    <td>&nbsp;&nbsp;</td>
    <td><img src='/images/delete.gif' alt='$Lang::tr{'remove'}' /></td>
    <td class='base'>$Lang::tr{'remove'}</td>
    <td align='center' width='30%'>
        <form method='post' action='$ENV{'SCRIPT_NAME'}'><input type='submit' name='ACTION' value='$Lang::tr{'instant update'}' /></form>
    </td>
</tr>
</table>
END
    ;
}

&Header::closebox();
&Header::closebigbox();
&Header::closepage();
