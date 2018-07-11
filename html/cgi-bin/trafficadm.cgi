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
# (c) 2008-2014, the IPCop team
#
# $Id: trafficadm.cgi 7240 2014-02-18 22:08:00Z owes $
#

use strict;

# enable only the following on debugging purpose
#use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ipcop/general-functions.pl';
require "/usr/lib/ipcop/lang.pl";
require "/usr/lib/ipcop/header.pl";
require "/usr/lib/ipcop/traffic-lib.pl";

my %cgiparams;
my $errormessage = '';
my $infomessage  = '';
my $saveerror    = 0;
my @days =
    (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
my @warnLevels = (50, 60, 70, 80, 90, 100);

#~ my @dummy = ($TRAFFIC::settingsfile);
#~ undef(@dummy);

&Header::showhttpheaders();

# Init parameters
$cgiparams{'ENABLED'}      = 'off';
$cgiparams{'DETAIL_LEVEL'} = 'Low';
$cgiparams{'SHOW_AT_HOME'} = 'off';
$cgiparams{'TRAFFIC_VIEW_REVERSE'} = 'off';
$cgiparams{'MONITOR_TRAFFIC_ENABLED'} = 'off';
$cgiparams{'PERIOD_TYPE'} = 'monthly';
$cgiparams{'STARTDAY'} = '1';
$cgiparams{'ROLLING_WINDOW'} = '30';
$cgiparams{'VOLUME_TOTAL_ENABLED'} = 'off';
$cgiparams{'VOLUME_TOTAL'} = '';
$cgiparams{'VOLUME_IN_ENABLED'} = 'off';
$cgiparams{'VOLUME_IN'} = '';
$cgiparams{'VOLUME_OUT_ENABLED'} = 'off';
$cgiparams{'VOLUME_OUT'} = '';
$cgiparams{'WARN_ENABLED'} = 'off';
$cgiparams{'WARN'} = '80';
$cgiparams{'CALC_INTERVAL'} = '60';
$cgiparams{'SEND_EMAIL_ENABLED'} = 'off';


&General::getcgihash(\%cgiparams);

if ($cgiparams{'ACTION'} eq $Lang::tr{'save'}) {
    &validSave();

    if ($errormessage) {
        $saveerror = 1;
    }
    else {    # no error, all right, save new settings
        &General::writehash($TRAFFIC::settingsfile, \%cgiparams);

        # set accouting iptables rules
        system("/usr/local/bin/accountingctrl");

        # calculate traffic
        #~  		`/usr/local/bin/monitorTraff --force < /dev/null > /dev/null 2>&1 &`;
    }
}    # end if ($cgiparams{'ACTION'} eq $Lang::tr{'save'})

# if user want to save settings and get a errormessage, we don´t
# overwrite users input
unless ($saveerror) {

    &TRAFFIC::readSettings();
    $cgiparams{'ENABLED'}      =  $TRAFFIC::settings{'ENABLED'};
    $cgiparams{'DETAIL_LEVEL'} = $TRAFFIC::settings{'DETAIL_LEVEL'};
    $cgiparams{'SHOW_AT_HOME'} = $TRAFFIC::settings{'SHOW_AT_HOME'};
    $cgiparams{'TRAFFIC_VIEW_REVERSE'} = $TRAFFIC::settings{'TRAFFIC_VIEW_REVERSE'};
    $cgiparams{'MONITOR_TRAFFIC_ENABLED'} = $TRAFFIC::settings{'MONITOR_TRAFFIC_ENABLED'};
    $cgiparams{'PERIOD_TYPE'} = $TRAFFIC::settings{'PERIOD_TYPE'};
    $cgiparams{'STARTDAY'} = $TRAFFIC::settings{'STARTDAY'};
    $cgiparams{'ROLLING_WINDOW'} = $TRAFFIC::settings{'ROLLING_WINDOW'};
    $cgiparams{'VOLUME_TOTAL_ENABLED'} = $TRAFFIC::settings{'VOLUME_TOTAL_ENABLED'};
    $cgiparams{'VOLUME_TOTAL'} = $TRAFFIC::settings{'VOLUME_TOTAL'};
    $cgiparams{'VOLUME_IN_ENABLED'} = $TRAFFIC::settings{'VOLUME_IN_ENABLED'};
    $cgiparams{'VOLUME_IN'} = $TRAFFIC::settings{'VOLUME_IN'};
    $cgiparams{'VOLUME_OUT_ENABLED'} = $TRAFFIC::settings{'VOLUME_OUT_ENABLED'};
    $cgiparams{'VOLUME_OUT'} = $TRAFFIC::settings{'VOLUME_OUT'};
    $cgiparams{'WARN_ENABLED'} = $TRAFFIC::settings{'WARN_ENABLED'};
    $cgiparams{'WARN'} = $TRAFFIC::settings{'WARN'};
    $cgiparams{'CALC_INTERVAL'} = $TRAFFIC::settings{'CALC_INTERVAL'};
    $cgiparams{'SEND_EMAIL_ENABLED'} = $TRAFFIC::settings{'SEND_EMAIL_ENABLED'};

}    # end unless ($saveerror)

#~ if ($cgiparams{'ACTION'} eq $Lang::tr{'send test mail'})
#~ {
#~ 	# send test email
#~ 	my $return = `/usr/local/bin/monitorTraff --testEmail`;

#~ 	if($return =~ /Email was sent successfully!/)
#~ 	{
#~ 		$infomessage = "$Lang::tr{'test email was sent'}<br/>";
#~ 	}
#~ 	else
#~ 	{
#~ 		$errormessage = "$Lang::tr{'test email could not be sent'}:<br/>";
#~ 		$errormessage .= "$return <br />";
#~ 	}

#~ } # end if ($cgiparams{'ACTION'} eq $Lang::tr{'send test mail'})

my %selected;

$selected{'DETAIL_LEVEL'}{'Low'}                      = '';
$selected{'DETAIL_LEVEL'}{'High'}                     = '';
$selected{'DETAIL_LEVEL'}{$cgiparams{'DETAIL_LEVEL'}} = "selected='selected'";

$selected{'CALC_INTERVAL'}{'5'} = '';
$selected{'CALC_INTERVAL'}{'10'} = '';
$selected{'CALC_INTERVAL'}{'15'} = '';
$selected{'CALC_INTERVAL'}{'30'} = '';
$selected{'CALC_INTERVAL'}{'60'} = '';
$selected{'CALC_INTERVAL'}{$cgiparams{'CALC_INTERVAL'}} = "selected='selected'";

my %checked;
$checked{'ENABLED'}{'off'}                 = '';
$checked{'ENABLED'}{'on'}                  = '';
$checked{'ENABLED'}{$cgiparams{'ENABLED'}} = "checked='checked'";

$checked{'SHOW_AT_HOME'}{'off'}                      = '';
$checked{'SHOW_AT_HOME'}{'on'}                       = '';
$checked{'SHOW_AT_HOME'}{$cgiparams{'SHOW_AT_HOME'}} = "checked='checked'";

$checked{'TRAFFIC_VIEW_REVERSE'}{'off'}                      = '';
$checked{'TRAFFIC_VIEW_REVERSE'}{'on'}                       = '';
$checked{'TRAFFIC_VIEW_REVERSE'}{$cgiparams{'TRAFFIC_VIEW_REVERSE'}} = "checked='checked'";

$checked{'MONITOR_TRAFFIC_ENABLED'}{'off'} = '';
$checked{'MONITOR_TRAFFIC_ENABLED'}{'on'} = '';
$checked{'MONITOR_TRAFFIC_ENABLED'}{$cgiparams{'MONITOR_TRAFFIC_ENABLED'}} = "checked='checked'";

$checked{'VOLUME_TOTAL_ENABLED'}{'off'} = '';
$checked{'VOLUME_TOTAL_ENABLED'}{'on'} = '';
$checked{'VOLUME_TOTAL_ENABLED'}{$cgiparams{'VOLUME_TOTAL_ENABLED'}} = "checked='checked'";

$checked{'VOLUME_IN_ENABLED'}{'off'} = '';
$checked{'VOLUME_IN_ENABLED'}{'on'} = '';
$checked{'VOLUME_IN_ENABLED'}{$cgiparams{'VOLUME_IN_ENABLED'}} = "checked='checked'";

$checked{'VOLUME_OUT_ENABLED'}{'off'} = '';
$checked{'VOLUME_OUT_ENABLED'}{'on'} = '';
$checked{'VOLUME_OUT_ENABLED'}{$cgiparams{'VOLUME_OUT_ENABLED'}} = "checked='checked'";

$checked{'WARN_ENABLED'}{'off'} = '';
$checked{'WARN_ENABLED'}{'on'} = '';
$checked{'WARN_ENABLED'}{$cgiparams{'WARN_ENABLED'}} = "checked='checked'";

$checked{'SEND_EMAIL_ENABLED'}{'off'} = '';
$checked{'SEND_EMAIL_ENABLED'}{'on'} = '';
$checked{'SEND_EMAIL_ENABLED'}{$cgiparams{'SEND_EMAIL_ENABLED'}} = "checked='checked'" ;

my %radio;
$radio{'PERIOD_TYPE'}{'monthly'}                   = '';
$radio{'PERIOD_TYPE'}{'rollingWindow'}                  = '';
$radio{'PERIOD_TYPE'}{$cgiparams{'PERIOD_TYPE'}} = "checked='checked'";

#~ my $btnTestmailDisabled = "";

#~ $btnTestmailDisabled = "disabled='disabled'" if($cgiparams{'SEND_EMAIL_ENABLED'} ne 'on');

&Header::openpage($Lang::tr{'traffic monitor'}, 1, '');
&Header::openbigbox('100%', 'left');

###############
# DEBUG DEBUG
if ($TRAFFIC::debugFormparams == 1) {
    &Header::openbox('100%', 'left', 'DEBUG');
    my $debugCount = 0;
    foreach my $line (sort keys %cgiparams) {
        print "$line = $cgiparams{$line}<br />\n";
        $debugCount++;
    }
    print "&nbsp;Count: $debugCount\n";
    &Header::closebox();
}

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}

if ($infomessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'traffic info messages'}:");
    print "<font class='base'>$infomessage&nbsp;</font>";
    &Header::closebox();
}

&Header::openbox('100%', 'left', "$Lang::tr{'traffic configuration'}:");

print <<END;
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td colspan='2'>$Lang::tr{'traffic accounting enabled'}:</td>
    <td><input type="checkbox" name="ENABLED" $checked{'ENABLED'}{'on'} /></td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2'>$Lang::tr{'detail level'}:</td>
    <td>
        <select name='DETAIL_LEVEL'>
            <option value='Low' $selected{'DETAIL_LEVEL'}{'Low'}>$Lang::tr{'low'}</option>
            <option value='High' $selected{'DETAIL_LEVEL'}{'High'} disabled='disabled'>$Lang::tr{'high'}</option>
        </select>
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2'>$Lang::tr{'display traffic at home'}:</td>
    <td><input type="checkbox" name="SHOW_AT_HOME" $checked{'SHOW_AT_HOME'}{'on'} />
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2'>$Lang::tr{'reverse sort'}:</td>
    <td><input type="checkbox" name="TRAFFIC_VIEW_REVERSE" $checked{'TRAFFIC_VIEW_REVERSE'}{'on'} />
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td colspan='5'><hr /></td>
</tr>
<tr>
    <td align='left' class='base' colspan='2'>
        $Lang::tr{'monitor traffic volume'}
    </td>
    <td align='left' class='base' >
        <input type="checkbox" name="MONITOR_TRAFFIC_ENABLED" $checked{'MONITOR_TRAFFIC_ENABLED'}{'on'} />
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td align='left' class='base' width='1%'>
        <input type='radio' name='PERIOD_TYPE' value='monthly' $radio{'PERIOD_TYPE'}{'monthly'} />
    </td>
    <td align='left' class='base'  width='24%'>
        $Lang::tr{'monthly base'}
    </td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr>
<tr>
    <td align='left' class='base' ></td>
    <td align='left' class='base' nowrap='nowrap' >
        $Lang::tr{'monthly volume start day'}: &nbsp;
    </td>
    <td align='left' class='base' >
        <select name='STARTDAY'>
END

foreach my $day (@days) {
    print "            <option ";
    if ($day == $cgiparams{'STARTDAY'}) {
        print 'selected=\'selected\' ';
    }
    print "value='$day'>$day</option>\n";
}
print <<END;
        </select>
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td align='left' class='base'>
        <input type='radio' name='PERIOD_TYPE' value='rollingWindow' $radio{'PERIOD_TYPE'}{'rollingWindow'} />
    </td>
    <td align='left' class='base'>
        $Lang::tr{'rolling window'}
    </td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
    <td width='25%'>&nbsp;</td>
</tr>
<tr>
    <td align='left' class='base' ></td>
    <td align='left' class='base' nowrap='nowrap' >
        $Lang::tr{'rolling window days'}: &nbsp;
    </td>
    <td align='left' class='base' >
        <select name='ROLLING_WINDOW'>
END

foreach my $day (@days) {
    print "            <option ";
    if ($day == $cgiparams{'ROLLING_WINDOW'}) {
        print 'selected=\'selected\' ';
    }
    print "value='$day'>$day</option>\n";
}
print <<END;
        </select>
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>


<tr>
    <td align='left' class='base'>
        <input type="checkbox" name="VOLUME_TOTAL_ENABLED" $checked{'VOLUME_TOTAL_ENABLED'}{'on'} />&nbsp;
    </td>
    <td align='left' class='base'>
        $Lang::tr{'monitor volume'} ($Lang::tr{'trafficsum'} MByte): &nbsp;
    </td>
    <td align='left' class='base' >
        <input type='text' name='VOLUME_TOTAL' value='$cgiparams{'VOLUME_TOTAL'}' size='20' maxlength='17' />
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td align='left' class='base'>
        <input type="checkbox" name="VOLUME_IN_ENABLED" $checked{'VOLUME_IN_ENABLED'}{'on'} />&nbsp;
    </td>
    <td align='left' class='base'>
        $Lang::tr{'monitor volume'} ($Lang::tr{'trafficin'} MByte): &nbsp;
    </td>
    <td align='left' class='base' >
        <input type='text' name='VOLUME_IN' value='$cgiparams{'VOLUME_IN'}' size='20' maxlength='17' />
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td align='left' class='base'>
        <input type="checkbox" name="VOLUME_OUT_ENABLED" $checked{'VOLUME_OUT_ENABLED'}{'on'} />&nbsp;
    </td>
    <td align='left' class='base'>
        $Lang::tr{'monitor volume'} ($Lang::tr{'trafficout'} MByte): &nbsp;
    </td>
    <td align='left' class='base' >
        <input type='text' name='VOLUME_OUT' value='$cgiparams{'VOLUME_OUT'}' size='20' maxlength='17' />
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td align='left' class='base'>
        <input type="checkbox" name="WARN_ENABLED" $checked{'WARN_ENABLED'}{'on'} />&nbsp;
    </td>
    <td align='left' class='base' nowrap='nowrap'>
        $Lang::tr{'warn when traffic reaches'}: &nbsp;
    </td>
    <td align='left' class='base'>
        <select name='WARN'>
END

foreach my $level (@warnLevels) {
    print "            <option ";
    if ($level == $cgiparams{'WARN'}) {
        print 'selected=\'selected\' ';
    }
    print "value='$level'>$level</option>\n";
}
print <<END;
        </select>
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td>&nbsp;</td>
    <td align='left' class='base' nowrap='nowrap' >
        $Lang::tr{'send email notification'}:
    </td>
    <td align='left' class='base'>
        <input type="checkbox" name="SEND_EMAIL_ENABLED" $checked{'SEND_EMAIL_ENABLED'}{'on'} />&nbsp;
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td align='left' class='base' nowrap='nowrap' colspan='2'>
        $Lang::tr{'calc traffic all x minutes'}: &nbsp;
    </td>
    <td align='left' class='base' >
        <select name='CALC_INTERVAL'>
            <option value='5'   $selected{'CALC_INTERVAL'}{'5'} > 5</option>
            <option value='10'  $selected{'CALC_INTERVAL'}{'10'}>10</option>
            <option value='15'  $selected{'CALC_INTERVAL'}{'15'}>15</option>
            <option value='30'  $selected{'CALC_INTERVAL'}{'30'}>30</option>
            <option value='60'  $selected{'CALC_INTERVAL'}{'60'}>60</option>
        </select>
    </td>
    <td colspan='2'>&nbsp;</td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment2buttons'>
    <!--
        <img src='/blob.gif' alt ='*' align='top' />&nbsp;$Lang::tr{'this field may be blank'}
     --></td>
    <td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='button2buttons'>
END

# if user input cause an error
# and user want a reset, we re-read settings from settingsfile
if ($errormessage ne '') {
    print "<input type='submit' name='ACTION' value='$Lang::tr{'reset'}' />";
}
else {
    print "<input type='reset' name='ACTION' value='$Lang::tr{'reset'}' />";
}

print <<END;
    </td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/status-traffic-accounting.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/traffic.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END

&Header::closebox();
&Header::closebigbox();
&Header::closepage();

sub validSave
{
    if ($cgiparams{'SHOW_AT_HOME'} ne 'on') {
        $cgiparams{'SHOW_AT_HOME'} = 'off';
    }

    unless ($cgiparams{'DETAIL_LEVEL'} =~ /^Low|High$/) {
        $errormessage = $Lang::tr{'invalid input'};
    }

    if ($cgiparams{'MONITOR_TRAFFIC_ENABLED'} ne 'on' ) {
        $cgiparams{'MONITOR_TRAFFIC_ENABLED'} = 'off';
    }

    if($cgiparams{'MONITOR_TRAFFIC_ENABLED'} eq 'on')
    {
        if($cgiparams{'PERIOD_TYPE'} !~ /^(monthly|rollingWindow)$/) {
            $errormessage .= "$Lang::tr{'monitor period bad'}<br/>";
        }

        if($cgiparams{'STARTDAY'} < 1 || 31 < $cgiparams{'STARTDAY'}) {
            $errormessage .= "$Lang::tr{'monthly start day bad'}<br/>";
        }

        if($cgiparams{'STARTDAY'} < 1 || 31 < $cgiparams{'STARTDAY'}) {
            $errormessage .= "$Lang::tr{'rolling window bad'}<br/>";
        }

        my $monitorCount = 0;

        if($cgiparams{'VOLUME_TOTAL_ENABLED'} eq 'on')
        {
            $monitorCount++;

            if($cgiparams{'VOLUME_TOTAL'} !~ /^\d+$/ || $cgiparams{'VOLUME_TOTAL'} < 1) {
                $errormessage .= "$Lang::tr{'monitor volume bad'}<br/>";
            }
        }
        if($cgiparams{'VOLUME_IN_ENABLED'} eq 'on')
        {
            $monitorCount++;

            if($cgiparams{'VOLUME_IN'} !~ /^\d+$/ || $cgiparams{'VOLUME_IN'} < 1) {
                $errormessage .= "$Lang::tr{'monitor volume bad'}<br/>";
            }
        }
        if($cgiparams{'VOLUME_OUT_ENABLED'} eq 'on')
        {
            $monitorCount++;

            if($cgiparams{'VOLUME_OUT'} !~ /^\d+$/ || $cgiparams{'VOLUME_OUT'} < 1) {
                $errormessage .= "$Lang::tr{'monitor volume bad'}<br/>";
            }
        }

        if($monitorCount == 0)
        {
             $errormessage .= "$Lang::tr{'at least monitor one volume'}<br/>";
        }


        if ($cgiparams{'WARN_ENABLED'} ne 'on' ) {
            $cgiparams{'WARN_ENABLED'} = 'off';
        }

        if($cgiparams{'WARN_ENABLED'} eq 'on' && $cgiparams{'WARN'} !~ /^\d+$/) {
            $errormessage .= "$Lang::tr{'traffic warn level bad'}<br/>";
        }

        if($cgiparams{'CALC_INTERVAL'} < 5 || 60 < $cgiparams{'CALC_INTERVAL'}) {
            $errormessage .= "$Lang::tr{'traffic calc time bad'}<br/>";
        }

        if ($cgiparams{'SEND_EMAIL_ENABLED'} ne 'on' ) {
            $cgiparams{'SEND_EMAIL_ENABLED'} = 'off';
        }

    } # monthly volumne == on

}
