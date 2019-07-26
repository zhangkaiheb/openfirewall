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

# Add entry in menu
# MENUTHRDLVL "dns service" 010 "edit hosts" "host configuration"
#
# Make sure translation exists $Lang::tr{'edit hosts'} $Lang::tr{'host configuration'}

use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

# Files used
my $settingsfilename = '/var/ofw/main/settings';
our $datafile = '/var/ofw/main/hosts';    #(our: used in subroutine)

our %settings = ();

#Settings1
# removed

#Settings2 for editing the multi-line list
#Must not be saved !
$settings{'EN'}   = '';                       # reuse for dummy field in position zero
$settings{'IP'}   = '';
$settings{'HOST'} = '';
$settings{'DOM'}  = '';
my @nosaved = ('EN', 'IP', 'HOST', 'DOM');    # List here ALL setting2 fields. Mandatory

$settings{'ACTION'} = '';                     # add/edit/remove
$settings{'KEY1'}   = '';                     # point record for ACTION

#Define each field that can be used to sort columns
my $sortstring = '^IP|^HOST|^DOM';
$settings{'SORT_HOSTSLIST'} = 'HOST';
my $errormessage = '';
my $warnmessage  = '';

&Header::showhttpheaders();

#Get GUI values
&General::getcgihash(\%settings);

# Load multiline data
our @current = ();
if (open(FILE, "$datafile")) {
    @current = <FILE>;
    close(FILE);
}

&General::readhash($settingsfilename, \%settings);

## Now manipulate the multi-line list with Settings2
# Basic actions are:
#       toggle the check box
#       add/update a new line
#       begin editing a line
#       remove a line

# Toggle enable/disable field.  Field is in second position
if ($settings{'ACTION'} eq $Lang::tr{'toggle enable disable'}) {

    #move out new line
    chomp(@current[ $settings{'KEY1'} ]);
    my @temp = split(/\,/, @current[ $settings{'KEY1'} ]);

    $temp[0] = $temp[0] ne '' ? '' : 'on';    # Toggle the field
    @current[ $settings{'KEY1'} ] = join(',', @temp) . "\n";
    $settings{'KEY1'} = '';                   # End edit mode

    &General::log($Lang::tr{'hosts config changed'});

    #Save current
    open(FILE, ">$datafile") or die 'hosts datafile error';
    print FILE @current;
    close(FILE);

    # Rebuild configuration file
    &BuildConfiguration;
}

if ($settings{'ACTION'} eq $Lang::tr{'add'}) {

    # Validate inputs
    unless (&General::validip($settings{'IP'})) {
        $errormessage = $Lang::tr{'invalid fixed ip address'};
    }

    unless (&General::validhostname($settings{'HOST'})) {
        $errormessage = $Lang::tr{'invalid hostname'};
    }

    if ($settings{'DOM'} && !&General::validdomainname($settings{'DOM'})) {
        $errormessage = $Lang::tr{'invalid domain name'};
    }

    unless ($errormessage) {
        if ($settings{'KEY1'} eq '') {    #add or edit ?
            unshift(@current, "$settings{'EN'},$settings{'IP'},$settings{'HOST'},$settings{'DOM'}\n");
            &General::log($Lang::tr{'hosts config added'});
        }
        else {
            @current[ $settings{'KEY1'} ] = "$settings{'EN'},$settings{'IP'},$settings{'HOST'},$settings{'DOM'}\n";
            &General::log($Lang::tr{'hosts config changed'});
        }

        # Write changes to config file.
        &SortDataFile;                    # sort newly added/modified entry
        &BuildConfiguration;              # then re-build new host

        map ($settings{$_}='' ,@nosaved, 'ACTION', 'KEY1');      # Clear fields
    }
}

if ($settings{'ACTION'} eq $Lang::tr{'edit'}) {

    #move out new line
    my $line = @current[ $settings{'KEY1'} ];    # KEY1 is the index in current
    chomp($line);
    my @temp = split(/\,/, $line);
    $settings{'EN'}   = $temp[0];                # Prepare the screen for editing
    $settings{'IP'}   = $temp[1];
    $settings{'HOST'} = $temp[2];
    $settings{'DOM'}  = $temp[3];
}

if ($settings{'ACTION'} eq $Lang::tr{'remove'}) {
    splice(@current, $settings{'KEY1'}, 1);      # Delete line
    open(FILE, ">$datafile") or die 'hosts datafile error';
    print FILE @current;
    close(FILE);
    &General::log($Lang::tr{'hosts config changed'});

    &BuildConfiguration;                         # then re-build conf which use new data
    map ($settings{$_} = '', @nosaved, 'ACTION', 'KEY1');  # and reinit vars to empty
}

##  Check if sorting is asked
# If same column clicked, reverse the sort.
if ($ENV{'QUERY_STRING'} =~ /$sortstring/) {
    my $newsort = $ENV{'QUERY_STRING'};
    my $actual  = $settings{'SORT_HOSTSLIST'};

    #Reverse actual sort ?
    if ($actual =~ $newsort) {
        my $Rev = '';
        if ($actual !~ 'Rev') {
            $Rev = 'Rev';
        }
        $newsort .= $Rev;
    }
    $settings{'SORT_HOSTSLIST'} = $newsort;
    map (delete($settings{$_}), (@nosaved, 'ACTION', 'KEY1'));    # Must never be saved
    &General::writehash($settingsfilename, \%settings);
    &SortDataFile;
    map ($settings{$_} = '', @nosaved, 'KEY1');                   # and reinit vars to empty
}

if ($settings{'ACTION'} eq '') {                                  # First launch from GUI
                                                                  # Place here default value when nothing is initialized
    $settings{'EN'}  = 'on';
    $settings{'DOM'} = $settings{'DOMAINNAME'};
}

&Header::openpage($Lang::tr{'hostname'}, 1, '');
&Header::openbigbox('100%', 'left', '');
my %checked = ();                                                 # Checkbox manipulations

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}


#
# Second check box is for editing the list
#
$checked{'EN'}{'on'} = ($settings{'EN'} eq '') ? '' : "checked='checked'";

my $buttontext = $Lang::tr{'add'};
if ($settings{'KEY1'} ne '') {
    $buttontext = $Lang::tr{'update'};
    &Header::openbox('100%', 'left', $Lang::tr{'edit an existing host'});
}
else {
    &Header::openbox('100%', 'left', "$Lang::tr{'add a host'}:");
}

#Edited line number (KEY1) passed until cleared by 'save' or 'remove' or 'new sort order'
print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='KEY1' value='$settings{'KEY1'}' />
<table width='100%'>
<tr>
    <td class='base'>$Lang::tr{'host ip'}:&nbsp;</td>
    <td><input type='text' name='IP' value='$settings{'IP'}' /></td>
    <td class='base'>$Lang::tr{'hostname'}:</td>
    <td><input type='text' name='HOST' value='$settings{'HOST'}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'domain name'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='DOM' value='$settings{'DOM'}' /></td>
    <td class='base'>$Lang::tr{'enabled'}:</td>
    <td><input type='checkbox' name='EN' $checked{'EN'}{'on'} /></td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'><input type='hidden' class='commonbuttons' name='ACTION' value='$Lang::tr{'add'}' /><input type='submit' name='SUBMIT' value='$buttontext' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-hosts.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table>
</form>
END
    ;
&Header::closebox();

# Add visual indicators to column headings to show sort order - EO
my $sortarrow1 = '';
my $sortarrow2 = '';
my $sortarrow3 = '';

if ($settings{'SORT_HOSTSLIST'} eq 'IPRev') {
    $sortarrow1 = $Header::sortdn;
}
elsif ($settings{'SORT_HOSTSLIST'} eq 'IP') {
    $sortarrow1 = $Header::sortup;
}
elsif ($settings{'SORT_HOSTSLIST'} eq 'HOSTRev') {
    $sortarrow2 = $Header::sortdn;
}
elsif ($settings{'SORT_HOSTSLIST'} eq 'HOST') {
    $sortarrow2 = $Header::sortup;
}
elsif ($settings{'SORT_HOSTSLIST'} eq 'DOMRev') {
    $sortarrow3 = $Header::sortdn;
}
else {
    $sortarrow3 = $Header::sortup;
}

#
# Box to show the list, in columns
#
# Columns headers may content a link. In this case it must be named in $sortstring
#
&Header::openbox('100%', 'left', "$Lang::tr{'current hosts'}:");
print <<END
<table width='100%'>
<tr>
    <td width='25%' align='center'><a href='$ENV{'SCRIPT_NAME'}?IP'><b>$Lang::tr{'host ip'}</b></a> $sortarrow1</td>
    <td width='25%' align='center'><a href='$ENV{'SCRIPT_NAME'}?HOST'><b>$Lang::tr{'hostname'}</b></a> $sortarrow2</td>
    <td width='50%' align='center'><a href='$ENV{'SCRIPT_NAME'}?DOM'><b>$Lang::tr{'domain name'}</b></a> $sortarrow3</td>
    <td colspan='3' class='boldbase' align='center'><b>$Lang::tr{'action'}</b></td>
</tr>
END
    ;

#
# Print each line of @current list
#

my $key = 0;
foreach my $line (@current) {
    chomp($line);    # remove newline
    my @temp = split(/\,/, $line);
    $temp[3] = '' unless defined $temp[3];    # not always populated

    #Choose icon for checkbox
    my $gif   = '';
    my $gdesc = '';
    if ($temp[0] ne '') {
        $gif   = 'on.gif';
        $gdesc = $Lang::tr{'click to disable'};
    }
    else {
        $gif   = 'off.gif';
        $gdesc = $Lang::tr{'click to enable'};
    }

    #Colorize each line
    if ($settings{'KEY1'} eq $key) {
        print "<tr class='selectcolour'>";
    }
    else {
        print "<tr class='table".int(($key % 2) + 1)."colour'>";
    }
    print <<END
<td align='center'>$temp[1]</td>
<td align='center'>$temp[2]</td>
<td align='center'>$temp[3]</td>
<td align='center'>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'toggle enable disable'}' />
<input type='image' name='$Lang::tr{'toggle enable disable'}' src='/images/$gif' alt='$gdesc' title='$gdesc' />
<input type='hidden' name='KEY1' value='$key' />
</form>
</td>

<td align='center'>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
<input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' alt='$Lang::tr{'edit'}' title='$Lang::tr{'edit'}' />
<input type='hidden' name='KEY1' value='$key' />
</form>
</td>

<td align='center'>
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
<input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' alt='$Lang::tr{'remove'}' title='$Lang::tr{'remove'}' />
<input type='hidden' name='KEY1' value='$key' />
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
<table>
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
</tr>
</table>
END
        ;
}

&Header::closebox();
&Header::closebigbox();
&Header::closepage();

## Ouf it's the end !

# Sort the "current" array according to choices
sub SortDataFile {
    our %entries = ();

    # Sort pair of record received in $a $b special vars.
    # When IP is specified use numeric sort else alpha.
    # If sortname ends with 'Rev', do reverse sort.
    #
    sub fixedleasesort {
        my $qs = '';    # The sort field specified minus 'Rev'
        if (rindex($settings{'SORT_HOSTSLIST'}, 'Rev') != -1) {
            $qs = substr($settings{'SORT_HOSTSLIST'}, 0, length($settings{'SORT_HOSTSLIST'}) - 3);
            if ($qs eq 'IP') {
                my @a = split(/\./, $entries{$a}->{$qs});
                my @b = split(/\./, $entries{$b}->{$qs});
                       ($b[0] <=> $a[0])
                    || ($b[1] <=> $a[1])
                    || ($b[2] <=> $a[2])
                    || ($b[3] <=> $a[3]);
            }
            else {
                $entries{$b}->{$qs} cmp $entries{$a}->{$qs};
            }
        }
        else {    #not reverse
            $qs = $settings{'SORT_HOSTSLIST'};
            if ($qs eq 'IP') {
                my @a = split(/\./, $entries{$a}->{$qs});
                my @b = split(/\./, $entries{$b}->{$qs});
                       ($a[0] <=> $b[0])
                    || ($a[1] <=> $b[1])
                    || ($a[2] <=> $b[2])
                    || ($a[3] <=> $b[3]);
            }
            else {
                $entries{$a}->{$qs} cmp $entries{$b}->{$qs};
            }
        }
    }

    #Use an associative array (%entries)
    my $key = 0;
    foreach my $line (@current) {
        chomp($line);    #remove newline because can be on field 5 or 6 (addition of REMARK)
        my @temp = ('', '', '', '');
        @temp = split(',', $line);

        # Build a pair 'Field Name',value for each of the data dataline.
        # Each SORTABLE field must have is pair.
        # Other data fields (non sortable) can be grouped in one

        my @record = ('KEY', $key++, 'EN', $temp[0], 'IP', $temp[1], 'HOST', $temp[2], 'DOM', $temp[3]);
        my $record = {};    # create a reference to empty hash
        %{$record} = @record;    # populate that hash with @record
        $entries{$record->{KEY}} = $record;    # add this to a hash of hashes
    }

    open(FILE, ">$datafile") or die 'hosts datafile error';

    # Each field value is printed , with the newline ! Don't forget separator and order of them.
    foreach my $entry (sort fixedleasesort keys %entries) {
        print FILE "$entries{$entry}->{EN},$entries{$entry}->{IP},$entries{$entry}->{HOST},$entries{$entry}->{DOM}\n";
    }

    close(FILE);

    # Reload sorted  @current
    open(FILE, "$datafile");
    @current = <FILE>;
    close(FILE);
}

#
# Build the configuration file
#
sub BuildConfiguration {
    system '/usr/local/bin/rebuildhosts';
}
