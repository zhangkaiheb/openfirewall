#
# general-functions.pl: various global variables, helper functions, etc. for scripts and the web GUI
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
# (c) The SmoothWall Team
# Copyright (C) 2002 Alex Hudson - getcgihash() rewrite
# Copyright (C) 2002 Bob Grant <bob@cache.ucr.edu> - validmac()
# Copyright (c) 2002/04/13 Steve Bootes - add alias section, helper functions
# Copyright (c) 2002/08/23 Mark Wormgoor <mark@wormgoor.com> validfqdn()
# Copyright (c) 2003/09/11 Darren Critchley <darrenc@telus.net> srtarray()
# Copyright (c) 2004-2014 The Openfirewall Team
#
# $Id: general-functions.pl 8065 2016-01-10 09:26:44Z owes $
#

package General;

use strict;
use Socket;
use CGI();
use IO::Socket;
use Net::DNS;
use Net::SSLeay;
use XML::Simple;

$| = 1;    # line buffering

$General::version    = 'VERSION';
$General::machine    = 'MACHINE';
$General::noipprefix = 'noipg-';
@General::weekDays   = ('sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday');
# Make sure the days are seen by translation stuff
# $Lang::tr{'sunday'} $Lang::tr{'monday'} $Lang::tr{'tuesday'} $Lang::tr{'wednesday'}
# $Lang::tr{'thursday'} $Lang::tr{'friday'} $Lang::tr{'saturday'}

@General::shortMonths = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');
@General::longMonths = (
    'january', 'february', 'march',     'april',   'may',      'june',
    'july',    'august',   'september', 'october', 'november', 'december'
);
# Make sure the months are seen by translation stuff
# $Lang::tr{'january'},   $Lang::tr{'february'}, $Lang::tr{'march'},    $Lang::tr{'april'},
# $Lang::tr{'may'},       $Lang::tr{'june'},     $Lang::tr{'july'},     $Lang::tr{'august'},
# $Lang::tr{'september'}, $Lang::tr{'october'},  $Lang::tr{'november'}, $Lang::tr{'december'}

#
# log ("message") use default 'openfirewall' tag
# log ("tag","message") use your tag
#
sub log
{
    my $tag = 'openfirewall';
    $tag = shift if (@_ > 1);
    my $logmessage = $_[0];
    $logmessage =~ /([\w\W]*)/;
    $logmessage = $1;
    system('/usr/bin/logger', '-t', $tag, $logmessage);
}

sub getcgihash
{
    my ($hash, $params) = @_;
    my $cgi = CGI->new();
    return if ($ENV{'REQUEST_METHOD'} ne 'POST');
    if (!$params->{'wantfile'}) {
        $CGI::DISABLE_UPLOADS = 1;
        $CGI::POST_MAX        = 512 * 1024;
    }
    else {
        $CGI::POST_MAX = 10 * 1024 * 1024;
    }

    $cgi->referer() =~ m/^https?\:\/\/([^\/]+)/;
    my $referer = $1;
    $cgi->url() =~ m/^https?\:\/\/([^\/]+)/;
    my $servername = $1;
    if ($referer eq "") {
        &General::log('openfirewall', "No referer: activate 'send referer' in your web browser.");
        return;
    }
    elsif ($referer ne $servername) {
        &General::log('openfirewall', "Invalid referer: doesn't match servername!");
        return;
    }

    ### Modified for getting multi-vars, split by |
    my %temp = $cgi->Vars();
    foreach my $key (keys %temp) {
        $hash->{$key} = $temp{$key};
        $hash->{$key} =~ s/\0/|/g;
        $hash->{$key} =~ s/^\s*(.*?)\s*$/$1/;
    }

    if (($params->{'wantfile'}) && ($params->{'filevar'})) {
        $hash->{$params->{'filevar'}} = $cgi->upload($params->{'filevar'});
    }
    return;
}

sub readhash
{
    my $filename = $_[0];
    my $hash     = $_[1];
    my ($var, $val);

    # Some openfirewall code expects that readhash 'complete' the hash if new entries
    # are presents. Not clear it !!!
    #%$hash = ();

    open(FILE, $filename) or die "Unable to read file $filename";

    while (<FILE>) {
        chop;
        ($var, $val) = split /=/, $_, 2;
        if ($var) {
            $val =~ s/^\'//g;
            $val =~ s/\'$//g;

            # Untaint variables read from hash
            $var =~ /([A-Za-z0-9_-]*)/;
            $var = $1;
            $val =~ /([\w\W]*)/;
            $val = $1;
            $hash->{$var} = $val;
        }
    }
    close FILE;
}

sub writehash
{
    my $filename = $_[0];
    my $hash     = $_[1];
    my ($var, $val);

    # write cgi vars to the file.
    open(FILE, ">${filename}") or die "Unable to write file $filename";
    flock FILE, 2;
    foreach $var (keys %$hash) {
        $val = $hash->{$var};

        # Darren Critchley Jan 17, 2003 added the following because when submitting with a graphic, the x and y
        # location of the mouse are submitted as well, this was being written to the settings file causing
        # some serious grief! This skips the variable.x and variable.y
        if (!($var =~ /\.(x|y)$/)) {
            if ($val =~ / /) {
                $val = "\'$val\'";
            }
            if (!($var =~ /^ACTION/)) {
                print FILE "${var}=${val}\n";
            }
        }
    }
    close FILE;
}

#
# Return age of file, '' if file does not exist
#
sub age
{
    my $filename = $_[0];
    return '' unless (-e $filename);
    my ($dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $filename;
    my $now = time;

    my $totalsecs  = $now - $mtime;
    my $days       = int($totalsecs / 86400);
    my $totalhours = int($totalsecs / 3600);
    my $hours      = $totalhours % 24;
    my $totalmins  = int($totalsecs / 60);
    my $mins       = $totalmins % 60;
    my $secs       = $totalsecs % 60;

    return "${days}d ${hours}h ${mins}m ${secs}s";
}

#
# Return age of update flagfile in days.
#   -1 in case no flagfile.
#
sub ageupdate
{
    my $filename = $_[0];
    my $age = &General::age("/var/log/updates/${filename}");

    if ($age =~ m/(\d{1,3})d/) {
        return $1;
    }
    return -1;
}

#
# Touch a flagfile in /var/log/updates.
# Flagfile should be something like updates.last, blacklist.check, etc.
#
sub touchupdate
{
    my $filename = $_[0];

    system("/usr/bin/touch /var/log/updates/${filename}");
    system("/bin/chown nobody.nobody /var/log/updates/${filename}");
}

sub validip
{
    my $ip = $_[0];

    if (!($ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)) {
        return 0;
    }
    else {
        my @octets = ($1, $2, $3, $4);
        foreach $_ (@octets) {
            if (/^0./) {
                return 0;
            }
            if ($_ < 0 || $_ > 255) {
                return 0;
            }
        }
        return 1;
    }
}

sub validmask
{
    my $mask = $_[0];

    # secord part an ip?
    if (&validip($mask)) {
        return 1;
    }

    # second part a number?
    if (/^0/) {
        return 0;
    }
    if (!($mask =~ /^\d+$/)) {
        return 0;
    }
    if ($mask >= 0 && $mask <= 32) {
        return 1;
    }
    return 0;
}

sub validipormask
{
    my $ipormask = $_[0];

    # see if it is a IP only.
    if (&validip($ipormask)) {
        return 1;
    }

    # split it into number and mask.
    if (!($ipormask =~ /^(.*?)\/(.*?)$/)) {
        return 0;
    }
    my $ip   = $1;
    my $mask = $2;

    # first part not a ip?
    if (!(&validip($ip))) {
        return 0;
    }
    return &validmask($mask);
}

sub validipandmask
{
    my $ipandmask = $_[0];

    # split it into number and mask.
    if (!($ipandmask =~ /^(.*?)\/(.*?)$/)) {
        return 0;
    }
    my $ip   = $1;
    my $mask = $2;

    # first part not a ip?
    if (!(&validip($ip))) {
        return 0;
    }
    return &validmask($mask);
}

sub validport
{
    $_ = $_[0];

    if (!/^\d+$/) {
        return 0;
    }
    if (/^0./) {
        return 0;
    }
    if ($_ >= 1 && $_ <= 65535) {
        return 1;
    }
    return 0;
}

sub validmac
{
    my $checkmac = $_[0];
    my $ot       = '[0-9a-f]{2}';    # 2 Hex digits (one octet)
    if ($checkmac !~ /^$ot:$ot:$ot:$ot:$ot:$ot$/i) {
        return 0;
    }
    return 1;
}

sub validhostname
{

    # Checks a hostname against less strict rules than RFC1035
    my $hostname = $_[0];

    # Each part should be at least two characters in length
    # but no more than 63 characters
    if (length($hostname) < 1 || length($hostname) > 63) {
        return 0;
    }

    # Only valid characters are a-z, A-Z, 0-9 and -
    if ($hostname !~ /^[a-zA-Z0-9-]*$/) {
        return 0;
    }

    # First character can only be a letter or a digit
    if (substr($hostname, 0, 1) !~ /^[a-zA-Z0-9]*$/) {
        return 0;
    }

    # Last character can only be a letter or a digit
    if (substr($hostname, -1, 1) !~ /^[a-zA-Z0-9]*$/) {
        return 0;
    }
    return 1;
}

sub validdomainname
{
    my $part;
    my $tld;

    # Checks a domain name against less strict rules than RFC1035
    my $domainname = $_[0];
    my @parts = split(/\./, $domainname);    # Split hostname at the '.'

    foreach $part (@parts) {

        # Each part should be at least 1 character in length
        # but no more than 63 characters
        if (length($part) < 1 || length($part) > 63) {
            return 0;
        }

        # Only valid characters are a-z, A-Z, 0-9 and -
        if ($part !~ /^[a-zA-Z0-9-]*$/) {
            return 0;
        }

        # First character can only be a letter or a digit
        if (substr($part, 0, 1) !~ /^[a-zA-Z0-9]*$/) {
            return 0;
        }

        # Last character can only be a letter or a digit
        if (substr($part, -1, 1) !~ /^[a-zA-Z0-9]*$/) {
            return 0;
        }

        # Store for additional check on TLD
        $tld = $part;
    }

    # TLD valid characters are a-z, A-Z
    if ($tld !~ /^[a-zA-Z]*$/) {
        return 0;
    }

    return 1;
}

sub validfqdn
{
    my $part;

    # Checks a fully qualified domain name against less strict rules than RFC1035
    # url like 0.us.pool.ntp.org are used
    my $fqdn = $_[0];
    my @parts = split(/\./, $fqdn);    # Split hostname at the '.'

    # At least two parts should exist in a FQDN (i.e. hostname.domain)
    if (scalar(@parts) < 2) {
        return 0;
    }

    return validdomainname($fqdn);
}

sub validiporfqdn    # check ip or fdqn
{
    my $test = shift;
    return validip($test) || validfqdn($test);
}

sub validportrange    # used to check a port range
{
    my $port = $_[0];    # port values
    $port =~ tr/-/:/;    # replace all - with colons just in case someone used -
    my $srcdst = $_[1];  # is it a source or destination port

    if (!($port =~ /^(\d+)\:(\d+)$/)) {

        if (!(&validport($port))) {
            if ($srcdst eq 'src') {
                return $Lang::tr{'source port numbers'};
            }
            else {
                return $Lang::tr{'destination port numbers'};
            }
        }
    }
    else {
        my @ports = ($1, $2);
        if ($1 >= $2) {
            if ($srcdst eq 'src') {
                return $Lang::tr{'bad source range'};
            }
            else {
                return $Lang::tr{'bad destination range'};
            }
        }
        foreach $_ (@ports) {
            if (!(&validport($_))) {
                if ($srcdst eq 'src') {
                    return $Lang::tr{'source port numbers'};
                }
                else {
                    return $Lang::tr{'destination port numbers'};
                }
            }
        }
        return;
    }
}

#
# verify host by using a DNS resolve
#
sub validdnshost {
    my $hostname = $_[0];
    unless ($hostname) { return "No hostname"};
    my $res = new Net::DNS::Resolver;
    my $query = $res->search("$hostname");
    if ($query) {
        foreach my $rr ($query->answer) {
            ## Potential bug - we are only looking at A records:
            return 0 if $rr->type eq "A";
        }
    } else {
        return $res->errorstring;
    }
}

# Test if IP is within a subnet
# Call: IpInSubnet (Addr, Subnet, Subnet Mask)
#       Subnet can be an IP of the subnet: 10.0.0.0 or 10.0.0.1
#       Everything in dottted notation
# Return: TRUE/FALSE
sub IpInSubnet
{
    my $ip    = unpack('N', &Socket::inet_aton(shift));
    my $start = unpack('N', &Socket::inet_aton(shift));
    my $mask  = unpack('N', &Socket::inet_aton(shift));
    $start &= $mask;    # base of subnet...
    my $end = $start + ~$mask;
    return (($ip >= $start) && ($ip <= $end));
}

#
# Return the following IP (IP+1) in dotted notation.
# Call: NextIP ('1.1.1.1');
# Return: '1.1.1.2'
#
sub NextIP
{
    return &Socket::inet_ntoa(pack("N", 1 + unpack('N', &Socket::inet_aton(shift))));
}

sub validemail
{
    my $mail = shift;
    return 0 if ($mail !~ /^([0-9a-zA-Z\.\-\_\=\+\#]+)\@([0-9a-zA-Z\.\-]+)$/);
    # 2 parts, check 2nd part for valid domain
    return validdomainname($2);
}

#
# Currently only vpnmain use this three procs (readhasharray, writehasharray, findhasharray)
# The 'key' used is numeric but is perfectly unneeded! This will to be removed so don't use
# this code. Vpnmain will be splitted in parts: x509/pki, connection ipsec, connection other,... .
#
sub readhasharray
{
    my ($filename, $hash) = @_;
    %$hash = ();

    open(FILE, $filename) or die "Unable to read file $filename";

    while (<FILE>) {
        my ($key, $rest, @temp);
        chomp;
        ($key, $rest) = split(/,/, $_, 2);
        if ($key =~ /^[0-9]+$/) {
            @temp = split(/,/, $rest);
            $hash->{$key} = \@temp;
        }
    }
    close FILE;
    return;
}

sub writehasharray
{
    my ($filename, $hash) = @_;
    my ($key, @temp, $i);

    open(FILE, ">$filename") or die "Unable to write to file $filename";

    foreach $key (keys %$hash) {
        if ($key =~ /^[0-9]+$/) {
            print FILE "$key";
            foreach $i (0 .. $#{$hash->{$key}}) {
                print FILE ",$hash->{$key}[$i]";
            }
            print FILE "\n";
        }
    }
    close FILE;
    return;
}

sub findhasharraykey
{
    foreach my $i (1 .. 1000000) {
        if (!exists $_[0]{$i}) {
            return $i;
        }
    }
}

sub srtarray

    # Darren Critchley - darrenc@telus.net - (c) 2003
    # &srtarray(SortOrder, AlphaNumeric, SortDirection, ArrayToBeSorted)
    # This subroutine will take the following parameters:
    #   ColumnNumber = the column which you want to sort on, starts at 1
    #   AlphaNumberic = a or n (lowercase) defines whether the sort should be alpha or numberic
    #   SortDirection = asc or dsc (lowercase) Ascending or Descending sort
    #   ArrayToBeSorted = the array that wants sorting
    #
    #   Returns an array that is sorted to your specs
    #
    #   If SortOrder is greater than the elements in array, then it defaults to the first element
    #
{
    my ($colno, $alpnum, $srtdir, @tobesorted) = @_;
    my @tmparray;
    my @srtedarray;
    my $line;
    my $newline;
    my $ctr;
    my $ttlitems = scalar @tobesorted;    # want to know the number of rows in the passed array
    if ($ttlitems < 1) {                  # if no items, don't waste our time lets leave
        return (@tobesorted);
    }
    my @tmp = split(/\,/, $tobesorted[0]);
    $ttlitems = scalar @tmp;              # this should be the number of elements in each row of the passed in array

    # Darren Critchley - validate parameters
    if ($colno > $ttlitems) { $colno = '1'; }
    $colno--;                             # remove one from colno to deal with arrays starting at 0
    if ($colno < 0) { $colno = '0'; }
    if   ($alpnum ne '') { $alpnum = lc($alpnum); }
    else                 { $alpnum = 'a'; }
    if   ($srtdir ne '') { $srtdir = lc($srtdir); }
    else                 { $srtdir = 'src'; }

    foreach $line (@tobesorted) {
        chomp($line);
        if ($line ne '') {
            my @temp = split(/\,/, $line);

            # Darren Critchley - juggle the fields so that the one we want to sort on is first
            my $tmpholder = $temp[0];
            $temp[0]      = $temp[$colno];
            $temp[$colno] = $tmpholder;
            $newline      = "";
            for ($ctr = 0; $ctr < $ttlitems; $ctr++) {
                $newline = $newline . $temp[$ctr] . ",";
            }
            chop($newline);
            push(@tmparray, $newline);
        }
    }
    if ($alpnum eq 'n') {
        @tmparray = sort { $a <=> $b } @tmparray;
    }
    else {
        @tmparray = (sort @tmparray);
    }
    foreach $line (@tmparray) {
        chomp($line);
        if ($line ne '') {
            my @temp = split(/\,/, $line);
            my $tmpholder = $temp[0];
            $temp[0]      = $temp[$colno];
            $temp[$colno] = $tmpholder;
            $newline      = "";
            for ($ctr = 0; $ctr < $ttlitems; $ctr++) {
                $newline = $newline . $temp[$ctr] . ",";
            }
            chop($newline);
            push(@srtedarray, $newline);
        }
    }

    if ($srtdir eq 'dsc') {
        @tmparray = reverse(@srtedarray);
        return (@tmparray);
    }
    else {
        return (@srtedarray);
    }
}

##
# Sort Hash Arrays
sub sortHashArray
{
    my ($col, $alpnum, $srtdir, $tobesortedRef) = @_;

    my @tobesortedKeys = keys %$tobesortedRef;
    my @tmparray;
    my @srtedarray;
    my $ttlitems = scalar @tobesortedKeys;    # want to know the number of rows in the passed array
    if ($ttlitems < 1) {                      # if no items, don't waste our time lets leave
        return (@tobesortedKeys);
    }

    # if column is not defined in Hash, return the sorted keys
    unless (defined($tobesortedRef->{$tobesortedKeys[0]}{$col})) {
        if ($srtdir eq 'dsc') {
            return reverse sort(@tobesortedKeys);
        }
        else {
            return sort(@tobesortedKeys);
        }
    }

    # validate parameters
    if   ($alpnum ne '') { $alpnum = lc($alpnum); }
    else                 { $alpnum = 'a'; }
    if   ($srtdir ne '') { $srtdir = lc($srtdir); }
    else                 { $srtdir = 'asc'; }

    if ($alpnum eq 'n') {

        # Use first numbers of the entry (e.g. for Portrange "1024:65535" it is sorted by "1024")
        @srtedarray = sort {
            (my $first = $tobesortedRef->{$a}{$col} =~ /^(\d+)/ ? $1 : 0)
                <=> (my $second = $tobesortedRef->{$b}{$col} =~ /^(\d+)/ ? $1 : 0)
        } @tobesortedKeys;
    }
    else {
        @srtedarray = sort { $tobesortedRef->{$a}{$col} cmp $tobesortedRef->{$b}{$col} } @tobesortedKeys;
    }

    if ($srtdir eq 'dsc') {
        @tmparray = reverse(@srtedarray);
        return (@tmparray);
    }
    else {
        return (@srtedarray);
    }
}

sub FetchPublicIp
{
    my %proxysettings;
    &General::readhash('/var/ofw/proxy/settings', \%proxysettings);
    if ($_ = $proxysettings{'UPSTREAM_PROXY'}) {
        my ($peer, $peerport) = (
/^(?:[a-zA-Z ]+\:\/\/)?(?:[A-Za-z0-9\_\.\-]*?(?:\:[A-Za-z0-9\_\.\-]*?)?\@)?([a-zA-Z0-9\.\_\-]*?)(?:\:([0-9]{1,5}))?(?:\/.*?)?$/
        );
        Net::SSLeay::set_proxy($peer, $peerport, $proxysettings{'UPSTREAM_USER'}, $proxysettings{'UPSTREAM_PASSWORD'});
    }
    my ($out, $response) =
        Net::SSLeay::get_http('checkip.dyndns.org', 80, "/", Net::SSLeay::make_headers('User-Agent' => 'Ipcop'));
    if ($response =~ m%HTTP/1\.. 200 OK%) {
        $out =~ /Current IP Address: (\d+.\d+.\d+.\d+)/;
        return $1;
    }
    return '';
}

sub connectionstatus
{
    my %pppsettings = ();
    $pppsettings{'METHOD'} = '';
    $pppsettings{'TYPE'} = '';
    my %netsettings = ();
    my $iface       = '';

    $pppsettings{'PROFILENAME'} = 'None';
    &General::readhash('/var/ofw/ppp/settings',      \%pppsettings);
    &General::readhash('/var/ofw/ethernet/settings', \%netsettings);

    my $profileused = '';
    if (!(($netsettings{'RED_COUNT'} >= 1) && $netsettings{'RED_1_TYPE'} =~ /^(DHCP|STATIC)$/)) {
        $profileused = "- $pppsettings{'PROFILENAME'}";
    }

    if (($pppsettings{'METHOD'} eq 'DHCP' && $netsettings{'RED_1_TYPE'} ne 'PPTP')
        || $netsettings{'RED_1_TYPE'} eq 'DHCP')
    {
        $iface = &General::getredinterface();
    }

    my $connstate;
    my $timestr = &General::age('/var/ofw/red/active');
    my $dialondemand = (-e '/var/ofw/red/dial-on-demand') ? 1 : 0;
    my $connecting = (-e '/var/ofw/red/connecting') ? 1 : 0;
    my $disconnecting = (-e '/var/ofw/red/disconnecting') ? 1 : 0;

    if (($netsettings{'RED_COUNT'} == 0) && ($pppsettings{'TYPE'} =~ /^isdn/)) {

        # Count ISDN channels
        my ($idmap, $chmap, $drmap, $usage, $flags, $phone);
        my @phonenumbers;
        my $count = 0;

        open(FILE, "/dev/isdninfo");

        $idmap = <FILE>;
        chop $idmap;
        $chmap = <FILE>;
        chop $chmap;
        $drmap = <FILE>;
        chop $drmap;
        $usage = <FILE>;
        chop $usage;
        $flags = <FILE>;
        chop $flags;
        $phone = <FILE>;
        chop $phone;

        $phone =~ s/^phone(\s*):(\s*)//;

        @phonenumbers = split / /, $phone;

        foreach (@phonenumbers) {
            if ($_ ne '???') {
                $count++;
            }
        }
        close(FILE);

        ## Connection status
        my $number;
        if ($count == 0) {
            $number = 'none!';
        }
        elsif ($count == 1) {
            $number = 'single';
        }
        else {
            $number = 'dual';
        }

        if ($timestr) {
            $connstate =
"<span class='ofw_StatusBig'>$Lang::tr{'connected'} - $number channel (<span class='ofw_StatusBigRed'>$timestr</span>) $profileused</span>";
        }
        else {
            if ($connecting) {
                $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'connecting'} $profileused</span>";
            }
            elsif ($disconnecting) {
                $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'disconnecting'} $profileused</span>";
            }
            elsif ($count == 0) {
                if ($dialondemand) {
                    $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'dod waiting'} $profileused</span>";
                }
                else {
                    $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'idle'} $profileused</span>";
                }
            }
            else {
                # Final resort, should not happen
                $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'connecting'} $profileused</span>";
            }
        }
    }
    elsif ($netsettings{'RED_1_TYPE'} eq "STATIC" || $pppsettings{'METHOD'} eq 'STATIC') {
        if ($timestr) {
            $connstate =
"<span class='ofw_StatusBig'>$Lang::tr{'connected'} (<span class='ofw_StatusBigRed'>$timestr</span>) $profileused</span>";
        }
        else {
            $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'idle'} $profileused</span>";
        }
    }
    elsif ($timestr) {
        if ($netsettings{'RED_1_TYPE'} eq 'DHCP') {
            $connstate =
"<span class='ofw_StatusBig'>$Lang::tr{'connected'} (<span class='ofw_StatusBigRed'>$timestr</span>) $profileused</span>";
        }
        elsif ($pppsettings{'TYPE'} =~ /^(modem|bewanadsl|conexantpciadsl|eagleusbadsl)$/) {
            my $speed;
            if ($pppsettings{'TYPE'} eq 'modem') {
                open(CONNECTLOG, "/var/log/connect.log");
                while (<CONNECTLOG>) {
                    if (/CONNECT/) {
                        $speed = (split / /)[6];
                    }
                }
                close(CONNECTLOG);
            }
            elsif ($pppsettings{'TYPE'} eq 'bewanadsl') {
                $speed = `/usr/bin/unicorn_status | /bin/grep Rate | /usr/bin/cut -f2 -d ':'`;
                $speed =~ s/(\d+) (\d+)/\1kbits \2kbits/;
            }
            elsif ($pppsettings{'TYPE'} eq 'conexantpciadsl') {
                $speed =
`/bin/cat /proc/net/atm/CnxAdsl:* | /bin/grep 'Line Rates' | /bin/sed -e 's+Line Rates:   Receive+Rx+' -e 's+Transmit+Tx+'`;
            }
            elsif ($pppsettings{'TYPE'} eq 'eagleusbadsl') {
                $speed = `/usr/sbin/eaglestat | /bin/grep Rate`;
            }
            $connstate =
"<span class='ofw_StatusBig'>$Lang::tr{'connected'} (<span class='ofw_StatusBigRed'>$timestr</span>) $profileused (\@$speed)</span>";
        }
        else {
            $connstate =
"<span class='ofw_StatusBig'>$Lang::tr{'connected'} (<span class='ofw_StatusBigRed'>$timestr</span>) $profileused</span>";
        }
    }
    elsif ($dialondemand) {
        $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'dod waiting'} $profileused</span>";
    }
    elsif ($connecting) {
        $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'connecting'} $profileused</span>";
    }
    elsif ($disconnecting) {
        $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'disconnecting'} $profileused</span>";
    }
    else {
        $connstate = "<span class='ofw_StatusBig'>$Lang::tr{'idle'} $profileused</span>";
    }
    return $connstate;
}

#
# Check if hostname.domain provided have IP provided
# use gethostbyname to verify that
# Params:
#	IP
#	hostname
#	domain
# Output
#	1 IP matches host.domain
#	0 not in sync
#
sub DyndnsServiceSync ($;$;$)
{

    my ($ip, $hostName, $domain) = @_;
    my @addresses;

    #fix me no ip GROUP, what is the name ?
    $hostName =~ s/$General::noipprefix//;
    if ($hostName) {    #may be empty
        $hostName  = "$hostName.$domain";
        @addresses = gethostbyname($hostName);
    }

    if ($addresses[0] eq '') {    # nothing returned ?
        $hostName  = $domain;                    # try resolving with domain only
        @addresses = gethostbyname($hostName);
    }

    if ($addresses[0] ne '') {                   # got something ?
                                                 #&General::log("name:$addresses[0], alias:$addresses[1]");
                                                 # Build clear text list of IP
        @addresses = map (&Socket::inet_ntoa($_), @addresses[ 4 .. $#addresses ]);
        if ($ip eq $addresses[0]) {
            return 1;
        }
    }
    return 0;
}

#
# This sub returns the red IP used to compare in DyndnsServiceSync
#
sub GetDyndnsRedIP
{
    my %settings;
    &General::readhash('/var/ofw/ddns/settings', \%settings);

    open(IP, '/var/ofw/red/local-ipaddress') or return 'unavailable';
    my $ip = <IP>;
    close(IP);
    chomp $ip;

    # non-public addresses according to RFC1918 and RFC6598
    if (   &General::IpInSubnet($ip, '10.0.0.0', '255.0.0.0')
        || &General::IpInSubnet($ip, '172.16.0.0', '255.240.0.0')
        || &General::IpInSubnet($ip, '192.168.0.0', '255.255.0.0')
        || &General::IpInSubnet($ip, '100.64.0.0', '255.192.0.0'))
    {
        if ($settings{'BEHINDROUTER'} eq 'FETCH_IP') {
            # Do not fetch internet IP but use stored IP from setddns
#            my $RealIP = &General::FetchPublicIp;
#            $ip = (&General::validip($RealIP) ? $RealIP : 'unavailable');

            open(IP, '/var/ofw/red/internet-ipaddress') or return 'unavailable';
            $ip = <IP>;
            close(IP);
            chomp $ip;
        }
    }
    return $ip;
}

#
# Get Interface from /var/ofw/red/iface, return "" if none
#
sub getredinterface
{
    my $iface = '';

    return $iface unless (open(IFACE, "/var/ofw/red/iface"));
    
    $iface = <IFACE>;
    close IFACE;
    chomp($iface);
    return &General::getinterface($iface);
}

#
# Get interface from a string
#
sub getinterface
{
    my $iface = shift;

    $iface =~ /([a-zA-Z0-9_\-:\.]*)/;
    $iface = $1;

    return $iface;
}

#
# Get interface from a file
#
sub getinterfacefromfile
{
    my $iface = '';
    my $filename = shift;

    return $iface unless (open(FILE, $filename));

    $iface = <FILE>;
    close FILE;
    chomp($iface);
    return &General::getinterface($iface);
}

#
# Get available space on partition in MiB
#   or percentage in use on partition.
# Return space on /root if called without parameter.
#
sub getavailabledisk
{
    my $where = '/root';
    $where = shift if (defined($_[0]));
    my $which = 'free';
    $which = shift if (defined($_[0]));

    open(XX, "/bin/df -B M $where | grep -v Filesystem |");
    my $df = <XX>;
    close(XX);
    my ($device, $size, $used, $free, $percent) = split(' ', $df);

    if ($which eq 'use') {
        # percentage, strip % character
        $percent =~ m/^(\d+)\%$/;
        $percent = $1;

        return $percent;
    }
    else {
        # available space, strip M character
        $free =~ m/^(\d+)M$/;
        $free = $1;

        return $free;
    }
}

#
# Translate interface
#
sub translateinterface
{
    my $iface = shift;
    my $tr_iface = $iface;
    
    $tr_iface = $Lang::tr{lc($iface)} if (defined($Lang::tr{lc($iface)}));
    
    return $tr_iface;
}

sub isrunning($)
{
    my $cmd     = $_[0];
    my $status  = "<td align='center' class='ofw_stopped'>$Lang::tr{'stopped'}</td>";
    my $pid     = '';
    my $testcmd = '';
    my $exename;
    my $vmsize;
    my $showsize = 1;

    $showsize = 0 if (defined($_[1]));
    $status = "<td>&nbsp;</td>".$status if ($showsize);

    $cmd =~ /([a-z]+$)/;
    $exename = $1;

    if ($exename eq 'squidguard') {
        # Special case for squidguard, no PID file(s) to check.
        my $counter = 0;
        my $output = '';

        $output = `/bin/ps -o vsz= -C squidGuard`;
        foreach my $line (split(/\n/, $output)) {
            $counter++;
            $vmsize = $vmsize + int($line);
        }
        if ($counter) {
                if ($showsize) {
                    $status = "<td align='center' >$vmsize kB</td>";
                }
                else {
                    $status = "";
                }
                $status .= "<td align='center' class='ofw_running'>$Lang::tr{'running'}</td>";
        }
        
        return($status);
    }

    if ($exename eq 'dhcpd') {
        # Special case for dnsmasq as DHCP server. dnsmasq is both DNS proxy and DHCP server, we want to
        # show both status. For DHCP we check if DHCP is enabled on at least 1 interface first.
        my $counter = int(`/bin/grep -v BOOTP /var/ofw/dhcp/settings | /bin/grep -c "ENABLED.*=on"`);
        return $status if ($counter == 0);

        $cmd = 'dnsmasq/dnsmasq';
        $exename = 'dnsmasq';
    }

    if (open(FILE, "/var/run/${cmd}.pid")) {
        $pid = <FILE>;
        chomp $pid;
        close FILE;
        if (open(FILE, "/proc/${pid}/status")) {
            while (<FILE>) {
                if (/^Name:\W+(.*)/)            { $testcmd = $1; }
                if (/^VmSize:\W+((\d+) \w{2})/) { $vmsize  = $1; }
            }
            close FILE;
            if ($testcmd =~ /$exename/) {
                if ($showsize) {
                    $status = "<td align='center' >$vmsize</td>";
                }
                else {
                    $status = "";
                }
                $status .= "<td align='center' class='ofw_running'>$Lang::tr{'running'}</td>";
            }
        }
    }
    return $status;
}

#
# Download a file
sub download
{
    return 0 unless (-e '/var/ofw/red/active');
    return 0 unless (@_ > 0);
    my $URL = $_[0];

    my $downloader = LWP::UserAgent->new;
    $downloader->timeout(5);

    my %proxysettings = ();
    &General::readhash('/var/ofw/proxy/settings', \%proxysettings);

    if ($_ = $proxysettings{'UPSTREAM_PROXY'}) {
        my ($peer, $peerport) = (
/^(?:[a-zA-Z ]+\:\/\/)?(?:[A-Za-z0-9\_\.\-]*?(?:\:[A-Za-z0-9\_\.\-]*?)?\@)?([a-zA-Z0-9\.\_\-]*?)(?:\:([0-9]{1,5}))?(?:\/.*?)?$/
        );
        if ($proxysettings{'UPSTREAM_USER'}) {
            $downloader->proxy("http",
                "http://$proxysettings{'UPSTREAM_USER'}:$proxysettings{'UPSTREAM_PASSWORD'}@" . "$peer:$peerport/");
        }
        else {
            $downloader->proxy("http", "http://$peer:$peerport/");
        }
    }
    return $downloader->get($URL, 'Cache-Control', 'no-cache');
}

#
# Download an update package
#
# Parameters:   version
#               called by GUI, overwrites already downloaded patch(es)
# Returns errorcodes from installpackage
#           32 = RED not active
#           33 = error when downloading
sub downloadpatch
{
    my $version = shift;
    my $guiload = shift;
    my $filename  = "openfirewall-${version}-update.${General::machine}.tgz.gpg";
    my $ret = 0;

    return 0 if (($guiload == 0) && -e "/var/patches/$filename");
    return 32 if (! -e '/var/ofw/red/active');

    &General::log("installpackage", "Download update: ${filename}");

    my $URL = "http://prdownloads.sourceforge.net/openfirewall/${filename}?download";
    my $databuf = &General::download($URL);

    if ($databuf && $databuf->is_success) {
        # write the datastream to a file
        open(FILE, ">/var/patches/${filename}");
        binmode(FILE);
        syswrite(FILE, $databuf->content);
        close(FILE);
        system("/bin/chown nobody:nobody /var/patches/${filename}");
        $ret = system("/usr/local/bin/installpackage --test=/var/patches/${filename} >/dev/null") >> 8;

        if ($ret) {
            &General::log("installpackage", "Update package error: $ret");
            # Remove the patch in case of error when automagic loading
            unlink("/var/patches/${filename}") if ($guiload == 0);
        }
        else {
            my $patchsize = 0;
            $patchsize = int((stat("/var/patches/${filename}"))[7] / 1024)+1;
            &General::log("installpackage", "Download complete, size: ${patchsize} KiB");
        }
    }
    else {
        &General::log("installpackage", "Download error: $databuf->status_line");
        $ret = 33;
    }

    return $ret;
}


#
# Check for available updates, update patches/available and optionally preload patches
#
# Returncode:
#   0   OK
#   1   RED is down
#   2   problem opening patches/available
#   3   problem downloading
#   4   installpackage in downloadpatch() returned an error... Look in the log for details.
#   5   not enough diskspace
sub downloadpatchlist
{
    if (! -e '/var/ofw/red/active') {
        return 1;
    }

    return 2 unless (-e '/var/ofw/patches/available.xml');

    my $preload = 'off';
    $preload = $_[0] if (@_ > 0);

    my $available = eval { XMLin('/var/ofw/patches/available.xml') };
    if ($@) {
        &General::log("Error in updates available XML file.");
        $available->{"latest"} = ${General::version};
    }
    elsif (!defined($available->{"latest"})) {
        # This can happen after fresh installation
        $available->{"latest"} = ${General::version};
    }

    my $version = $available->{"latest"};
    my $done = 0;
    while (! $done) {
        #print "Retrieving $version\n";

        my $URL = "http://www.openfirewall.org/patches/$version.xml";
        my $return = download($URL);
        unless ($return && $return->is_success) {
            return 3;
        }
        my $update = XMLin($return->content);

        $available->{"update-$version"} = $update->{"update"};
        if (defined($update->{"update"}->{latest})) {
            $available->{"latest"} = $version;
            #print "$version is latest\n";
            $done = 1;
        }
        else {
            delete $available->{"update-$version"}->{latest} if (defined($available->{"update-$version"}->{latest}));
            $version = $update->{"update"}->{nextversion};
            &General::log("Update $version is available.");
        }
    }

    &General::touchupdate('update.check');
    if (${General::version} eq $available->{"latest"}) {
        # We are uptodate, nothing left to do
        return 0;
    }

    unless (open(FILE, '>/var/ofw/patches/available.xml')) {
        die "Could not open updates available XML file.";
    }
    flock FILE, 2;
    print FILE XMLout($available, RootName => 'ipcop');
    close(FILE);

    if (($preload eq 'on') && (${General::version} ne $available->{"latest"})) {
        my $number = 0;
        my $done = 0;
        my $ret = 0;
        $version = $available->{"update-${General::version}"}->{nextversion};

        while (($number < 10) && ! $done) {
            # installpackage wants 2 * update size + 1,5 MiB.
            # So we will need at least 3 * size + 1,5 MiB before update.
            my $spacerequired = int($available->{"update-$version"}->{size} / 1024) * 3 + 2;
            my $free = getavailabledisk('/var/patches');
            if ($spacerequired > $free) {
                &General::log("Not enough diskspace to download update, required is $spacerequired MiB.");
                return 5;
            }

            $ret = downloadpatch($version, 0);
            return 1 if ($ret == 32);
            return 3 if ($ret == 33);
            return 4 if ($ret != 0);

            if (defined($available->{"update-$version"}->{latest})) {
                $done = 1;
            }
            else {
                $version = $available->{"update-$version"}->{nextversion};
            }
            $number++;
        }
    }

    return 0;
}

#
# Do we know about available updates?
#
sub ispatchavailable
{
    my $available = eval { XMLin('/var/ofw/patches/available.xml') };
    if ($@) {
        return "$Lang::tr{'could not open available updates file'}";
    }

    if (defined($available->{"latest"}) && ($available->{"latest"} ne ${General::version})) {
        return "$Lang::tr{'there are updates'}";
    }

    my $age = &General::ageupdate('update.check');
    if ($age == -1) {
        $age = &General::age('/var/ofw/patches/available.xml');
    }
    if ($age =~ m/(\d{1,3})d*/) {
        if ($1 >= 7) {
            return "$Lang::tr{'updates is old1'} $1 $Lang::tr{'updates is old2'}";
        }
    }

    return "";
}

#
# Used by installpackage to merge update/information.xml into installed.xml after installation
#
sub updateinstalledpatches
{
    my $informationfile = shift;
    my $information = eval { XMLin($informationfile) };
    if ($@) {
        &General::log("Error in update information XML file.");
        return;
    }

    my $installed = eval { XMLin('/var/ofw/patches/installed.xml') };
    if ($@) {
        &General::log("Error in updates installed XML file.");
    }

    # Insert installation date
    $information->{'update'}->{'installdate'} = `/bin/date "+%Y-%m-%d"`;
    chomp($information->{'update'}->{'installdate'});

    # Add the info to our list of installed updates        
    $installed->{"update-$information->{'update'}->{'version'}"} = $information->{'update'};

    # Write the new list of installed updates
    unless (open(FILE, '>/var/ofw/patches/installed.xml')) {
        die "Could not open updates available XML file.";
    }
    flock FILE, 2;
    print FILE XMLout($installed, RootName => 'ipcop');
    close(FILE);
}

#
# Used by installpackage to merge update/information.xml into available.xml after test
#
sub updateavailablepatches
{
    my $informationfile = shift;
    my $information = eval { XMLin($informationfile) };
    if ($@) {
        &General::log("Error in update information XML file.");
        return;
    }
    
    my $available = eval { XMLin('/var/ofw/patches/available.xml') };
    if ($@) {
        &General::log("Error in updates available XML file.");
        $available->{"latest"} = ${General::version};
    }
    elsif (!defined($available->{"latest"})) {
        # This can happen after fresh installation
        $available->{"latest"} = ${General::version};
    }

    my $info_version = $information->{update}->{version};
    
    # Do we have this version in available list ?
    my $version = $available->{"update-${General::version}"}->{nextversion};
    my $done = 0;
    while (($version ne "") && ! $done) {
        if ($version eq $info_version) {
            # Got it, no need to do anything
            return;
        }
        if (defined($available->{"update-$version"}->{latest})) {
            $done = 1;
        }
        else {
            $version = $available->{"update-$version"}->{nextversion};
        }
    }
    
    # TODO: probably need more specialised tests and tweaks to handle multiple offline updates
    #   i.e. 2.0.0 is running and 2.0.1, 2.0.2 and 2.0.3 are uploaded through the GUI
    
    # We don't know about this update (yet)
    if ($information->{update}->{previousversion} eq "${General::version}") {
        # seems to be valid upgrade to currently running version
        $available->{"update-${General::version}"}->{nextversion} = $info_version;
    }
    elsif ($information->{update}->{previousversion} eq $version) {
        # seems to be valid upgrade to last version in available list version
        delete $available->{"update-$version"}->{latest} if (defined($available->{"update-$version"}->{latest}));
        $available->{"update-$version"}->{nextversion} = $info_version;
    }
    else {
        return;
    }

    $available->{"update-$info_version"} = $information->{update};
    $available->{"latest"} = $info_version;

    unless (open(FILE, '>/var/ofw/patches/available.xml')) {
        die "Could not open updates available XML file.";
    }
    flock FILE, 2;
    print FILE XMLout($available, RootName => 'ipcop');
    close(FILE);
}

# Translate ICMP code to text
# ref: http://www.iana.org/assignments/icmp-parameters
sub GetIcmpDescription ($)
{
    my $index            = shift;
    my @icmp_description = (
        'Echo Reply',    #0
        'Unassigned',
        'Unassigned',
        'Destination Unreachable',
        'Source Quench',
        'Redirect',
        'Alternate Host Address',
        'Unassigned',
        'Echo',
        'Router Advertisement',
        'Router Solicitation',    #10
        'Time Exceeded',
        'Parameter Problem',
        'Timestamp',
        'Timestamp Reply',
        'Information Request',
        'Information Reply',
        'Address Mask Request',
        'Address Mask Reply',
        'Reserved (for Security)',
        'Reserved (for Robustness Experiment)',    #20
        'Reserved',
        'Reserved',
        'Reserved',
        'Reserved',
        'Reserved',
        'Reserved',
        'Reserved',
        'Reserved',
        'Reserved',
        'Traceroute',                              #30
        'Datagram Conversion Error',
        'Mobile Host Redirect',
        'IPv6 Where-Are-You',
        'IPv6 I-Am-Here',
        'Mobile Registration Request',
        'Mobile Registration Reply',
        'Domain Name Request',
        'Domain Name Reply',
        'SKIP',
        'Photur',                                  #40
        'Experimental'
    );
    if   ($index > 41) { return 'unknown' }
    else               { return $icmp_description[$index] }
}

#
# Sorting of allocated leases
#
sub CheckSortOrder
{
    my %dhcpsettings = ();
    &General::readhash('/var/ofw/dhcp/settings', \%dhcpsettings);

    if ($ENV{'QUERY_STRING'} =~ /^IPADDR|^ETHER|^HOSTNAME|^ENDTIME/) {
        my $newsort = $ENV{'QUERY_STRING'};
        my $act     = $dhcpsettings{'SORT_LEASELIST'};

        #Default sort if unspecified
        $act = 'IPADDRRev' if !defined($act);

        #Reverse actual ?
        if ($act =~ $newsort) {
            my $Rev = '';
            if ($act !~ 'Rev') { $Rev = 'Rev' }
            $newsort .= $Rev;
        }

        $dhcpsettings{'SORT_LEASELIST'} = $newsort;
        &General::writehash('/var/ofw/dhcp/settings', \%dhcpsettings);
    }
}

#
# Arg: an (optional) button name that 'activates' an action.
#
sub PrintActualLeases
{
    our %dhcpsettings = ();
    our %entries      = ();
    our %networksettings = ();

    sub leasesort
    {
        my $qs = '';
        if (rindex($dhcpsettings{'SORT_LEASELIST'}, 'Rev') != -1) {
            $qs = substr($dhcpsettings{'SORT_LEASELIST'}, 0, length($dhcpsettings{'SORT_LEASELIST'}) - 3);
            if ($qs eq 'IPADDR') {
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
        else    #not reverse
        {
            $qs = $dhcpsettings{'SORT_LEASELIST'};
            if ($qs eq 'IPADDR') {
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

    my $buttonname = shift;

    my ($ip, $endtime, $ether, $hostname, @record, $record);
    open(LEASES, "/var/run/dnsmasq/dnsmasq.leases");
    while (my $line = <LEASES>) {
        next if ($line =~ /^\s*#/);
        chomp($line);
        my @temp = split(' ', $line);

        @record = ('IPADDR', $temp[2], 'ENDTIME', $temp[0], 'ETHER', $temp[1], 'HOSTNAME', $temp[3]);
        $record = {};    # create a reference to empty hash
        %{$record} = @record;    # populate that hash with @record
        $entries{$record->{'IPADDR'}} = $record;    # add this to a hash of hashes
    }
    close(LEASES);

    # Get sort method
    &General::readhash('/var/ofw/dhcp/settings', \%dhcpsettings);  # maybe saved?
    if ($dhcpsettings{'SORT_LEASELIST'} eq '') {
        $dhcpsettings{'SORT_LEASELIST'} = 'IPADDR';                  # default, if not
    }

    # Add visual indicators to column headings to show sort order - EO
    my ($a1, $a2, $a3, $a4) = '';

    if ($dhcpsettings{'SORT_LEASELIST'} eq 'ETHERRev') {
        $a1 = $Header::sortdn;
    }
    elsif ($dhcpsettings{'SORT_LEASELIST'} eq 'ETHER') {
        $a1 = $Header::sortup;
    }
    elsif ($dhcpsettings{'SORT_LEASELIST'} eq 'IPADDRRev') {
        $a2 = $Header::sortdn;
    }
    elsif ($dhcpsettings{'SORT_LEASELIST'} eq 'IPADDR') {
        $a2 = $Header::sortup;
    }
    elsif ($dhcpsettings{'SORT_LEASELIST'} eq 'HOSTNAMERev') {
        $a3 = $Header::sortdn;
    }
    elsif ($dhcpsettings{'SORT_LEASELIST'} eq 'HOSTNAME') {
        $a3 = $Header::sortup;
    }
    elsif ($dhcpsettings{'SORT_LEASELIST'} eq 'ENDTIMERev') {
        $a4 = $Header::sortdn;
    }
    elsif ($dhcpsettings{'SORT_LEASELIST'} eq 'ENDTIME') {
        $a4 = $Header::sortup;
    }

    &Header::openbox('100%', 'left', "$Lang::tr{'current dynamic leases'}:");
    print "<table width='100%'>";
    print "<tr>";
    print <<END
<td width='25%' align='center'><a href='$ENV{'SCRIPT_NAME'}?ETHER'><b>$Lang::tr{'mac address'}</b></a> $a1</td>
<td width='25%' align='center'><a href='$ENV{'SCRIPT_NAME'}?IPADDR'><b>$Lang::tr{'ip address'}</b></a> $a2</td>
<td width='20%' align='center'><a href='$ENV{'SCRIPT_NAME'}?HOSTNAME'><b>$Lang::tr{'hostname'}</b></a> $a3</td>
<td width='30%' align='center'><a href='$ENV{'SCRIPT_NAME'}?ENDTIME'><b>$Lang::tr{'lease expires'} (local time d/m/y)</b></a> $a4</td>
END
    ;
    print "<td></td>" if ($buttonname);    # a column for button graphic
    print "</tr>"; 

    my $id = 0;
    foreach my $key (sort leasesort keys %entries) {

        my $hostname = &Header::cleanhtml($entries{$key}->{HOSTNAME}, "y");

        print "<tr class='table".int(($id % 2) + 1)."colour'>";
        print <<END
<td align='center'>$entries{$key}->{ETHER}</td>
<td align='center'>$entries{$key}->{IPADDR}</td>
<td align='center'>&nbsp;$hostname </td>
<td align='center'>
END
            ;

        if ($entries{$key}->{ENDTIME} eq 'never') {
            print "$Lang::tr{'no time limit'}";
        }
        else {
            my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $dst);
            ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $dst) = localtime($entries{$key}->{ENDTIME});
            my $enddate = sprintf("%02d/%02d/%d %02d:%02d:%02d", $mday, $mon + 1, $year + 1900, $hour, $min, $sec);

            if ($entries{$key}->{ENDTIME} < time()) {
                print "<strike>$enddate</strike>";
            }
            else {
                print "$enddate";
            }
        }
        print "</td>";

        # check if MAC address is already in list of fixed leases
        my $macinfixed = '';
        my $subnetcolor = 'green';
        if ($buttonname eq $Lang::tr{'add new lease'}) {
            $macinfixed = `/bin/grep $entries{$key}->{ETHER} /var/ofw/dhcp/fixedleases`;

            # change colour of 'Add a new fixed lease' icon if 
            # the IP address is in a Blue Subnet
            &General::readhash('/var/ofw/ethernet/settings', \%networksettings);
            my $count;
            for ($count = 1; $count <= $networksettings{'BLUE_COUNT'}; $count++) {
                if (&IpInSubnet (
	                    $entries{$key}->{IPADDR},
	                    $networksettings{"BLUE_${count}_NETADDRESS"},
	                    $networksettings{"BLUE_${count}_NETMASK"})) {
                    $subnetcolor = 'blue';
                }
            }
        }

        if ($buttonname) {
            if ($macinfixed eq '') { 
                print <<END
<td align='center'>
	<form method='post' name='addfromlist$id' action='$ENV{'SCRIPT_NAME'}'>
	<input type='hidden' name='ACTION' value='$buttonname' />
	<input type='hidden' name='ADD_FROM_LIST' value='$entries{$key}->{IPADDR}!$entries{$key}->{ETHER}!$hostname' />
	<input type='image' name='$buttonname' src='/images/add$subnetcolor.gif' alt='$buttonname' title='$buttonname' />
	</form>
</td>
END
                ;
            }
            else {
                # disable button if entry is already a fixed lease 
                print <<END
<td align='center'>
	<img src='/images/addfaint.gif' alt='' width='20' />
</td>
END
                ;
            }
        }
        print "</tr>";
        $id++;
    }

    print "</table>";

    &Header::closebox();
}

sub speedtouchversion
{
    my $speedtouch;
    $speedtouch = `lsusb -d 06b9:4061 -v | /bin/grep bcdDevice`;
    $speedtouch =~ s/bcdDevice//g;
    $speedtouch =~ s/\s//g;
 
    if ($speedtouch eq '') {
            $speedtouch = $Lang::tr{'connect the modem'};
    }
    return $speedtouch;
}

#
# Make a link from the selected profile to the "default" one.
# And update the secrets file.
#
sub SelectProfile
{
    my $profilenr = shift;
    our %modemsettings = ();
    our %pppsettings = ();

    die "No such profile: ${profilenr}" unless(-e "/var/ofw/ppp/settings-${profilenr}");

    unlink('/var/ofw/ppp/settings');
    link("/var/ofw/ppp/settings-${profilenr}", '/var/ofw/ppp/settings');
    system('/usr/bin/touch', '/var/ofw/ppp/updatesettings');

    if ($pppsettings{'TYPE'} eq 'eagleusbadsl') {

        # eagle-usb.conf is in backup but link DSPcode.bin can't, so the link is created in rc.eagleusbadsl
        open(FILE, ">//var/ofw/eagle-usb/eagle-usb.conf") or die "Unable to write eagle-usb.conf file";
        flock(FILE, 2);

        # decimal to hexa
        $modemsettings{'VPI'} = uc(sprintf('%X', $pppsettings{'VPI'}));
        $modemsettings{'VCI'} = uc(sprintf('%X', $pppsettings{'VCI'}));
        if ($pppsettings{'PROTOCOL'} eq 'RFC1483') {
            $modemsettings{'Encapsulation'} = 1 + $pppsettings{'ENCAP'};
        }
        elsif ($pppsettings{'PROTOCOL'} eq 'RFC2364') {
            $modemsettings{'Encapsulation'} = 6 - $pppsettings{'ENCAP'};
        }
        print FILE "<eaglectrl>\n";
        print FILE "VPI=$modemsettings{'VPI'}\n";
        print FILE "VCI=$modemsettings{'VCI'}\n";
        print FILE "Encapsulation=$modemsettings{'Encapsulation'}\n";
        print FILE "Linetype=0A\n";
        print FILE "RatePollFreq=00000009\n";
        print FILE "</eaglectrl>\n";
        close FILE;
    }

    # Read pppsettings to be able to write username and password to secrets file
    &General::readhash("/var/ofw/ppp/settings-${profilenr}", \%pppsettings);

    # Write secrets file
    open(FILE, ">/var/ofw/ppp/secrets") or die "Unable to write secrets file.";
    flock(FILE, 2);
    print FILE "'$pppsettings{'USERNAME'}' * '$pppsettings{'PASSWORD'}'\n";
    chmod 0600, "/var/ofw/ppp/secrets";
    close FILE;
}


sub color_devices()
{
    my @itfs = ('ORANGE', 'BLUE', 'GREEN', 'RED');
    my $output = shift;
    $output = &Header::cleanhtml($output, "y");
    my %netsettings = ();
    &General::readhash('/var/ofw/ethernet/settings', \%netsettings);

    foreach my $itf (@itfs) {
        my $ColorName = '';
        my $lc_itf    = lc($itf);
        $ColorName = "${lc_itf}";    #dereference variable name...
        my $icount = $netsettings{"${itf}_COUNT"};
        while ($icount > 0) {
            my $dev = $netsettings{"${itf}_${icount}_DEV"};
            $output =~ s/\b$dev/<b><span class='ipcop_iface_$ColorName'>$dev<\/span><\/b>/g;
            $icount--;
        }
    }

    if (-e '/proc/net/ipsec_eroute') {
        $output =~ s/ipsec(\d*)/<b><span class='ofw_iface_ipsec'>ipsec$1<\/span><\/b>/g ;
    }

    if (-e '/var/run/openvpn.pid') {
        # TODO: find the tunX interface used by the OpenVPN server and not fix to tun0
        $output =~ s/tun0/<b><span class='ofw_iface_ovpn'>tun0<\/span><\/b>/g ;
    }

    if (!(($netsettings{'RED_COUNT'} >= 1) && $netsettings{'RED_1_TYPE'} =~ /^(DHCP|STATIC)$/)) {
        # Only for PPPoE and similar 'interfaces'
        if (open(REDIFACE, '/var/ofw/red/iface')) {
            my $reddev = <REDIFACE>;
            close(REDIFACE);
            chomp $reddev;
            $output =~ s/\b$reddev/<b><span class='ofw_iface_red'>${reddev}<\/span><\/b>/g;
        }
    }

    return $output;
}


#
# Get columns screen size, caller should subtract 10 for beautify output
#
sub getcolumns
{
    my $columns = int(`/bin/stty size | /usr/bin/cut -f 2 -d " "`);

    return $columns;
}

#
# Pretty Done/Fail output for rc.net, rc.red, etc. when booting
#
sub testok
{
    my $columns = shift;

    if ($columns == 0) {
        # Not booting, just print to goto next line
        print "\n";
    }
    elsif ($?) {
        # 'Fail' in red
        print "\033[${columns}G\033[0;31mFail\033[0;39m\n"
    }
    else {
        # 'Done' in green
        print "\033[${columns}G\033[0;32mDone\033[0;39m\n"
    }
}


#
# Calculate a new date.
# Parameters: year (can be 0), month (0-11), day (can be 0), change (can be -1, 0 or 1)
#   if year is 0 the current year will be used
#   if day is 0 the calculated date will be the first date of previous (change == -1), 
#       current (change == 0) or next (change == 1) month
# Returnparameter is a date/time array, see Perl localtime() for format.
#
sub calculatedate
{
    my @now  = localtime();
    my @this_date;
    $this_date[5] = shift;   # year
    if ($this_date[5]) {
        $this_date[5] -= 1900;
    }
    else {
        $this_date[5] = $now[5];
    }
    $this_date[4] = shift;   # month
    $this_date[3] = shift;   # day
    my $change = shift;
    my @new_date = ();

    if ($this_date[3] == 0) {
        # This is a special case for log, and selects all days in one month
        $this_date[3] = 1;
        $this_date[4] = ($this_date[4] + $change) % 12;
        @new_date = localtime(POSIX::mktime(@this_date));
        $new_date[3] = 0;
    }
    else {
        @new_date = localtime(POSIX::mktime(@this_date) + (86400*$change));
    }

    return (@new_date);
}


#
# Validate a date. This sub serves 2 purposes:
#   1st check if date based on month and day is in the 'future', if yes decrease the year.
#   2nd check if a date is valid, in the GUI log it is for example possible to select 31 February as date
#       if date invalid, decrease the date. 31 February will become 28 February.
# Parameters: year (can be 0), month (0-11), day (can be 0)
#   if year != 0 the 1st test will be skipped
#   if day is 0 the 2nd test will be skipped (we assume valid months are choosen)
# Returnparameter is a date/time array, see Perl localtime() for format.
#
sub validatedate
{
    my @now  = localtime();
    my @this_date;
    $this_date[5] = shift;   # year
    $this_date[4] = shift;   # month
    $this_date[3] = shift;   # day

    if ($this_date[5]) {
        $this_date[5] -= 1900;
    }
    else {
        # Check if this month/day is in the future
        if ( (($this_date[4] eq $now[4]) && ($this_date[3] > $now[3]))
                || ($this_date[4] > $now[4])) {
            $this_date[5] = $now[5] - 1;
        }
        else {
            $this_date[5] = $now[5];
        }
    }

    if ($this_date[3]) {
        # Check if this is a valid date
        my @valid_temp;

validate_day:
        @valid_temp = localtime(POSIX::mktime( 0, 0, 0, $this_date[3], $this_date[4], $this_date[5]));
        #&General::log("validate daymonth $valid_temp[5] $valid_temp[4] $valid_temp[3]");
        if ($valid_temp[3] != $this_date[3]) {
            $this_date[3]--;
            goto validate_day;
        }
    }

    return (@this_date);
}


###
### escape all characters not digit-letter eg: frank&openfirewall => franck\&openfirewall
###
sub escape_shell ($) {
    my $ret = shift;
    $ret =~ s/(\W)/\\$1/g;
    return $ret;
}

1;
