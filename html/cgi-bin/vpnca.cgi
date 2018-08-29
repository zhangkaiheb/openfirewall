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
# (c) 2001-2016 The Openfirewall Team
#
# $Id: vpnca.cgi 8074 2016-01-18 21:01:51Z owes $
#

# Add entry in menu
# MENUENTRY vpn 030 "CA" "virtual private networking"
#
# Make sure translation exists $Lang::tr{'virtual private networking'}

use File::Copy;
use File::Temp qw(tempfile tempdir);
use POSIX();
use Scalar::Util qw(blessed reftype);
use strict;
# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/vpn-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';
require '/usr/lib/ofw/countries.pl';

my $sleepDelay = 4;     # small delay after call to ipsecctrl before reading status

our %rootcertsettings = ();
my $warnmessage = '';
my $errormessage = '';
my $error_ca = '';
my $error_rootcert = '';

my %confighash=();
my %cahash=();

our %cgiparams=();
$cgiparams{'ACTION'} = '';
$cgiparams{'AREUSURE'} = '';
$cgiparams{'CA_NAME'} = '';
$cgiparams{'ROOTCERT_ORGANIZATION'} = '';
$cgiparams{'ROOTCERT_HOSTNAME'} = '';
$cgiparams{'ROOTCERT_EMAIL'} = '';
$cgiparams{'ROOTCERT_OU'} = '';
$cgiparams{'ROOTCERT_CITY'} = '';
$cgiparams{'ROOTCERT_STATE'} = '';
$cgiparams{'ROOTCERT_COUNTRY'} = '';
$cgiparams{'SUBJECTALTNAME'} = '';
$cgiparams{'P12_PASS'} = '';
$cgiparams{'ROOTCERT_DIGEST'} = '';
$cgiparams{'ROOTCERT_ROOTBITS'} = '';
$cgiparams{'ROOTCERT_HOSTBITS'} = '';

my @now  = localtime();
$cgiparams{'DAY'}   = $now[3];
$cgiparams{'MONTH'} = $now[4];
my $this_year = $now[5] + 1900;
# default to 15 years valid
$cgiparams{'YEAR'}  = $now[5] + 1900 + 15;

# Those cgiparams are used as checkbox values have to be initalized with 'off' before reading %cgiparams
# If a checkbox is not select, there will be no such cgiparam.
&General::getcgihash(\%cgiparams, {'wantfile' => 1, 'filevar' => 'FH'});


###
### Reset all step 2 (after confirmation)
###
if ($cgiparams{'ACTION'} eq $Lang::tr{'remove x509'} && $cgiparams{'AREUSURE'} eq 'yes') {
    %confighash = ();
    &General::readhasharray('/var/ofw/ipsec/config', \%confighash);
    foreach my $key (keys %confighash) {
        if ($confighash{$key}[4] eq 'cert') {
            delete $confighash{$key};
        }
    }
    &General::writehasharray('/var/ofw/ipsec/config', \%confighash);

    %confighash = ();
    &General::readhasharray('/var/ofw/openvpn/config', \%confighash);
    foreach my $key (keys %confighash) {
        if ($confighash{$key}[4] eq 'cert') {
            delete $confighash{$key};
        }
    }
    &General::writehasharray('/var/ofw/openvpn/config', \%confighash);

    while (my $file = glob('/var/ofw/{ca,certs,crls,private}/*')) {
        unlink $file
    }
    &VPN::cleanssldatabase();
    if (open(FILE, '>/var/ofw/vpn/caconfig')) {
        print FILE '';
        close FILE;
    }
    
    &VPN::writeipsecfiles();

    &General::log("ipsec", "Reload certificates and secrets");
    system('/usr/local/bin/ipsecctrl', '--reload');
    system('/usr/local/bin/restartopenvpn', '--restart');
    sleep $sleepDelay;

###
### Reset all step 1
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'remove x509'}) {
    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'certificate authorities'}, 1, '');
    &Header::openbigbox('100%', 'left', '', '');
    &Header::openbox('100%', 'left', $Lang::tr{'are you sure'}, 'warning');
    print <<END
    <form method='post' action='$ENV{'SCRIPT_NAME'}'>
    <table width='100%'>
        <tr>
        <td align='center'>
        <input type='hidden' name='AREUSURE' value='yes' />
        <font class='ofw_StatusBigRed'>$Lang::tr{'capswarning'}</font>:
        $Lang::tr{'resetting the vpn configuration will remove the root ca, the host certificate and all certificate based connections'}</td>
        </tr><tr>
        <td align='center'>
        <input type='submit' name='ACTION' value='$Lang::tr{'remove x509'}' />
        <input type='submit' name='ACTION' value='$Lang::tr{'cancel'}' /></td>
        </tr>
    </table>
    </form>
END
    ;
    &Header::closebox();
    &Header::closebigbox();
    &Header::closepage();
    exit (0);

###
### Upload CA Certificate
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'upload ca certificate'}) {
    &General::readhasharray("/var/ofw/vpn/caconfig", \%cahash);

    if ($cgiparams{'CA_NAME'} !~ /^[a-zA-Z0-9]+$/) {
        $errormessage = $Lang::tr{'name must only contain characters'};
        goto UPLOADCA_ERROR;
    }

    if (length($cgiparams{'CA_NAME'}) >60) {
        $errormessage = $Lang::tr{'name too long'};
        goto UPLOADCA_ERROR;
    }

    if ($cgiparams{'CA_NAME'} eq 'ca') {
        $errormessage = $Lang::tr{'name is invalid'};
        goto UPLOAD_CA_ERROR;
    }

    # Check if there is no other entry with this name
    foreach my $key (keys %cahash) {
        if ($cahash{$key}[0] eq $cgiparams{'CA_NAME'}) {
            $errormessage = $Lang::tr{'a ca certificate with this name already exists'};
            goto UPLOADCA_ERROR;
        }
    }

    if (blessed($cgiparams{'FH'}) ne 'CGI::File::Temp') {
        $errormessage = $Lang::tr{'there was no file upload'};
        goto UPLOADCA_ERROR;
    }
    # Move uploaded ca to a temporary file
    (my $fh, my $filename) = tempfile( );
    if (copy ($cgiparams{'FH'}, $fh) != 1) {
        $errormessage = $!;
        goto UPLOADCA_ERROR;
    }
    my $temp = `/usr/bin/openssl x509 -text -in $filename`;
    if ($temp !~ /CA:TRUE/i) {
        $errormessage = $Lang::tr{'not a valid ca certificate'};
        unlink ($filename);
        goto UPLOADCA_ERROR;
    } 
    else {
        move($filename, "/var/ofw/ca/$cgiparams{'CA_NAME'}cert.pem");
        if ($? ne 0) {
            $errormessage = "$Lang::tr{'certificate file move failed'}: $!";
            unlink ($filename);
            goto UPLOADCA_ERROR;
        }
    }

    my $key = &General::findhasharraykey (\%cahash);
    $cahash{$key}[0] = $cgiparams{'CA_NAME'};
    $cahash{$key}[1] = &Header::cleanhtml(&VPN::getsubjectfromcert("/var/ofw/ca/$cgiparams{'CA_NAME'}cert.pem"));
    &General::writehasharray("/var/ofw/vpn/caconfig", \%cahash);

    &General::log("ipsec", "Reload certificates and secrets");
    system('/usr/local/bin/ipsecctrl', '--reload');
    # TODO: restart OpenVPN
    # sleep $sleepDelay;

    UPLOADCA_ERROR:
    $error_ca = 'error' if ($errormessage);

###
### Display CA Certificate
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'show ca certificate'}) {
    &General::readhasharray("/var/ofw/vpn/caconfig", \%cahash);

    if ( -f "/var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem") {
        &Header::showhttpheaders();
        &Header::openpage($Lang::tr{'certificate authorities'}, 1, '');
        &Header::openbigbox('100%', 'left', '', '');
        &Header::openbox('100%', 'left', "$Lang::tr{'ca certificate'}:");
        my $output = `/usr/bin/openssl x509 -text -in /var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem`;
        $output = &Header::cleanhtml($output,"y");
        print <<END
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/vpnca.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
<hr />
<pre>$output</pre>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/vpnca.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
        ;
        &Header::closebox();
        &Header::closebigbox();
        &Header::closepage();
        exit(0);
    } 
    else {
        $errormessage = $Lang::tr{'invalid key'};
    }

###
### Export CA Certificate to browser
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'download ca certificate'}) {
    &General::readhasharray("/var/ofw/vpn/caconfig", \%cahash);

    if ( -f "/var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem" ) {
        print "Content-Type: application/force-download\n";
        print "Content-Type: application/octet-stream\r\n";
        print "Content-Disposition: attachment; filename=$cahash{$cgiparams{'KEY'}}[0]cert.pem\r\n\r\n";
        print `/usr/bin/openssl x509 -in /var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem`;
        exit(0);
    }
    else {
        $errormessage = $Lang::tr{'invalid key'};
    }

###
### Remove CA Certificate (step 2)
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'remove ca certificate'} && $cgiparams{'AREUSURE'} eq 'yes') {
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);
    &General::readhasharray("/var/ofw/vpn/caconfig", \%cahash);

    if ( -f "/var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem" ) {
        foreach my $key (keys %confighash) {
            my $test = `/usr/bin/openssl verify -CAfile /var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem /var/ofw/certs/$confighash{$key}[1]cert.pem`;
            if ($test =~ /: OK/) {
                # Delete connection
                if (&VPN::ipsecenabled()) {
                    &General::log("ipsec", "Delete connection #$key");
                    system("/usr/local/bin/ipsecctrl --stop=$key");
                }
                unlink ("/var/ofw/certs/$confighash{$key}[1]cert.pem");
                unlink ("/var/ofw/certs/$confighash{$key}[1].p12");
                delete $confighash{$key};
                &General::writehasharray("/var/ofw/ipsec/config", \%confighash);

                &VPN::writeipsecfiles();
            }
        }
        unlink ("/var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem");
        delete $cahash{$cgiparams{'KEY'}};
        &General::writehasharray("/var/ofw/vpn/caconfig", \%cahash);

        &General::log("ipsec", "Reload certificates and secrets");
        system('/usr/local/bin/ipsecctrl', '--reload');
        system('/usr/local/bin/restartopenvpn', '--restart');
        sleep $sleepDelay;
    }
    else {
        $errormessage = $Lang::tr{'invalid key'};
    }

###
### Remove CA Certificate (step 1)
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'remove ca certificate'}) {
    &General::readhasharray("/var/ofw/ipsec/config", \%confighash);
    &General::readhasharray("/var/ofw/vpn/caconfig", \%cahash);

    my $assignedcerts = 0;
    if ( -f "/var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem" ) {
        foreach my $key (keys %confighash) {
            my $test = `/usr/bin/openssl verify -CAfile /var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem /var/ofw/certs/$confighash{$key}[1]cert.pem`;
            if ($test =~ /: OK/) {
                $assignedcerts++;
            }
        }
        # TODO: also check OpenVPN certs ?
        if ($assignedcerts) {
            &Header::showhttpheaders();
            &Header::openpage($Lang::tr{'certificate authorities'}, 1, '');
            &Header::openbigbox('100%', 'left', '', '');
            &Header::openbox('100%', 'left', $Lang::tr{'are you sure'}, 'warning');
            print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td align='center'>
    <input type='hidden' name='KEY' value='$cgiparams{'KEY'}' />
    <input type='hidden' name='AREUSURE' value='yes' /></td>
</tr><tr>
    <td align='center'>
    <font class='ofw_StatusBigRed'>$Lang::tr{'capswarning'}</font>
    $Lang::tr{'connections are associated with this ca.  deleting the ca will delete these connections as well.'}</td>
</tr><tr>
    <td align='center'>
    <input type='submit' name='ACTION' value='$Lang::tr{'remove ca certificate'}' />
    <input type='submit' name='ACTION' value='$Lang::tr{'cancel'}' /></td>
</tr>
</table>
</form>
END
            ;
            &Header::closebox();
            &Header::closebigbox();
            &Header::closepage();
            exit (0);
        }
        else {
            unlink ("/var/ofw/ca/$cahash{$cgiparams{'KEY'}}[0]cert.pem");
            delete $cahash{$cgiparams{'KEY'}};
            &General::writehasharray("/var/ofw/vpn/caconfig", \%cahash);

            &General::log("ipsec", "Reload certificates and secrets");
            system('/usr/local/bin/ipsecctrl', '--reload');
            # TODO: restart OpenVPN
            # sleep $sleepDelay;
        }
    } 
    else {
        $errormessage = $Lang::tr{'invalid key'};
    }

###
### Display root and host certificate
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'show root certificate'} ||
    $cgiparams{'ACTION'} eq $Lang::tr{'show host certificate'}) {

    my $output;
    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'certificate authorities'}, 1, '');
    &Header::openbigbox('100%', 'left', '', '');
    if ($cgiparams{'ACTION'} eq $Lang::tr{'show root certificate'}) {
        &Header::openbox('100%', 'left', "$Lang::tr{'root certificate'}:");
        $output = `/usr/bin/openssl x509 -text -in /var/ofw/ca/cacert.pem`;
    } 
    else {
        &Header::openbox('100%', 'left', "$Lang::tr{'host certificate'}:");
        $output = `/usr/bin/openssl x509 -text -in /var/ofw/certs/hostcert.pem`;
    }
    $output = &Header::cleanhtml($output,"y");
    print <<END
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/vpnca.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
<hr />
<pre>$output</pre>
<hr />
<table width='100%'><tr>
    <td width='10%'><a href='/cgi-bin/vpnca.cgi'><img src='/images/back.png' alt='$Lang::tr{'back'}' title='$Lang::tr{'back'}' /></a></td>
    <td>&nbsp;</td>
</tr></table>
END
    ;
    &Header::closebox();
    &Header::closebigbox();
    &Header::closepage();
    exit(0);

###
### Export root certificate to browser
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'download root certificate'}) {
    if ( -f '/var/ofw/ca/cacert.pem' ) {
        print "Content-Type: application/force-download\n";
        print "Content-Disposition: attachment; filename=cacert.pem\r\n\r\n";
        print `/usr/bin/openssl x509 -in /var/ofw/ca/cacert.pem`;
        exit(0);
    }

###
### Export host certificate to browser
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'download host certificate'}) {
    if ( -f '/var/ofw/certs/hostcert.pem' ) {
        print "Content-Type: application/force-download\n";
        print "Content-Disposition: attachment; filename=hostcert.pem\r\n\r\n";
        print `/usr/bin/openssl x509 -in /var/ofw/certs/hostcert.pem`;
        exit(0);
    }

###
### Form for generating/importing the caroot+host certificate
###
} elsif ($cgiparams{'ACTION'} eq $Lang::tr{'generate root/host certificates'} ||
     $cgiparams{'ACTION'} eq $Lang::tr{'upload p12 file'}) {

    if (-f '/var/ofw/ca/cacert.pem') {
        $errormessage = $Lang::tr{'valid root certificate already exists'};
        goto ROOTCERT_SKIP;
    }

    &General::readhash('/var/ofw/vpn/rootcertsettings', \%rootcertsettings) if (-f '/var/ofw/vpn/rootcertsettings');

    if (($cgiparams{'GENERATE_ROOT'} eq 'first') && ($cgiparams{'ACTION'} eq $Lang::tr{'generate root/host certificates'})) {
        # fill in initial values
        if (-e "/var/ofw/red/active" && open(IPADDR, "/var/ofw/red/local-ipaddress")) {
            my $ipaddr = <IPADDR>;
            close IPADDR;
            chomp ($ipaddr);
            $cgiparams{'ROOTCERT_HOSTNAME'} = (gethostbyaddr(pack("C4", split(/\./, $ipaddr)), 2))[0];
            if ($cgiparams{'ROOTCERT_HOSTNAME'} eq '') {
                $cgiparams{'ROOTCERT_HOSTNAME'} = $ipaddr;
            }
        }
        $cgiparams{'ROOTCERT_ORGANIZATION'} = $rootcertsettings{'ROOTCERT_ORGANIZATION'} if (!$cgiparams{'ROOTCERT_ORGANIZATION'});
        $cgiparams{'ROOTCERT_EMAIL'} = $rootcertsettings{'ROOTCERT_EMAIL'} if (!$cgiparams{'ROOTCERT_EMAIL'});
        $cgiparams{'ROOTCERT_OU'} = $rootcertsettings{'ROOTCERT_OU'} if (!$cgiparams{'ROOTCERT_OU'});
        $cgiparams{'ROOTCERT_CITY'} = $rootcertsettings{'ROOTCERT_CITY'} if (!$cgiparams{'ROOTCERT_CITY'});
        $cgiparams{'ROOTCERT_STATE'} = $rootcertsettings{'ROOTCERT_STATE'} if (!$cgiparams{'ROOTCERT_STATE'});
        $cgiparams{'ROOTCERT_COUNTRY'} = $rootcertsettings{'ROOTCERT_COUNTRY'} if (!$cgiparams{'ROOTCERT_COUNTRY'});
        $cgiparams{'ROOTCERT_DIGEST'} = $rootcertsettings{'ROOTCERT_DIGEST'} if (!$cgiparams{'ROOTCERT_DIGEST'});
        $cgiparams{'ROOTCERT_ROOTBITS'} = $rootcertsettings{'ROOTCERT_ROOTBITS'} if (!$cgiparams{'ROOTCERT_ROOTBITS'});
        $cgiparams{'ROOTCERT_HOSTBITS'} = $rootcertsettings{'ROOTCERT_HOSTBITS'} if (!$cgiparams{'ROOTCERT_HOSTBITS'});
        # set proper defaults
        $cgiparams{'ROOTCERT_DIGEST'} = 'sha256' if (!$cgiparams{'ROOTCERT_DIGEST'});
        $cgiparams{'ROOTCERT_ROOTBITS'} = '2048' if (!$cgiparams{'ROOTCERT_ROOTBITS'});
        $cgiparams{'ROOTCERT_HOSTBITS'} = '2048' if (!$cgiparams{'ROOTCERT_HOSTBITS'});
    }
    elsif (($cgiparams{'GENERATE_ROOT'} eq 'second') && ($cgiparams{'ACTION'} eq $Lang::tr{'generate root/host certificates'})) {

        # Validate input since the form was submitted
        if ($cgiparams{'ROOTCERT_ORGANIZATION'} eq ''){
            $errormessage = $Lang::tr{'organization cant be empty'};
            goto ROOTCERT_ERROR;
        }
        if (length($cgiparams{'ROOTCERT_ORGANIZATION'}) >60) {
            $errormessage = $Lang::tr{'organization too long'};
            goto ROOTCERT_ERROR;
        }
        if ($cgiparams{'ROOTCERT_ORGANIZATION'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
            $errormessage = $Lang::tr{'invalid input for organization'};
            goto ROOTCERT_ERROR;
        }
        if ($cgiparams{'ROOTCERT_HOSTNAME'} eq ''){
            $errormessage = $Lang::tr{'hostname cant be empty'};
            goto ROOTCERT_ERROR;
        }
        unless (&General::validiporfqdn($cgiparams{'ROOTCERT_HOSTNAME'})) {
            $errormessage = $Lang::tr{'invalid input for hostname'};
            goto ROOTCERT_ERROR;
        }
        if ($cgiparams{'ROOTCERT_EMAIL'} ne '' && (! &General::validemail($cgiparams{'ROOTCERT_EMAIL'}))) {
            $errormessage = $Lang::tr{'invalid input for e-mail address'};
            goto ROOTCERT_ERROR;
        }
        if (length($cgiparams{'ROOTCERT_EMAIL'}) > 40) {
            $errormessage = $Lang::tr{'e-mail address too long'};
            goto ROOTCERT_ERROR;
        }
        if ($cgiparams{'ROOTCERT_OU'} ne '' && $cgiparams{'ROOTCERT_OU'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
            $errormessage = $Lang::tr{'invalid input for department'};
            goto ROOTCERT_ERROR;
        }
        if ($cgiparams{'ROOTCERT_CITY'} ne '' && $cgiparams{'ROOTCERT_CITY'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
            $errormessage = $Lang::tr{'invalid input for city'};
            goto ROOTCERT_ERROR;
        }
        if ($cgiparams{'ROOTCERT_STATE'} ne '' && $cgiparams{'ROOTCERT_STATE'} !~ /^[a-zA-Z0-9 ,\.\-_]*$/) {
            $errormessage = $Lang::tr{'invalid input for state or province'};
            goto ROOTCERT_ERROR;
        }
        if ($cgiparams{'ROOTCERT_COUNTRY'} !~ /^[A-Z]*$/) {
            $errormessage = $Lang::tr{'invalid input for country'};
            goto ROOTCERT_ERROR;
        }
        #the exact syntax is a list comma separated of
        #  email:any-validemail
        #   URI: a uniform resource indicator
        #   DNS: a DNS domain name
        #   RID: a registered OBJECT IDENTIFIER
        #   IP: an IP address
        # example: email:franck@foo.com,IP:10.0.0.10,DNS:franck.foo.com

        if ($cgiparams{'SUBJECTALTNAME'} ne '' && $cgiparams{'SUBJECTALTNAME'} !~ /^(email|URI|DNS|RID|IP):[a-zA-Z0-9 :\/,\.\-_@]*$/) {
            $errormessage = $Lang::tr{'vpn altname syntax'};
            goto ROOTCERT_ERROR;
        }

        if (($cgiparams{'YEAR'} < $this_year) 
            || (($cgiparams{'YEAR'} == $this_year) && ($cgiparams{'MONTH'} < $now[4]))
            || (($cgiparams{'YEAR'} == $this_year) && ($cgiparams{'MONTH'} == $now[4]) && ($cgiparams{'DAY'} < $now[3])) ) {
            $errormessage = $Lang::tr{'invalid date entered'};
            goto ROOTCERT_ERROR;
        }
        my $certdays = (POSIX::mktime( 0, 0, 1, $cgiparams{'DAY'}, $cgiparams{'MONTH'}, $cgiparams{'YEAR'}-1900) - POSIX::mktime( 0, 0, 0, $now[3], $now[4], $now[5])) / 86400;
        if ($certdays <= 1) {
            $errormessage = $Lang::tr{'invalid date entered'};
            goto ROOTCERT_ERROR;
        }

        # Copy the cgisettings to rootcertsettings and save the configfile
        $rootcertsettings{'ROOTCERT_ORGANIZATION'}  = $cgiparams{'ROOTCERT_ORGANIZATION'};
        $rootcertsettings{'ROOTCERT_HOSTNAME'}      = $cgiparams{'ROOTCERT_HOSTNAME'};
        $rootcertsettings{'ROOTCERT_EMAIL'}         = $cgiparams{'ROOTCERT_EMAIL'};
        $rootcertsettings{'ROOTCERT_OU'}            = $cgiparams{'ROOTCERT_OU'};
        $rootcertsettings{'ROOTCERT_CITY'}          = $cgiparams{'ROOTCERT_CITY'};
        $rootcertsettings{'ROOTCERT_STATE'}         = $cgiparams{'ROOTCERT_STATE'};
        $rootcertsettings{'ROOTCERT_COUNTRY'}       = $cgiparams{'ROOTCERT_COUNTRY'};
        $rootcertsettings{'ROOTCERT_DIGEST'}        = $cgiparams{'ROOTCERT_DIGEST'};
        $rootcertsettings{'ROOTCERT_ROOTBITS'}      = $cgiparams{'ROOTCERT_ROOTBITS'};
        $rootcertsettings{'ROOTCERT_HOSTBITS'}      = $cgiparams{'ROOTCERT_HOSTBITS'};
        &General::writehash("/var/ofw/vpn/rootcertsettings", \%rootcertsettings);

        # Replace empty strings with a .
        (my $ou = $cgiparams{'ROOTCERT_OU'}) =~ s/^\s*$/\./;
        (my $city = $cgiparams{'ROOTCERT_CITY'}) =~ s/^\s*$/\./;
        (my $state = $cgiparams{'ROOTCERT_STATE'}) =~ s/^\s*$/\./;

        # Create the CA certificate
        if (!$errormessage) {
            &General::log("vpn", "Creating cacert...");
            if (open(STDIN, "-|")) {
                my $opt  = " req -x509 -nodes -rand /proc/interrupts:/proc/net/rt_cache";
                $opt .= " -days $certdays";
                $opt .= " -newkey rsa:$rootcertsettings{'ROOTCERT_ROOTBITS'} -$rootcertsettings{'ROOTCERT_DIGEST'}";
                $opt .= " -keyout /var/ofw/private/cakey.pem";
                $opt .= " -out /var/ofw/ca/cacert.pem";

                $errormessage = &VPN::callssl ($opt);
            }
            else {    #child
                print  "$cgiparams{'ROOTCERT_COUNTRY'}\n";
                print  "$state\n";
                print  "$city\n";
                print  "$cgiparams{'ROOTCERT_ORGANIZATION'}\n";
                print  "$ou\n";
                print  "$cgiparams{'ROOTCERT_ORGANIZATION'} CA\n";
                print  "$cgiparams{'ROOTCERT_EMAIL'}\n";
                exit (0);
            }
        }

        # Create the Host certificate request
        if (!$errormessage) {
            &General::log("vpn", "Creating host cert...");
            if (open(STDIN, "-|")) {
                my $opt  = " req -nodes -rand /proc/interrupts:/proc/net/rt_cache";
                $opt .= " -newkey rsa:$rootcertsettings{'ROOTCERT_HOSTBITS'} -$rootcertsettings{'ROOTCERT_DIGEST'}";
                $opt .= " -keyout /var/ofw/certs/hostkeytmp.pem";
                $opt .= " -out /var/ofw/certs/hostreq.pem";
                $opt .= " -extensions server";
                $errormessage = &VPN::callssl ($opt);
            } 
            else {    #child
                print  "$cgiparams{'ROOTCERT_COUNTRY'}\n";
                print  "$state\n";
                print  "$city\n";
                print  "$cgiparams{'ROOTCERT_ORGANIZATION'}\n";
                print  "$ou\n";
                print  "$cgiparams{'ROOTCERT_HOSTNAME'}\n";
                print  "$cgiparams{'ROOTCERT_EMAIL'}\n";
                print  ".\n";
                print  ".\n";
                exit (0);
            }
        }

        # Sign the host certificate request
        if (!$errormessage) {
            &General::log("vpn", "Self signing host cert...");

            #No easy way for specifying the contain of subjectAltName without writing a config file...
            my ($fh, $v3extname) = tempfile ('/tmp/XXXXXXXX');
            print $fh <<END
basicConstraints=CA:FALSE
nsCertType=server
nsComment="OpenSSL Server Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always
END
            ;
            print $fh "subjectAltName=$cgiparams{'SUBJECTALTNAME'}" if ($cgiparams{'SUBJECTALTNAME'});
            close ($fh);

            my  $opt  = " ca -days $certdays";
            $opt .= " -md $rootcertsettings{'ROOTCERT_DIGEST'} -batch -notext";
            $opt .= " -in /var/ofw/certs/hostreq.pem";
            $opt .= " -out /var/ofw/certs/hostcert.pem";
            $opt .= " -extfile $v3extname";
            $errormessage = &VPN::callssl ($opt);
            unlink ("/var/ofw/certs/hostreq.pem"); #no more needed
            unlink ($v3extname);
        }

        # Manipulate hostkey to make openswan happy
        if (!$errormessage) {
            &General::log("vpn", "decrypt hostkey");
            my $opt  = " rsa -in /var/ofw/certs/hostkeytmp.pem";
            $opt .= " -out /var/ofw/certs/hostkey.pem";
            $errormessage = &VPN::callssl ($opt);
            unlink ("/var/ofw/certs/hostkeytmp.pem");
        }

        # Create an empty CRL
        if (!$errormessage) {
            &General::log("vpn", "Creating emptycrl...");
            my  $opt  = " ca -gencrl";
            $opt .= " -out /var/ofw/crls/cacrl.pem";
            $errormessage = &VPN::callssl ($opt);
        }

        # Create Diffie Hellmann Parameter
        if (!$errormessage) {
            &General::log("vpn", "Creating DH parameter...");
            my $opt  = " dhparam -rand /proc/interrupts:/proc/net/rt_cache";
            $opt .= " -out /var/ofw/private/dh1024.pem 1024";
            $errormessage = &VPN::callssl ($opt);
        }

        # Successfully build CA / CERT!
        if (!$errormessage) {
            &VPN::cleanssldatabase();
            &General::log("vpn", "Root and host certificate built");
            goto ROOTCERT_SUCCESS;
        }

        #Cleanup
        unlink ("/var/ofw/ca/cacert.pem");
        unlink ("/var/ofw/certs/hostkey.pem");
        unlink ("/var/ofw/certs/hostcert.pem");
        unlink ("/var/ofw/crls/cacrl.pem");
        &VPN::cleanssldatabase();
    }
    elsif ($cgiparams{'ACTION'} eq $Lang::tr{'upload p12 file'}) {
        &General::log("vpn", "Importing from p12...");

        if (blessed($cgiparams{'FH'}) ne 'CGI::File::Temp') {
            $errormessage = $Lang::tr{'there was no file upload'};
            goto ROOTCERT_ERROR;
        }

        # Move uploaded certificate request to a temporary file
        (my $fh, my $filename) = tempfile( );
        if (copy ($cgiparams{'FH'}, $fh) != 1) {
            $errormessage = $!;
            goto ROOTCERT_ERROR;
        }

        # Extract the CA certificate from the file
        &General::log("vpn", "Extracting caroot from p12...");
        if (open(STDIN, "-|")) {
            my  $opt  = " pkcs12 -cacerts -nokeys";
            $opt .= " -in $filename";
            $opt .= " -out /tmp/newcacert";
            $errormessage = &VPN::callssl ($opt);
        } 
        else {    #child
            print "$cgiparams{'P12_PASS'}\n";
            exit (0);
        }

        # Extract the Host certificate from the file
        if (!$errormessage) {
            &General::log("vpn", "Extracting host cert from p12...");
            if (open(STDIN, "-|")) {
                my  $opt  = " pkcs12 -clcerts -nokeys";
                $opt .= " -in $filename";
                $opt .= " -out /tmp/newhostcert";
                $errormessage = &VPN::callssl ($opt);
            } 
            else {    #child
                print "$cgiparams{'P12_PASS'}\n";
                exit (0);
            }
        }

        # Extract the Host key from the file
        if (!$errormessage) {
            &General::log("vpn", "Extracting private key from p12...");
            if (open(STDIN, "-|")) {
                my  $opt  = " pkcs12 -nocerts -nodes";
                $opt .= " -in $filename";
                $opt .= " -out /tmp/newhostkey";
                $errormessage = &VPN::callssl ($opt);
            }
            else {    #child
                print "$cgiparams{'P12_PASS'}\n";
                exit (0);
            }
        }

        if (!$errormessage) {
            &General::log("vpn", "Moving cacert...");
            move("/tmp/newcacert", "/var/ofw/ca/cacert.pem");
            $errormessage = "$Lang::tr{'certificate file move failed'}: $!" if ($? ne 0);
        }

        if (!$errormessage) {
            &General::log("vpn", "Moving host cert...");
            move("/tmp/newhostcert", "/var/ofw/certs/hostcert.pem");
            $errormessage = "$Lang::tr{'certificate file move failed'}: $!" if ($? ne 0);
        }

        if (!$errormessage) {
            &General::log("vpn", "Moving private key...");
            move("/tmp/newhostkey", "/var/ofw/certs/hostkey.pem");
            $errormessage = "$Lang::tr{'certificate file move failed'}: $!" if ($? ne 0);
        }

        #cleanup temp files
        unlink ($filename);
        unlink ('/tmp/newcacert');
        unlink ('/tmp/newhostcert');
        unlink ('/tmp/newhostkey');
        if ($errormessage) {
            unlink ("/var/ofw/ca/cacert.pem");
            unlink ("/var/ofw/certs/hostcert.pem");
            unlink ("/var/ofw/certs/hostkey.pem");
            goto ROOTCERT_ERROR;
        }

        # Create empty CRL cannot be done because we don't have
        # the private key for this CAROOT
        # Openfirewall can only import certificates

        &General::log("vpn", "p12 import completed!");
        &VPN::cleanssldatabase();
        goto ROOTCERT_SUCCESS;
    }

    ROOTCERT_ERROR:
    my %selected = ();
    # List digest options using: openssl dgst --help. Documentation is likely out of date.
    $selected{'ROOTCERT_DIGEST'}{'md5'} = '';
    $selected{'ROOTCERT_DIGEST'}{'sha256'} = '';
    $selected{'ROOTCERT_DIGEST'}{'sha512'} = '';
    $selected{'ROOTCERT_DIGEST'}{$cgiparams{'ROOTCERT_DIGEST'}} = "selected='selected'";
    $selected{'ROOTCERT_ROOTBITS'}{'1024'} = '';
    $selected{'ROOTCERT_ROOTBITS'}{'2048'} = '';
    $selected{'ROOTCERT_ROOTBITS'}{'4096'} = '';
    $selected{'ROOTCERT_ROOTBITS'}{$cgiparams{'ROOTCERT_ROOTBITS'}} = "selected='selected'";
    $selected{'ROOTCERT_HOSTBITS'}{'1024'} = '';
    $selected{'ROOTCERT_HOSTBITS'}{'2048'} = '';
    $selected{'ROOTCERT_HOSTBITS'}{'4096'} = '';
    $selected{'ROOTCERT_HOSTBITS'}{$cgiparams{'ROOTCERT_HOSTBITS'}} = "selected='selected'";
    &Header::showhttpheaders();
    &Header::openpage($Lang::tr{'certificate authorities'}, 1, '');
    &Header::openbigbox('100%', 'left', '', $errormessage);
    if ($errormessage) {
        $error_rootcert = 'error';
        &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
        print "<font class='base'>$errormessage&nbsp;</font>";
        &Header::closebox();
    }
    &Header::openbox('100%', 'left', "$Lang::tr{'generate root/host certificates'}:", $error_rootcert);
    print <<END
<form method='post' enctype='multipart/form-data' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='40%' class='base'>$Lang::tr{'organization name'}:</td>
    <td width='60%' class='base' nowrap='nowrap'><input type='text' name='ROOTCERT_ORGANIZATION' value='$cgiparams{'ROOTCERT_ORGANIZATION'}' size='32' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'ipcops hostname'}:</td>
    <td class='base' nowrap='nowrap'><input type='text' name='ROOTCERT_HOSTNAME' value='$cgiparams{'ROOTCERT_HOSTNAME'}' size='32' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'your e-mail'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='ROOTCERT_EMAIL' value='$cgiparams{'ROOTCERT_EMAIL'}' size='32' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'your department'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='ROOTCERT_OU' value='$cgiparams{'ROOTCERT_OU'}' size='32' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'city'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='ROOTCERT_CITY' value='$cgiparams{'ROOTCERT_CITY'}' size='32' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'state or province'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='text' name='ROOTCERT_STATE' value='$cgiparams{'ROOTCERT_STATE'}' size='32' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'country'}:</td>
    <td class='base'><select name='ROOTCERT_COUNTRY'>
END
    ;
    foreach my $country (sort keys %{Countries::countries}) {
        print "<option value='$Countries::countries{$country}'";
        if ( $Countries::countries{$country} eq $cgiparams{'ROOTCERT_COUNTRY'} ) {
            print " selected='selected'";
        }
        print ">$country</option>";
    }
    print <<END
        </select></td>
</tr><tr>
    <td class='base'>$Lang::tr{'vpn subjectaltname'}&nbsp;<img src='/blob.gif' alt='*' /> (subjectAltName=email:*,URI:*,DNS:*,RID:*)</td>
    <td class='base' nowrap='nowrap'><input type='text' name='SUBJECTALTNAME' value='$cgiparams{'SUBJECTALTNAME'}' size='32' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'valid until'}:</td>
    <td class='base' nowrap='nowrap'>
    <select name='YEAR'>
END
    ;
    for (my $year = $this_year; $year <= $this_year + 25; $year++) {
        print "\t<option ";
        print "selected='selected' " if ($year == $cgiparams{'YEAR'});
        print "value='$year'>$year</option>\n";
    }
    print "</select>&nbsp;<select name='MONTH'>";
    for (my $month = 0; $month < 12; $month++) {
        print "\t<option ";
        print "selected='selected' " if ($month == $cgiparams{'MONTH'});
        print "value='$month'>$Lang::tr{$General::longMonths[$month]}</option>\n";
    }
    print "</select>&nbsp;<select name='DAY'>";
    for (my $day = 1; $day <= 31; $day++) {
        print "\t<option ";
        print "selected='selected' " if ($day == $cgiparams{'DAY'});
        print "value='$day'>$day</option>\n";
    }
    print <<END
    </select>
    </td>
</tr><tr>
    <td class='base'>Message digest algorithm:</td>
    <td class='base' nowrap='nowrap'>
    <select name='ROOTCERT_DIGEST'>
        <option value='md5' $selected{'ROOTCERT_DIGEST'}{'md5'}>md5</option>
        <option value='sha256' $selected{'ROOTCERT_DIGEST'}{'sha256'}>sha256</option>
        <option value='sha512' $selected{'ROOTCERT_DIGEST'}{'sha512'}>sha512</option>
    </select>
    </td>
</tr><tr>
    <td class='base'>$Lang::tr{'root certificate'}:</td>
    <td class='base' nowrap='nowrap'>
    <select name='ROOTCERT_ROOTBITS'>
        <option value='1024' $selected{'ROOTCERT_ROOTBITS'}{'1024'}>1024 bits</option>
        <option value='2048' $selected{'ROOTCERT_ROOTBITS'}{'2048'}>2048 bits</option>
        <option value='4096' $selected{'ROOTCERT_ROOTBITS'}{'4096'}>4096 bits</option>
    </select>
    </td>
</tr><tr>
    <td class='base'>$Lang::tr{'host certificate'}:</td>
    <td class='base' nowrap='nowrap'>
    <select name='ROOTCERT_HOSTBITS'>
        <option value='1024' $selected{'ROOTCERT_HOSTBITS'}{'1024'}>1024 bits</option>
        <option value='2048' $selected{'ROOTCERT_HOSTBITS'}{'2048'}>2048 bits</option>
        <option value='4096' $selected{'ROOTCERT_HOSTBITS'}{'4096'}>4096 bits</option>
    </select>
    </td>
</tr><tr>
    <td>&nbsp;</td>
    <td><br />
        <input type='submit' name='ACTION' value='$Lang::tr{'generate root/host certificates'}' />
        <input type='hidden' name='GENERATE_ROOT' value='second' /><br /><br /></td>
</tr><tr>
    <td class='base' colspan='2' align='left'>
    <font class='ofw_StatusBigRed'>$Lang::tr{'capswarning'}</font>:
        $Lang::tr{'generating the root and host certificates may take a long time. it can take up to several minutes on older hardware. please be patient'}</td>
</tr><tr>
    <td colspan='2'><hr /></td>
</tr>
</table>
<table width='100%'>
<tr>
    <td class='base' nowrap='nowrap'>$Lang::tr{'upload p12 file'}:</td>
    <td nowrap='nowrap'><input type='file' name='FH' size='32' />&nbsp;<input type='submit' name='ACTION' value='$Lang::tr{'upload p12 file'}' /></td>
</tr><tr>
    <td class='base'>$Lang::tr{'pkcs12 file password'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td class='base' nowrap='nowrap'><input type='password' name='P12_PASS' value='$cgiparams{'P12_PASS'}' size='32' /></td>
</tr></table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'>&nbsp;</td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-ca.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr></table></form>
END
    ;
    &Header::closebox();
    &Header::closebigbox();
    &Header::closepage();
    exit(0);

    ROOTCERT_SUCCESS:
    ;
    # TODO: restart IPsec and OpenVPN ?
    # if (&VPN::ipsecenabled) {
    # system('/usr/local/bin/ipsecctrl', '--start');
    # sleep $sleepDelay;
    # }

    ROOTCERT_SKIP:
    ;
}


&Header::showhttpheaders();

&Header::openpage($Lang::tr{'certificate authorities'}, 1, '');
&Header::openbigbox('100%', 'left', '', $errormessage);

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>";
    &Header::closebox();
}

if ($warnmessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'warning messages'}:", 'warning');
    print "<font class='base'>$warnmessage&nbsp;</font>";
    &Header::closebox();
}


&General::readhasharray('/var/ofw/vpn/caconfig', \%cahash);

&Header::openbox('100%', 'left', "$Lang::tr{'certificate authorities'}:", $error_ca);
print <<END
<table width='100%' border='0' cellspacing='1' cellpadding='2'>
<tr>
    <td width='25%' class='boldbase' align='center'>$Lang::tr{'name'}</td>
    <td width='65%' class='boldbase' align='center'>$Lang::tr{'subject'}</td>
    <td width='10%' class='boldbase' colspan='3' align='center'>$Lang::tr{'action'}</td>
</tr>
END
;

if (-f '/var/ofw/ca/cacert.pem') {
    my $casubject = &Header::cleanhtml(&VPN::getsubjectfromcert('/var/ofw/ca/cacert.pem'));

    print <<END
<tr class='table1colour'>
    <td class='base'>$Lang::tr{'root certificate'}</td>
    <td class='base'>$casubject</td>
    <td width='3%' align='center'><form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'show root certificate'}' />
        <input type='image' name='$Lang::tr{'edit'}' src='/images/info.gif' alt='$Lang::tr{'show root certificate'}' title='$Lang::tr{'show root certificate'}' />
    </form></td>
    <td width='3%' align='center'><form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'download root certificate'}' src='/images/floppy.gif' alt='$Lang::tr{'download root certificate'}' title='$Lang::tr{'download root certificate'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'download root certificate'}' />
    </form></td>
    <td width='3%'>&nbsp;</td></tr>
END
    ;
} 
else {
    print <<END
<tr class='table1colour'>
    <td class='base'>$Lang::tr{'root certificate'}:</td>
    <td class='base'>$Lang::tr{'not present'}</td>
    <td colspan='3'><img src='/images/null.gif' width='1' height='20' border='0' alt='' /></td>
</tr>
END
    ;
}

if (-f "/var/ofw/certs/hostcert.pem") {
    my $hostsubject = &Header::cleanhtml(&VPN::getsubjectfromcert ("/var/ofw/certs/hostcert.pem"));

    print <<END
<tr class='table2colour'>
    <td class='base'>$Lang::tr{'host certificate'}</td>
    <td class='base'>$hostsubject</td>
    <td width='3%' align='center'><form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'show host certificate'}' />
        <input type='image' name='$Lang::tr{'show host certificate'}' src='/images/info.gif' alt='$Lang::tr{'show host certificate'}' title='$Lang::tr{'show host certificate'}' />
    </form></td>
    <td width='3%' align='center'><form method='post' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'download host certificate'}' src='/images/floppy.gif' alt='$Lang::tr{'download host certificate'}' title='$Lang::tr{'download host certificate'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'download host certificate'}' />
    </form></td>
    <td width='3%'><img src='/images/null.gif' width='20' height='20' border='0' alt='' /></td>
</tr>
END
    ;
}
else {
    print <<END
<tr class='table2colour'>
    <td width='25%' class='base'>$Lang::tr{'host certificate'}:</td>
    <td class='base'>$Lang::tr{'not present'}</td>
    <td colspan='3'><img src='/images/null.gif' width='1' height='20' border='0' alt='' /></td>
</tr>
END
    ;
}

my $rowcolor = 0;
if (keys %cahash > 0) {
    foreach my $key (keys %cahash) {
        print "<tr class='table".int(($rowcolor % 2) + 1)."colour'>";
        print "<td class='base'>$cahash{$key}[0]</td>\n";
        print "<td class='base'>$cahash{$key}[1]</td>\n";
        print <<END
    <td align='center'><form method='post' name='cafrm${key}a' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'show ca certificate'}' src='/images/info.gif' alt='$Lang::tr{'show ca certificate'}' title='$Lang::tr{'show ca certificate'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'show ca certificate'}' />
        <input type='hidden' name='KEY' value='$key' />
    </form></td>
    <td align='center'><form method='post' name='cafrm${key}b' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'download ca certificate'}' src='/images/floppy.gif' alt='$Lang::tr{'download ca certificate'}' title='$Lang::tr{'download ca certificate'}' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'download ca certificate'}' />
        <input type='hidden' name='KEY' value='$key' />
    </form></td>
    <td align='center'><form method='post' name='cafrm${key}c' action='$ENV{'SCRIPT_NAME'}'>
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove ca certificate'}' />
        <input type='image'  name='$Lang::tr{'remove ca certificate'}' src='/images/delete.gif' alt='$Lang::tr{'remove ca certificate'}' title='$Lang::tr{'remove ca certificate'}' />
        <input type='hidden' name='KEY' value='$key' />
    </form></td>
</tr>
END
        ;

        $rowcolor++;
    }
}
print '</table>';

# If the file contains entries, print Key to action icons
if ( -f '/var/ofw/ca/cacert.pem') {
    print <<END
<table><tr>
    <td class='boldbase'>&nbsp; $Lang::tr{'legend'}:</td>
    <td>&nbsp; &nbsp; <img src='/images/info.gif' alt='$Lang::tr{'show certificate'}' /></td>
    <td class='base'>$Lang::tr{'show certificate'}</td>
    <td>&nbsp; &nbsp; <img src='/images/floppy.gif' alt='$Lang::tr{'download certificate'}' /></td>
    <td class='base'>$Lang::tr{'download certificate'}</td>
</tr></table>
END
    ;
}

print <<END
<hr />
<form method='post' enctype='multipart/form-data' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
END
;

if (! -f '/var/ofw/ca/cacert.pem') {
    print <<END
<tr>
    <td colspan='3'></td>
    <td>
        <input type='hidden' name='GENERATE_ROOT' value='first' />
        <input type='submit' name='ACTION' value='$Lang::tr{'generate root/host certificates'}' />
    </td>
    <td>&nbsp;</td>
</tr>
END
    ;
}

print <<END
<tr>
    <td class='base' nowrap='nowrap'>$Lang::tr{'ca name'}:</td>
    <td nowrap='nowrap'><input type='text' name='CA_NAME' value='$cgiparams{'CA_NAME'}' size='15' /> </td>
    <td nowrap='nowrap'><input type='file' name='FH' size='30' /></td>
    <td nowrap='nowrap'><input type='submit' name='ACTION' value='$Lang::tr{'upload ca certificate'}' /></td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='3'>&nbsp;</td>
    <td nowrap='nowrap'><input type='submit' name='ACTION' value='$Lang::tr{'show crl'}' disabled='disabled' /></td>
    <td>&nbsp;</td>
</tr><tr>
    <td colspan='3'>$Lang::tr{'resetting the vpn configuration will remove the root ca, the host certificate and all certificate based connections'}:</td>
    <td><input type='submit' name='ACTION' value='$Lang::tr{'remove x509'}' /></td>
    <td>&nbsp;</td>
</tr></table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'>&nbsp;</td>
    <td class='button1button'>&nbsp;</td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/vpns-ca.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a></td>
</tr></table></form>
END
;

&Header::closebox();

&Header::closebigbox();
&Header::closepage();
