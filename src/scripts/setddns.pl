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
# Copyright (c) 2002-2016 The IPCop Team
#
# $Id: setddns.pl 8065 2016-01-10 09:26:44Z owes $
#


use strict;
use IO::Socket;
use Net::SSLeay;
use Fcntl qw(:flock);

require '/usr/lib/ipcop/general-functions.pl';
require '/usr/lib/ipcop/ddns-lib.pl';

# Settings and hosts are automatically pulled in through ddns-lib.pl

# Suppress used only once warnings
my @dummy = ( ${DDNS::settings}, ${General::version}, @{General::noipprefix} );
undef (@dummy);

#Prototypes functions
sub encode_base64($;$);
sub myexit($);

my $logDirName = "/var/log/dyndns";
my $id = 0;
my $lockfile;

# Delete the logdir before fetching IP or doing anything else
if ($ARGV[0] eq '--force') {

    # delete all cache files.
    # next regular calls will try again if this force update fails.
    system("/bin/rm -f $logDirName/*");
    # remember we want to force update, for every host!
    for $id (0 .. $#DDNS::hosts) {
        system("/usr/bin/touch $logDirName/$DDNS::hosts[$id]{'SERVICE'}.$DDNS::hosts[$id]{'HOSTNAME'}.$DDNS::hosts[$id]{'DOMAIN'}.force");
    }
}

if (! -e '/var/ipcop/red/active') {
    if (($ARGV[0] eq '--cron') || ($ARGV[0] eq '--force')) {
        # silently exit
        myexit(0);
    }

    print "RED connection is down.\n";
    myexit(1);
}

my $ip;
if (open(IP, '/var/ipcop/red/local-ipaddress')) {
    $ip = <IP>;
    close(IP);
    chomp $ip;
}
else {
    &General::log('Dynamic DNS failure: unable to open local-ipaddress file.');
    myexit(2);
}


unless (open($lockfile, '>', '/var/lock/setddns')) {
    &General::log("ERROR in setddns: open lockfile failed");
    myexit(3);
}
unless (flock($lockfile, LOCK_EX | LOCK_NB)) {
    # Some other setddns is already running, GUI?, red up?
    &General::log("setddns already running, cannot lock");
    # close and undef lockfile to avoid error message in myexit
    close($lockfile);
    undef($lockfile);
    myexit(4);
}

# If IP is reserved network, we are behind a router. May we ask for our real public IP ?
if (   &General::IpInSubnet($ip, '10.0.0.0', '255.0.0.0')
    || &General::IpInSubnet($ip, '172.16.0.0', '255.240.0.0')
    || &General::IpInSubnet($ip, '192.168.0.0', '255.255.0.0')
    || &General::IpInSubnet($ip, '100.64.0.0', '255.192.0.0'))
{

    # We can, but are we authorized by GUI ?
    if ($DDNS::settings{'BEHINDROUTER'} eq 'FETCH_IP') {

        my %fetchIpState = ();
        $fetchIpState{'FETCHED_IP'}           = "";
        $fetchIpState{'BEHINDROUTERWAITLOOP'} = -1;
        &General::readhash("$logDirName/fetchIpState", \%fetchIpState) if (-e "$logDirName/fetchIpState");

        if ($ARGV[0] eq '--force') {
            # When forced option, fetch PublicIP now
            $fetchIpState{'BEHINDROUTERWAITLOOP'} = -1;
        }

        # Increment counter modulo 4. When it is zero, fetch ip else exit
        # This divides by 4 the requests to the dyndns server.
        $fetchIpState{'BEHINDROUTERWAITLOOP'} = ($fetchIpState{'BEHINDROUTERWAITLOOP'} + 1) % 4;
        &General::writehash("$logDirName/fetchIpState", \%fetchIpState);

        myexit(0) if ($fetchIpState{'BEHINDROUTERWAITLOOP'} ne 0);
        my $RealIP = &General::FetchPublicIp;
        $ip = (&General::validip($RealIP) ? $RealIP : 'unavailable');
        $fetchIpState{'FETCHED_IP'} = $ip;
        &General::writehash("$logDirName/fetchIpState", \%fetchIpState);
        &General::log("Dynamic DNS public router IP is: $ip");

        myexit(0) if ($ip eq 'unavailable');
        system("echo $ip  > /var/ipcop/red/internet-ipaddress");
    }
}


# use proxy ?
my %proxysettings;
&General::readhash('/var/ipcop/proxy/settings', \%proxysettings);
if ($_ = $proxysettings{'UPSTREAM_PROXY'}) {
    my ($peer, $peerport) = (
/^(?:[a-zA-Z ]+\:\/\/)?(?:[A-Za-z0-9\_\.\-]*?(?:\:[A-Za-z0-9\_\.\-]*?)?\@)?([a-zA-Z0-9\.\_\-]*?)(?:\:([0-9]{1,5}))?(?:\/.*?)?$/
    );
    Net::SSLeay::set_proxy($peer, $peerport, $proxysettings{'UPSTREAM_USER'}, $proxysettings{'UPSTREAM_PASSWORD'});
}


for $id (0 .. $#DDNS::hosts) {
    my %settings = ();

    $settings{'ENABLED'}   = $DDNS::hosts[$id]{'ENABLED'};
    next if ($settings{'ENABLED'} ne 'on');

    # Use these as shortcuts
    $settings{'SERVICE'}   = $DDNS::hosts[$id]{'SERVICE'};
    $settings{'HOSTNAME'}  = $DDNS::hosts[$id]{'HOSTNAME'};
    $settings{'DOMAIN'}    = $DDNS::hosts[$id]{'DOMAIN'};
    $settings{'PROXY'}     = $DDNS::hosts[$id]{'PROXY'};
    $settings{'WILDCARDS'} = $DDNS::hosts[$id]{'WILDCARDS'};
    $settings{'LOGIN'}     = $DDNS::hosts[$id]{'LOGIN'};
    $settings{'PASSWORD'}  = $DDNS::hosts[$id]{'PASSWORD'};

    my $ipcache     = 0;
    my $success     = 0;
    my $ipCacheFile = "$logDirName/$settings{'SERVICE'}.$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
    if (-e $ipCacheFile && ! -e "$ipCacheFile.force") {
        open(IPCACHE, $ipCacheFile);
        $ipcache = <IPCACHE>;
        close(IPCACHE);
        chomp $ipcache;
    }

    next if ($ip eq $ipcache);

    my @service = split(/\./, "$settings{'SERVICE'}");
    $settings{'SERVICE'} = "$service[0]";
    
    if ($settings{'SERVICE'} eq 'all-inkl') {
        if ($settings{'DOMAIN'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'HOSTNAME'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_https(
            "dyndns.kasserver.com",
            443,
            "/",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'Ipcop',
                'Authorization' => 'Basic ' . encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}")
            )
        );

        #Valid responses from service are:
        # 'good' , 'nochg'  (ez-ipupdate like)
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out =~ m/good|nochg/) {
                &General::log("Dynamic DNS ip-update for the all-inkl domain $settings{'HOSTDOMAIN'} : success ($out)");
                $success++;
            }
            else {
                &General::log("Dynamic DNS ip-update for the all-inkl domain $settings{'HOSTDOMAIN'} : failure ($out)");
            }
        }
        elsif ($out =~ m/<title>(.*)<\/title>/ig) {
            &General::log("Dynamic DNS ip-update for the all-inkl domain $settings{'HOSTDOMAIN'} : failure ($1)");
        }
        else {
            &General::log("Dynamic DNS ip-update for the all-inkl domain $settings{'HOSTDOMAIN'} : failure ($response)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'cjb') {

        my ($out, $response) = Net::SSLeay::get_http(
            'www.cjb.net', 80,
            "/cgi-bin/dynip.cgi?username=$settings{'LOGIN'}&password=$settings{'PASSWORD'}&ip=$ip",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # has been updated to point to
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/has been updated to point to/) {
                &General::log(
                    "Dynamic DNS ip-update for cjb.net ($settings{'LOGIN'}) : failure (bad password or login)");
            }
            else {
                &General::log("Dynamic DNS ip-update for cjb.net ($settings{'LOGIN'}) : success");
                $success++;
            }
        }
        else {
            &General::log(
                "Dynamic DNS ip-update for cjb.net ($settings{'LOGIN'}) : failure (could not connect to server)");
        }
    }

    # dhs.org=>ez-ipupdate
    elsif ($settings{'SERVICE'} eq 'dnsmadeeasy') {

        # replace the ';' with ',' because comma is the separator in the config file.
        $settings{'HOSTNAME'} =~ tr /;/,/;
        my ($out, $response) = Net::SSLeay::get_https(
            'www.dnsmadeeasy.com',
            443,
"/servlet/updateip?username=$settings{'LOGIN'}&password=$settings{'PASSWORD'}&id=$settings{'HOSTNAME'}&ip=$ip",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # success
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/success/) {
                $out =~ s/\cM//g;
                &General::log("Dynamic DNS ip-update for dnsmadeeasy ID $settings{'HOSTNAME'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for dnsmadeeasy ID $settings{'HOSTNAME'} : success");
                $success++;
            }
        }
        else {
            &General::log(
                "Dynamic DNS ip-update for dnsmadeeasy ID $settings{'HOSTNAME'} : failure (could not connect to server)"
            );
        }
    }
    elsif ($settings{'SERVICE'} eq 'dnspark') {

        if ($settings{'HOSTNAME'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_https(
            "www.dnspark.net",
            443,
            "/api/dynamic/update.php?hostname=$settings{'HOSTDOMAIN'}&ip=$ip",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'Ipcop',
                'Authorization' => 'Basic ' . encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}")
            )
        );

        # Valid response are
        # 'ok'   'nochange'
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/^(ok|nochange)/) {
                $out =~ s/\n/ /g;
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log(
"Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure (could not connect to server, check your credentials)"
            );
        }
    }
    elsif ($settings{'SERVICE'} eq 'dtdns') {

        if ($settings{'HOSTNAME'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_http(
            'www.dtdns.com', 80,
            "/api/autodns.cfm?id=$settings{'HOSTDOMAIN'}&pw=$settings{'PASSWORD'}",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        #   now points to
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/Host .* now points to/ig) {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure (could not connect to server)");
        }
    }

    # dyndns-custom,dyndns-static,dyndns.org,dyns.cx => ez-ipupdate
    elsif ($settings{'SERVICE'} eq 'dynu') {

        if ($settings{'HOSTNAME'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_http(
            'dynserv.ca',
            80,
"/dyn/dynengine.cgi?func=set&name=$settings{'LOGIN'}&pass=$settings{'PASSWORD'}&ip=$ip&domain=$settings{'HOSTDOMAIN'}",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # 02 == Domain already exists, refreshing data for ... => xxx.xxx.xxx.xxx
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/Domain already exists, refreshing data for/ig) {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure (could not connect to server)");
        }
    }

    # easydns => see 'ez-ipupdate'
    elsif ($settings{'SERVICE'} eq 'editdns') {

        if ($settings{'HOSTNAME'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_http(
            'dyndns.editdns.net', 80,
            "/api/dynLinux.php?r=$settings{'HOSTDOMAIN'}&p=$settings{'PASSWORD'}",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # Record has been updated
        # Record already exists with the same IP
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/Record (has been updated|already exists with the same IP)/) {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure (could not connect to server)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'enom') {

        if ($settings{'HOSTNAME'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_http(
            'dynamic.name-services.com',
            80,
"/interface.asp?Command=SetDNSHost&Zone=$settings{'HOSTDOMAIN'}&DomainPassword=$settings{'PASSWORD'}&Address=$ip",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # ErrCount=0
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/ErrCount=0/) {
                $out =~ s/(\n|\x0D)/ /g;
                $out =~ /Err1=([\w ]+)  /;
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($1)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure (could not connect to server)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'everydns') {

        if ($settings{'HOSTNAME'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }
        my $code64 = encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}");
        my $version = "0.1";    # developped for this version of dyn server.

        my ($out, $response) = Net::SSLeay::get_http(
            'dyn.everydns.net',
            80,
            "/index.php?ver=$version&ip=$ip&domain=$settings{'HOSTDOMAIN'}",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'Ipcop',
                'Authorization' => "Basic $code64"
            )
        );

        #Valid responses from service are:
        # "... Exit code: 0"    0:ok else error
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/Exit code: 0/ig) {
                &General::log("Dynamic DNS everydns for $settings{'HOSTDOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS everydns for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS everydns for $settings{'HOSTDOMAIN'} : failure (could not connect to server)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'freedns') {

        my ($out, $response) = Net::SSLeay::get_https(
            'freedns.afraid.org', 443,
            "/dynamic/update.php?$settings{'LOGIN'}",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # Updated n host(s) <domain>
        # ERROR: <ip> has not changed.
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/(^Updated|Address .* has not changed)/ig) {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log(
"Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : failure (could not connect to server)"
            );
        }
    }

    # loopia => ez-ipupdate
    elsif ($settings{'SERVICE'} eq 'loopia') {

       if ($settings{'DOMAIN'} eq '') {
           $settings{'HOSTDOMAIN'} = $settings{'HOSTNAME'};
       }
       else {
           $settings{'HOSTDOMAIN'} = "$settings{'DOMAIN'}";
       }

       my ($out, $response) = Net::SSLeay::get_https(
           "dns.loopia.se",
           443,
           "/XDynDNSServer/XDynDNS.php?hostname=$settings{'HOSTDOMAIN'}&myip=$ip",
           Net::SSLeay::make_headers(
               'User-Agent'    => 'Ipcop',
               'Authorization' => 'Basic ' . encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}")
           )
       );

       #Valid responses from service are:
       # 'good' , 'nochg'  (ez-ipupdate like)
       if ($response =~ m%HTTP/1\.. 200 OK%) {
           if ($out =~ m/good|nochg/) {
               &General::log("Dynamic DNS ip-update for the Loopia domain $settings{'HOSTDOMAIN'} : success ($out)");
               $success++;
           }
           else {
               &General::log("Dynamic DNS ip-update for the Loopia domain $settings{'HOSTDOMAIN'} : failure ($out)");
           }
       }
       elsif ($out =~ m/<title>(.*)<\/title>/ig) {
           &General::log("Dynamic DNS ip-update for the Loopia domain $settings{'HOSTDOMAIN'} : failure ($1)");
       }
       else {
           &General::log("Dynamic DNS ip-update for the Loopia domain $settings{'HOSTDOMAIN'} : failure ($response)");
       }
    }
    elsif ($settings{'SERVICE'} eq 'namecheap') {

        my ($out, $response) = Net::SSLeay::get_https(
            'dynamicdns.park-your-domain.com',
            443,
            "/update?host=$settings{'HOSTNAME'}&domain=$settings{'DOMAIN'}&password=$settings{'PASSWORD'}&ip=$ip",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # wait confirmation!!
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/<ErrCount>0<\/ErrCount>/) {
                $out =~ m/<Err1>(.*)<\/Err1>/;
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : failure ($1)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log(
"Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : failure (could not connect to server)"
            );
        }
    }
    elsif ($settings{'SERVICE'} eq 'no-ip') {

        my $request = "username=$settings{'LOGIN'}&pass=$settings{'PASSWORD'}&ip=$ip";
        my $display;
        if ($settings{'HOSTNAME'} !~ s/$General::noipprefix//) {
            if ($settings{'HOSTNAME'} eq "") {
                $request .= "&h[]=$settings{'DOMAIN'}";
                $display = "$settings{'DOMAIN'}";
            }
            else {
                $request .= "&h[]=$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
                $display = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
            }
        }
        else {
            $request .= "&groupname=$settings{'HOSTNAME'}";
            $display = "group:$settings{'HOSTNAME'}";
        }
        $request = encode_base64($request, "");

        my ($out, $response) = Net::SSLeay::get_http(
            'dynupdate.no-ip.com', 80,
            "/ducupdate.php?requestL=$request",
            Net::SSLeay::make_headers('User-Agent' => 'IPCop/' . ${General::version})
        );

        if ($response =~ m%HTTP/1\.. 200 OK%) {

            # expected response format: [host].[domain]:[return_code]
            # example: myhost.example.com:0
            if ($out =~ m/:(.*)/) {
                if (($1 == 0) || ($1 == 11) || ($1 == 12)) {

                    # 0 is success, 11 is success group, 12 is already set group
                    &General::log("Dynamic DNS ip-update for $display : success");
                    $success++;
                }
                else {
                    &General::log("Dynamic DNS ip-update for $display : failure ($1)");
                }
            }
            else {
                &General::log("Dynamic DNS ip-update for $display : failure ($out)");
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $display : failure (could not connect to server)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'nsupdate') {

        # Fetch UI configurable values and assemble the host name.

        my $hostName = "$settings{'DOMAIN'}";
        if ($settings{'HOSTNAME'} ne "") {
            $hostName = "$settings{'HOSTNAME'}.$hostName";
        }
        my $keyName   = $settings{'LOGIN'};
        my $keySecret = $settings{'PASSWORD'};

        # Use a relatively long TTL value to reduce load on DNS.
        # Some public Dynamic DNS servers use values around 4 hours,
        # some use values as low as 60 seconds.
        # XXX Maybe we could fetch the master value from the server
        # (not the timed-down version supplied by DNS cache)

        my $timeToLive = "3600";

        # Internal setting that can be used to override the DNS server
        # where the update is applied. It can be of use when testing
        # against a private DNS server.

        my $masterServer = "";

        # Prepare the nsupdate command script to remove and re-add the
        # updated A record for the domain.

        my $cmdFile = "/tmp/nsupdate-$hostName-commands";
        my $logFile = "/tmp/nsupdate-$hostName-result";
        open(TF, ">$cmdFile");
        if ($masterServer ne "") {
            print TF "server $masterServer\n";
        }
        if ($keyName ne "" && $keySecret ne "") {
            print TF "key $keyName $keySecret\n";
        }
        print TF "update delete $hostName A\n";
        print TF "update add $hostName $timeToLive A $ip\n";
        print TF "send\n";
        close(TF);

        # Run nsupdate with -v to use TCP instead of UDP because we're
        # issuing multiple cmds and potentially long keys, and -d to
        # get diagnostic result output.

        my $result = system("/usr/bin/nsupdate -v -d $cmdFile 2>$logFile");
        if ($result != 0) {
            &General::log("Dynamic DNS ip-update for $hostName : failure");
            open(NSLOG, "$logFile");
            my @nsLog = <NSLOG>;
            close(NSLOG);
            my $logLine;
            foreach $logLine (@nsLog) {
                chomp($logLine);
                if ($logLine ne "") {
                    &General::log("... $logLine");
                }
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $hostName : success");
            $success++;
        }
        unlink $cmdFile, $logFile;
    }

    # ods => ez-ipupdate
    elsif ($settings{'SERVICE'} eq 'opendns') {

        if ($settings{'DOMAIN'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'HOSTNAME'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_https(
            "updates.opendns.com",
            443,
            "/account/ddns.php?hostname=$settings{'HOSTDOMAIN'}&myip=$ip",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'Ipcop',
                'Authorization' => 'Basic ' . encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}")
            )
        );

        #Valid responses from service are:
        # 'good ip-address' , 'nochg ip-address'  (ez-ipupdate like)
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out =~ m/good |nochg /ig) {
                &General::log("Dynamic DNS ip-update for opendns $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
            else {
                &General::log("Dynamic DNS ip-update for opendns $settings{'HOSTDOMAIN'} : failure ($out)");
            }
        }
        elsif ($out =~ m/<title>(.*)<\/title>/ig) {
            &General::log("Dynamic DNS ip-update for opendns $settings{'HOSTDOMAIN'} : failure ($1)");
        }
        else {
            &General::log("Dynamic DNS ip-update for opendns $settings{'HOSTDOMAIN'} : failure ($response)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'ovh') {

        if ($settings{'HOSTNAME'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }

        my $code64 = encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}");
        chomp($code64);
        my ($out, $response) = Net::SSLeay::get_https(
            'www.ovh.com',
            443,
            "/nic/update?system=dyndns&hostname=$settings{'HOSTDOMAIN'}&myip=$ip",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'Ipcop',
                'Authorization' => "Basic $code64"
            )
        );

        #Valid responses from service are:
        # 'good ip-address' , 'nochg ip-address'  (ez-ipupdate like)
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out =~ m/good |nochg /ig) {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
            else {
                &General::log("Dynamic DNS ovh.com for $settings{'HOSTDOMAIN'} : failure ($out)");
            }
        }
        elsif ($out =~ m/<title>(.*)<\/title>/ig) {
            &General::log("Dynamic DNS ovh.com for $settings{'HOSTDOMAIN'} : failure ($1)");
        }
        else {
            &General::log("Dynamic DNS ovh.com for $settings{'HOSTDOMAIN'} : failure ($response)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'regfish') {

        my ($out, $response) = Net::SSLeay::get_https(
            'dyndns.regfish.de', 443,
            "/?fqdn=$settings{'DOMAIN'}&ipv4=$ip&forcehost=1&authtype=secure&token=$settings{'LOGIN'}",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # success|100|update succeeded!
        # success|101|no update needed at this time..
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/(success\|(100|101)\|)/ig) {
                &General::log("Dynamic DNS ip-update for $settings{'DOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'DOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'DOMAIN'} : failure (could not connect to server)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'registerfly') {

        my ($out, $response) = Net::SSLeay::get_https(
            'dynamic.registerfly.com', 443,
            "?domain=$settings{'DOMAIN'}&password=$settings{'PASSWORD'}&host=$settings{'HOSTNAME'}&ipaddress=$ip",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # <strong><b>Your Dynamic DNS change was accepted by our system</b></strong>
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/DNS change was accepted/ig) {
                $out =~ /<strong>(.*)<\/strong>/;
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : failure ($1)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log(
"Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : failure (could not connect to server)"
            );
        }
    }
    elsif ($settings{'SERVICE'} eq 'sitelutions') {

        my ($out, $response) = Net::SSLeay::get_https(
            'www.sitelutions.com', 443,
            "/dnsup?ttl=60&id=$settings{'HOSTNAME'}&user=$settings{'LOGIN'}&pass=$settings{'PASSWORD'}&ip=$ip",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # success
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/(success)/) {
                $out =~ s/\n/ /g;
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'} : failure (could not connect to server)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'selfhost') {

        if ($settings{'DOMAIN'} eq '') {
            $settings{'HOSTDOMAIN'} = "selfhost.de ($settings{'LOGIN'})";
        }
        else {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }

        my ($out, $response) = Net::SSLeay::get_https(
            'carol.selfhost.de', 443,
            "/update?username=$settings{'LOGIN'}&password=$settings{'PASSWORD'}&textmodi=1",
            Net::SSLeay::make_headers('User-Agent' => 'Ipcop')
        );

        #Valid responses from service are:
        # status=200  status=204
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/status=(200|204)/) {
                $out =~ s/\n/ /g;
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure (could not connect to server)");
        }
    }

    # spdns.de
    elsif ($settings{'SERVICE'} eq 'spdns') {
 
        my ($out, $response) = Net::SSLeay::get_https(
            'update.spdns.de', 443,
            "/nic/update?hostname=$settings{'HOSTNAME'}.$settings{'DOMAIN'}&myip=$ip",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'Ipcop',
                'Authorization' => 'Basic ' . encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}")
            )
        );
 
        #Valid responses from service are:
        # status=good  status=nochg
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out !~ m/(good|nochg)/) {
                $out =~ s/\n/ /g;
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : failure ($out)");
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : success");
                $success++;
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTNAME'}.$settings{'DOMAIN'} : failure (could not connect to server)");
        }
    }

    # strato
    elsif ($settings{'SERVICE'} eq 'strato') {

        if ($settings{'HOSTNAME'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_https(
            "dyndns.strato.com",
            443,
            "/nic/update?hostname=$settings{'HOSTDOMAIN'}&myip=$ip",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'Ipcop',
                'Authorization' => 'Basic ' . encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}")
            )
        );

        # Valid response are 'ok'   'nochange'
        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out =~ m/good |nochg /ig) {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : success");
                $success++;
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($out)");
            }
        }
        elsif ($out =~ m/<title>(.*)<\/title>/ig) {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($1)");
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'} : failure ($response)");
        }
    }
    elsif ($settings{'SERVICE'} eq 'tiggerswelt') {
        $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";

        my ($out, $response) = Net::SSLeay::get_https(
            "ssl.tiggerswelt.net",
            443,
            "/nic/update?hostname=$settings{'HOSTDOMAIN'}&myip=$ip",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'IPCop',
                'Authorization' => 'Basic ' . encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}")
            )
        );

        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out =~ m/good |nochg /ig) {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'}: success");
                $success++;
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'}: failure ($out)");
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'}: failure ($response)");
        }
    }

    # yi.org => ez-ipupdate
    elsif ($settings{'SERVICE'} eq 'yi') {

        if ($settings{'DOMAIN'} eq '') {
            $settings{'HOSTDOMAIN'} = $settings{'HOSTNAME'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'DOMAIN'}";
        }

        my ($out, $response) = Net::SSLeay::get_http(
            "www.yi.org",
            80,
            "/bin/dyndns.fcgi?ipaddr=$ip",
            Net::SSLeay::make_headers(
                'User-Agent'    => 'Ipcop',
                'Authorization' => 'Basic ' . encode_base64("$settings{'LOGIN'}:$settings{'PASSWORD'}")
            )
        );

        if ($response =~ m%HTTP/1\.. 200 OK%) {
            if ($out =~ m/ STATUS:OK /) {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'}: success");
                $success++;
            }
            else {
                &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'}: failure ($out)");
            }
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'}: failure ($response)");
        }
    }

    # zoneedit => see 'ez-ipupdate'
    else {
        if ($settings{'WILDCARDS'} eq 'on') {
            $settings{'WILDCARDS'} = '-w';
        }
        else {
            $settings{'WILDCARDS'} = '';
        }
        if (
            (
                   $settings{'SERVICE'} eq 'dyndns-custom'
                || $settings{'SERVICE'} eq 'easydns'
                || $settings{'SERVICE'} eq 'zoneedit'
            )
            && $settings{'HOSTNAME'} eq ''
            )
        {
            $settings{'HOSTDOMAIN'} = $settings{'DOMAIN'};
        }
        else {
            $settings{'HOSTDOMAIN'} = "$settings{'HOSTNAME'}.$settings{'DOMAIN'}";
        }
        my @ddnscommand = (
            '/usr/bin/ez-ipupdate', '-a', "$ip", '-S', "$settings{'SERVICE'}", '-u',
            "$settings{'LOGIN'}:$settings{'PASSWORD'}",
            '-h', "$settings{'HOSTDOMAIN'}", "$settings{'WILDCARDS'}", '-q'
        );
        my $result = system(@ddnscommand);
        if ($result != 0) {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'}: failure");
        }
        else {
            &General::log("Dynamic DNS ip-update for $settings{'HOSTDOMAIN'}: success");
            $success++;
        }
    }

    # DEBUG:
    #print "Success: $success, file: $ipCacheFile\n";
    # write current IP to specific cache file
    if ($success == 1) {
        open(IPCACHE, ">$ipCacheFile");
        flock IPCACHE, 2;
        print IPCACHE $ip;
        close(IPCACHE);

        unlink("$ipCacheFile.force") if (-e "$ipCacheFile.force");
    }
}
myexit(0);

# Extracted from Base64.pm
sub encode_base64 ($;$) {
    my $res = "";
    my $eol = $_[1];
    $eol = "\n" unless defined $eol;
    pos($_[0]) = 0;    # ensure start at the beginning
    while ($_[0] =~ /(.{1,45})/gs) {
        $res .= substr(pack('u', $1), 1);
        chop($res);
    }
    $res =~ tr|` -_|AA-Za-z0-9+/|;    # `# help emacs
                                      # fix padding at the end
    my $padding = (3 - length($_[0]) % 3) % 3;
    $res =~ s/.{$padding}$/'=' x $padding/e if $padding;

    # break encoded string into lines of no more than 76 characters each
    if (length $eol) {
        $res =~ s/(.{1,76})/$1$eol/g;
    }
    $res;
}

sub myexit($)
{
    my $retcode = shift;

    if (defined($lockfile)) {
        &General::log("ERROR in setddns: unlock failed") unless (flock($lockfile, LOCK_UN));
        close($lockfile);
    }

    exit($retcode);
}
