#!/usr/bin/perl
#
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
# Copyright (C) 2009-2015, the Openfirewall Team.
#
# $Id: makesquidconf.pl 7901 2015-02-22 22:03:25Z owes $
#

use strict;
use NetAddr::IP;
#use warnings;

require '/usr/lib/ofw/general-functions.pl';

my $http_port='81';
my $http_intercept_port='82';
my $https_port='8443';      # default value, pull actual value from main/settings later

my %mainsettings=();
my %proxysettings=();
my %netsettings=();
my %ovpnsettings=();
my $ovpnactive = 0;

my @useragent=();
my @useragentlist=();

my @temp=();

my $replybodymaxsize = '';
my $browser_regexp='';

my $acldir   = "/var/ofw/proxy/acls";
my $ncsadir  = "/var/ofw/proxy/ncsa";
my $ntlmdir  = "/var/ofw/proxy/ntlm";
my $raddir   = "/var/ofw/proxy/radius";
my $identdir = "/var/ofw/proxy/ident";
my $credir   = "/var/ofw/proxy/cre";

my $userdb = "$ncsadir/passwd";
my $stdgrp = "$ncsadir/standard.grp";
my $extgrp = "$ncsadir/extended.grp";
my $disgrp = "$ncsadir/disabled.grp";

my $browserdb = "/var/ofw/proxy/useragents";
my $mimetypes = "/var/ofw/proxy/mimetypes";
my $throttled_urls = "/var/ofw/proxy/throttle";
my $redirectwrapper = "/usr/local/bin/redirectwrapper";
my $activeredirectors = 0;

my $cre_groups  = "/var/ofw/proxy/cre/classrooms";
my $cre_svhosts = "/var/ofw/proxy/cre/supervisors";

my $identhosts = "$identdir/hosts";

my $authdir  = "/usr/lib/squid";
my $errordir = "/usr/lib/squid/errors";

my $acl_src_subnets  = "$acldir/src_subnets.acl";
my $acl_src_networks = "$acldir/src_networks.acl";
my $acl_src_banned_ip  = "$acldir/src_banned_ip.acl";
my $acl_src_banned_mac = "$acldir/src_banned_mac.acl";
my $acl_src_unrestricted_ip  = "$acldir/src_unrestricted_ip.acl";
my $acl_src_unrestricted_mac = "$acldir/src_unrestricted_mac.acl";
my $acl_src_noaccess_ip  = "$acldir/src_noaccess_ip.acl";
my $acl_src_noaccess_mac = "$acldir/src_noaccess_mac.acl";
my $acl_dst_noauth = "$acldir/dst_noauth.acl";
my $acl_dst_noauth_dom = "$acldir/dst_noauth_dom.acl";
my $acl_dst_noauth_net = "$acldir/dst_noauth_net.acl";
my $acl_dst_noauth_url = "$acldir/dst_noauth_url.acl";
my $acl_dst_nocache = "$acldir/dst_nocache.acl";
my $acl_dst_nocache_dom = "$acldir/dst_nocache_dom.acl";
my $acl_dst_nocache_net = "$acldir/dst_nocache_net.acl";
my $acl_dst_nocache_url = "$acldir/dst_nocache_url.acl";
my $acl_dst_mime_exceptions = "$acldir/dst_mime_exceptions.acl";
my $acl_dst_mime_exceptions_dom = "$acldir/dst_mime_exceptions_dom.acl";
my $acl_dst_mime_exceptions_net = "$acldir/dst_mime_exceptions_net.acl";
my $acl_dst_mime_exceptions_url = "$acldir/dst_mime_exceptions_url.acl";
my $acl_dst_throttle = "$acldir/dst_throttle.acl";
my $acl_ports_safe = "$acldir/ports_safe.acl";
my $acl_ports_ssl  = "$acldir/ports_ssl.acl";
my $acl_include = "$acldir/include.acl";

# Read all the settings required for the proxy service

&General::readhash("/var/ofw/main/settings", \%mainsettings);
&General::readhash("/var/ofw/ethernet/settings", \%netsettings);
&General::readhash("/var/ofw/proxy/settings", \%proxysettings);
&General::readhash("/var/ofw/openvpn/settings", \%ovpnsettings);

# Check if OpenVPN is active

if ((defined($ovpnsettings{'ENABLED_RED_1'}) && $ovpnsettings{'ENABLED_RED_1'} eq 'on')
    || (defined($ovpnsettings{'ENABLED_BLUE_1'}) && $ovpnsettings{'ENABLED_BLUE_1'} eq 'on')) {
    $ovpnactive = 1;
}

# Set port for the GUI

$https_port = $mainsettings{'GUIPORT'} if (defined($mainsettings{'GUIPORT'}));

# Read useragent definitions

if (-e $browserdb) {
    open FILE, $browserdb;
    @useragentlist = sort { reverse(substr(reverse(substr($a,index($a,',')+1)),index(reverse(substr($a,index($a,','))),',')+1)) cmp reverse(substr(reverse(substr($b,index($b,',')+1)),index(reverse(substr($b,index($b,','))),',')+1))} grep !/(^$)|(^\s*#)/,<FILE>;
    close(FILE);
}

# Build a regular expression of selected useragents

foreach (@useragentlist)
{
    chomp;
    @useragent = split(/,/);
    if (defined($proxysettings{'UA_'.$useragent[0]}) && $proxysettings{'UA_'.$useragent[0]} eq 'on') {
        $browser_regexp .= "$useragent[2]|";
    }
}
chop($browser_regexp);


# Write the file for proxy auto configuration (pac)

&writepacfile;

# Write the squid redirector wrapper

&writewrapper;

# Write the squid.conf file

&writeconfigfile;


# -------------------------------------------------------------------
# Build a chain of redirector processes and write the wrapper program for the redirectors

sub writewrapper
{
    my %redirectors = ();
    my $lastredirector = 0;

    foreach my $redirector (</var/ofw/proxy/redirector/*>) {
        if (-e $redirector) {
            my %redirectorsettings=();
            $redirectorsettings{'OPTION_CHAIN'} = '';
            &General::readhash($redirector, \%redirectorsettings);

            if (defined($redirectorsettings{'NAME'})) {
                $redirectors{$redirectorsettings{'NAME'}}{'ENABLED'} = $redirectorsettings{'ENABLED'};
                $redirectors{$redirectorsettings{'NAME'}}{'ORDER'} = $redirectorsettings{'ORDER'};
                $redirectors{$redirectorsettings{'NAME'}}{'CMD'} = $redirectorsettings{'CMD'};
                $redirectors{$redirectorsettings{'NAME'}}{'OPTION_CHAIN'} = $redirectorsettings{'OPTION_CHAIN'};
                if (($redirectorsettings{'ORDER'} > $lastredirector) && ($redirectorsettings{'ENABLED'} eq 'on')) {
                    # could be the last one in the chain
                    $lastredirector = $redirectorsettings{'ORDER'};
                }
            }
        }
    }

    #sort redirectors
    my @redirectornames =  &General::sortHashArray('ORDER', 'n', 'asc', \%redirectors);

    my $chain = '';
    foreach my $redirector (@redirectornames) {

        if ($redirectors{$redirector}{'ENABLED'} eq 'on') {
            $activeredirectors++;
            if ($chain ne '') {
                $chain .= "|";
            }
            $chain .= "$redirectors{$redirector}{'CMD'}";
            if ($redirectors{$redirector}{'ORDER'} < $lastredirector) {
                # more redirectors will follow
                $chain .= " $redirectors{$redirector}{'OPTION_CHAIN'}";
            }
        }
    }

    open (FILE, ">$redirectwrapper");
    print FILE "#!/bin/sh\n";
    print FILE $chain;
    print FILE "\n";
    close FILE;
    system("chmod 755 $redirectwrapper");
}

# -------------------------------------------------------------------

sub writepacfile
{
    open(FILE, ">/usr/local/apache/vhost81/html/proxy.pac");
    flock(FILE, 2);
    print FILE "function FindProxyForURL(url, host)\n{\n";

    if (($proxysettings{'ENABLED_GREEN_1'} eq 'on') || ($proxysettings{'ENABLED_BLUE_1'} eq 'on') || ($proxysettings{'ENABLED_OVPN'} eq 'on')) {
        print FILE <<END
    // URL without dots
    if (isPlainHostName(host))
        return "DIRECT";

    // our domain
    if (dnsDomainIs(host, ".$mainsettings{'DOMAINNAME'}"))
        return "DIRECT";

    var resolved_host = dnsResolve(host);
    // 'internal' IPs
    if (
        (isInNet(resolved_host, "10.0.0.0", "255.0.0.0")) ||
        (isInNet(resolved_host, "172.16.0.0", "255.240.0.0")) ||
        (isInNet(resolved_host, "192.168.0.0", "255.255.0.0")) ||
        (isInNet(resolved_host, "169.254.0.0", "255.255.0.0")) ||
        (isInNet(resolved_host, "127.0.0.0", "255.0.0.0"))
    )
        return "DIRECT";
END
;
        if ($ovpnactive && ($proxysettings{'ENABLED_OVPN'} eq 'on')) {
            my $ovpnnet  = NetAddr::IP->new($ovpnsettings{'DOVPN_SUBNET'})->network()->addr();
            my $ovpnmask = NetAddr::IP->new($ovpnsettings{'DOVPN_SUBNET'})->mask();
            my $serverip = NetAddr::IP->new($ovpnsettings{'DOVPN_SUBNET'})->first()->addr();
            print FILE <<END

    // OpenVPN Network
    else if (isInNet(myIpAddress(), "$ovpnnet", "$ovpnmask"))
        return "PROXY $serverip:$proxysettings{'PROXY_PORT'}";
END
            ;
        }
        if (($netsettings{'BLUE_COUNT'} >= 1) && ($proxysettings{'ENABLED_BLUE_1'} eq 'on')) {
            print FILE <<END

    // BLUE Network
    else if (isInNet(myIpAddress(), "$netsettings{'BLUE_1_NETADDRESS'}", "$netsettings{'BLUE_1_NETMASK'}"))
        return "PROXY $netsettings{'BLUE_1_ADDRESS'}:$proxysettings{'PROXY_PORT'}";
END
            ;
        }
        if ($proxysettings{'ENABLED_GREEN_1'} eq 'on') {
            print FILE "\n    return \"PROXY $netsettings{'GREEN_1_ADDRESS'}:$proxysettings{'PROXY_PORT'}\";\n";
        }
        else {
            print FILE "\n    return \"DIRECT\";\n";
        }
    }
    print FILE "}\n";
    close(FILE);
}

# -------------------------------------------------------------------

sub writeconfigfile
{
    my $authrealm;
    my $delaypools;

    if ($proxysettings{'THROTTLING_GREEN_TOTAL'} eq 'unlimited'
        && $proxysettings{'THROTTLING_GREEN_HOST'} eq 'unlimited'
        && $proxysettings{'THROTTLING_BLUE_TOTAL'} eq 'unlimited'
        && $proxysettings{'THROTTLING_BLUE_HOST'} eq 'unlimited')
    {
        $delaypools = 0;
    }
    else {
        $delaypools = 1;
    }

    if ($proxysettings{'AUTH_REALM'} eq '')
    {
        $authrealm = "IPCop Proxy Server";
    }
    else {
        $authrealm = $proxysettings{'AUTH_REALM'};
    }

    $_ = $proxysettings{'UPSTREAM_PROXY'};
    my ($remotehost, $remoteport) = (/^(?:[a-zA-Z ]+\:\/\/)?(?:[A-Za-z0-9\_\.\-]*?(?:\:[A-Za-z0-9\_\.\-]*?)?\@)?([a-zA-Z0-9\.\_\-]*?)(?:\:([0-9]{1,5}))?(?:\/.*?)?$/);

    if ( (!defined($remoteport)) || $remoteport eq '') {
        $remoteport = 80;
    }

    open(FILE, ">/var/ofw/proxy/squid.conf");
    flock(FILE, 2);
    print FILE <<END
# Do not modify '/var/ofw/proxy/squid.conf' directly since any changes
# you make will be overwritten whenever you resave proxy settings using the
# web interface!
#
# Instead, modify the file '$acl_include' and
# then restart the proxy service using the web interface. Changes made to the
# 'include.acl' file will propagate to the 'squid.conf' file at that time.

shutdown_lifetime 5 seconds
icp_port 0

http_port 127.0.0.1:82
END
    ;

    if ($proxysettings{'ENABLED_GREEN_1'} eq 'on') {
        print FILE "http_port $netsettings{'GREEN_1_ADDRESS'}:$proxysettings{'PROXY_PORT'}";
        if ($proxysettings{'NO_CONNECTION_AUTH'} eq 'on') { print FILE " no-connection-auth" }
        print FILE "\n";
        # intercept port, disables authentication so no need to add no-auth
        if ($proxysettings{'TRANSPARENT_GREEN_1'} eq 'on') { print FILE "http_port $netsettings{'GREEN_1_ADDRESS'}:$http_intercept_port intercept\n" }
    }
    if (($netsettings{'BLUE_COUNT'} >= 1) && ($proxysettings{'ENABLED_BLUE_1'} eq 'on')) {
        print FILE "http_port $netsettings{'BLUE_1_ADDRESS'}:$proxysettings{'PROXY_PORT'}";
        if ($proxysettings{'NO_CONNECTION_AUTH'} eq 'on') { print FILE " no-connection-auth" }
        print FILE "\n";
        # intercept port, disables authentication so no need to add no-auth
        if ($proxysettings{'TRANSPARENT_BLUE_1'} eq 'on') { print FILE "http_port $netsettings{'BLUE_1_ADDRESS'}:$http_intercept_port intercept\n" }
    }
    if ($proxysettings{'ENABLED_OVPN'} eq 'on') {
        my $serverip = NetAddr::IP->new($ovpnsettings{'DOVPN_SUBNET'})->first()->addr();
        print FILE "http_port $serverip:$proxysettings{'PROXY_PORT'}";
        if ($proxysettings{'NO_CONNECTION_AUTH'} eq 'on') { print FILE " no-connection-auth" }
        print FILE "\n";
        # intercept port, disables authentication so no need to add no-auth
        if ($proxysettings{'TRANSPARENT_OVPN'} eq 'on') { print FILE "http_port $serverip:$http_intercept_port intercept\n" }
    }

    if (($proxysettings{'CACHE_SIZE'} > 0) || ($proxysettings{'CACHE_MEM'} > 0)) {
        print FILE "\n";

        if (!-z $acl_dst_nocache_dom) {
            print FILE "acl no_cache_domains dstdomain \"$acl_dst_nocache_dom\"\n";
            print FILE "cache deny no_cache_domains\n";
        }
        if (!-z $acl_dst_nocache_net) {
            print FILE "acl no_cache_ipaddr dst \"$acl_dst_nocache_net\"\n";
            print FILE "cache deny no_cache_ipaddr\n";
        }
        if (!-z $acl_dst_nocache_url) {
            print FILE "acl no_cache_hosts url_regex -i \"$acl_dst_nocache_url\"\n";
            print FILE "cache deny no_cache_hosts\n";
        }
    }

    print FILE <<END

cache_effective_user squid
cache_effective_group squid
umask 022

pid_filename /var/run/squid.pid

cache_mem $proxysettings{'CACHE_MEM'} MB
END
    ;

    unless ($proxysettings{'CACHE_SIZE'} eq '0') {
        print FILE "cache_dir aufs /var/log/cache $proxysettings{'CACHE_SIZE'} $proxysettings{'L1_DIRS'} 256\n\n";
    }

    if (($proxysettings{'ERR_DESIGN'} eq 'ofw') && ($proxysettings{'VISIBLE_HOSTNAME'} eq '')) {
        print FILE "error_directory $errordir.ofw/$proxysettings{'ERR_LANGUAGE'}\n\n";
    } else {
        print FILE "error_directory $errordir/$proxysettings{'ERR_LANGUAGE'}\n\n";
    }

    if ($proxysettings{'OFFLINE_MODE'} eq 'on') {  print FILE "offline_mode on\n\n"; }

    if ((!($proxysettings{'MEM_POLICY'} eq 'LRU')) || (!($proxysettings{'CACHE_POLICY'} eq 'LRU'))) {
        if (!($proxysettings{'MEM_POLICY'} eq 'LRU'))
        {
            print FILE "memory_replacement_policy $proxysettings{'MEM_POLICY'}\n";
        }
        if (!($proxysettings{'CACHE_POLICY'} eq 'LRU'))
        {
            print FILE "cache_replacement_policy $proxysettings{'CACHE_POLICY'}\n";
        }
        print FILE "\n";
    }

    if ($proxysettings{'LOGGING'} eq 'on') {
        my $loganonym = '';
        $loganonym = 'anonym' if ((exists($proxysettings{'LOGUSERNAME'})) && ($proxysettings{'LOGUSERNAME'} eq 'off'));

        print FILE <<END
logformat anonym %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru ANON %Sh/%<a %mt
access_log stdio:/var/log/squid/access.log $loganonym
cache_log /var/log/squid/cache.log
cache_store_log none
END
        ;
        if ($proxysettings{'LOGUSERAGENT'} eq 'on') { print FILE "access_log stdio:\/var\/log\/squid\/user_agent.log useragent\n"; }
        if ($proxysettings{'LOGQUERY'} eq 'on') { print FILE "\nstrip_query_terms off\n"; }
    } else {
        print FILE <<END
access_log stdio:/dev/null
cache_log /dev/null
cache_store_log none
END
    ;}
    print FILE <<END

log_mime_hdrs off
logfile_rotate 0
END
    ;

    if ($proxysettings{'FORWARD_IPADDRESS'} eq 'on')
    {
        print FILE "forwarded_for on\n";
    } else {
        print FILE "forwarded_for off\n";
    }
    if ($proxysettings{'FORWARD_VIA'} eq 'on')
    {
        print FILE "via on\n";
    } else {
        print FILE "via off\n";
    }
    print FILE "\n";

    if ((!($proxysettings{'AUTH_METHOD'} eq 'none')) && (!($proxysettings{'AUTH_METHOD'} eq 'ident')))
    {
        if ($proxysettings{'AUTH_METHOD'} eq 'ncsa')
        {
            print FILE "auth_param basic program $authdir/basic_ncsa_auth $userdb\n";
            print FILE "auth_param basic children $proxysettings{'AUTH_CHILDREN'}\n";
            print FILE "auth_param basic realm $authrealm\n";
            print FILE "auth_param basic credentialsttl $proxysettings{'AUTH_CACHE_TTL'} minutes\n";
            if (!($proxysettings{'AUTH_IPCACHE_TTL'} eq '0')) { print FILE "\nauthenticate_ip_ttl $proxysettings{'AUTH_IPCACHE_TTL'} minutes\n"; }
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'ldap')
        {
            print FILE "auth_param basic program $authdir/basic_ldap_auth -b \"$proxysettings{'LDAP_BASEDN'}\"";
            if (!($proxysettings{'LDAP_BINDDN_USER'} eq '')) { print FILE " -D \"$proxysettings{'LDAP_BINDDN_USER'}\""; }
            if (!($proxysettings{'LDAP_BINDDN_PASS'} eq '')) { print FILE " -w $proxysettings{'LDAP_BINDDN_PASS'}"; }
            if ($proxysettings{'LDAP_TYPE'} eq 'ADS')
            {
                if ($proxysettings{'LDAP_GROUP'} eq '')
                {
                    print FILE " -f \"(\&(objectClass=person)(sAMAccountName=\%s))\"";
                } else {
                    print FILE " -f \"(\&(\&(objectClass=person)(sAMAccountName=\%s))(memberOf=$proxysettings{'LDAP_GROUP'}))\"";
                }
                print FILE " -u sAMAccountName -P";
            }
            if ($proxysettings{'LDAP_TYPE'} eq 'NDS')
            {
                if ($proxysettings{'LDAP_GROUP'} eq '')
                {
                    print FILE " -f \"(\&(objectClass=person)(cn=\%s))\"";
                } else {
                    print FILE " -f \"(\&(\&(objectClass=person)(cn=\%s))(groupMembership=$proxysettings{'LDAP_GROUP'}))\"";
                }
                print FILE " -u cn -P";
            }
            if (($proxysettings{'LDAP_TYPE'} eq 'V2') || ($proxysettings{'LDAP_TYPE'} eq 'V3'))
            {
                if ($proxysettings{'LDAP_GROUP'} eq '')
                {
                    print FILE " -f \"(\&(objectClass=person)(uid=\%s))\"";
                } else {
                    print FILE " -f \"(\&(\&(objectClass=person)(uid=\%s))(posixGroup=$proxysettings{'LDAP_GROUP'}))\"";
                }
                if ($proxysettings{'LDAP_TYPE'} eq 'V2') { print FILE " -v 2"; }
                if ($proxysettings{'LDAP_TYPE'} eq 'V3') { print FILE " -v 3"; }
                print FILE " -u uid -P";
            }
            print FILE " $proxysettings{'LDAP_SERVER'}:$proxysettings{'LDAP_PORT'}\n";
            print FILE "auth_param basic children $proxysettings{'AUTH_CHILDREN'}\n";
            print FILE "auth_param basic realm $authrealm\n";
            print FILE "auth_param basic credentialsttl $proxysettings{'AUTH_CACHE_TTL'} minutes\n";
            if (!($proxysettings{'AUTH_IPCACHE_TTL'} eq '0')) { print FILE "\nauthenticate_ip_ttl $proxysettings{'AUTH_IPCACHE_TTL'} minutes\n"; }
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'ntlm')
        {
            if ($proxysettings{'NTLM_ENABLE_INT_AUTH'} eq 'on')
            {
                print FILE "auth_param ntlm program $authdir/ntlm_smb_lm_auth $proxysettings{'NTLM_DOMAIN'}/$proxysettings{'NTLM_PDC'}";
                if ($proxysettings{'NTLM_BDC'} eq '') { print FILE "\n"; } else { print FILE " $proxysettings{'NTLM_DOMAIN'}/$proxysettings{'NTLM_BDC'}\n"; }
                print FILE "auth_param ntlm children $proxysettings{'AUTH_CHILDREN'}\n";
                if (!($proxysettings{'AUTH_IPCACHE_TTL'} eq '0')) { print FILE "\nauthenticate_ip_ttl $proxysettings{'AUTH_IPCACHE_TTL'} minutes\n"; }
            } else {
                print FILE "auth_param basic program $authdir/msnt_auth\n";
                print FILE "auth_param basic children $proxysettings{'AUTH_CHILDREN'}\n";
                print FILE "auth_param basic realm $authrealm\n";
                print FILE "auth_param basic credentialsttl $proxysettings{'AUTH_CACHE_TTL'} minutes\n";
                if (!($proxysettings{'AUTH_IPCACHE_TTL'} eq '0')) { print FILE "\nauthenticate_ip_ttl $proxysettings{'AUTH_IPCACHE_TTL'} minutes\n"; }

                open(MSNTCONF, ">$ntlmdir/msntauth.conf");
                flock(MSNTCONF,2);
                print MSNTCONF "server $proxysettings{'NTLM_PDC'}";
                if ($proxysettings{'NTLM_BDC'} eq '') { print MSNTCONF " $proxysettings{'NTLM_PDC'}"; } else { print MSNTCONF " $proxysettings{'NTLM_BDC'}"; }
                print MSNTCONF " $proxysettings{'NTLM_DOMAIN'}\n";
                if ($proxysettings{'NTLM_ENABLE_ACL'} eq 'on')
                {
                    if ($proxysettings{'NTLM_USER_ACL'} eq 'positive')
                    {
                        print MSNTCONF "allowusers $ntlmdir/msntauth.allowusers\n";
                    } else {
                        print MSNTCONF "denyusers $ntlmdir/msntauth.denyusers\n";
                    }
                }
                close(MSNTCONF);
            }
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'radius')
        {
            print FILE "auth_param basic program $authdir/basic_radius_auth -h $proxysettings{'RADIUS_SERVER'} -p $proxysettings{'RADIUS_PORT'} ";
            if (!($proxysettings{'RADIUS_IDENTIFIER'} eq '')) { print FILE "-i $proxysettings{'RADIUS_IDENTIFIER'} "; }
            print FILE "-w $proxysettings{'RADIUS_SECRET'}\n";
            print FILE "auth_param basic children $proxysettings{'AUTH_CHILDREN'}\n";
            print FILE "auth_param basic realm $authrealm\n";
            print FILE "auth_param basic credentialsttl $proxysettings{'AUTH_CACHE_TTL'} minutes\n";
            if (!($proxysettings{'AUTH_IPCACHE_TTL'} eq '0')) { print FILE "\nauthenticate_ip_ttl $proxysettings{'AUTH_IPCACHE_TTL'} minutes\n"; }
        }

        print FILE "\n";
        print FILE "acl for_inetusers proxy_auth REQUIRED\n";
        if (($proxysettings{'AUTH_METHOD'} eq 'ntlm') && ($proxysettings{'NTLM_ENABLE_INT_AUTH'} eq 'on') && ($proxysettings{'NTLM_ENABLE_ACL'} eq 'on'))
        {
            if ((!-z "$ntlmdir/msntauth.allowusers") && ($proxysettings{'NTLM_USER_ACL'} eq 'positive'))
            {
                print FILE "acl for_acl_users proxy_auth \"$ntlmdir/msntauth.allowusers\"\n";
            }
            if ((!-z "$ntlmdir/msntauth.denyusers") && ($proxysettings{'NTLM_USER_ACL'} eq 'negative'))
            {
                print FILE "acl for_acl_users proxy_auth \"$ntlmdir/msntauth.denyusers\"\n";
            }
        }
        if (($proxysettings{'AUTH_METHOD'} eq 'radius') && ($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on'))
        {
            if ((!-z "$raddir/radauth.allowusers") && ($proxysettings{'RADIUS_USER_ACL'} eq 'positive'))
            {
                print FILE "acl for_acl_users proxy_auth \"$raddir/radauth.allowusers\"\n";
            }
            if ((!-z "$raddir/radauth.denyusers") && ($proxysettings{'RADIUS_USER_ACL'} eq 'negative'))
            {
                print FILE "acl for_acl_users proxy_auth \"$raddir/radauth.denyusers\"\n";
            }
        }
        if ($proxysettings{'AUTH_METHOD'} eq 'ncsa')
        {
            print FILE "\n";
            if (!-z $extgrp) { print FILE "acl for_extended_users proxy_auth \"$extgrp\"\n"; }
            if (!-z $disgrp) { print FILE "acl for_disabled_users proxy_auth \"$disgrp\"\n"; }
        }
        if (!($proxysettings{'AUTH_MAX_USERIP'} eq '')) { print FILE "\nacl concurrent max_user_ip -s $proxysettings{'AUTH_MAX_USERIP'}\n"; }
        print FILE "\n";

        if (!-z $acl_dst_noauth_net) { print FILE "acl to_ipaddr_without_auth dst \"$acl_dst_noauth_net\"\n"; }
        if (!-z $acl_dst_noauth_dom) { print FILE "acl to_domains_without_auth dstdomain \"$acl_dst_noauth_dom\"\n"; }
        if (!-z $acl_dst_noauth_url) { print FILE "acl to_hosts_without_auth url_regex -i \"$acl_dst_noauth_url\"\n"; }
        print FILE "\n";
    }

    if ($proxysettings{'AUTH_METHOD'} eq 'ident')
    {
        if ($proxysettings{'IDENT_REQUIRED'} eq 'on')
        {
            print FILE "acl for_inetusers ident REQUIRED\n";
        }
        if ($proxysettings{'IDENT_ENABLE_ACL'} eq 'on')
        {
            if ((!-z "$identdir/identauth.allowusers") && ($proxysettings{'IDENT_USER_ACL'} eq 'positive'))
            {
                print FILE "acl for_acl_users ident_regex -i \"$identdir/identauth.allowusers\"\n\n";
            }
            if ((!-z "$identdir/identauth.denyusers") && ($proxysettings{'IDENT_USER_ACL'} eq 'negative'))
            {
                print FILE "acl for_acl_users ident_regex -i \"$identdir/identauth.denyusers\"\n\n";
            }
        }
        if (!-z $acl_dst_noauth_net) { print FILE "acl to_ipaddr_without_auth dst \"$acl_dst_noauth_net\"\n"; }
        if (!-z $acl_dst_noauth_dom) { print FILE "acl to_domains_without_auth dstdomain \"$acl_dst_noauth_dom\"\n"; }
        if (!-z $acl_dst_noauth_url) { print FILE "acl to_hosts_without_auth url_regex -i \"$acl_dst_noauth_url\"\n"; }
        print FILE "\n";
    }

    if (($delaypools) && (!-z $acl_dst_throttle)) {
        print FILE "acl for_throttled_urls url_regex -i \"$acl_dst_throttle\"\n\n";
    }

    if ($proxysettings{'ENABLE_BROWSER_CHECK'} eq 'on') { print FILE "acl with_allowed_useragents browser $browser_regexp\n\n"; }

    print FILE "acl within_timeframe time ";
    if ($proxysettings{'TIME_MON'} eq 'on') { print FILE "M"; }
    if ($proxysettings{'TIME_TUE'} eq 'on') { print FILE "T"; }
    if ($proxysettings{'TIME_WED'} eq 'on') { print FILE "W"; }
    if ($proxysettings{'TIME_THU'} eq 'on') { print FILE "H"; }
    if ($proxysettings{'TIME_FRI'} eq 'on') { print FILE "F"; }
    if ($proxysettings{'TIME_SAT'} eq 'on') { print FILE "A"; }
    if ($proxysettings{'TIME_SUN'} eq 'on') { print FILE "S"; }
    print FILE " $proxysettings{'TIME_FROM_HOUR'}:";
    print FILE "$proxysettings{'TIME_FROM_MINUTE'}-";
    print FILE "$proxysettings{'TIME_TO_HOUR'}:";
    print FILE "$proxysettings{'TIME_TO_MINUTE'}\n\n";

    if ((!-z $mimetypes) && ($proxysettings{'ENABLE_MIME_FILTER'} eq 'on')) {
        print FILE "acl blocked_mimetypes rep_mime_type \"$mimetypes\"\n";
        if (!-z $acl_dst_mime_exceptions_dom) { print FILE "acl mime_exception_domains dstdomain \"$acl_dst_mime_exceptions_dom\")\n"; }
        if (!-z $acl_dst_mime_exceptions_net) { print FILE "acl mime_exception_ipaddr dst \"$acl_dst_mime_exceptions_net\")\n"; }
        if (!-z $acl_dst_mime_exceptions_url) { print FILE "acl mime_exception_hosts url_regex -i \"$acl_dst_mime_exceptions_url\")\n"; }
        print FILE "\n";
    }

    print FILE <<END
acl manager url_regex -i ^cache_object:// /squid-internal-mgr/
acl localhost src 127.0.0.1/32
END
    ;
    open(PORTS,"$acl_ports_ssl");
    @temp = <PORTS>;
    close PORTS;
    if (@temp) {
        foreach (@temp) {
            if (substr($_, 0, 1) eq '#') {
                print FILE "$_";
            }
            else {
                print FILE "acl SSL_ports port $_";
            }
        }
    }
    open(PORTS,"$acl_ports_safe");
    @temp = <PORTS>;
    close PORTS;
    if (@temp) {
        foreach (@temp) {
            if (substr($_, 0, 1) eq '#') {
                print FILE "$_";
            }
            else {
                print FILE "acl Safe_ports port $_";
            }
        }
    }
    print FILE <<END

acl Ofw_http  port $http_port
acl Ofw_https port $https_port
acl Ofw_ips              dst $netsettings{'GREEN_1_ADDRESS'}
acl Ofw_networks         src "$acl_src_networks"
acl Ofw_servers          dst "$acl_src_subnets"
END
    ;
    print FILE "acl Ofw_green_network    src " . NetAddr::IP->new ("$netsettings{'GREEN_1_NETADDRESS'}/$netsettings{'GREEN_1_NETMASK'}") . "\n";
    print FILE "acl Ofw_green_servers    dst " . NetAddr::IP->new ("$netsettings{'GREEN_1_NETADDRESS'}/$netsettings{'GREEN_1_NETMASK'}") . "\n";
    if ($netsettings{'BLUE_COUNT'} >= 1) { print FILE "acl Ofw_blue_network     src " . NetAddr::IP->new ("$netsettings{'BLUE_1_NETADDRESS'}/$netsettings{'BLUE_1_NETMASK'}") . "\n"; }
    if ($netsettings{'BLUE_COUNT'} >= 1) { print FILE "acl Ofw_blue_servers     dst " . NetAddr::IP->new ("$netsettings{'BLUE_1_NETADDRESS'}/$netsettings{'BLUE_1_NETMASK'}") . "\n"; }
    if (!-z $acl_src_banned_ip) { print FILE "acl Ofw_banned_ips       src \"$acl_src_banned_ip\"\n"; }
    if (!-z $acl_src_banned_mac) { print FILE "acl Ofw_banned_mac       arp \"$acl_src_banned_mac\"\n"; }
    if (!-z $acl_src_unrestricted_ip) { print FILE "acl Ofw_unrestricted_ips src \"$acl_src_unrestricted_ip\"\n"; }
    if (!-z $acl_src_unrestricted_mac) { print FILE "acl Ofw_unrestricted_mac arp \"$acl_src_unrestricted_mac\"\n"; }
    print FILE <<END
acl CONNECT method CONNECT
END
    ;

    if ($proxysettings{'CLASSROOM_EXT'} eq 'on') {
        print FILE <<END

#Classroom extensions
acl Ofw_no_access_ips src "$acl_src_noaccess_ip"
acl Ofw_no_access_mac arp "$acl_src_noaccess_mac"
END
        ;
        print FILE "deny_info ";
        if ((($proxysettings{'ERR_DESIGN'} eq 'ofw') && (-e "$errordir.ofw/$proxysettings{'ERR_LANGUAGE'}/ERR_ACCESS_DISABLED")) ||
            (($proxysettings{'ERR_DESIGN'} eq 'squid') && (-e "$errordir/$proxysettings{'ERR_LANGUAGE'}/ERR_ACCESS_DISABLED")))
        {
            print FILE "ERR_ACCESS_DISABLED";
        } else {
            print FILE "ERR_ACCESS_DENIED";
        }
        print FILE " Ofw_no_access_ips\n";
        print FILE "deny_info ";
        if ((($proxysettings{'ERR_DESIGN'} eq 'ofw') && (-e "$errordir.ofw/$proxysettings{'ERR_LANGUAGE'}/ERR_ACCESS_DISABLED")) ||
            (($proxysettings{'ERR_DESIGN'} eq 'squid') && (-e "$errordir/$proxysettings{'ERR_LANGUAGE'}/ERR_ACCESS_DISABLED")))
        {
            print FILE "ERR_ACCESS_DISABLED";
        } else {
            print FILE "ERR_ACCESS_DENIED";
        }
        print FILE " Ofw_no_access_mac\n";

        print FILE <<END
http_access deny Ofw_no_access_ips
http_access deny Ofw_no_access_mac
END
    ;
    }

    #Insert acl file and replace __VAR__ with correct values
    my $blue_net = ''; #BLUE empty by default
    my $blue_ip = '';
    if (($netsettings{'BLUE_COUNT'} >= 1) && ($proxysettings{'ENABLED_BLUE_1'} eq 'on')) {
        $blue_net = "$netsettings{'BLUE_1_NETADDRESS'}/$netsettings{'BLUE_1_NETMASK'}";
        $blue_ip  = "$netsettings{'BLUE_1_ADDRESS'}";
    }
    if (!-z $acl_include) {
        open (ACL, "$acl_include");
        print FILE "\n#Start of custom includes\n\n";
        while (<ACL>) {
            $_ =~ s/__GREEN_IP__/$netsettings{'GREEN_1_ADDRESS'}/;
            $_ =~ s/__GREEN_NET__/$netsettings{'GREEN_1_NETADDRESS'}\/$netsettings{'GREEN_1_NETMASK'}/;
            $_ =~ s/__BLUE_IP__/$netsettings{'BLUE_1_ADDRESS'}/;
            $_ =~ s/__BLUE_NET__/$netsettings{'BLUE_1_NETADDRESS'}\/$netsettings{'BLUE_1_NETMASK'}/;
            $_ =~ s/__PROXY_PORT__/$proxysettings{'PROXY_PORT'}/;
            print FILE $_;
        }
        print FILE "\n#End of custom includes\n";
        close (ACL);
    }
    if ((!-z $extgrp) && ($proxysettings{'AUTH_METHOD'} eq 'ncsa') && ($proxysettings{'NCSA_BYPASS_REDIR'} eq 'on')) {
        print FILE "\nredirector_access deny for_extended_users\n"; 
    }

    print FILE <<END

#Access to squid manager from localhost:
http_access allow         localhost manager  
http_access deny          manager
#local machine, no restriction
http_access allow         localhost

#GUI admin if local machine connects
http_access allow         Ofw_ips Ofw_networks Ofw_http
http_access allow CONNECT Ofw_ips Ofw_networks Ofw_https

#Deny not web services
http_access deny          !Safe_ports
http_access deny  CONNECT !SSL_ports

END
    ;

if ($proxysettings{'AUTH_METHOD'} eq 'ident')
{
print FILE "#Set ident ACLs\n";
if (!-z $identhosts)
    {
        print FILE "acl on_ident_aware_hosts src \"$identhosts\"\n";
        print FILE "ident_lookup_access allow on_ident_aware_hosts\n";
        print FILE "ident_lookup_access deny all\n";
    } else {
        print FILE "ident_lookup_access allow all\n";
    }
    print FILE "ident_timeout $proxysettings{'IDENT_TIMEOUT'} seconds\n\n";
}

if ($delaypools) {
    print FILE "#Set download throttling\n";

    if ($netsettings{'BLUE_COUNT'} >= 1) {
        print FILE "delay_pools 2\n";
    }
    else {
        print FILE "delay_pools 1\n";
    }

    print FILE "delay_class 1 3\n";
    if ($netsettings{'BLUE_COUNT'} >= 1) {
        print FILE "delay_class 2 3\n";
    }

    print FILE "delay_parameters 1 ";
    if ($proxysettings{'THROTTLING_GREEN_TOTAL'} eq 'unlimited') {
        print FILE "-1/-1";
    }
    else {
        print FILE $proxysettings{'THROTTLING_GREEN_TOTAL'} * 125;
        print FILE "/";
        print FILE $proxysettings{'THROTTLING_GREEN_TOTAL'} * 250;
    }

    print FILE " -1/-1 ";
    if ($proxysettings{'THROTTLING_GREEN_HOST'} eq 'unlimited')
    {
        print FILE "-1/-1";
    }
    else {
        print FILE $proxysettings{'THROTTLING_GREEN_HOST'} * 125;
        print FILE "/";
        print FILE $proxysettings{'THROTTLING_GREEN_HOST'} * 250;
    }
    print FILE "\n";

    if ($netsettings{'BLUE_COUNT'} >= 1)
    {
        print FILE "delay_parameters 2 ";

        if ($proxysettings{'THROTTLING_BLUE_TOTAL'} eq 'unlimited')
        {
            print FILE "-1/-1";
        }
        else {
            print FILE $proxysettings{'THROTTLING_BLUE_TOTAL'} * 125;
            print FILE "/";
            print FILE $proxysettings{'THROTTLING_BLUE_TOTAL'} * 250;
        }

        print FILE " -1/-1 ";

        if ($proxysettings{'THROTTLING_BLUE_HOST'} eq 'unlimited') {
            print FILE "-1/-1";
        }
        else {
            print FILE $proxysettings{'THROTTLING_BLUE_HOST'} * 125;
            print FILE "/";
            print FILE $proxysettings{'THROTTLING_BLUE_HOST'} * 250;
        }
        print FILE "\n";
    }

    print FILE "delay_access 1 deny  Ofw_ips\n";
    if (!-z $acl_src_unrestricted_ip)  { print FILE "delay_access 1 deny  Ofw_unrestricted_ips\n"; }
    if (!-z $acl_src_unrestricted_mac) { print FILE "delay_access 1 deny  Ofw_unrestricted_mac\n"; }
    if (($proxysettings{'AUTH_METHOD'} eq 'ncsa') && (!-z $extgrp)) {
        print FILE "delay_access 1 deny  for_extended_users\n";
    }

    if ($netsettings{'BLUE_COUNT'} >= 1)
    {
        print FILE "delay_access 1 allow Ofw_green_network";
        if (!-z $acl_dst_throttle) {
            print FILE " for_throttled_urls";
        }
        print FILE "\n";
        print FILE "delay_access 1 deny  all\n";
    }
    else {
        print FILE "delay_access 1 allow all";
        if (!-z $acl_dst_throttle) {
            print FILE " for_throttled_urls";
        }
        print FILE "\n";
    }

    if ($netsettings{'BLUE_COUNT'} >= 1)
    {
        print FILE "delay_access 2 deny  Ofw_ips\n";
        if (!-z $acl_src_unrestricted_ip)  { print FILE "delay_access 2 deny  Ofw_unrestricted_ips\n"; }
        if (!-z $acl_src_unrestricted_mac) { print FILE "delay_access 2 deny  Ofw_unrestricted_mac\n"; }
        if (($proxysettings{'AUTH_METHOD'} eq 'ncsa') && (!-z $extgrp)) { print FILE "delay_access 2 deny  for_extended_users\n"; }
        print FILE "delay_access 2 allow Ofw_blue_network";
        if (!-z $acl_dst_throttle) { print FILE " for_throttled_urls"; }
        print FILE "\n";
        print FILE "delay_access 2 deny  all\n";
    }

    print FILE "delay_initial_bucket_level 100\n";
    print FILE "\n";
}

if ($proxysettings{'NO_PROXY_LOCAL'} eq 'on')
{
    print FILE "#Prevent internal proxy access\n";
    print FILE "http_access deny Ofw_servers\n\n";
}

if ($proxysettings{'NO_PROXY_LOCAL_GREEN'} eq 'on')
{
    print FILE "#Prevent internal proxy access to Green\n";
    print FILE "http_access deny Ofw_green_servers !Ofw_green_network\n\n";
}

if (($proxysettings{'NO_PROXY_LOCAL_BLUE'} eq 'on') && ($netsettings{'BLUE_COUNT'} >= 1))
{
    print FILE "#Prevent internal proxy access from Blue\n";
    print FILE "http_access allow Ofw_blue_network Ofw_blue_servers\n";
    print FILE "http_access deny  Ofw_blue_network Ofw_servers\n\n";
}

    print FILE <<END
#Set custom configured ACLs
END
    ;
    if (!-z $acl_src_banned_ip) { print FILE "http_access deny  Ofw_banned_ips\n"; }
    if (!-z $acl_src_banned_mac) { print FILE "http_access deny  Ofw_banned_mac\n"; }

    if ((!-z $acl_dst_noauth) && (!($proxysettings{'AUTH_METHOD'} eq 'none')))
    {
        if (!-z $acl_src_unrestricted_ip)
        {
            if (!-z $acl_dst_noauth_net) { print FILE "http_access allow Ofw_unrestricted_ips to_ipaddr_without_auth\n"; }
            if (!-z $acl_dst_noauth_dom) { print FILE "http_access allow Ofw_unrestricted_ips to_domains_without_auth\n"; }
            if (!-z $acl_dst_noauth_url) { print FILE "http_access allow Ofw_unrestricted_ips to_hosts_without_auth\n"; }
        }
        if (!-z $acl_src_unrestricted_mac)
        {
            if (!-z $acl_dst_noauth_net) { print FILE "http_access allow Ofw_unrestricted_mac to_ipaddr_without_auth\n"; }
            if (!-z $acl_dst_noauth_dom) { print FILE "http_access allow Ofw_unrestricted_mac to_domains_without_auth\n"; }
            if (!-z $acl_dst_noauth_url) { print FILE "http_access allow Ofw_unrestricted_mac to_hosts_without_auth\n"; }
        }
        if (!-z $acl_dst_noauth_net)
        {
            print FILE "http_access allow Ofw_networks";
            if ($proxysettings{'TIME_ACCESS_MODE'} eq 'deny') {
                print FILE " !within_timeframe";
            } else {
                print FILE " within_timeframe"; }
            if ($proxysettings{'ENABLE_BROWSER_CHECK'} eq 'on') { print FILE " with_allowed_useragents"; }
            print FILE " to_ipaddr_without_auth\n";
        }
        if (!-z $acl_dst_noauth_dom)
        {
            print FILE "http_access allow Ofw_networks";
            if ($proxysettings{'TIME_ACCESS_MODE'} eq 'deny') {
                print FILE " !within_timeframe";
            } else {
                print FILE " within_timeframe"; }
            if ($proxysettings{'ENABLE_BROWSER_CHECK'} eq 'on') { print FILE " with_allowed_useragents"; }
            print FILE " to_domains_without_auth\n";
        }
        if (!-z $acl_dst_noauth_url)
        {
            print FILE "http_access allow Ofw_networks";
            if ($proxysettings{'TIME_ACCESS_MODE'} eq 'deny') {
                print FILE " !within_timeframe";
            } else {
                print FILE " within_timeframe"; }
            if ($proxysettings{'ENABLE_BROWSER_CHECK'} eq 'on') { print FILE " with_allowed_useragents"; }
            print FILE " to_hosts_without_auth\n";
        }
    }

    if (($proxysettings{'AUTH_METHOD'} eq 'ident') && ($proxysettings{'IDENT_REQUIRED'} eq 'on') && ($proxysettings{'AUTH_ALWAYS_REQUIRED'} eq 'on'))
    {
        print FILE "http_access deny  !for_inetusers";
        if (!-z $identhosts) { print FILE " on_ident_aware_hosts"; }
        print FILE "\n";
    }

    if (
         ($proxysettings{'AUTH_METHOD'} eq 'ident') &&
         ($proxysettings{'AUTH_ALWAYS_REQUIRED'} eq 'on') &&
         ($proxysettings{'IDENT_ENABLE_ACL'} eq 'on') &&
         ($proxysettings{'IDENT_USER_ACL'} eq 'negative') &&
         (!-z "$identdir/identauth.denyusers")
       )
    {
        print FILE "http_access deny  for_acl_users";
        if (($proxysettings{'AUTH_METHOD'} eq 'ident') && (!-z "$identdir/hosts")) { print FILE " on_ident_aware_hosts"; }
        print FILE "\n";
    }

    if (!-z $acl_src_unrestricted_ip)
    {
        print FILE "http_access allow Ofw_unrestricted_ips";
        if ($proxysettings{'AUTH_ALWAYS_REQUIRED'} eq 'on')
        {
            if ($proxysettings{'AUTH_METHOD'} eq 'ncsa')
            {
                if (!-z $disgrp) { print FILE " !for_disabled_users"; } else { print FILE " for_inetusers"; }
            }
            if (($proxysettings{'AUTH_METHOD'} eq 'ldap') || (($proxysettings{'AUTH_METHOD'} eq 'ntlm') && ($proxysettings{'NTLM_ENABLE_INT_AUTH'} eq 'off')) || ($proxysettings{'AUTH_METHOD'} eq 'radius'))
            {
                print FILE " for_inetusers";
            }
            if (($proxysettings{'AUTH_METHOD'} eq 'ntlm') && ($proxysettings{'NTLM_ENABLE_INT_AUTH'} eq 'on'))
            {
                if ($proxysettings{'NTLM_ENABLE_ACL'} eq 'on')
                {
                    if (($proxysettings{'NTLM_USER_ACL'} eq 'positive') && (!-z "$ntlmdir/msntauth.allowusers"))
                    {
                        print FILE " for_acl_users";
                    }
                    if (($proxysettings{'NTLM_USER_ACL'} eq 'negative') && (!-z "$ntlmdir/msntauth.denyusers"))
                    {
                        print FILE " !for_acl_users";
                    }
                } else { print FILE " for_inetusers"; }
            }
            if (($proxysettings{'AUTH_METHOD'} eq 'radius') && ($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on'))
            {
                if ($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on')
                {
                    if (($proxysettings{'RADIUS_USER_ACL'} eq 'positive') && (!-z "$raddir/radauth.allowusers"))
                    {
                        print FILE " for_acl_users";
                    }
                    if (($proxysettings{'RADIUS_USER_ACL'} eq 'negative') && (!-z "$raddir/radauth.denyusers"))
                    {
                        print FILE " !for_acl_users";
                    }
                } else { print FILE " for_inetusers"; }
            }
        }
        print FILE "\n";
    }

    if (!-z $acl_src_unrestricted_mac)
    {
        print FILE "http_access allow Ofw_unrestricted_mac";
        if ($proxysettings{'AUTH_ALWAYS_REQUIRED'} eq 'on')
        {
            if ($proxysettings{'AUTH_METHOD'} eq 'ncsa')
            {
                if (!-z $disgrp) { print FILE " !for_disabled_users"; } else { print FILE " for_inetusers"; }
            }
            if (($proxysettings{'AUTH_METHOD'} eq 'ldap') || (($proxysettings{'AUTH_METHOD'} eq 'ntlm') && ($proxysettings{'NTLM_ENABLE_INT_AUTH'} eq 'off')) || ($proxysettings{'AUTH_METHOD'} eq 'radius'))
            {
                print FILE " for_inetusers";
            }
            if (($proxysettings{'AUTH_METHOD'} eq 'ntlm') && ($proxysettings{'NTLM_ENABLE_INT_AUTH'} eq 'on'))
            {
                if ($proxysettings{'NTLM_ENABLE_ACL'} eq 'on')
                {
                    if (($proxysettings{'NTLM_USER_ACL'} eq 'positive') && (!-z "$ntlmdir/msntauth.allowusers"))
                    {
                        print FILE " for_acl_users";
                    }
                    if (($proxysettings{'NTLM_USER_ACL'} eq 'negative') && (!-z "$ntlmdir/msntauth.denyusers"))
                    {
                        print FILE " !for_acl_users";
                    }
                } else { print FILE " for_inetusers"; }
            }
            if (($proxysettings{'AUTH_METHOD'} eq 'radius') && ($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on'))
            {
                if ($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on')
                {
                    if (($proxysettings{'RADIUS_USER_ACL'} eq 'positive') && (!-z "$raddir/radauth.allowusers"))
                    {
                        print FILE " for_acl_users";
                    }
                    if (($proxysettings{'RADIUS_USER_ACL'} eq 'negative') && (!-z "$raddir/radauth.denyusers"))
                    {
                        print FILE " !for_acl_users";
                    }
                } else { print FILE " for_inetusers"; }
            }
        }
        print FILE "\n";
    }

    if ($proxysettings{'AUTH_METHOD'} eq 'ncsa')
    {
        if (!-z $disgrp) { print FILE "http_access deny  for_disabled_users\n"; }
        if (!-z $extgrp) { print FILE "http_access allow Ofw_networks for_extended_users\n"; }
    }

    if (
        (
         ($proxysettings{'AUTH_METHOD'} eq 'ntlm') &&
         ($proxysettings{'NTLM_ENABLE_INT_AUTH'} eq 'on') &&
         ($proxysettings{'NTLM_ENABLE_ACL'} eq 'on') &&
         ($proxysettings{'NTLM_USER_ACL'} eq 'negative') &&
         (!-z "$ntlmdir/msntauth.denyusers")
        )
        ||
        (
         ($proxysettings{'AUTH_METHOD'} eq 'radius') &&
         ($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on') &&
         ($proxysettings{'RADIUS_USER_ACL'} eq 'negative') &&
         (!-z "$raddir/radauth.denyusers")
        )
        ||
        (
         ($proxysettings{'AUTH_METHOD'} eq 'ident') &&
         ($proxysettings{'AUTH_ALWAYS_REQUIRED'} eq 'off') &&
         ($proxysettings{'IDENT_ENABLE_ACL'} eq 'on') &&
         ($proxysettings{'IDENT_USER_ACL'} eq 'negative') &&
         (!-z "$identdir/identauth.denyusers")
        )
       )
    {
        print FILE "http_access deny  for_acl_users";
        if (($proxysettings{'AUTH_METHOD'} eq 'ident') && (!-z "$identdir/hosts")) { print FILE " on_ident_aware_hosts"; }
        print FILE "\n";
    }

    if (($proxysettings{'AUTH_METHOD'} eq 'ident') && ($proxysettings{'IDENT_REQUIRED'} eq 'on') && (!-z "$identhosts"))
    {
        print FILE "http_access allow";
        if ($proxysettings{'TIME_ACCESS_MODE'} eq 'deny') {
            print FILE " !within_timeframe";
        } else {
            print FILE " within_timeframe"; }
        if ($proxysettings{'ENABLE_BROWSER_CHECK'} eq 'on') { print FILE " with_allowed_useragents"; }
        print FILE " !on_ident_aware_hosts\n";
    }

    print FILE "http_access allow Ofw_networks";
    if (
        (
         ($proxysettings{'AUTH_METHOD'} eq 'ntlm') &&
         ($proxysettings{'NTLM_ENABLE_INT_AUTH'} eq 'on') &&
         ($proxysettings{'NTLM_ENABLE_ACL'} eq 'on') &&
         ($proxysettings{'NTLM_USER_ACL'} eq 'positive') &&
         (!-z "$ntlmdir/msntauth.allowusers")
        )
        ||
        (
         ($proxysettings{'AUTH_METHOD'} eq 'radius') &&
         ($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on') &&
         ($proxysettings{'RADIUS_USER_ACL'} eq 'positive') &&
         (!-z "$raddir/radauth.allowusers")
        )
        ||
        (
         ($proxysettings{'AUTH_METHOD'} eq 'ident') &&
         ($proxysettings{'IDENT_REQUIRED'} eq 'on') &&
         ($proxysettings{'IDENT_ENABLE_ACL'} eq 'on') &&
         ($proxysettings{'IDENT_USER_ACL'} eq 'positive') &&
         (!-z "$identdir/identauth.allowusers")
        )
       )
    {
        print FILE " for_acl_users";
    } elsif (((!($proxysettings{'AUTH_METHOD'} eq 'none')) && (!($proxysettings{'AUTH_METHOD'} eq 'ident'))) ||
        (($proxysettings{'AUTH_METHOD'} eq 'ident') && ($proxysettings{'IDENT_REQUIRED'} eq 'on'))) {
        print FILE " for_inetusers";
    }
    if ((!($proxysettings{'AUTH_MAX_USERIP'} eq '')) && (!($proxysettings{'AUTH_METHOD'} eq 'none')) && (!($proxysettings{'AUTH_METHOD'} eq 'ident')))
    {
        print FILE " !concurrent";
    }
    if ($proxysettings{'TIME_ACCESS_MODE'} eq 'deny') {
        print FILE " !within_timeframe";
    } else {
        print FILE " within_timeframe"; }
    if ($proxysettings{'ENABLE_BROWSER_CHECK'} eq 'on') { print FILE " with_allowed_useragents"; }
    print FILE "\n";

    print FILE "http_access deny  all\n\n";

    if (($proxysettings{'FORWARD_IPADDRESS'} eq 'off') || ($proxysettings{'FORWARD_VIA'} eq 'off') ||
        (!($proxysettings{'FAKE_USERAGENT'} eq '')) || (!($proxysettings{'FAKE_REFERER'} eq '')))
    {
        print FILE "#Strip HTTP Header\n";

        if ($proxysettings{'FORWARD_IPADDRESS'} eq 'off')
        {
            print FILE "request_header_access X-Forwarded-For deny all\n";
        }
        if ($proxysettings{'FORWARD_VIA'} eq 'off')
        {
            print FILE "request_header_access Via deny all\n";
        }
        if (!($proxysettings{'FAKE_USERAGENT'} eq ''))
        {
            print FILE "request_header_access User-Agent deny all\n";
        }
        if (!($proxysettings{'FAKE_REFERER'} eq ''))
        {
            print FILE "request_header_access Referer deny all\n";
        }

        print FILE "\n";

        if ((!($proxysettings{'FAKE_USERAGENT'} eq '')) || (!($proxysettings{'FAKE_REFERER'} eq '')))
        {
            if (!($proxysettings{'FAKE_USERAGENT'} eq ''))
            {
                print FILE "header_replace User-Agent $proxysettings{'FAKE_USERAGENT'}\n";
            }
            if (!($proxysettings{'FAKE_REFERER'} eq ''))
            {
                print FILE "header_replace Referer $proxysettings{'FAKE_REFERER'}\n";
            }
            print FILE "\n";
        }
    }

    if ($proxysettings{'SUPPRESS_VERSION'} eq 'on') { print FILE "httpd_suppress_version_string on\n\n" }

    if ((!-z $mimetypes) && ($proxysettings{'ENABLE_MIME_FILTER'} eq 'on')) {
        if (!-z $acl_src_unrestricted_ip)  { print FILE "http_reply_access allow Ofw_unrestricted_ips\n"; }
        if (!-z $acl_src_unrestricted_mac) { print FILE "http_reply_access allow Ofw_unrestricted_mac\n"; }
        if ($proxysettings{'AUTH_METHOD'} eq 'ncsa')
        {
            if (!-z $extgrp) { print FILE "http_reply_access allow for_extended_users\n"; }
        }
        if (!-z $acl_dst_mime_exceptions_dom) { print FILE "http_reply_access allow mime_exception_domains\n"; }
        if (!-z $acl_dst_mime_exceptions_net) { print FILE "http_reply_access allow mime_exception_ipaddr\n"; }
        if (!-z $acl_dst_mime_exceptions_url) { print FILE "http_reply_access allow mime_exception_hosts\n"; }
        print FILE "http_reply_access deny  blocked_mimetypes\n";
        print FILE "http_reply_access allow all\n\n";
    }

    if (($proxysettings{'CACHE_SIZE'} > 0) || ($proxysettings{'CACHE_MEM'} > 0)) {
        print FILE <<END
maximum_object_size $proxysettings{'MAX_SIZE'} KB
minimum_object_size $proxysettings{'MIN_SIZE'} KB

END
        ;
    }
    else {
        print FILE "cache deny all\n\n";
    }

    print FILE <<END
request_body_max_size $proxysettings{'MAX_OUTGOING_SIZE'} KB
END
    ;
    if ($proxysettings{'MAX_INCOMING_SIZE'} > 0) {
        if (!-z $acl_src_unrestricted_ip) { print FILE "reply_body_max_size none Ofw_unrestricted_ips\n"; }
        if (!-z $acl_src_unrestricted_mac) { print FILE "reply_body_max_size none Ofw_unrestricted_mac\n"; }
        if ($proxysettings{'AUTH_METHOD'} eq 'ncsa')
        {
            if (!-z $extgrp) { print FILE "reply_body_max_size none for_extended_users\n"; }
        }
    }
    if ($proxysettings{'MAX_INCOMING_SIZE'} == 0) {
        $replybodymaxsize = 'none';
    }
    else {
        $replybodymaxsize = "$proxysettings{'MAX_INCOMING_SIZE'} KB";
    }

    print FILE "reply_body_max_size $replybodymaxsize all\n\n";

    print FILE "visible_hostname";
    if ($proxysettings{'VISIBLE_HOSTNAME'} eq '')
    {
        print FILE " $mainsettings{'HOSTNAME'}.$mainsettings{'DOMAINNAME'}\n\n";
    } else {
        print FILE " $proxysettings{'VISIBLE_HOSTNAME'}\n\n";
    }

    if (!($proxysettings{'ADMIN_MAIL_ADDRESS'} eq '')) { print FILE "cache_mgr $proxysettings{'ADMIN_MAIL_ADDRESS'}\n\n"; }

    # Write the parent proxy info, if needed.
    if ($remotehost ne '') {
        print FILE "cache_peer $remotehost parent $remoteport 3130 default no-query";

        # Enter authentication for the parent cache. Option format is
        # login=*:password          ($proxysettings{'FORWARD_USERNAME'} eq 'on')
        # login=PASS                ($proxysettings{'UPSTREAM_USER'}='PASS')
        # login=<user>:<password>   ($proxysettings{'UPSTREAM_USER'}='<user>')
        if ($proxysettings{'FORWARD_USERNAME'} eq 'on') {
            print FILE " login=*:password";
        }
        elsif (($proxysettings{'UPSTREAM_USER'} ne '')) {
            print FILE " login=$proxysettings{'UPSTREAM_USER'}";
            if ($proxysettings{'UPSTREAM_USER'} ne 'PASS') {
                print FILE ":$proxysettings{'UPSTREAM_PASSWORD'}";
            }
        }

        print FILE "\nalways_direct allow Ofw_ips\n";
        print FILE "never_direct  allow all\n\n";
    }

    if (($proxysettings{'ENABLE_REDIRECTOR'} eq 'on') && ($activeredirectors > 0)) {
        print FILE <<END
url_rewrite_program $redirectwrapper
url_rewrite_children $proxysettings{'CHILDREN'} startup=1 idle=1 concurrency=0
url_rewrite_access deny manager
url_rewrite_access deny Ofw_ips
url_rewrite_access allow all

END
        ;
    }

    close FILE;
}

# -------------------------------------------------------------------
