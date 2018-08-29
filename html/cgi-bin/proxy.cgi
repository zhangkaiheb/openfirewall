#!/usr/bin/perl
#
# openfirewall CGIs - proxy.cgi: web proxy service configuration
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
# (c) 2004-2009 marco.s - http://www.advproxy.net
# (c) 2009-2015 The Openfirewall Team
#
# $Id: proxy.cgi 7770 2015-01-06 09:08:19Z owes $
#

# Add entry in menu
# MENUENTRY services 010 "proxy" "web proxy configuration"
#
# Make sure translation exists $Lang::tr{'proxy'}

use strict;
use NetAddr::IP;

# enable only the following on debugging purpose
#use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

# enable(==1)/disable(==0) HTML Form debugging
my $debugFormparams = 0;

my @squidversion = `/usr/sbin/squid -v`;

my %proxysettings=();
my %netsettings=();
my %ovpnsettings=();
my $ovpnactive = 0;

my %checked=();
my %selected=();

my @throttle_limits=(64,128,256,384,512,1024,2048,3072,5120,8192,10240);
my $throttle_binary="7z|bz2|bin|cab|dmg|exe|gz|rar|sea|tar|tgz|zip";
my $throttle_dskimg="b5t|bin|bwt|ccd|cdi|cue|flp|gho|img|iso|mds|nrg|pqi|raw|tib";
my $throttle_mmedia="aiff?|asf|avi|divx|flv|mov|mp(3|4)|mpe?g|qt|ra?m";

my $def_ports_safe="80 # http\n21 # ftp\n443 # https\n1025-65535 # unprivileged ports\n8080 # Squids port (for icons)\n";
my $def_ports_ssl="443 # https\n8443 # alternative https\n";

my %language = (
"af","Afrikaans",
"ar","Arabic",
"az","Azerbaijani",
"bg","Bulgarian",
"ca","Catalan",
"cs","Czech",
"da","Danish",
"de","German",
"el","Greek",
"en","English",
"es","Spanish",
"et","Estonian",
"fa","Persian",
"fi","Finnish",
"fr","French",
"he","Hebrew",
"hu","Hungarian",
"hy","Armenian",
"id","Indonesian",
"it","Italian",
"ja","Japanese",
"ko","Korean",
"lt","Lithuanian",
"lv","Latvian",
"ms","Malay",
"nl","Dutch",
"oc","Occitan",
"pl","Polish",
"pt","Portuguese",
"pt-br","Portuguese - Brazil",
"ro","Romanian",
"ru","Russian",
"sk","Slovak",
"sl","Slovenian",
"sr-cyrl","Serbian - Cyrillic",
"sr-latn","Serbian - Latin",
"sv","Swedish",
"th","Thai",
"tr","Turkish",
"uk","Ukrainian",
"uz","Uzbek",
"vi","Vietnamese",
"zh-hans","Chinese - China",
"zh-hant","Chinese - Taiwan",
);

my @useragent=();
my @useragentlist=();

my $ncsa_buttontext='';
my $countrycode='';
my $i=0;
my $n=0;
my $id=0;
my $line='';
my $user='';
my $redirector='';
my @userlist=();
my @grouplist=();
my @temp=();
my @templist=();

my $cachemem=0;
my $proxy1='';
my $proxy2='';
my $replybodymaxsize=0;
my $browser_regexp='';
my $needhup = 0;
my $errormessage='';
my $error_settings='';
my $error_options='';

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

unless (-d "$acldir")   { mkdir("$acldir"); }
unless (-d "$ncsadir")  { mkdir("$ncsadir"); }
unless (-d "$ntlmdir")  { mkdir("$ntlmdir"); }
unless (-d "$raddir")   { mkdir("$raddir"); }
unless (-d "$identdir") { mkdir("$identdir"); }
unless (-d "$credir")   { mkdir("$credir"); }

unless (-e $cre_groups)  { system("touch $cre_groups"); }
unless (-e $cre_svhosts) { system("touch $cre_svhosts"); }

unless (-e $userdb) { system("touch $userdb"); }
unless (-e $stdgrp) { system("touch $stdgrp"); }
unless (-e $extgrp) { system("touch $extgrp"); }
unless (-e $disgrp) { system("touch $disgrp"); }

unless (-e $acl_src_subnets)    { system("touch $acl_src_subnets"); }
unless (-e $acl_src_networks)   { system("touch $acl_src_networks"); }
unless (-e $acl_src_banned_ip)  { system("touch $acl_src_banned_ip"); }
unless (-e $acl_src_banned_mac) { system("touch $acl_src_banned_mac"); }
unless (-e $acl_src_unrestricted_ip)  { system("touch $acl_src_unrestricted_ip"); }
unless (-e $acl_src_unrestricted_mac) { system("touch $acl_src_unrestricted_mac"); }
unless (-e $acl_src_noaccess_ip)  { system("touch $acl_src_noaccess_ip"); }
unless (-e $acl_src_noaccess_mac) { system("touch $acl_src_noaccess_mac"); }
unless (-e $acl_dst_noauth)     { system("touch $acl_dst_noauth"); }
unless (-e $acl_dst_noauth_dom) { system("touch $acl_dst_noauth_dom"); }
unless (-e $acl_dst_noauth_net) { system("touch $acl_dst_noauth_net"); }
unless (-e $acl_dst_noauth_url) { system("touch $acl_dst_noauth_url"); }
unless (-e $acl_dst_nocache)     { system("touch $acl_dst_nocache"); }
unless (-e $acl_dst_nocache_dom) { system("touch $acl_dst_nocache_dom"); }
unless (-e $acl_dst_nocache_net) { system("touch $acl_dst_nocache_net"); }
unless (-e $acl_dst_nocache_url) { system("touch $acl_dst_nocache_url"); }
unless (-e $acl_dst_mime_exceptions)     { system("touch $acl_dst_mime_exceptions"); }
unless (-e $acl_dst_mime_exceptions_dom) { system("touch $acl_dst_mime_exceptions_dom"); }
unless (-e $acl_dst_mime_exceptions_net) { system("touch $acl_dst_mime_exceptions_net"); }
unless (-e $acl_dst_mime_exceptions_url) { system("touch $acl_dst_mime_exceptions_url"); }
unless (-e $acl_dst_throttle) { system("touch $acl_dst_throttle"); }
unless (-e $acl_ports_safe) { system("touch $acl_ports_safe"); }
unless (-e $acl_ports_ssl)  { system("touch $acl_ports_ssl"); }
unless (-e $acl_include) { system("touch $acl_include"); }

unless (-e $browserdb) { system("touch $browserdb"); }
unless (-e $mimetypes) { system("touch $mimetypes"); }

open FILE, $browserdb;
@useragentlist = sort { reverse(substr(reverse(substr($a,index($a,',')+1)),index(reverse(substr($a,index($a,','))),',')+1)) cmp reverse(substr(reverse(substr($b,index($b,',')+1)),index(reverse(substr($b,index($b,','))),',')+1))} grep !/(^$)|(^\s*#)/,<FILE>;
close(FILE);

&General::readhash("/var/ofw/ethernet/settings", \%netsettings);

if (-e "/var/ofw/openvpn/settings") {
    &General::readhash("/var/ofw/openvpn/settings", \%ovpnsettings);

    if ((defined($ovpnsettings{'ENABLED_RED_1'}) && $ovpnsettings{'ENABLED_RED_1'} eq 'on')
        || (defined($ovpnsettings{'ENABLED_BLUE_1'}) && $ovpnsettings{'ENABLED_BLUE_1'} eq 'on')) {
        $ovpnactive = 1;
    }
}

# In case proxy is still restarting, show box and refresh
if (! system("/bin/ps ax | /bin/grep -q [r]estartsquid") ) {
    &Header::page_show($Lang::tr{'web proxy configuration'}, 'warning', $Lang::tr{'web proxy will now restart'}, "<meta http-equiv='refresh' content='5; URL=/cgi-bin/proxy.cgi' />");
    exit(0);
}

&Header::showhttpheaders();

$proxysettings{'ACTION'} = '';
$proxysettings{'VALID'} = '';

$proxysettings{'ENABLED_GREEN_1'} = 'off';
$proxysettings{'ENABLED_BLUE_1'} = 'off';
$proxysettings{'ENABLED_OVPN'} = 'off';
$proxysettings{'TRANSPARENT_GREEN_1'} = 'off';
$proxysettings{'TRANSPARENT_BLUE_1'} = 'off';
$proxysettings{'TRANSPARENT_OVPN'} = 'off';
$proxysettings{'PROXY_PORT'} = '8080';
$proxysettings{'VISIBLE_HOSTNAME'} = '';
$proxysettings{'ADMIN_MAIL_ADDRESS'} = '';
$proxysettings{'ERR_LANGUAGE'} = 'en';
$proxysettings{'ERR_DESIGN'} = 'IPCop';
$proxysettings{'SUPPRESS_VERSION'} = 'off';
$proxysettings{'FORWARD_VIA'} = 'off';
$proxysettings{'FORWARD_IPADDRESS'} = 'off';
$proxysettings{'FORWARD_USERNAME'} = 'off';
$proxysettings{'NO_CONNECTION_AUTH'} = 'off';
$proxysettings{'UPSTREAM_PROXY'} = '';
$proxysettings{'UPSTREAM_USER'} = '';
$proxysettings{'UPSTREAM_PASSWORD'} = '';
$proxysettings{'LOGGING'} = 'off';
$proxysettings{'LOGQUERY'} = 'off';
$proxysettings{'LOGUSERAGENT'} = 'off';
# Defaults to on, needs different handling
#$proxysettings{'LOGUSERNAME'} = 'on';
$proxysettings{'CACHE_MEM'} = '4';
$proxysettings{'CACHE_SIZE'} = '50';
$proxysettings{'MAX_SIZE'} = '4096';
$proxysettings{'MIN_SIZE'} = '0';
$proxysettings{'MEM_POLICY'} = 'LRU';
$proxysettings{'CACHE_POLICY'} = 'LRU';
$proxysettings{'L1_DIRS'} = '16';
$proxysettings{'OFFLINE_MODE'} = 'off';
$proxysettings{'CLASSROOM_EXT'} = 'off';
$proxysettings{'SUPERVISOR_PASSWORD'} = '';
$proxysettings{'NO_PROXY_LOCAL'} = 'off';
$proxysettings{'NO_PROXY_LOCAL_GREEN'} = 'off';
$proxysettings{'NO_PROXY_LOCAL_BLUE'} = 'off';
$proxysettings{'TIME_ACCESS_MODE'} = 'allow';
$proxysettings{'TIME_FROM_HOUR'} = '00';
$proxysettings{'TIME_FROM_MINUTE'} = '00';
$proxysettings{'TIME_TO_HOUR'} = '24';
$proxysettings{'TIME_TO_MINUTE'} = '00';
$proxysettings{'MAX_OUTGOING_SIZE'} = '0';
$proxysettings{'MAX_INCOMING_SIZE'} = '0';
$proxysettings{'THROTTLING_GREEN_TOTAL'} = 'unlimited';
$proxysettings{'THROTTLING_GREEN_HOST'} = 'unlimited';
$proxysettings{'THROTTLING_BLUE_TOTAL'} = 'unlimited';
$proxysettings{'THROTTLING_BLUE_HOST'} = 'unlimited';
$proxysettings{'THROTTLE_BINARY'} = 'off';
$proxysettings{'THROTTLE_DSKIMG'} = 'off';
$proxysettings{'THROTTLE_MMEDIA'} = 'off';
$proxysettings{'ENABLE_MIME_FILTER'} = 'off';
$proxysettings{'ENABLE_BROWSER_CHECK'} = 'off';
$proxysettings{'FAKE_USERAGENT'} = '';
$proxysettings{'FAKE_REFERER'} = '';
$proxysettings{'AUTH_METHOD'} = 'none';
$proxysettings{'AUTH_REALM'} = '';
$proxysettings{'AUTH_MAX_USERIP'} = '';
$proxysettings{'AUTH_CACHE_TTL'} = '60';
$proxysettings{'AUTH_IPCACHE_TTL'} = '0';
$proxysettings{'AUTH_CHILDREN'} = '5';
$proxysettings{'NCSA_MIN_PASS_LEN'} = '6';
$proxysettings{'NCSA_BYPASS_REDIR'} = 'off';
$proxysettings{'NCSA_USERNAME'} = '';
$proxysettings{'NCSA_GROUP'} = '';
$proxysettings{'NCSA_PASS'} = '';
$proxysettings{'NCSA_PASS_CONFIRM'} = '';
$proxysettings{'LDAP_BASEDN'} = '';
$proxysettings{'LDAP_TYPE'} = 'ADS';
$proxysettings{'LDAP_SERVER'} = '';
$proxysettings{'LDAP_PORT'} = '389';
$proxysettings{'LDAP_BINDDN_USER'} = '';
$proxysettings{'LDAP_BINDDN_PASS'} = '';
$proxysettings{'LDAP_GROUP'} = '';
$proxysettings{'NTLM_DOMAIN'} = '';
$proxysettings{'NTLM_PDC'} = '';
$proxysettings{'NTLM_BDC'} = '';
$proxysettings{'NTLM_ENABLE_ACL'} = 'off';
$proxysettings{'NTLM_USER_ACL'} = 'positive';
$proxysettings{'RADIUS_SERVER'} = '';
$proxysettings{'RADIUS_PORT'} = '1812';
$proxysettings{'RADIUS_IDENTIFIER'} = '';
$proxysettings{'RADIUS_SECRET'} = '';
$proxysettings{'RADIUS_ENABLE_ACL'} = 'off';
$proxysettings{'RADIUS_USER_ACL'} = 'positive';
$proxysettings{'IDENT_REQUIRED'} = 'off';
$proxysettings{'IDENT_TIMEOUT'} = '10';
$proxysettings{'IDENT_ENABLE_ACL'} = 'off';
$proxysettings{'IDENT_USER_ACL'} = 'positive';
$proxysettings{'CHILDREN'} = '5';
$proxysettings{'ENABLE_REDIRECTOR'} = 'off';

$ncsa_buttontext = $Lang::tr{'NCSA create user'};

&General::getcgihash(\%proxysettings);

if ($proxysettings{'THROTTLING_GREEN_TOTAL'} eq 0) {$proxysettings{'THROTTLING_GREEN_TOTAL'} = 'unlimited';}
if ($proxysettings{'THROTTLING_GREEN_HOST'}  eq 0) {$proxysettings{'THROTTLING_GREEN_HOST'}  = 'unlimited';}
if ($proxysettings{'THROTTLING_BLUE_TOTAL'}  eq 0) {$proxysettings{'THROTTLING_BLUE_TOTAL'}  = 'unlimited';}
if ($proxysettings{'THROTTLING_BLUE_HOST'}   eq 0) {$proxysettings{'THROTTLING_BLUE_HOST'}   = 'unlimited';}

if ($proxysettings{'ACTION'}) {

    if ($proxysettings{'ACTION'} eq $Lang::tr{'NCSA user management'})
    {
        $proxysettings{'NCSA_EDIT_MODE'} = 'yes';
    }

    if ($proxysettings{'ACTION'} eq $Lang::tr{'add'})
    {
        $proxysettings{'NCSA_EDIT_MODE'} = 'yes';
        if (length($proxysettings{'NCSA_PASS'}) < $proxysettings{'NCSA_MIN_PASS_LEN'}) {
            $errormessage = $Lang::tr{'errmsg password length 1'}.$proxysettings{'NCSA_MIN_PASS_LEN'}.$Lang::tr{'errmsg password length 2'};
        }
        if (!($proxysettings{'NCSA_PASS'} eq $proxysettings{'NCSA_PASS_CONFIRM'})) {
            $errormessage = $Lang::tr{'errmsg passwords different'};
        }
        if ($proxysettings{'NCSA_USERNAME'} eq '') {
            $errormessage = $Lang::tr{'errmsg no username'};
        }
        if (!$errormessage) {
            $proxysettings{'NCSA_USERNAME'} =~ tr/A-Z/a-z/;
            &adduser($proxysettings{'NCSA_USERNAME'}, $proxysettings{'NCSA_PASS'}, $proxysettings{'NCSA_GROUP'});
        }
        $proxysettings{'NCSA_USERNAME'} = '';
        $proxysettings{'NCSA_GROUP'} = '';
        $proxysettings{'NCSA_PASS'} = '';
        $proxysettings{'NCSA_PASS_CONFIRM'} = '';
    }

    if ($proxysettings{'ACTION'} eq $Lang::tr{'remove'})
    {
        $proxysettings{'NCSA_EDIT_MODE'} = 'yes';
        &deluser($proxysettings{'ID'});
    }

    if ($proxysettings{'ACTION'} eq $Lang::tr{'edit'})
    {
        $proxysettings{'NCSA_EDIT_MODE'} = 'yes';
        $ncsa_buttontext = $Lang::tr{'NCSA update user'};
        @temp = split(/:/,$proxysettings{'ID'});
        $proxysettings{'NCSA_USERNAME'} = $temp[0];
        $proxysettings{'NCSA_GROUP'} = $temp[1];
        $proxysettings{'NCSA_PASS'} = "lEaVeAlOnE";
        $proxysettings{'NCSA_PASS_CONFIRM'} = $proxysettings{'NCSA_PASS'};
    }

    if ($proxysettings{'ACTION'} eq $Lang::tr{'save'})
    {
        if ($proxysettings{'ENABLED_GREEN_1'} !~ /^(on|off)$/ ||
            $proxysettings{'TRANSPARENT_GREEN_1'} !~ /^(on|off)$/ ||
            $proxysettings{'ENABLED_BLUE_1'} !~ /^(on|off)$/ ||
            $proxysettings{'TRANSPARENT_BLUE_1'} !~ /^(on|off)$/  ||
            $proxysettings{'ENABLED_OVPN'} !~ /^(on|off)$/ ||
            $proxysettings{'TRANSPARENT_OVPN'} !~ /^(on|off)$/ ) {
            $errormessage = $Lang::tr{'invalid input'};
            goto ERROR;
        }
        if (!(&General::validport($proxysettings{'PROXY_PORT'})))
        {
            $errormessage = $Lang::tr{'errmsg invalid proxy port'};
            $error_settings = 'error';
            goto ERROR;
        }
        my @free = `/bin/df -B M /var/log/cache | /bin/grep -v Filesystem | /usr/bin/cut -d M -f1`;
        if (!($proxysettings{'CACHE_SIZE'} =~ /^\d+/) || ($proxysettings{'CACHE_SIZE'} < 10)) {
            if (!($proxysettings{'CACHE_SIZE'} eq '0')) {
                $errormessage = $Lang::tr{'errmsg hdd cache size'};
                $error_options = 'error';
                goto ERROR;
            }
        }
        else {
            my @cachedisk = split(' ', $free[0]);
            # Make sure we have enough space for logs etc.
            $cachedisk[1] = $cachedisk[1] - 128;
            $cachedisk[1] = 0 if ($cachedisk[1] < 10);
            $proxysettings{'CACHE_SIZE'} = $cachedisk[1] if ($proxysettings{'CACHE_SIZE'} > $cachedisk[1]);
        }
        if (!($proxysettings{'CACHE_MEM'} =~ /^\d+/)) {
            $errormessage = $Lang::tr{'errmsg mem cache size'};
            $error_options = 'error';
            goto ERROR;
        }
        @free = `/usr/bin/free`;
        $free[1] =~ m/(\d+)/;
        $cachemem = int $1 / 2048;
        if ($proxysettings{'CACHE_MEM'} > $cachemem) {
            $proxysettings{'CACHE_MEM'} = $cachemem;
        }
        if (!($proxysettings{'MAX_SIZE'} =~ /^\d+/))
        {
            $errormessage = $Lang::tr{'invalid maximum object size'};
            $error_options = 'error';
            goto ERROR;
        }
        if (!($proxysettings{'MIN_SIZE'} =~ /^\d+/))
        {
            $errormessage = $Lang::tr{'invalid minimum object size'};
            $error_options = 'error';
            goto ERROR;
        }
        if (!($proxysettings{'MAX_OUTGOING_SIZE'} =~ /^\d+/))
        {
            $errormessage = $Lang::tr{'invalid maximum outgoing size'};
            $error_options = 'error';
            goto ERROR;
        }
        if (!($proxysettings{'TIME_TO_HOUR'}.$proxysettings{'TIME_TO_MINUTE'} gt $proxysettings{'TIME_FROM_HOUR'}.$proxysettings{'TIME_FROM_MINUTE'}))
        {
            $errormessage = $Lang::tr{'errmsg time restriction'};
            $error_options = 'error';
            goto ERROR;
        }
        if (!($proxysettings{'MAX_INCOMING_SIZE'} =~ /^\d+/))
        {
            $errormessage = $Lang::tr{'invalid maximum incoming size'};
            $error_options = 'error';
            goto ERROR;
        }
        if ($proxysettings{'ENABLE_BROWSER_CHECK'} eq 'on')
        {
            $browser_regexp = '';
            foreach (@useragentlist)
            {
                chomp;
                @useragent = split(/,/);
                if ($proxysettings{'UA_'.$useragent[0]} eq 'on') { $browser_regexp .= "$useragent[2]|"; }
            }
            chop($browser_regexp);
            if (!$browser_regexp)
            {
                $errormessage = $Lang::tr{'errmsg no browser'};
                goto ERROR;
            }
        }
        if (!($proxysettings{'AUTH_METHOD'} eq 'none'))
        {
            unless (($proxysettings{'AUTH_METHOD'} eq 'ident') &&
                ($proxysettings{'IDENT_REQUIRED'} eq 'off') &&
                ($proxysettings{'IDENT_ENABLE_ACL'} eq 'off'))
            {
                my $transparent = 0;

                if ($netsettings{'BLUE_COUNT'} >= 1)
                {
                    if (($proxysettings{'ENABLED_BLUE_1'} eq 'on') && ($proxysettings{'TRANSPARENT_BLUE_1'} eq 'on'))
                    {
                        $transparent++;
                    }
                }
                if ($ovpnactive)
                {
                    if (($proxysettings{'ENABLED_OVPN'} eq 'on') && ($proxysettings{'TRANSPARENT_OVPN'} eq 'on'))
                    {
                        $transparent++;
                    }
                }
                if (($proxysettings{'ENABLED_GREEN_1'} eq 'on') && ($proxysettings{'TRANSPARENT_GREEN_1'} eq 'on'))
                {
                    $transparent++;
                }

                if($transparent > 0)
                {
                    $errormessage = $Lang::tr{'errmsg non-transparent proxy required'};
                    goto ERROR;
                }
            }
            if ((!($proxysettings{'AUTH_MAX_USERIP'} eq '')) &&
                ((!($proxysettings{'AUTH_MAX_USERIP'} =~ /^\d+/)) || ($proxysettings{'AUTH_MAX_USERIP'} < 1) || ($proxysettings{'AUTH_MAX_USERIP'} > 255)))
            {
                $errormessage = $Lang::tr{'errmsg max userip'};
                goto ERROR;
            }
            if (!($proxysettings{'AUTH_CACHE_TTL'} =~ /^\d+/))
            {
                $errormessage = $Lang::tr{'errmsg auth cache ttl'};
                goto ERROR;
            }
            if (!($proxysettings{'AUTH_IPCACHE_TTL'} =~ /^\d+/))
            {
                $errormessage = $Lang::tr{'errmsg auth ipcache ttl'};
                goto ERROR;
            }
            if ((!($proxysettings{'AUTH_MAX_USERIP'} eq '')) && ($proxysettings{'AUTH_IPCACHE_TTL'} eq '0'))
            {
                $errormessage = $Lang::tr{'errmsg auth ipcache may not be null'};
                goto ERROR;
            }
            if ((!($proxysettings{'AUTH_CHILDREN'} =~ /^\d+/)) || ($proxysettings{'AUTH_CHILDREN'} < 1) || ($proxysettings{'AUTH_CHILDREN'} > 255))
            {
                $errormessage = $Lang::tr{'errmsg auth children'};
                goto ERROR;
            }
        }
        if ($proxysettings{'AUTH_METHOD'} eq 'ncsa')
        {
            if ((!($proxysettings{'NCSA_MIN_PASS_LEN'} =~ /^\d+/)) || ($proxysettings{'NCSA_MIN_PASS_LEN'} < 1) || ($proxysettings{'NCSA_MIN_PASS_LEN'} > 255))
            {
                $errormessage = $Lang::tr{'errmsg password length'};
                goto ERROR;
            }
        }
        if ($proxysettings{'AUTH_METHOD'} eq 'ident')
        {
            if ((!($proxysettings{'IDENT_TIMEOUT'} =~ /^\d+/)) || ($proxysettings{'IDENT_TIMEOUT'} < 1))
            {
                $errormessage = $Lang::tr{'errmsg ident timeout'};
                goto ERROR;
            }
        }
        if ($proxysettings{'AUTH_METHOD'} eq 'ldap')
        {
            if ($proxysettings{'LDAP_BASEDN'} eq '')
            {
                $errormessage = $Lang::tr{'errmsg ldap base dn'};
                goto ERROR;
            }
            if (!&General::validip($proxysettings{'LDAP_SERVER'}))
            {
                $errormessage = $Lang::tr{'errmsg ldap server'};
                goto ERROR;
            }
            if (!&General::validport($proxysettings{'LDAP_PORT'}))
            {
                $errormessage = $Lang::tr{'errmsg ldap port'};
                goto ERROR;
            }
            if (($proxysettings{'LDAP_TYPE'} eq 'ADS') || ($proxysettings{'LDAP_TYPE'} eq 'NDS'))
            {
                if (($proxysettings{'LDAP_BINDDN_USER'} eq '') || ($proxysettings{'LDAP_BINDDN_PASS'} eq ''))
                {
                    $errormessage = $Lang::tr{'errmsg ldap bind dn'};
                    goto ERROR;
                }
            }
        }
        if ($proxysettings{'AUTH_METHOD'} eq 'ntlm')
        {
            if ($proxysettings{'NTLM_DOMAIN'} eq '')
            {
                $errormessage = $Lang::tr{'errmsg ntlm domain'};
                goto ERROR;
            }
            if ($proxysettings{'NTLM_PDC'} eq '')
            {
                $errormessage = $Lang::tr{'errmsg ntlm pdc'};
                goto ERROR;
            }
            if (!&General::validhostname($proxysettings{'NTLM_PDC'}))
            {
                $errormessage = $Lang::tr{'errmsg invalid pdc'};
                goto ERROR;
            }
            if ((!($proxysettings{'NTLM_BDC'} eq '')) && (!&General::validhostname($proxysettings{'NTLM_BDC'})))
            {
                $errormessage = $Lang::tr{'errmsg invalid bdc'};
                goto ERROR;
            }

            $proxysettings{'NTLM_DOMAIN'} = lc($proxysettings{'NTLM_DOMAIN'});
            $proxysettings{'NTLM_PDC'}    = lc($proxysettings{'NTLM_PDC'});
            $proxysettings{'NTLM_BDC'}    = lc($proxysettings{'NTLM_BDC'});
        }
        if ($proxysettings{'AUTH_METHOD'} eq 'radius')
        {
            if (!&General::validip($proxysettings{'RADIUS_SERVER'}))
            {
                $errormessage = $Lang::tr{'errmsg radius server'};
                goto ERROR;
            }
            if (!&General::validport($proxysettings{'RADIUS_PORT'}))
            {
                $errormessage = $Lang::tr{'errmsg radius port'};
                goto ERROR;
            }
            if ($proxysettings{'RADIUS_SECRET'} eq '')
            {
                $errormessage = $Lang::tr{'errmsg radius secret'};
                goto ERROR;
            }
        }

        # Quick parent proxy error checking of username and password info. If username password don't both exist give an error.
        $proxy1 = 'YES';
        $proxy2 = 'YES';
        if (($proxysettings{'UPSTREAM_USER'} eq '')) {$proxy1 = '';}
        if (($proxysettings{'UPSTREAM_PASSWORD'} eq '')) {$proxy2 = '';}
        if ($proxysettings{'UPSTREAM_USER'} eq 'PASS')  {$proxy1=$proxy2='PASS'; $proxysettings{'UPSTREAM_PASSWORD'} = '';}
        if (($proxy1 ne $proxy2))
        {
            $errormessage = $Lang::tr{'errmsg invalid upstream proxy username or password setting'};
            $error_settings = 'error';
            goto ERROR;
        }


        if ((!($proxysettings{'CHILDREN'} =~ /^\d+$/)) || ($proxysettings{'CHILDREN'} < 1)) {
            $errormessage = $Lang::tr{'errmsg filter children'};
            goto ERROR;
        }

ERROR:
        &check_acls;

        ###############
        # DEBUG DEBUG
        if ($debugFormparams == 1) {
            &Header::openbox('100%', 'left', 'DEBUG');
            my $debugCount = 0;
            foreach my $line (sort keys %proxysettings) {
                print "$line = $proxysettings{$line}<br />\n";
                $debugCount++;
            }
            print "&nbsp;Count: $debugCount\n";
            &Header::closebox();
        }

        # DEBUG DEBUG
        ###############

        if ($errormessage) {
            $proxysettings{'VALID'} = 'no'; }
        else {
            $proxysettings{'VALID'} = 'yes'; }

        if ($proxysettings{'VALID'} eq 'yes')
        {
            &write_acls;

            delete $proxysettings{'SRC_SUBNETS'};
            delete $proxysettings{'SRC_BANNED_IP'};
            delete $proxysettings{'SRC_BANNED_MAC'};
            delete $proxysettings{'SRC_UNRESTRICTED_IP'};
            delete $proxysettings{'SRC_UNRESTRICTED_MAC'};
            delete $proxysettings{'DST_NOCACHE'};
            delete $proxysettings{'DST_NOAUTH'};
            delete $proxysettings{'PORTS_SAFE'};
            delete $proxysettings{'PORTS_SSL'};
            delete $proxysettings{'MIME_TYPES'};
            delete $proxysettings{'MIME_EXCEPTIONS'};
            delete $proxysettings{'NTLM_ALLOW_USERS'};
            delete $proxysettings{'NTLM_DENY_USERS'};
            delete $proxysettings{'RADIUS_ALLOW_USERS'};
            delete $proxysettings{'RADIUS_DENY_USERS'};
            delete $proxysettings{'IDENT_HOSTS'};
            delete $proxysettings{'IDENT_ALLOW_USERS'};
            delete $proxysettings{'IDENT_DENY_USERS'};

            delete $proxysettings{'CRE_GROUPS'};
            delete $proxysettings{'CRE_SVHOSTS'};

            delete $proxysettings{'NCSA_USERNAME'};
            delete $proxysettings{'NCSA_GROUP'};
            delete $proxysettings{'NCSA_PASS'};
            delete $proxysettings{'NCSA_PASS_CONFIRM'};

            $proxysettings{'TIME_MON'} = 'off' unless exists $proxysettings{'TIME_MON'};
            $proxysettings{'TIME_TUE'} = 'off' unless exists $proxysettings{'TIME_TUE'};
            $proxysettings{'TIME_WED'} = 'off' unless exists $proxysettings{'TIME_WED'};
            $proxysettings{'TIME_THU'} = 'off' unless exists $proxysettings{'TIME_THU'};
            $proxysettings{'TIME_FRI'} = 'off' unless exists $proxysettings{'TIME_FRI'};
            $proxysettings{'TIME_SAT'} = 'off' unless exists $proxysettings{'TIME_SAT'};
            $proxysettings{'TIME_SUN'} = 'off' unless exists $proxysettings{'TIME_SUN'};

            $proxysettings{'AUTH_ALWAYS_REQUIRED'} = 'off' unless exists $proxysettings{'AUTH_ALWAYS_REQUIRED'};
            $proxysettings{'NTLM_ENABLE_INT_AUTH'} = 'off' unless exists $proxysettings{'NTLM_ENABLE_INT_AUTH'};

            $proxysettings{'LOGUSERNAME'} = 'off' unless exists $proxysettings{'LOGUSERNAME'};

            &General::writehash("/var/ofw/proxy/settings", \%proxysettings);

            system('/usr/local/bin/restartsquid --config');

            system('/usr/local/bin/restartsquid --waitpid >/dev/null &');
            &Header::page_show('title', 'warning', $Lang::tr{'web proxy will now restart'}, "<meta http-equiv='refresh' content='5; URL=/cgi-bin/proxy.cgi' />");
            exit 0;
        }
    }

    if ($proxysettings{'ACTION'} eq $Lang::tr{'clear cache'}) {
        system('/usr/local/bin/restartsquid --flush --waitpid');
    }

} # end of ACTION

if (!$errormessage)
{
    if (-e "/var/ofw/proxy/settings") {
        &General::readhash("/var/ofw/proxy/settings", \%proxysettings);
    }
    &read_acls;
}

$checked{'ENABLED_GREEN_1'}{'off'} = '';
$checked{'ENABLED_GREEN_1'}{'on'} = '';
$checked{'ENABLED_GREEN_1'}{$proxysettings{'ENABLED_GREEN_1'}} = "checked='checked'";

$checked{'TRANSPARENT_GREEN_1'}{'off'} = '';
$checked{'TRANSPARENT_GREEN_1'}{'on'} = '';
$checked{'TRANSPARENT_GREEN_1'}{$proxysettings{'TRANSPARENT_GREEN_1'}} = "checked='checked'";

$checked{'ENABLED_BLUE_1'}{'off'} = '';
$checked{'ENABLED_BLUE_1'}{'on'} = '';
$checked{'ENABLED_BLUE_1'}{$proxysettings{'ENABLED_BLUE_1'}} = "checked='checked'";

$checked{'TRANSPARENT_BLUE_1'}{'off'} = '';
$checked{'TRANSPARENT_BLUE_1'}{'on'} = '';
$checked{'TRANSPARENT_BLUE_1'}{$proxysettings{'TRANSPARENT_BLUE_1'}} = "checked='checked'";

$checked{'ENABLED_OVPN'}{'off'} = '';
$checked{'ENABLED_OVPN'}{'on'} = '';
$checked{'ENABLED_OVPN'}{$proxysettings{'ENABLED_OVPN'}} = "checked='checked'";

$checked{'TRANSPARENT_OVPN'}{'off'} = '';
$checked{'TRANSPARENT_OVPN'}{'on'} = '';
$checked{'TRANSPARENT_OVPN'}{$proxysettings{'TRANSPARENT_OVPN'}} = "checked='checked'";

$checked{'SUPPRESS_VERSION'}{'off'} = '';
$checked{'SUPPRESS_VERSION'}{'on'} = '';
$checked{'SUPPRESS_VERSION'}{$proxysettings{'SUPPRESS_VERSION'}} = "checked='checked'";

$checked{'FORWARD_IPADDRESS'}{'off'} = '';
$checked{'FORWARD_IPADDRESS'}{'on'} = '';
$checked{'FORWARD_IPADDRESS'}{$proxysettings{'FORWARD_IPADDRESS'}} = "checked='checked'";
$checked{'FORWARD_USERNAME'}{'off'} = '';
$checked{'FORWARD_USERNAME'}{'on'} = '';
$checked{'FORWARD_USERNAME'}{$proxysettings{'FORWARD_USERNAME'}} = "checked='checked'";
$checked{'FORWARD_VIA'}{'off'} = '';
$checked{'FORWARD_VIA'}{'on'} = '';
$checked{'FORWARD_VIA'}{$proxysettings{'FORWARD_VIA'}} = "checked='checked'";
$checked{'NO_CONNECTION_AUTH'}{'off'} = '';
$checked{'NO_CONNECTION_AUTH'}{'on'} = '';
$checked{'NO_CONNECTION_AUTH'}{$proxysettings{'NO_CONNECTION_AUTH'}} = "checked='checked'";

$selected{'MEM_POLICY'}{$proxysettings{'MEM_POLICY'}} = "selected='selected'";
$selected{'CACHE_POLICY'}{$proxysettings{'CACHE_POLICY'}} = "selected='selected'";
$selected{'L1_DIRS'}{$proxysettings{'L1_DIRS'}} = "selected='selected'";
$checked{'OFFLINE_MODE'}{'off'} = '';
$checked{'OFFLINE_MODE'}{'on'} = '';
$checked{'OFFLINE_MODE'}{$proxysettings{'OFFLINE_MODE'}} = "checked='checked'";

$checked{'LOGGING'}{'off'} = '';
$checked{'LOGGING'}{'on'} = '';
$checked{'LOGGING'}{$proxysettings{'LOGGING'}} = "checked='checked'";
$checked{'LOGQUERY'}{'off'} = '';
$checked{'LOGQUERY'}{'on'} = '';
$checked{'LOGQUERY'}{$proxysettings{'LOGQUERY'}} = "checked='checked'";
$checked{'LOGUSERAGENT'}{'off'} = '';
$checked{'LOGUSERAGENT'}{'on'} = '';
$checked{'LOGUSERAGENT'}{$proxysettings{'LOGUSERAGENT'}} = "checked='checked'";
$proxysettings{'LOGUSERNAME'} = 'on' unless exists $proxysettings{'LOGUSERNAME'};
$checked{'LOGUSERNAME'}{'off'} = '';
$checked{'LOGUSERNAME'}{'on'} = '';
$checked{'LOGUSERNAME'}{$proxysettings{'LOGUSERNAME'}} = "checked='checked'";

$selected{'ERR_DESIGN'}{$proxysettings{'ERR_DESIGN'}} = "selected='selected'";

$checked{'NO_PROXY_LOCAL'}{'off'} = '';
$checked{'NO_PROXY_LOCAL'}{'on'} = '';
$checked{'NO_PROXY_LOCAL'}{$proxysettings{'NO_PROXY_LOCAL'}} = "checked='checked'";
$checked{'NO_PROXY_LOCAL_GREEN'}{'off'} = '';
$checked{'NO_PROXY_LOCAL_GREEN'}{'on'} = '';
$checked{'NO_PROXY_LOCAL_GREEN'}{$proxysettings{'NO_PROXY_LOCAL_GREEN'}} = "checked='checked'";
$checked{'NO_PROXY_LOCAL_BLUE'}{'off'} = '';
$checked{'NO_PROXY_LOCAL_BLUE'}{'on'} = '';
$checked{'NO_PROXY_LOCAL_BLUE'}{$proxysettings{'NO_PROXY_LOCAL_BLUE'}} = "checked='checked'";

$checked{'CLASSROOM_EXT'}{'off'} = '';
$checked{'CLASSROOM_EXT'}{'on'} = '';
$checked{'CLASSROOM_EXT'}{$proxysettings{'CLASSROOM_EXT'}} = "checked='checked'";

$selected{'TIME_ACCESS_MODE'}{$proxysettings{'TIME_ACCESS_MODE'}} = "selected='selected'";

$proxysettings{'TIME_MON'} = 'on' unless exists $proxysettings{'TIME_MON'};
$proxysettings{'TIME_TUE'} = 'on' unless exists $proxysettings{'TIME_TUE'};
$proxysettings{'TIME_WED'} = 'on' unless exists $proxysettings{'TIME_WED'};
$proxysettings{'TIME_THU'} = 'on' unless exists $proxysettings{'TIME_THU'};
$proxysettings{'TIME_FRI'} = 'on' unless exists $proxysettings{'TIME_FRI'};
$proxysettings{'TIME_SAT'} = 'on' unless exists $proxysettings{'TIME_SAT'};
$proxysettings{'TIME_SUN'} = 'on' unless exists $proxysettings{'TIME_SUN'};

$checked{'TIME_MON'}{'off'} = '';
$checked{'TIME_MON'}{'on'} = '';
$checked{'TIME_MON'}{$proxysettings{'TIME_MON'}} = "checked='checked'";
$checked{'TIME_TUE'}{'off'} = '';
$checked{'TIME_TUE'}{'on'} = '';
$checked{'TIME_TUE'}{$proxysettings{'TIME_TUE'}} = "checked='checked'";
$checked{'TIME_WED'}{'off'} = '';
$checked{'TIME_WED'}{'on'} = '';
$checked{'TIME_WED'}{$proxysettings{'TIME_WED'}} = "checked='checked'";
$checked{'TIME_THU'}{'off'} = '';
$checked{'TIME_THU'}{'on'} = '';
$checked{'TIME_THU'}{$proxysettings{'TIME_THU'}} = "checked='checked'";
$checked{'TIME_FRI'}{'off'} = '';
$checked{'TIME_FRI'}{'on'} = '';
$checked{'TIME_FRI'}{$proxysettings{'TIME_FRI'}} = "checked='checked'";
$checked{'TIME_SAT'}{'off'} = '';
$checked{'TIME_SAT'}{'on'} = '';
$checked{'TIME_SAT'}{$proxysettings{'TIME_SAT'}} = "checked='checked'";
$checked{'TIME_SUN'}{'off'} = '';
$checked{'TIME_SUN'}{'on'} = '';
$checked{'TIME_SUN'}{$proxysettings{'TIME_SUN'}} = "checked='checked'";

$checked{'THROTTLE_BINARY'}{'off'} = '';
$checked{'THROTTLE_BINARY'}{'on'} = '';
$checked{'THROTTLE_BINARY'}{$proxysettings{'THROTTLE_BINARY'}} = "checked='checked'";
$checked{'THROTTLE_DSKIMG'}{'off'} = '';
$checked{'THROTTLE_DSKIMG'}{'on'} = '';
$checked{'THROTTLE_DSKIMG'}{$proxysettings{'THROTTLE_DSKIMG'}} = "checked='checked'";
$checked{'THROTTLE_MMEDIA'}{'off'} = '';
$checked{'THROTTLE_MMEDIA'}{'on'} = '';
$checked{'THROTTLE_MMEDIA'}{$proxysettings{'THROTTLE_MMEDIA'}} = "checked='checked'";

$checked{'ENABLE_MIME_FILTER'}{'off'} = '';
$checked{'ENABLE_MIME_FILTER'}{'on'} = '';
$checked{'ENABLE_MIME_FILTER'}{$proxysettings{'ENABLE_MIME_FILTER'}} = "checked='checked'";

$checked{'ENABLE_BROWSER_CHECK'}{'off'} = '';
$checked{'ENABLE_BROWSER_CHECK'}{'on'} = '';
$checked{'ENABLE_BROWSER_CHECK'}{$proxysettings{'ENABLE_BROWSER_CHECK'}} = "checked='checked'";

foreach (@useragentlist) {
    @useragent = split(/,/);
    $checked{'UA_'.$useragent[0]}{'off'} = '';
    $checked{'UA_'.$useragent[0]}{'on'} = '';
    if(defined($proxysettings{'UA_'.$useragent[0]})) {
        $checked{'UA_'.$useragent[0]}{$proxysettings{'UA_'.$useragent[0]}} = "checked='checked'";
    }
    else {
        $checked{'UA_'.$useragent[0]}{'off'} = "checked='checked'";
    }
}

$checked{'AUTH_METHOD'}{'none'} = '';
$checked{'AUTH_METHOD'}{'ncsa'} = '';
$checked{'AUTH_METHOD'}{'ident'} = '';
$checked{'AUTH_METHOD'}{'ldap'} = '';
$checked{'AUTH_METHOD'}{'ntlm'} = '';
$checked{'AUTH_METHOD'}{'radius'} = '';
$checked{'AUTH_METHOD'}{$proxysettings{'AUTH_METHOD'}} = "checked='checked'";

$proxysettings{'AUTH_ALWAYS_REQUIRED'} = 'on' unless exists $proxysettings{'AUTH_ALWAYS_REQUIRED'};

$checked{'AUTH_ALWAYS_REQUIRED'}{'off'} = '';
$checked{'AUTH_ALWAYS_REQUIRED'}{'on'} = '';
$checked{'AUTH_ALWAYS_REQUIRED'}{$proxysettings{'AUTH_ALWAYS_REQUIRED'}} = "checked='checked'";

$checked{'NCSA_BYPASS_REDIR'}{'off'} = '';
$checked{'NCSA_BYPASS_REDIR'}{'on'} = '';
$checked{'NCSA_BYPASS_REDIR'}{$proxysettings{'NCSA_BYPASS_REDIR'}} = "checked='checked'";

$selected{'NCSA_GROUP'}{$proxysettings{'NCSA_GROUP'}} = "selected='selected'";

$selected{'LDAP_TYPE'}{$proxysettings{'LDAP_TYPE'}} = "selected='selected'";

$proxysettings{'NTLM_ENABLE_INT_AUTH'} = 'on' unless exists $proxysettings{'NTLM_ENABLE_INT_AUTH'};

$checked{'NTLM_ENABLE_INT_AUTH'}{'off'} = '';
$checked{'NTLM_ENABLE_INT_AUTH'}{'on'} = '';
$checked{'NTLM_ENABLE_INT_AUTH'}{$proxysettings{'NTLM_ENABLE_INT_AUTH'}} = "checked='checked'";

$checked{'NTLM_ENABLE_ACL'}{'off'} = '';
$checked{'NTLM_ENABLE_ACL'}{'on'} = '';
$checked{'NTLM_ENABLE_ACL'}{$proxysettings{'NTLM_ENABLE_ACL'}} = "checked='checked'";

$checked{'NTLM_USER_ACL'}{'positive'} = '';
$checked{'NTLM_USER_ACL'}{'negative'} = '';
$checked{'NTLM_USER_ACL'}{$proxysettings{'NTLM_USER_ACL'}} = "checked='checked'";

$checked{'RADIUS_ENABLE_ACL'}{'off'} = '';
$checked{'RADIUS_ENABLE_ACL'}{'on'} = '';
$checked{'RADIUS_ENABLE_ACL'}{$proxysettings{'RADIUS_ENABLE_ACL'}} = "checked='checked'";

$checked{'RADIUS_USER_ACL'}{'positive'} = '';
$checked{'RADIUS_USER_ACL'}{'negative'} = '';
$checked{'RADIUS_USER_ACL'}{$proxysettings{'RADIUS_USER_ACL'}} = "checked='checked'";

$checked{'IDENT_REQUIRED'}{'off'} = '';
$checked{'IDENT_REQUIRED'}{'on'} = '';
$checked{'IDENT_REQUIRED'}{$proxysettings{'IDENT_REQUIRED'}} = "checked='checked'";

$checked{'IDENT_ENABLE_ACL'}{'off'} = '';
$checked{'IDENT_ENABLE_ACL'}{'on'} = '';
$checked{'IDENT_ENABLE_ACL'}{$proxysettings{'IDENT_ENABLE_ACL'}} = "checked='checked'";

$checked{'IDENT_USER_ACL'}{'positive'} = '';
$checked{'IDENT_USER_ACL'}{'negative'} = '';
$checked{'IDENT_USER_ACL'}{$proxysettings{'IDENT_USER_ACL'}} = "checked='checked'";

$checked{'ENABLE_REDIRECTOR'}{'off'} = '';
$checked{'ENABLE_REDIRECTOR'}{'on'} = '';
$checked{'ENABLE_REDIRECTOR'}{$proxysettings{'ENABLE_REDIRECTOR'}} = "checked='checked'";

&Header::openpage($Lang::tr{'web proxy configuration'}, 1, '');

&Header::openbigbox('100%', 'left', '', $errormessage);

if ($errormessage) {
    &Header::openbox('100%', 'left', "$Lang::tr{'error messages'}:", 'error');
    print "<font class='base'>$errormessage&nbsp;</font>\n";
    &Header::closebox();
}

if ($squidversion[0] =~ /^Squid\sCache:\sVersion\s/i) {
    $squidversion[0] =~ s/^Squid\sCache:\sVersion//i;
    $squidversion[0] =~ s/^\s+//g;
    $squidversion[0] =~ s/\s+$//g;
}
else {
    $squidversion[0] = $Lang::tr{'unknown'};
}

# ===================================================================
#  Main settings
# ===================================================================

unless (defined($proxysettings{'NCSA_EDIT_MODE'}) && $proxysettings{'NCSA_EDIT_MODE'} eq 'yes') {

    print "<form method='post' action='$ENV{'SCRIPT_NAME'}'>\n";

    &Header::openbox('100%', 'left', "$Lang::tr{'settings'}", $error_settings);
    my $sactive = &General::isrunning('squid', 'nosize');

    print <<END
<table width='100%'>
<tr>
    <td>$Lang::tr{'web proxy'}:</td>
    $sactive
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
<tr>
    <td colspan='4' class='base'><hr /></td>
</tr>
<tr>
    <td colspan='4' class='base'><b>$Lang::tr{'common settings'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'enabled on'} <span class='ofw_iface_green' style='font-weight: bold;'>$Lang::tr{'green'}</span>:</td>
    <td width='20%'><input type='checkbox' name='ENABLED_GREEN_1' $checked{'ENABLED_GREEN_1'}{'on'} /></td>
    <td width='30%' class='base'>$Lang::tr{'transparent on'} <span class='ofw_iface_green' style='font-weight: bold;'>$Lang::tr{'green'}</span>:</td>
    <td width='25%'><input type='checkbox' name='TRANSPARENT_GREEN_1' $checked{'TRANSPARENT_GREEN_1'}{'on'} /></td>
</tr>
END
;
    if ($netsettings{'BLUE_COUNT'} >= 1) {
        print "<tr><td class='base'>$Lang::tr{'enabled on'} <span class='ofw_iface_blue' style='font-weight: bold;'>$Lang::tr{'blue'}</span>:</td>";
        print "<td><input type='checkbox' name='ENABLED_BLUE_1' $checked{'ENABLED_BLUE_1'}{'on'} /></td>";
        print "<td class='base'>$Lang::tr{'transparent on'} <span class='ofw_iface_blue' style='font-weight: bold;'>$Lang::tr{'blue'}</span>:</td>";
        print "<td><input type='checkbox' name='TRANSPARENT_BLUE_1' $checked{'TRANSPARENT_BLUE_1'}{'on'} /></td></tr>";
    }
    if ($ovpnactive) {
        print "<tr><td class='base'>$Lang::tr{'enabled on'} <span class='ofw_iface_ovpn' style='font-weight: bold;'>OpenVPN</span>:</td>";
        print "<td><input type='checkbox' name='ENABLED_OVPN' $checked{'ENABLED_OVPN'}{'on'} /></td>";
        print "<td class='base'>$Lang::tr{'transparent on'} <span class='ofw_iface_ovpn' style='font-weight: bold;'>OpenVPN</span>:</td>";
        print "<td><input type='checkbox' name='TRANSPARENT_OVPN' $checked{'TRANSPARENT_OVPN'}{'on'} /></td></tr>";
    }
    print <<END

<tr>
    <td class='base'>$Lang::tr{'proxy port'}:</td>
    <td><input type='text' name='PROXY_PORT' value='$proxysettings{'PROXY_PORT'}' size='5' /></td>
    <td class='base'>$Lang::tr{'visible hostname'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='VISIBLE_HOSTNAME' value='$proxysettings{'VISIBLE_HOSTNAME'}' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'error language'}:</td>
    <td class='base'>
    <select name='ERR_LANGUAGE'>
END
;
    foreach (<$errordir/*>) {
        if (-d) {
            $countrycode = substr($_,rindex($_,"/")+1);
            my $selected = '';
            if($countrycode eq $proxysettings{'ERR_LANGUAGE'}) {
                $selected = "selected='selected'";
            }
            my $langname = $countrycode;
            if(defined($language{$countrycode})) {
                $langname = $language{$countrycode};
            }
            print "<option value='$countrycode' $selected>$langname</option>\n";
        }
    }
    print <<END
    </select>
    </td>
    <td class='base'>$Lang::tr{'admin mail'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='ADMIN_MAIL_ADDRESS' value='$proxysettings{'ADMIN_MAIL_ADDRESS'}' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'error design'}:</td>
    <td class='base'><select name='ERR_DESIGN'>
        <option value='ipcop' $selected{'ERR_DESIGN'}{'ipcop'}>IPCop</option>
        <option value='squid' $selected{'ERR_DESIGN'}{'squid'}>$Lang::tr{'standard'}</option>
    </select></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'suppress version'}:</td>
    <td><input type='checkbox' name='SUPPRESS_VERSION' $checked{'SUPPRESS_VERSION'}{'on'} /></td>
    <td class='base'>$Lang::tr{'squid version'}:</td>
    <td class='base'>&nbsp;[ $squidversion[0] ]</td>
</tr>
<tr>
    <td colspan='4'><hr size='1'/></td>
</tr>
<tr>
    <td colspan='4' class='base'><b>$Lang::tr{'upstream proxy'}</b></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'via forwarding'}:</td>
    <td><input type='checkbox' name='FORWARD_VIA' $checked{'FORWARD_VIA'}{'on'} /></td>
    <td class='base'>$Lang::tr{'upstream proxy host:port'}&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='UPSTREAM_PROXY' value='$proxysettings{'UPSTREAM_PROXY'}' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'client IP forwarding'}:</td>
    <td><input type='checkbox' name='FORWARD_IPADDRESS' $checked{'FORWARD_IPADDRESS'}{'on'} /></td>
    <td class='base'>$Lang::tr{'upstream username'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='UPSTREAM_USER' value='$proxysettings{'UPSTREAM_USER'}' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'username forwarding'}:</td>
    <td><input type='checkbox' name='FORWARD_USERNAME' $checked{'FORWARD_USERNAME'}{'on'} /></td>
    <td class='base'>$Lang::tr{'upstream password'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='password' name='UPSTREAM_PASSWORD' value='$proxysettings{'UPSTREAM_PASSWORD'}' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'no connection auth'}:</td>
    <td><input type='checkbox' name='NO_CONNECTION_AUTH' $checked{'NO_CONNECTION_AUTH'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
<tr>
    <td colspan='4'><hr size='1'/></td>
</tr>
<tr>
    <td colspan='4' class='base'><b>$Lang::tr{'log settings'}</b></td>
</tr><tr>
    <td class='base'>$Lang::tr{'log enabled'}:</td>
    <td><input type='checkbox' name='LOGGING' $checked{'LOGGING'}{'on'} /></td>
    <td class='base'>$Lang::tr{'log query'}:</td>
    <td><input type='checkbox' name='LOGQUERY' $checked{'LOGQUERY'}{'on'} /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'log useragent'}:</td>
    <td><input type='checkbox' name='LOGUSERAGENT' $checked{'LOGUSERAGENT'}{'on'} /></td>
</tr><tr>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
    <td class='base'>$Lang::tr{'log username'}:</td>
    <td><input type='checkbox' name='LOGUSERNAME' $checked{'LOGUSERNAME'}{'on'} /></td>
</tr>
</table>

<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;
    <font class='base'>$Lang::tr{'this field may be blank'}</font>
    </td>
    <td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'clear cache'}' /></td>
    <td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-webproxy.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>

    </td>
</tr>
</table>

END
;

    &Header::closebox();

    &Header::openbox('100%', 'left', "$Lang::tr{'adv options'}", $error_options);

    print <<END
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'cache management'}</b></td>
</tr>
<tr>
    <td width='25%'></td> <td width='20%'> </td><td width='25%'> </td><td width='30%'></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'ram cache size'}:</td>
    <td><input type='text' name='CACHE_MEM' value='$proxysettings{'CACHE_MEM'}' size='5' /></td>
    <td class='base'>$Lang::tr{'hdd cache size'}:</td>
    <td><input type='text' name='CACHE_SIZE' value='$proxysettings{'CACHE_SIZE'}' size='5' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'min size'}:</td>
    <td><input type='text' name='MIN_SIZE' value='$proxysettings{'MIN_SIZE'}' size='5' /></td>
    <td class='base'>$Lang::tr{'max size'}:</td>
    <td><input type='text' name='MAX_SIZE' value='$proxysettings{'MAX_SIZE'}' size='5' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'number of L1 dirs'}:</td>
    <td class='base'><select name='L1_DIRS'>
        <option value='16'  $selected{'L1_DIRS'}{'16'}>16</option>
        <option value='32'  $selected{'L1_DIRS'}{'32'}>32</option>
        <option value='64'  $selected{'L1_DIRS'}{'64'}>64</option>
        <option value='128' $selected{'L1_DIRS'}{'128'}>128</option>
        <option value='256' $selected{'L1_DIRS'}{'256'}>256</option>
    </select></td>
    <td colspan='2' rowspan= '5' valign='top' class='base'>
        <table cellspacing='0' cellpadding='0'>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
            <td>$Lang::tr{'no cache sites'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
            </tr>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
            <td><textarea name='DST_NOCACHE' cols='32' rows='6' wrap='off'>
END
;

    if(defined($proxysettings{'DST_NOCACHE'})) {
        print $proxysettings{'DST_NOCACHE'};
    }

    print <<END
</textarea></td>
        </tr>
        </table>
    </td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'memory replacement policy'}:</td>
    <td class='base'><select name='MEM_POLICY'>
        <option value='LRU' $selected{'MEM_POLICY'}{'LRU'}>LRU</option>
        <option value='heap LFUDA' $selected{'MEM_POLICY'}{'heap LFUDA'}>heap LFUDA</option>
        <option value='heap GDSF' $selected{'MEM_POLICY'}{'heap GDSF'}>heap GDSF</option>
        <option value='heap LRU' $selected{'MEM_POLICY'}{'heap LRU'}>heap LRU</option>
    </select></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'cache replacement policy'}:</td>
    <td class='base'><select name='CACHE_POLICY'>
        <option value='LRU' $selected{'CACHE_POLICY'}{'LRU'}>LRU</option>
        <option value='heap LFUDA' $selected{'CACHE_POLICY'}{'heap LFUDA'}>heap LFUDA</option>
        <option value='heap GDSF' $selected{'CACHE_POLICY'}{'heap GDSF'}>heap GDSF</option>
        <option value='heap LRU' $selected{'CACHE_POLICY'}{'heap LRU'}>heap LRU</option>
    </select></td>
</tr>
<tr>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'offline mode'}:</td>
    <td><input type='checkbox' name='OFFLINE_MODE' $checked{'OFFLINE_MODE'}{'on'} /></td>
</tr>
</table>
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'destination ports'}</b></td>
</tr>
<tr>
    <td width='25%'></td> <td width='20%'> </td><td width='25%'> </td><td width='30%'></td>
</tr>
<tr>
    <td colspan='2' class='base'>$Lang::tr{'standard ports'}:</td>
    <td colspan='2' class='base'>$Lang::tr{'ssl ports'}:</td>
</tr>
<tr>
    <td colspan='2'><textarea name='PORTS_SAFE' cols='32' rows='6' wrap='off'>
END
;
    if (!$proxysettings{'PORTS_SAFE'}) {
        print $def_ports_safe;
    }
    else {
        print $proxysettings{'PORTS_SAFE'};
    }

    print <<END
</textarea></td>
    <td colspan='2'><textarea name='PORTS_SSL' cols='32' rows='6' wrap='off'>
END
;
    if (!$proxysettings{'PORTS_SSL'}) { print $def_ports_ssl; } else { print $proxysettings{'PORTS_SSL'}; }

    print <<END
</textarea></td>
</tr>
</table>
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'network based access'}</b></td>
</tr>
<tr>
    <td width='25%'></td> <td width='20%'> </td><td width='30%'> </td><td width='25%'></td>
</tr>
<tr>
    <td colspan='2' class='base'>$Lang::tr{'allowed subnets'}:</td>
    <td colspan='2'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2' rowspan='4' valign='top'><textarea name='SRC_SUBNETS' cols='32' rows='6' wrap='off'>
END
;

    if (!$proxysettings{'SRC_SUBNETS'})
    {
        print "$netsettings{'GREEN_1_NETADDRESS'}\/$netsettings{'GREEN_1_NETMASK'}\n";
        if ($netsettings{'BLUE_COUNT'} >= 1)
        {
            print "$netsettings{'BLUE_1_NETADDRESS'}\/$netsettings{'BLUE_1_NETMASK'}\n";
        }
    }
    else {
        print $proxysettings{'SRC_SUBNETS'};
    }

    print <<END
</textarea></td>
END
;

    $line = $Lang::tr{'no internal proxy'};
    print "<td class='base'>$line:</td>\n";
    print <<END
    <td><input type='checkbox' name='NO_PROXY_LOCAL' $checked{'NO_PROXY_LOCAL'}{'on'} /></td>
</tr>
END
;

    $line = $Lang::tr{'no internal proxy on green'};
    $line =~ s/Green/<span class='ofw_iface_green' style='font-weight: bold;'>$Lang::tr{'green'}<\/span>/i;
    print "<tr><td class='base'>$line:</td>\n";
    print <<END
    <td><input type='checkbox' name='NO_PROXY_LOCAL_GREEN' $checked{'NO_PROXY_LOCAL_GREEN'}{'on'} /></td>
</tr>
END
;
    if ($netsettings{'BLUE_COUNT'} >= 1) {
        $line = $Lang::tr{'no internal proxy on blue'};
        $line =~ s/Blue/<span class='ofw_iface_blue' style='font-weight: bold;'>$Lang::tr{'blue'}<\/span>/i;
        print "<tr>\n";
        print "<td class='base'>$line:</td>\n";
        print <<END
    <td><input type='checkbox' name='NO_PROXY_LOCAL_BLUE' $checked{'NO_PROXY_LOCAL_BLUE'}{'on'} /></td>
</tr>
END
;
    }
    print <<END
<tr>
    <td colspan='2'>&nbsp;</td>
</tr>
</table>
<table width='100%'>
<tr>
    <td width='25%'></td> <td width='20%'> </td><td width='25%'> </td><td width='30%'></td>
</tr>
<tr>
    <td colspan='2' class='base'>$Lang::tr{'unrestricted ip clients'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='2' class='base'>$Lang::tr{'unrestricted mac clients'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr>
<tr>
    <td colspan='2'><textarea name='SRC_UNRESTRICTED_IP' cols='32' rows='6' wrap='off'>
END
;

    if(defined($proxysettings{'SRC_UNRESTRICTED_IP'})) {
        print $proxysettings{'SRC_UNRESTRICTED_IP'};
    }

    print <<END
</textarea></td>
    <td colspan='2'><textarea name='SRC_UNRESTRICTED_MAC' cols='32' rows='6' wrap='off'>
END
;

    if(defined($proxysettings{'SRC_UNRESTRICTED_MAC'})) {
        print $proxysettings{'SRC_UNRESTRICTED_MAC'};
    }

    print <<END
</textarea></td>
</tr>
</table>
<table width='100%'>
<tr>
    <td width='25%'></td> <td width='20%'> </td><td width='25%'> </td><td width='30%'></td>
</tr>
<tr>
    <td colspan='2' class='base'>$Lang::tr{'banned ip clients'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td colspan='2' class='base'>$Lang::tr{'banned mac clients'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr>
<tr>
    <td colspan='2'><textarea name='SRC_BANNED_IP' cols='32' rows='6' wrap='off'>
END
;

    if(defined($proxysettings{'SRC_BANNED_IP'})) {
        print $proxysettings{'SRC_BANNED_IP'};
    }

    print <<END
</textarea></td>
    <td colspan='2'><textarea name='SRC_BANNED_MAC' cols='32' rows='6' wrap='off'>
END
;

    if(defined($proxysettings{'SRC_BANNED_MAC'})) {
        print $proxysettings{'SRC_BANNED_MAC'};
    }

    print <<END
</textarea></td>
</tr>
</table>

<hr size='1'/>

END
;
# -------------------------------------------------------------------
#  CRE GUI
# -------------------------------------------------------------------

    print <<END
<table width='100%'>

<tr>
    <td colspan='4'><b>$Lang::tr{'classroom extensions'}</b></td>
</tr>
<tr>
    <td width='25%'></td> <td width='20%'> </td><td width='25%'> </td><td width='30%'></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'enabled'}:</td>
    <td><input type='checkbox' name='CLASSROOM_EXT' $checked{'CLASSROOM_EXT'}{'on'} /></td>
    <td class='base'>$Lang::tr{'supervisor password'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='password' name='SUPERVISOR_PASSWORD' value='$proxysettings{'SUPERVISOR_PASSWORD'}' size='12' /></td>
</tr>
<tr>
    <td colspan='2' class='base'>$Lang::tr{'cre group definitions'}:</td>
    <td colspan='2' class='base'>$Lang::tr{'cre supervisors'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr>
<tr>
    <td colspan='2'><textarea name='CRE_GROUPS' cols='32' rows='6' wrap='off'>$proxysettings{'CRE_GROUPS'}</textarea></td>
    <td colspan='2'><textarea name='CRE_SVHOSTS' cols='32' rows='6' wrap='off'>$proxysettings{'CRE_SVHOSTS'}</textarea></td>
</tr>

</table>

<hr size='1'/>
END
;

# -------------------------------------------------------------------

    print <<END

<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'time restrictions'}</b></td>
</tr>
<tr>
    <td width='2%'>$Lang::tr{'access'}</td>
    <td width='1%'>&nbsp;</td>
    <td width='2%' align='center'>$Lang::tr{'monday short'}</td>
    <td width='2%' align='center'>$Lang::tr{'tuesday short'}</td>
    <td width='2%' align='center'>$Lang::tr{'wednesday short'}</td>
    <td width='2%' align='center'>$Lang::tr{'thursday short'}</td>
    <td width='2%' align='center'>$Lang::tr{'friday short'}</td>
    <td width='2%' align='center'>$Lang::tr{'saturday short'}</td>
    <td width='2%' align='center'>$Lang::tr{'sunday short'}</td>
    <td width='1%'>&nbsp;&nbsp;</td>
    <td width='7%' colspan=3>$Lang::tr{'from'}</td>
    <td width='1%'>&nbsp;</td>
    <td width='7%' colspan=3>$Lang::tr{'to'}</td>
    <td>&nbsp;</td>
</tr>
<tr>
    <td class='base'>
    <select name='TIME_ACCESS_MODE'>
    <option value='allow' $selected{'TIME_ACCESS_MODE'}{'allow'}>$Lang::tr{'mode allow'}</option>
    <option value='deny'  $selected{'TIME_ACCESS_MODE'}{'deny'}>$Lang::tr{'mode deny'}</option>
    </select>
    </td>
    <td>&nbsp;</td>
    <td class='base'><input type='checkbox' name='TIME_MON' $checked{'TIME_MON'}{'on'} /></td>
    <td class='base'><input type='checkbox' name='TIME_TUE' $checked{'TIME_TUE'}{'on'} /></td>
    <td class='base'><input type='checkbox' name='TIME_WED' $checked{'TIME_WED'}{'on'} /></td>
    <td class='base'><input type='checkbox' name='TIME_THU' $checked{'TIME_THU'}{'on'} /></td>
    <td class='base'><input type='checkbox' name='TIME_FRI' $checked{'TIME_FRI'}{'on'} /></td>
    <td class='base'><input type='checkbox' name='TIME_SAT' $checked{'TIME_SAT'}{'on'} /></td>
    <td class='base'><input type='checkbox' name='TIME_SUN' $checked{'TIME_SUN'}{'on'} /></td>
    <td>&nbsp;</td>
    <td class='base'>
    <select name='TIME_FROM_HOUR'>
END
    ;
    for ($i=0;$i<=24;$i++) {
        my $fromHour = sprintf("%02s",$i);

        my $selected = '';
        if($fromHour eq $proxysettings{'TIME_FROM_HOUR'}) {
             $selected = "selected='selected'";
        }

        print "<option $selected>$fromHour</option>\n";
    }

    print <<END
    </select>
    </td>
    <td>:</td>
    <td class='base'>
    <select name='TIME_FROM_MINUTE'>
END
;
    for ($i=0;$i<=45;$i+=15) {
        my $fromMinute = sprintf("%02s",$i);

        my $selected = '';
        if($fromMinute eq $proxysettings{'TIME_FROM_MINUTE'}) {
             $selected = "selected='selected'";
        }

        print "<option $selected>$fromMinute</option>\n";
    }

    print <<END
    </select>
    </td>
    <td> - </td>
    <td class='base'>
    <select name='TIME_TO_HOUR'>
END
;
    for ($i=0;$i<=24;$i++) {
        my $toHour = sprintf("%02s",$i);

        my $selected = '';
        if($toHour eq $proxysettings{'TIME_TO_HOUR'}) {
             $selected = "selected='selected'";
        }

        print "<option $selected>$toHour</option>\n";
    }

    print <<END
    </select>
    </td>
    <td>:</td>
    <td class='base'>
    <select name='TIME_TO_MINUTE'>
END
;
    for ($i=0;$i<=45;$i+=15) {
        my $toMinute = sprintf("%02s",$i);

        my $selected = '';
        if($toMinute eq $proxysettings{'TIME_TO_MINUTE'}) {
             $selected = "selected='selected'";
        }

        print "<option $selected>$toMinute</option>\n";
    }

    print <<END
    </select>
    </td>
</tr>
</table>
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'transfer limits'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'max download size'}:</td>
    <td width='20%'><input type='text' name='MAX_INCOMING_SIZE' value='$proxysettings{'MAX_INCOMING_SIZE'}' size='5' /></td>
    <td width='25%' class='base'>$Lang::tr{'max upload size'}:</td>
    <td width='30%'><input type='text' name='MAX_OUTGOING_SIZE' value='$proxysettings{'MAX_OUTGOING_SIZE'}' size='5' /></td>
</tr>
</table>
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'download throttling'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'throttling total on'} <span class='ofw_iface_green' style='font-weight: bold;'>$Lang::tr{'green'}</span>:</td>
    <td width='20%' class='base'>
    <select name='THROTTLING_GREEN_TOTAL'>
END
;

    foreach my $limit (@throttle_limits) {
        my $selected = '';
        if($limit eq $proxysettings{'THROTTLING_GREEN_TOTAL'}) {
             $selected = "selected='selected'";
        }

        print "\t<option value='$limit' $selected>$limit kBit/s</option>\n";
    }

    my $selectedGT = '';
    if($proxysettings{'THROTTLING_GREEN_TOTAL'} eq 'unlimited') {
        $selectedGT = "selected='selected'";
    }

    print <<END
    <option value='0' $selectedGT>$Lang::tr{'throttling unlimited'}</option>
    </select>
    </td>
    <td width='25%' class='base'>$Lang::tr{'throttling per host on'} <span class='ofw_iface_green' style='font-weight: bold;'>$Lang::tr{'green'}</span>:</td>
    <td width='30%' class='base'>
    <select name='THROTTLING_GREEN_HOST'>
END
;

    foreach my $limit (@throttle_limits) {
        my $selected = '';
        if($limit eq $proxysettings{'THROTTLING_GREEN_HOST'}) {
             $selected = "selected='selected'";
        }

        print "\t<option value='$limit' $selected>$limit kBit/s</option>\n";
    }

    my $selectedGH = '';
    if($proxysettings{'THROTTLING_GREEN_HOST'} eq 'unlimited') {
        $selectedGH = "selected='selected'";
    }

    print <<END
    <option value='0' $selectedGH>$Lang::tr{'throttling unlimited'}</option>
    </select>
    </td>
</tr>
END
;

    if ($netsettings{'BLUE_COUNT'} >= 1) {
        print <<END
<tr>
    <td class='base'>$Lang::tr{'throttling total on'} <span class='ofw_iface_blue' style='font-weight: bold;'>$Lang::tr{'blue'}</span>:</td>
    <td class='base'>
    <select name='THROTTLING_BLUE_TOTAL'>
END
;

        foreach my $limit (@throttle_limits) {
            my $selected = '';
            if($limit eq $proxysettings{'THROTTLING_BLUE_TOTAL'}) {
                 $selected = "selected='selected'";
            }

            print "\t<option value='$limit' $selected>$limit kBit/s</option>\n";
        }

        my $selectedBT = '';
        if($proxysettings{'THROTTLING_BLUE_TOTAL'} eq 'unlimited') {
            $selectedBT = "selected='selected'";
        }

        print <<END
    <option value='0' $selectedBT>$Lang::tr{'throttling unlimited'}</option>
    </select>
    </td>
    <td class='base'>$Lang::tr{'throttling per host on'} <span class='ofw_iface_blue' style='font-weight: bold;'>$Lang::tr{'blue'}</span>:</td>
    <td class='base'>
    <select name='THROTTLING_BLUE_HOST'>
END
;

        foreach my $limit (@throttle_limits) {
            my $selected = '';
            if($limit eq $proxysettings{'THROTTLING_BLUE_HOST'}) {
                 $selected = "selected='selected'";
            }

            print "\t<option value='$limit' $selected>$limit kBit/s</option>\n";
        }

        my $selectedBH = '';
        if($proxysettings{'THROTTLING_BLUE_HOST'} eq 'unlimited') {
            $selectedBH = "selected='selected'";
        }

        print <<END
    <option value='0' $selectedBH>$Lang::tr{'throttling unlimited'}</option>
    </select>
    </td>
</tr>
END
;
    }

    print <<END
</table>
<table width='100%'>
<tr>
    <td colspan='4'><i>$Lang::tr{'content based throttling'}:</i></td>
</tr>
<tr>
    <td width='15%' class='base'>$Lang::tr{'binary files'}:</td>
    <td width='10%'><input type='checkbox' name='THROTTLE_BINARY' $checked{'THROTTLE_BINARY'}{'on'} /></td>
    <td width='15%' class='base'>$Lang::tr{'disk images'}:</td>
    <td width='10%'><input type='checkbox' name='THROTTLE_DSKIMG' $checked{'THROTTLE_DSKIMG'}{'on'} /></td>
    <td width='15%' class='base'>$Lang::tr{'multimedia'}:</td>
    <td width='10%'><input type='checkbox' name='THROTTLE_MMEDIA' $checked{'THROTTLE_MMEDIA'}{'on'} /></td>
    <td width='15%'>&nbsp;</td>
    <td width='10%'>&nbsp;</td>
</tr>
</table>
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'MIME filter'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'enabled'}:</td>
    <td width='20%'><input type='checkbox' name='ENABLE_MIME_FILTER' $checked{'ENABLE_MIME_FILTER'}{'on'} /></td>
</tr>
<tr>
    <td  colspan='2' class='base'>$Lang::tr{'MIME block types'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td  colspan='2' class='base'>$Lang::tr{'MIME filter exceptions'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr>
<tr>
    <td colspan='2'><textarea name='MIME_TYPES' cols='32' rows='6' wrap='off'>
END
;

    if(defined($proxysettings{'MIME_TYPES'})) {
        print $proxysettings{'MIME_TYPES'};
    }

    print <<END
</textarea></td>
    <td colspan='2'><textarea name='MIME_EXCEPTIONS' cols='32' rows='6' wrap='off'>
END
;

    if(defined($proxysettings{'MIME_EXCEPTIONS'})) {
        print $proxysettings{'MIME_EXCEPTIONS'};
    }

    print <<END
</textarea></td>
</tr>
</table>
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'web browser'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'UA enable filter'}:</td>
    <td width='20%'><input type='checkbox' name='ENABLE_BROWSER_CHECK' $checked{'ENABLE_BROWSER_CHECK'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
<tr>
    <td colspan='4'><i>
END
;
    if (@useragentlist) {
        print "$Lang::tr{'allowed web browsers'}:";
    }
    else {
        print "$Lang::tr{'no clients defined'}";
    }

    print <<END
</i></td>
</tr>
</table>
<table width='100%'>
END
;

    for ($n=0; $n<=@useragentlist; $n = $n + $i) {
        for ($i=0; $i<=3; $i++) {
            if ($i eq 0) { print "<tr>\n"; }
            if (($n+$i) < @useragentlist) {
                @useragent = split(/,/,$useragentlist[$n+$i]);
                print "<td width='15%'>$useragent[1]:<\/td>\n";
                print "<td width='10%'><input type='checkbox' name='UA_$useragent[0]' $checked{'UA_'.$useragent[0]}{'on'} /></td>\n";
            }
            if ($i eq 3) { print "<\/tr>\n"; }
        }
    }

    print <<END
</table>
<hr size='1'/>
<table width='100%'>
<tr>
    <td><b>$Lang::tr{'privacy'}</b></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'fake useragent'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr>
<tr>
    <td><input type='text' name='FAKE_USERAGENT' value='$proxysettings{'FAKE_USERAGENT'}' size='56' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'fake referer'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr>
<tr>
    <td><input type='text' name='FAKE_REFERER' value='$proxysettings{'FAKE_REFERER'}' size='56' /></td>
</tr>
</table>
<hr size='1'/>
END
;

    my %redirectors = ();
    foreach $redirector (</var/ofw/proxy/redirector/*>) {
        if (-e $redirector) {
            my %redirectorsettings=();
            &General::readhash($redirector, \%redirectorsettings);

            if (defined($redirectorsettings{'NAME'})) {
                $redirectors{$redirectorsettings{'NAME'}}{'ENABLED'} = $redirectorsettings{'ENABLED'};
                $redirectors{$redirectorsettings{'NAME'}}{'ORDER'} = $redirectorsettings{'ORDER'};
            }
        }
    }

    #sort redirectors
    my @redirectornames =  &General::sortHashArray('ORDER', 'n', 'asc', \%redirectors);

    if($#redirectornames >= 0) {
        print <<END
<table width='100%'>
<tr>
    <td class='base' colspan='4'><b>$Lang::tr{'redirectors'}</b></td>
</tr>
<tr>
    <td class='base' width='25%'>$Lang::tr{'enabled'}:</td>
    <td class='base' width='20%'><input type='checkbox' name='ENABLE_REDIRECTOR' $checked{'ENABLE_REDIRECTOR'}{'on'} /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'redirector children'}:</td>
    <td class='base'><input type='text' name='CHILDREN' value='$proxysettings{'CHILDREN'}' size='5' /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
<tr>
    <td class='base' colspan='4'><i>$Lang::tr{'available redirectors'}:</i></td>
</tr>
END
;



        foreach my $redirector (@redirectornames) {

            my $checked = '';
            if ($redirectors{$redirector}{'ENABLED'} eq 'on') {
                $checked = "checked='checked'";
            }

            print <<END
    <tr>
        <td class='base'>&nbsp;&nbsp;&nbsp;$redirector:</td>
        <td class='base'><input type='checkbox' $checked disabled='disabled'/></td>
        <td class='base' colspan='2'></td>
    </tr>

END
;
        }


        print <<END
</table>
<hr size='1'/>
END
;
    }
    else {
        print <<END
<table width='100%'>
<tr>
    <td>
        <input type='hidden' name='ENABLE_REDIRECTOR' value='off'/>
        <input type='hidden' name='CHILDREN' value='$proxysettings{'CHILDREN'}'/>
    </td>
</tr>
END
;
    }

    print <<END
<table width='100%'>
<tr>
    <td colspan='5'><b>$Lang::tr{'AUTH method'}</b></td>
</tr>
<tr>
    <td width='16%' class='base'><input type='radio' name='AUTH_METHOD' value='none' $checked{'AUTH_METHOD'}{'none'} />$Lang::tr{'AUTH method none'}</td>
    <td width='16%' class='base'><input type='radio' name='AUTH_METHOD' value='ncsa' $checked{'AUTH_METHOD'}{'ncsa'} />$Lang::tr{'AUTH method ncsa'}</td>
    <td width='16%' class='base'><input type='radio' name='AUTH_METHOD' value='ident' $checked{'AUTH_METHOD'}{'ident'} />$Lang::tr{'AUTH method ident'}</td>
    <td width='16%' class='base'><input type='radio' name='AUTH_METHOD' value='ldap' $checked{'AUTH_METHOD'}{'ldap'} />$Lang::tr{'AUTH method ldap'}</td>
    <td width='16%' class='base'><input type='radio' name='AUTH_METHOD' value='ntlm' $checked{'AUTH_METHOD'}{'ntlm'} />$Lang::tr{'AUTH method ntlm'}</td>
    <td width='16%' class='base'><input type='radio' name='AUTH_METHOD' value='radius' $checked{'AUTH_METHOD'}{'radius'} />$Lang::tr{'AUTH method radius'}</td>
</tr>
</table>
END
;

    if (!($proxysettings{'AUTH_METHOD'} eq 'none')) {
        if (!($proxysettings{'AUTH_METHOD'} eq 'ident')) {
            print <<END
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'AUTH global settings'}</b></td>
</tr>
<tr>
    <td width='25%'></td> <td width='20%'> </td><td width='25%'> </td><td width='30%'></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'AUTH number of auth processes'}:</td>
    <td><input type='text' name='AUTH_CHILDREN' value='$proxysettings{'AUTH_CHILDREN'}' size='5' /></td>
    <td colspan='2' rowspan= '6' valign='top' class='base'>
        <table cellpadding='0' cellspacing='0'>
            <tr>
            <td class='base'>$Lang::tr{'AUTH realm'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
            </tr>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
            <td><input type='text' name='AUTH_REALM' value='$proxysettings{'AUTH_REALM'}' size='40' /></td>
            </tr>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
            <td>$Lang::tr{'AUTH no auth'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
            </tr>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
                <!-- intentionally left empty -->
            </tr>
            <tr>
            <td><textarea name='DST_NOAUTH' cols='32' rows='6' wrap='off'>
END
;

            print $proxysettings{'DST_NOAUTH'};

            print <<END
</textarea></td>
        </tr>
        </table>
    </td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'AUTH auth cache TTL'}:</td>
    <td><input type='text' name='AUTH_CACHE_TTL' value='$proxysettings{'AUTH_CACHE_TTL'}' size='5' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'AUTH limit of IP addresses'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='AUTH_MAX_USERIP' value='$proxysettings{'AUTH_MAX_USERIP'}' size='5' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'AUTH user IP cache TTL'}:</td>
    <td><input type='text' name='AUTH_IPCACHE_TTL' value='$proxysettings{'AUTH_IPCACHE_TTL'}' size='5' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'AUTH always required'}:</td>
    <td><input type='checkbox' name='AUTH_ALWAYS_REQUIRED' $checked{'AUTH_ALWAYS_REQUIRED'}{'on'} /></td>
</tr>
<tr>
    <td colspan='2'>&nbsp;</td>
</tr>
</table>
END
;
        }

# ===================================================================
#  NCSA auth settings
# ===================================================================

        if ($proxysettings{'AUTH_METHOD'} eq 'ncsa') {
            print <<END
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'NCSA auth'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'NCSA min password length'}:</td>
    <td width='20%'><input type='text' name='NCSA_MIN_PASS_LEN' value='$proxysettings{'NCSA_MIN_PASS_LEN'}' size='5' /></td>
    <td width='25%' class='base'>$Lang::tr{'NCSA redirector bypass'} \'$Lang::tr{'NCSA grp extended'}\':</td>
    <td width='20%'><input type='checkbox' name='NCSA_BYPASS_REDIR' $checked{'NCSA_BYPASS_REDIR'}{'on'} /></td>
</tr>
<tr>
    <td colspan='2'><br>&nbsp;<input type='submit' name='ACTION' value='$Lang::tr{'NCSA user management'}'></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
</table>
END
;
        }

# ===================================================================
#  IDENTD auth settings
# ===================================================================

        if ($proxysettings{'AUTH_METHOD'} eq 'ident') {
            print <<END
<hr size ='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'IDENT identd settings'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'IDENT required'}:</td>
    <td width='20%'><input type='checkbox' name='IDENT_REQUIRED' $checked{'IDENT_REQUIRED'}{'on'} /></td>
    <td width='25%' class='base'>$Lang::tr{'AUTH always required'}:</td>
    <td width='30%'><input type='checkbox' name='AUTH_ALWAYS_REQUIRED' $checked{'AUTH_ALWAYS_REQUIRED'}{'on'} /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'IDENT timeout'}:</td>
    <td><input type='text' name='IDENT_TIMEOUT' value='$proxysettings{'IDENT_TIMEOUT'}' size='5' /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
<tr>
    <td colspan='2' class='base'>$Lang::tr{'IDENT aware hosts'}:</td>
    <td colspan='2' class='base'>$Lang::tr{'AUTH no auth'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
</tr>
<tr>
    <td colspan='2'><textarea name='IDENT_HOSTS' cols='32' rows='6' wrap='off'>
END
;
            if (!$proxysettings{'IDENT_HOSTS'}) {
                print "$netsettings{'GREEN_1_NETADDRESS'}\/$netsettings{'GREEN_1_NETMASK'}\n";
                if ($netsettings{'BLUE_COUNT'} >= 1) {
                    print "$netsettings{'BLUE_1_NETADDRESS'}\/$netsettings{'BLUE_1_NETMASK'}\n";
                }
            }
            else {
                print $proxysettings{'IDENT_HOSTS'};
            }

            print <<END
</textarea></td>
            <td colspan='2'><textarea name='DST_NOAUTH' cols='32' rows='6' wrap='off'>
END
;

            print $proxysettings{'DST_NOAUTH'};

            print <<END
</textarea></td>
</tr>
</table>
<hr size ='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'IDENT user based access restrictions'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'enabled'}:</td>
    <td width='20%'><input type='checkbox' name='IDENT_ENABLE_ACL' $checked{'IDENT_ENABLE_ACL'}{'on'} /></td>
    <td width='25%'>&nbsp;</td>
    <td width='30%'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2'><input type='radio' name='IDENT_USER_ACL' value='positive' $checked{'IDENT_USER_ACL'}{'positive'} />
    $Lang::tr{'IDENT use positive access list'}:</td>
    <td colspan='2'><input type='radio' name='IDENT_USER_ACL' value='negative' $checked{'IDENT_USER_ACL'}{'negative'} />
    $Lang::tr{'IDENT use negative access list'}:</td>
</tr>
<tr>
    <td colspan='2'>$Lang::tr{'IDENT authorized users'}</td>
    <td colspan='2'>$Lang::tr{'IDENT unauthorized users'}</td>
</tr>
<tr>
    <td colspan='2'><textarea name='IDENT_ALLOW_USERS' cols='32' rows='6' wrap='off'>
END
;
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'ident') {
            print $proxysettings{'IDENT_ALLOW_USERS'};
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'ident') {
            print <<END
</textarea></td>
    <td colspan='2'><textarea name='IDENT_DENY_USERS' cols='32' rows='6' wrap='off'>
END
;
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'ident') {
            print $proxysettings{'IDENT_DENY_USERS'};
        }


        if ($proxysettings{'AUTH_METHOD'} eq 'ident') {
            print <<END
</textarea></td>
</tr>
</table>
END
;
        }

# ===================================================================
#  NTLM auth settings
# ===================================================================

        if ($proxysettings{'AUTH_METHOD'} eq 'ntlm') {
            print <<END
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='6'><b>$Lang::tr{'NTLM domain settings'}</b></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'NTLM domain'}:</td>
    <td><input type='text' name='NTLM_DOMAIN' value='$proxysettings{'NTLM_DOMAIN'}' size='15' /></td>
    <td class='base'>$Lang::tr{'NTLM PDC hostname'}:</td>
    <td><input type='text' name='NTLM_PDC' value='$proxysettings{'NTLM_PDC'}' size='14' /></td>
    <td class='base'>$Lang::tr{'NTLM BDC hostname'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='NTLM_BDC' value='$proxysettings{'NTLM_BDC'}' size='14' /></td>
</tr>
</table>
<hr size ='1'/>
<table width='100%'>
<tr>
    <td colspan='3'><b>$Lang::tr{'NTLM auth mode'}</b></td>
</tr>
<tr>
    <td width='25%' class='base' width='25%'>$Lang::tr{'NTLM use integrated auth'}:</td>
    <td width='20%'><input type='checkbox' name='NTLM_ENABLE_INT_AUTH' $checked{'NTLM_ENABLE_INT_AUTH'}{'on'} /></td>
    <td>&nbsp;</td>
</tr>
</table>
<hr size ='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'NTLM user based access restrictions'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'enabled'}:</td>
    <td width='20%'><input type='checkbox' name='NTLM_ENABLE_ACL' $checked{'NTLM_ENABLE_ACL'}{'on'} /></td>
    <td width='25%'>&nbsp;</td>
    <td width='30%'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2'><input type='radio' name='NTLM_USER_ACL' value='positive' $checked{'NTLM_USER_ACL'}{'positive'} />
    $Lang::tr{'NTLM use positive access list'}:</td>
    <td colspan='2'><input type='radio' name='NTLM_USER_ACL' value='negative' $checked{'NTLM_USER_ACL'}{'negative'} />
    $Lang::tr{'NTLM use negative access list'}:</td>
</tr>
<tr>
    <td colspan='2'>$Lang::tr{'NTLM authorized users'}</td>
    <td colspan='2'>$Lang::tr{'NTLM unauthorized users'}</td>
</tr>
<tr>
    <td colspan='2'><textarea name='NTLM_ALLOW_USERS' cols='32' rows='6' wrap='off'>$proxysettings{'NTLM_ALLOW_USERS'}</textarea></td>
    <td colspan='2'><textarea name='NTLM_DENY_USERS' cols='32' rows='6' wrap='off'>$proxysettings{'NTLM_DENY_USERS'}</textarea></td>
</tr>
</table>
END
;
        }

# ===================================================================
#  LDAP auth settings
# ===================================================================

        if ($proxysettings{'AUTH_METHOD'} eq 'ldap') {
            print <<END
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'LDAP common settings'}</b></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'LDAP basedn'}:</td>
    <td><input type='text' name='LDAP_BASEDN' value='$proxysettings{'LDAP_BASEDN'}' size='37' /></td>
    <td class='base'>$Lang::tr{'LDAP type'}:</td>
    <td class='base'><select name='LDAP_TYPE'>
        <option value='ADS' $selected{'LDAP_TYPE'}{'ADS'}>$Lang::tr{'LDAP ADS'}</option>
        <option value='NDS' $selected{'LDAP_TYPE'}{'NDS'}>$Lang::tr{'LDAP NDS'}</option>
        <option value='V2' $selected{'LDAP_TYPE'}{'V2'}>$Lang::tr{'LDAP V2'}</option>
        <option value='V3' $selected{'LDAP_TYPE'}{'V3'}>$Lang::tr{'LDAP V3'}</option>
    </select></td>
</tr>
<tr>
    <td width='20%' class='base'>$Lang::tr{'LDAP server'}:</td>
    <td width='40%'><input type='text' name='LDAP_SERVER' value='$proxysettings{'LDAP_SERVER'}' size='14' /></td>
    <td width='20%' class='base'>$Lang::tr{'LDAP port'}:</td>
    <td><input type='text' name='LDAP_PORT' value='$proxysettings{'LDAP_PORT'}' size='3' /></td>
</tr>
</table>
<hr size ='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'LDAP binddn settings'}</b></td>
</tr>
<tr>
    <td width='20%' class='base'>$Lang::tr{'LDAP binddn username'}:</td>
    <td width='40%'><input type='text' name='LDAP_BINDDN_USER' value='$proxysettings{'LDAP_BINDDN_USER'}' size='37' /></td>
    <td width='20%' class='base'>$Lang::tr{'LDAP binddn password'}:</td>
    <td><input type='password' name='LDAP_BINDDN_PASS' value='$proxysettings{'LDAP_BINDDN_PASS'}' size='14' /></td>
</tr>
</table>
<hr size ='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'LDAP group access control'}</b></td>
</tr>
<tr>
    <td width='20%' class='base'>$Lang::tr{'LDAP group required'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='40%'><input type='text' name='LDAP_GROUP' value='$proxysettings{'LDAP_GROUP'}' size='37' /></td>
    <td>&nbsp;</td>
    <td>&nbsp;</td>
</tr>
</table>
END
;
        }

# ===================================================================
#  RADIUS auth settings
# ===================================================================

        if ($proxysettings{'AUTH_METHOD'} eq 'radius') {
            print <<END
<hr size='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'RADIUS radius settings'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'RADIUS server'}:</td>
    <td width='20%'><input type='text' name='RADIUS_SERVER' value='$proxysettings{'RADIUS_SERVER'}' size='14' /></td>
    <td width='25%' class='base'>$Lang::tr{'RADIUS port'}:</td>
    <td width='30%'><input type='text' name='RADIUS_PORT' value='$proxysettings{'RADIUS_PORT'}' size='3' /></td>
</tr>
<tr>
    <td class='base'>$Lang::tr{'RADIUS identifier'}:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td><input type='text' name='RADIUS_IDENTIFIER' value='$proxysettings{'RADIUS_IDENTIFIER'}' size='14' /></td>
    <td class='base'>$Lang::tr{'RADIUS secret'}:</td>
    <td><input type='password' name='RADIUS_SECRET' value='$proxysettings{'RADIUS_SECRET'}' size='14' /></td>
</tr>
</table>
<hr size ='1'/>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'RADIUS user based access restrictions'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'enabled'}:</td>
    <td width='20%'><input type='checkbox' name='RADIUS_ENABLE_ACL' $checked{'RADIUS_ENABLE_ACL'}{'on'} /></td>
    <td width='25%'>&nbsp;</td>
    <td width='30%'>&nbsp;</td>
</tr>
<tr>
    <td colspan='2'><input type='radio' name='RADIUS_USER_ACL' value='positive' $checked{'RADIUS_USER_ACL'}{'positive'} />
    $Lang::tr{'RADIUS use positive access list'}:</td>
    <td colspan='2'><input type='radio' name='RADIUS_USER_ACL' value='negative' $checked{'RADIUS_USER_ACL'}{'negative'} />
    $Lang::tr{'RADIUS use negative access list'}:</td>
</tr>
<tr>
    <td colspan='2'>$Lang::tr{'RADIUS authorized users'}</td>
    <td colspan='2'>$Lang::tr{'RADIUS unauthorized users'}</td>
</tr>
<tr>
    <td colspan='2'><textarea name='RADIUS_ALLOW_USERS' cols='32' rows='6' wrap='off'>
END
;
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'radius') {
            print $proxysettings{'RADIUS_ALLOW_USERS'};
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'radius') {
            print <<END
</textarea></td>
    <td colspan='2'><textarea name='RADIUS_DENY_USERS' cols='32' rows='6' wrap='off'>
END
;
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'radius') {
            print $proxysettings{'RADIUS_DENY_USERS'};
        }

        if ($proxysettings{'AUTH_METHOD'} eq 'radius') {
            print <<END
</textarea></td>
</tr>
</table>
END
;
        }

# ===================================================================

    }

    print "<table>\n<tr>\n";

    if ($proxysettings{'AUTH_METHOD'} eq 'none') {
        print <<END
<td><input type='hidden' name='AUTH_CHILDREN'        value='$proxysettings{'AUTH_CHILDREN'}'/></td>
<td><input type='hidden' name='AUTH_CACHE_TTL'       value='$proxysettings{'AUTH_CACHE_TTL'}' size='5' /></td>
<td><input type='hidden' name='AUTH_MAX_USERIP'      value='$proxysettings{'AUTH_MAX_USERIP'}' size='5' /></td>
<td><input type='hidden' name='AUTH_IPCACHE_TTL'     value='$proxysettings{'AUTH_IPCACHE_TTL'}' size='5' /></td>
<td><input type='hidden' name='AUTH_ALWAYS_REQUIRED' value='$proxysettings{'AUTH_ALWAYS_REQUIRED'}'/></td>
<td><input type='hidden' name='AUTH_REALM'           value='$proxysettings{'AUTH_REALM'}'/></td>
<td><input type='hidden' name='DST_NOAUTH'           value='$proxysettings{'DST_NOAUTH'}'/></td>
END
;
    }

    if ($proxysettings{'AUTH_METHOD'} eq 'ident') {
        print <<END
<td><input type='hidden' name='AUTH_CHILDREN'        value='$proxysettings{'AUTH_CHILDREN'}'/></td>
<td><input type='hidden' name='AUTH_CACHE_TTL'       value='$proxysettings{'AUTH_CACHE_TTL'}' size='5' /></td>
<td><input type='hidden' name='AUTH_MAX_USERIP'      value='$proxysettings{'AUTH_MAX_USERIP'}' size='5' /></td>
<td><input type='hidden' name='AUTH_IPCACHE_TTL'     value='$proxysettings{'AUTH_IPCACHE_TTL'}' size='5' /></td>
<td><input type='hidden' name='AUTH_REALM'           value='$proxysettings{'AUTH_REALM'}'/></td>
END
;
    }

    if (!($proxysettings{'AUTH_METHOD'} eq 'ncsa')) {
        print <<END
<td><input type='hidden' name='NCSA_MIN_PASS_LEN' value='$proxysettings{'NCSA_MIN_PASS_LEN'}'/></td>
<td><input type='hidden' name='NCSA_BYPASS_REDIR' value='$proxysettings{'NCSA_BYPASS_REDIR'}'/></td>
END
;
    }

    if (!($proxysettings{'AUTH_METHOD'} eq 'ident')) {
        print <<END
<td><input type='hidden' name='IDENT_REQUIRED'    value='$proxysettings{'IDENT_REQUIRED'}'/></td>
<td><input type='hidden' name='IDENT_TIMEOUT'     value='$proxysettings{'IDENT_TIMEOUT'}'/></td>
<td><input type='hidden' name='IDENT_HOSTS'       value='$proxysettings{'IDENT_HOSTS'}'/></td>
<td><input type='hidden' name='IDENT_ENABLE_ACL'  value='$proxysettings{'IDENT_ENABLE_ACL'}'/></td>
<td><input type='hidden' name='IDENT_USER_ACL'    value='$proxysettings{'IDENT_USER_ACL'}'/></td>
<td><input type='hidden' name='IDENT_ALLOW_USERS' value='$proxysettings{'IDENT_ALLOW_USERS'}'/></td>
<td><input type='hidden' name='IDENT_DENY_USERS'  value='$proxysettings{'IDENT_DENY_USERS'}'/></td>
END
;
    }

    if (!($proxysettings{'AUTH_METHOD'} eq 'ldap')) {
        print <<END
<td><input type='hidden' name='LDAP_BASEDN'      value='$proxysettings{'LDAP_BASEDN'}'/></td>
<td><input type='hidden' name='LDAP_TYPE'        value='$proxysettings{'LDAP_TYPE'}'/></td>
<td><input type='hidden' name='LDAP_SERVER'      value='$proxysettings{'LDAP_SERVER'}'/></td>
<td><input type='hidden' name='LDAP_PORT'        value='$proxysettings{'LDAP_PORT'}'/></td>
<td><input type='hidden' name='LDAP_BINDDN_USER' value='$proxysettings{'LDAP_BINDDN_USER'}'/></td>
<td><input type='hidden' name='LDAP_BINDDN_PASS' value='$proxysettings{'LDAP_BINDDN_PASS'}'/></td>
<td><input type='hidden' name='LDAP_GROUP'       value='$proxysettings{'LDAP_GROUP'}'/></td>
END
;
    }

    if (!($proxysettings{'AUTH_METHOD'} eq 'ntlm')) {
        print <<END
<td><input type='hidden' name='NTLM_DOMAIN'          value='$proxysettings{'NTLM_DOMAIN'}'/></td>
<td><input type='hidden' name='NTLM_PDC'             value='$proxysettings{'NTLM_PDC'}'/></td>
<td><input type='hidden' name='NTLM_BDC'             value='$proxysettings{'NTLM_BDC'}'/></td>
<td><input type='hidden' name='NTLM_ENABLE_INT_AUTH' value='$proxysettings{'NTLM_ENABLE_INT_AUTH'}'/></td>
<td><input type='hidden' name='NTLM_ENABLE_ACL'      value='$proxysettings{'NTLM_ENABLE_ACL'}'/></td>
<td><input type='hidden' name='NTLM_USER_ACL'        value='$proxysettings{'NTLM_USER_ACL'}'/></td>
<td><input type='hidden' name='NTLM_ALLOW_USERS'     value='$proxysettings{'NTLM_ALLOW_USERS'}'/></td>
<td><input type='hidden' name='NTLM_DENY_USERS'      value='$proxysettings{'NTLM_DENY_USERS'}'/></td>
END
;
    }

    if (!($proxysettings{'AUTH_METHOD'} eq 'radius')) {
        print <<END
<td><input type='hidden' name='RADIUS_SERVER'      value='$proxysettings{'RADIUS_SERVER'}'/></td>
<td><input type='hidden' name='RADIUS_PORT'        value='$proxysettings{'RADIUS_PORT'}'/></td>
<td><input type='hidden' name='RADIUS_IDENTIFIER'  value='$proxysettings{'RADIUS_IDENTIFIER'}'/></td>
<td><input type='hidden' name='RADIUS_SECRET'      value='$proxysettings{'RADIUS_SECRET'}'/></td>
<td><input type='hidden' name='RADIUS_ENABLE_ACL'  value='$proxysettings{'RADIUS_ENABLE_ACL'}'/></td>
<td><input type='hidden' name='RADIUS_USER_ACL'    value='$proxysettings{'RADIUS_USER_ACL'}'/></td>
<td><input type='hidden' name='RADIUS_ALLOW_USERS' value='$proxysettings{'RADIUS_ALLOW_USERS'}'/></td>
<td><input type='hidden' name='RADIUS_DENY_USERS'  value='$proxysettings{'RADIUS_DENY_USERS'}'/></td>
END
;
    }

    print "</tr></table>\n";

    print <<END
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;
    <font class='base'>$Lang::tr{'this field may be blank'}</font>
    </td>
    <td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'clear cache'}' /></td>
    <td class='button2buttons'><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/services-webproxy.html' target='_blank'>
        <img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>

    </td>
</tr>
</table>
END
;

    &Header::closebox();

    print "</form>\n";

}
else {

# ===================================================================
#  NCSA user management
# ===================================================================

    &Header::openbox('100%', 'left', "$Lang::tr{'NCSA auth'}");
    print <<END
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td colspan='4'><b>$Lang::tr{'NCSA user management'}</b></td>
</tr>
<tr>
    <td width='25%' class='base'>$Lang::tr{'NCSA username'}:</td>
    <td width='25%'><input type='text' name='NCSA_USERNAME' value='$proxysettings{'NCSA_USERNAME'}' size='12'
END
;
    if ($proxysettings{'ACTION'} eq $Lang::tr{'edit'}) {
        print " readonly ";
    }

    print <<END
     /></td>
    <td width='25%' class='base'>$Lang::tr{'NCSA group'}:</td>
    <td class='base'>
        <select name='NCSA_GROUP'>
        <option value='standard' $selected{'NCSA_GROUP'}{'standard'}>$Lang::tr{'NCSA grp standard'}</option>
        <option value='extended' $selected{'NCSA_GROUP'}{'extended'}>$Lang::tr{'NCSA grp extended'}</option>
        <option value='disabled' $selected{'NCSA_GROUP'}{'disabled'}>$Lang::tr{'NCSA grp disabled'}</option>
        </select>
    </td>

</tr>
<tr>
    <td class='base'>$Lang::tr{'NCSA password'}:</td>
    <td><input type='password' name='NCSA_PASS' value='$proxysettings{'NCSA_PASS'}' size='14' /></td>
    <td class='base'>$Lang::tr{'NCSA password confirm'}:</td>
    <td><input type='password' name='NCSA_PASS_CONFIRM' value='$proxysettings{'NCSA_PASS_CONFIRM'}' size='14' /></td>
</tr>
</table>
<br>
<table>
<tr>
    <td>&nbsp;</td>
    <td><input type='submit' name='SUBMIT' value='$ncsa_buttontext' /></td>
    <td><input type='hidden' name='ACTION' value='$Lang::tr{'add'}' /></td>
    <td><input type='hidden' name='NCSA_MIN_PASS_LEN' value='$proxysettings{'NCSA_MIN_PASS_LEN'}'/></td>
END
;
    if ($proxysettings{'ACTION'} eq $Lang::tr{'edit'}) {
        print "<td><input type='reset' name='ACTION' value='$Lang::tr{'reset'}' /></td>\n";
    }

    print <<END
    <td>&nbsp;</td>
    <td>&nbsp;</td>
    <td><input type='button' name='return2main' value='$Lang::tr{'back to main page'}' onClick='self.location.href="$ENV{'SCRIPT_NAME'}"'/></td>
</tr>
</table>
</form>
<hr size='1'/>
<table width='100%'>
<tr>
    <td><b>$Lang::tr{'NCSA user accounts'}:</b></td>
</tr>
</table>
<table width='100%' align='center'>
END
;

    if (-e $extgrp)
    {
        open(FILE, $extgrp); @grouplist = <FILE>; close(FILE);
        foreach $user (@grouplist) { chomp($user); push(@userlist,$user.":extended"); }
    }
    if (-e $stdgrp)
    {
        open(FILE, $stdgrp); @grouplist = <FILE>; close(FILE);
        foreach $user (@grouplist) { chomp($user); push(@userlist,$user.":standard"); }
    }
    if (-e $disgrp)
    {
        open(FILE, $disgrp); @grouplist = <FILE>; close(FILE);
        foreach $user (@grouplist) { chomp($user); push(@userlist,$user.":disabled"); }
    }

    @userlist = sort(@userlist);

    # If the password file contains entries, print entries and action icons

    if (! -z "$userdb") {
        print <<END
    <tr>
        <td width='50%' class='boldbase' align='center'><b>$Lang::tr{'NCSA username'}</b></td>
        <td width='50%' class='boldbase' align='center'><b>$Lang::tr{'NCSA group membership'}</b></td>
        <td class='boldbase' colspan='2' align='center'>&nbsp;</td>
    </tr>
END
;
        $id = 0;
        foreach $line (@userlist)
        {
            $id++;
            chomp($line);
            @temp = split(/:/,$line);
            if($proxysettings{'ACTION'} eq $Lang::tr{'edit'} && $proxysettings{'ID'} eq $line) {
                print "<tr class='selectcolour'>";
            }
            else {
                print "<tr class='table".int((($id + 1) % 2) + 1)."colour'>";
            }
            print <<END
        <td align='center'>$temp[0]</td>
        <td align='center'>
END
;
            if ($temp[1] eq 'standard') {
                print $Lang::tr{'NCSA grp standard'};
            }
            elsif ($temp[1] eq 'extended') {
                print $Lang::tr{'NCSA grp extended'};
            }
            elsif ($temp[1] eq 'disabled') {
                print $Lang::tr{'NCSA grp disabled'};
            }

            print <<END
        </td>
        <td width='8%' align='center'>
        <form method='post' name='frma$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'edit'}' src='/images/edit.gif' title='$Lang::tr{'edit'}' alt='$Lang::tr{'edit'}' />
        <input type='hidden' name='ID' value='$line' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'edit'}' />
        </form>
        </td>

        <td width='8%' align='center'>
        <form method='post' name='frmb$id' action='$ENV{'SCRIPT_NAME'}'>
        <input type='image' name='$Lang::tr{'remove'}' src='/images/delete.gif' title='$Lang::tr{'remove'}' alt='$Lang::tr{'remove'}' />
        <input type='hidden' name='ID' value='$temp[0]' />
        <input type='hidden' name='ACTION' value='$Lang::tr{'remove'}' />
        </form>
        </td>
    </tr>
END
;
        }

        print <<END
</table>
<br>
<table>
<tr>
    <td class='boldbase'>&nbsp; <b>$Lang::tr{'legend'}:</b></td>
    <td>&nbsp; &nbsp; <img src='/images/edit.gif' alt='$Lang::tr{'edit'}' /></td>
    <td class='base'>$Lang::tr{'edit'}</td>
    <td>&nbsp; &nbsp; <img src='/images/delete.gif' alt='$Lang::tr{'remove'}' /></td>
    <td class='base'>$Lang::tr{'remove'}</td>
</tr>
END
;
    }
    else {
        print <<END
    <tr>
        <td><i>$Lang::tr{'NCSA no accounts'}</i></td>
    </tr>
END
;
    }

    print <<END
</table>
END
;

    &Header::closebox();

}

# ===================================================================

&Header::closebigbox();

&Header::closepage();


# -------------------------------------------------------------------

sub read_acls
{
    if (-e "$acl_src_subnets") {
        open(FILE,"$acl_src_subnets");
        delete $proxysettings{'SRC_SUBNETS'};
        while (<FILE>) { $proxysettings{'SRC_SUBNETS'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_src_banned_ip") {
        open(FILE,"$acl_src_banned_ip");
        delete $proxysettings{'SRC_BANNED_IP'};
        while (<FILE>) { $proxysettings{'SRC_BANNED_IP'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_src_banned_mac") {
        open(FILE,"$acl_src_banned_mac");
        delete $proxysettings{'SRC_BANNED_MAC'};
        while (<FILE>) { $proxysettings{'SRC_BANNED_MAC'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_src_unrestricted_ip") {
        open(FILE,"$acl_src_unrestricted_ip");
        delete $proxysettings{'SRC_UNRESTRICTED_IP'};
        while (<FILE>) { $proxysettings{'SRC_UNRESTRICTED_IP'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_src_unrestricted_mac") {
        open(FILE,"$acl_src_unrestricted_mac");
        delete $proxysettings{'SRC_UNRESTRICTED_MAC'};
        while (<FILE>) { $proxysettings{'SRC_UNRESTRICTED_MAC'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_dst_nocache") {
        open(FILE,"$acl_dst_nocache");
        delete $proxysettings{'DST_NOCACHE'};
        while (<FILE>) { $proxysettings{'DST_NOCACHE'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_dst_noauth") {
        open(FILE,"$acl_dst_noauth");
        delete $proxysettings{'DST_NOAUTH'};
        while (<FILE>) { $proxysettings{'DST_NOAUTH'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_ports_safe") {
        open(FILE,"$acl_ports_safe");
        delete $proxysettings{'PORTS_SAFE'};
        while (<FILE>) { $proxysettings{'PORTS_SAFE'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_ports_ssl") {
        open(FILE,"$acl_ports_ssl");
        delete $proxysettings{'PORTS_SSL'};
        while (<FILE>) { $proxysettings{'PORTS_SSL'} .= $_ };
        close(FILE);
    }
    if (-e "$mimetypes") {
        open(FILE,"$mimetypes");
        delete $proxysettings{'MIME_TYPES'};
        while (<FILE>) { $proxysettings{'MIME_TYPES'} .= $_ };
        close(FILE);
    }
    if (-e "$acl_dst_mime_exceptions") {
        open(FILE,"$acl_dst_mime_exceptions");
        delete $proxysettings{'MIME_EXCEPTIONS'};
        while (<FILE>) { $proxysettings{'MIME_EXCEPTIONS'} .= $_ };
        close(FILE);
    }
    if (-e "$ntlmdir/msntauth.allowusers") {
        open(FILE,"$ntlmdir/msntauth.allowusers");
        delete $proxysettings{'NTLM_ALLOW_USERS'};
        while (<FILE>) { $proxysettings{'NTLM_ALLOW_USERS'} .= $_ };
        close(FILE);
    }
    if (-e "$ntlmdir/msntauth.denyusers") {
        open(FILE,"$ntlmdir/msntauth.denyusers");
        delete $proxysettings{'NTLM_DENY_USERS'};
        while (<FILE>) { $proxysettings{'NTLM_DENY_USERS'} .= $_ };
        close(FILE);
    }
    if (-e "$raddir/radauth.allowusers") {
        open(FILE,"$raddir/radauth.allowusers");
        delete $proxysettings{'RADIUS_ALLOW_USERS'};
        while (<FILE>) { $proxysettings{'RADIUS_ALLOW_USERS'} .= $_ };
        close(FILE);
    }
    if (-e "$raddir/radauth.denyusers") {
        open(FILE,"$raddir/radauth.denyusers");
        delete $proxysettings{'RADIUS_DENY_USERS'};
        while (<FILE>) { $proxysettings{'RADIUS_DENY_USERS'} .= $_ };
        close(FILE);
    }
    if (-e "$identdir/identauth.allowusers") {
        open(FILE,"$identdir/identauth.allowusers");
        delete $proxysettings{'IDENT_ALLOW_USERS'};
        while (<FILE>) { $proxysettings{'IDENT_ALLOW_USERS'} .= $_ };
        close(FILE);
    }
    if (-e "$identdir/identauth.denyusers") {
        open(FILE,"$identdir/identauth.denyusers");
        delete $proxysettings{'IDENT_DENY_USERS'};
        while (<FILE>) { $proxysettings{'IDENT_DENY_USERS'} .= $_ };
        close(FILE);
    }
    if (-e "$identhosts") {
        open(FILE,"$identhosts");
        delete $proxysettings{'IDENT_HOSTS'};
        while (<FILE>) { $proxysettings{'IDENT_HOSTS'} .= $_ };
        close(FILE);
    }
    if (-e "$cre_groups") {
        open(FILE,"$cre_groups");
        delete $proxysettings{'CRE_GROUPS'};
        while (<FILE>) { $proxysettings{'CRE_GROUPS'} .= $_ };
        close(FILE);
    }
    if (-e "$cre_svhosts") {
        open(FILE,"$cre_svhosts");
        delete $proxysettings{'CRE_SVHOSTS'};
        while (<FILE>) { $proxysettings{'CRE_SVHOSTS'} .= $_ };
        close(FILE);
    }
}

# -------------------------------------------------------------------

sub check_acls
{
    @temp = split(/\n/,$proxysettings{'PORTS_SAFE'});
    undef $proxysettings{'PORTS_SAFE'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g;
        if ($_)
        {
            $line = $_;
            if (/^[^#]+\s+#\sSquids\sport/) { s/(^[^#]+)(\s+#\sSquids\sport)/$proxysettings{'PROXY_PORT'}\2/; $line=$_; }
            s/#.*//g; s/\s+//g;
            if (/.*-.*-.*/) { $errormessage = $Lang::tr{'errmsg invalid destination port'}; }
            @templist = split(/-/);
            foreach (@templist) { unless (&General::validport($_)) { $errormessage = $Lang::tr{'errmsg invalid destination port'}; } }
            $proxysettings{'PORTS_SAFE'} .= $line."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'PORTS_SSL'});
    undef $proxysettings{'PORTS_SSL'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g;
        if ($_)
        {
            $line = $_;
            s/#.*//g; s/\s+//g;
            if (/.*-.*-.*/) { $errormessage = $Lang::tr{'errmsg invalid destination port'}; }
            @templist = split(/-/);
            foreach (@templist) { unless (&General::validport($_)) { $errormessage = $Lang::tr{'errmsg invalid destination port'}; } }
            $proxysettings{'PORTS_SSL'} .= $line."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'DST_NOCACHE'});
    undef $proxysettings{'DST_NOCACHE'};
    foreach (@temp)
    {
        s/^\s+//g;
        unless (/^#/) { s/\s+//g; }
        if ($_)
        {
            if (/^\./) { $_ = '*'.$_; }
            $proxysettings{'DST_NOCACHE'} .= $_."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'SRC_SUBNETS'});
    undef $proxysettings{'SRC_SUBNETS'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g;
        if ($_)
        {
            $_ = NetAddr::IP->new ($_);
            unless (&General::validipandmask($_)) { $errormessage = $Lang::tr{'errmsg invalid ip or mask'}; }
            $proxysettings{'SRC_SUBNETS'} .= $_."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'SRC_BANNED_IP'});
    undef $proxysettings{'SRC_BANNED_IP'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g;
        if ($_)
        {
            $_ = NetAddr::IP->new ($_);
            s/\/32$//;
            unless (&General::validipormask($_)) { $errormessage = $Lang::tr{'errmsg invalid ip or mask'}; }
            $proxysettings{'SRC_BANNED_IP'} .= $_."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'SRC_BANNED_MAC'});
    undef $proxysettings{'SRC_BANNED_MAC'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g; s/-/:/g;
        if ($_)
        {
            unless (&General::validmac($_)) { $errormessage = $Lang::tr{'errmsg invalid mac'}; }
            $proxysettings{'SRC_BANNED_MAC'} .= $_."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'SRC_UNRESTRICTED_IP'});
    undef $proxysettings{'SRC_UNRESTRICTED_IP'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g;
        if ($_)
        {
            $_ = NetAddr::IP->new ($_);
            s/\/32$//;
            unless (&General::validipormask($_)) { $errormessage = $Lang::tr{'errmsg invalid ip or mask'}; }
            $proxysettings{'SRC_UNRESTRICTED_IP'} .= $_."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'SRC_UNRESTRICTED_MAC'});
    undef $proxysettings{'SRC_UNRESTRICTED_MAC'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g; s/-/:/g;
        if ($_)
        {
            unless (&General::validmac($_)) { $errormessage = $Lang::tr{'errmsg invalid mac'}; }
            $proxysettings{'SRC_UNRESTRICTED_MAC'} .= $_."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'MIME_EXCEPTIONS'});
    undef $proxysettings{'MIME_EXCEPTIONS'};
    foreach (@temp)
    {
        s/^\s+//g;
        unless (/^#/) { s/\s+//g; }
        if ($_)
        {
            if (/^\./) { $_ = '*'.$_; }
            $proxysettings{'MIME_EXCEPTIONS'} .= $_."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'DST_NOAUTH'});
    undef $proxysettings{'DST_NOAUTH'};
    foreach (@temp)
    {
        s/^\s+//g;
        unless (/^#/) { s/\s+//g; }
        if ($_)
        {
            if (/^\./) { $_ = '*'.$_; }
            $proxysettings{'DST_NOAUTH'} .= $_."\n";
        }
    }

    if (($proxysettings{'NTLM_ENABLE_ACL'} eq 'on') && ($proxysettings{'NTLM_USER_ACL'} eq 'positive'))
    {
        @temp = split(/\n/,$proxysettings{'NTLM_ALLOW_USERS'});
        undef $proxysettings{'NTLM_ALLOW_USERS'};
        foreach (@temp)
        {
            s/^\s+//g; s/\s+$//g;
            if ($_) { $proxysettings{'NTLM_ALLOW_USERS'} .= $_."\n"; }
        }
        if ($proxysettings{'NTLM_ALLOW_USERS'} eq '') { $errormessage = $Lang::tr{'errmsg acl cannot be empty'}; }
    }

    if (($proxysettings{'NTLM_ENABLE_ACL'} eq 'on') && ($proxysettings{'NTLM_USER_ACL'} eq 'negative'))
    {
        @temp = split(/\n/,$proxysettings{'NTLM_DENY_USERS'});
        undef $proxysettings{'NTLM_DENY_USERS'};
        foreach (@temp)
        {
            s/^\s+//g; s/\s+$//g;
            if ($_) { $proxysettings{'NTLM_DENY_USERS'} .= $_."\n"; }
        }
        if ($proxysettings{'NTLM_DENY_USERS'} eq '') { $errormessage = $Lang::tr{'errmsg acl cannot be empty'}; }
    }

    if (($proxysettings{'IDENT_ENABLE_ACL'} eq 'on') && ($proxysettings{'IDENT_USER_ACL'} eq 'positive'))
    {
        @temp = split(/\n/,$proxysettings{'IDENT_ALLOW_USERS'});
        undef $proxysettings{'IDENT_ALLOW_USERS'};
        foreach (@temp)
        {
            s/^\s+//g; s/\s+$//g;
            if ($_) { $proxysettings{'IDENT_ALLOW_USERS'} .= $_."\n"; }
        }
        if ($proxysettings{'IDENT_ALLOW_USERS'} eq '') { $errormessage = $Lang::tr{'errmsg acl cannot be empty'}; }
    }

    if (($proxysettings{'IDENT_ENABLE_ACL'} eq 'on') && ($proxysettings{'IDENT_USER_ACL'} eq 'negative'))
    {
        @temp = split(/\n/,$proxysettings{'IDENT_DENY_USERS'});
        undef $proxysettings{'IDENT_DENY_USERS'};
        foreach (@temp)
        {
            s/^\s+//g; s/\s+$//g;
            if ($_) { $proxysettings{'IDENT_DENY_USERS'} .= $_."\n"; }
        }
        if ($proxysettings{'IDENT_DENY_USERS'} eq '') { $errormessage = $Lang::tr{'errmsg acl cannot be empty'}; }
    }

    if (($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on') && ($proxysettings{'RADIUS_USER_ACL'} eq 'positive'))
    {
        @temp = split(/\n/,$proxysettings{'RADIUS_ALLOW_USERS'});
        undef $proxysettings{'RADIUS_ALLOW_USERS'};
        foreach (@temp)
        {
            s/^\s+//g; s/\s+$//g;
            if ($_) { $proxysettings{'RADIUS_ALLOW_USERS'} .= $_."\n"; }
        }
        if ($proxysettings{'RADIUS_ALLOW_USERS'} eq '') { $errormessage = $Lang::tr{'errmsg acl cannot be empty'}; }
    }

    if (($proxysettings{'RADIUS_ENABLE_ACL'} eq 'on') && ($proxysettings{'RADIUS_USER_ACL'} eq 'negative'))
    {
        @temp = split(/\n/,$proxysettings{'RADIUS_DENY_USERS'});
        undef $proxysettings{'RADIUS_DENY_USERS'};
        foreach (@temp)
        {
            s/^\s+//g; s/\s+$//g;
            if ($_) { $proxysettings{'RADIUS_DENY_USERS'} .= $_."\n"; }
        }
        if ($proxysettings{'RADIUS_DENY_USERS'} eq '') { $errormessage = $Lang::tr{'errmsg acl cannot be empty'}; }
    }

    @temp = split(/\n/,$proxysettings{'IDENT_HOSTS'});
    undef $proxysettings{'IDENT_HOSTS'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g;
        if ($_)
        {
            $_ = NetAddr::IP->new ($_);
            s/\/32$//;
            unless (&General::validipormask($_)) { $errormessage = $Lang::tr{'errmsg invalid ip or mask'}; }
            $proxysettings{'IDENT_HOSTS'} .= $_."\n";
        }
    }

    @temp = split(/\n/,$proxysettings{'CRE_SVHOSTS'});
    undef $proxysettings{'CRE_SVHOSTS'};
    foreach (@temp)
    {
        s/^\s+//g; s/\s+$//g;
        if ($_)
        {
            $_ = NetAddr::IP->new ($_);
            s/\/32$//;
            unless (&General::validipormask($_)) { $errormessage = $Lang::tr{'errmsg invalid ip or mask'}; }
            $proxysettings{'CRE_SVHOSTS'} .= $_."\n";
        }
    }
}

# -------------------------------------------------------------------

sub write_acls
{
    open(FILE, ">$acl_src_subnets");
    flock(FILE, 2);
    if (!$proxysettings{'SRC_SUBNETS'})
    {
        print FILE NetAddr::IP->new("$netsettings{'GREEN_1_NETADDRESS'}\/$netsettings{'GREEN_1_NETMASK'}")."\n";
        if ($netsettings{'BLUE_COUNT'} >= 1)
        {
            print FILE NetAddr::IP->new("$netsettings{'BLUE_1_NETADDRESS'}\/$netsettings{'BLUE_1_NETMASK'}")."\n";
        }
    }
    else {
        print FILE $proxysettings{'SRC_SUBNETS'};
    }
    close(FILE);

    open(FILE, ">$acl_src_networks");
    flock(FILE, 2);
    if (!$proxysettings{'SRC_SUBNETS'})
    {
        print FILE NetAddr::IP->new("$netsettings{'GREEN_1_NETADDRESS'}\/$netsettings{'GREEN_1_NETMASK'}")."\n";
        if ($netsettings{'BLUE_COUNT'} >= 1)
        {
            print FILE NetAddr::IP->new("$netsettings{'BLUE_1_NETADDRESS'}\/$netsettings{'BLUE_1_NETMASK'}")."\n";
        }
    }
    else {
        print FILE $proxysettings{'SRC_SUBNETS'};
    }

    if (($proxysettings{'ENABLED_OVPN'} eq 'on') && $ovpnactive) {
        print FILE NetAddr::IP->new("$ovpnsettings{'DOVPN_SUBNET'}")."\n";
    }
    close(FILE);

    open(FILE, ">$acl_src_banned_ip");
    flock(FILE, 2);
    print FILE $proxysettings{'SRC_BANNED_IP'};
    close(FILE);

    open(FILE, ">$acl_src_banned_mac");
    flock(FILE, 2);
    print FILE $proxysettings{'SRC_BANNED_MAC'};
    close(FILE);

    open(FILE, ">$acl_src_unrestricted_ip");
    flock(FILE, 2);
    print FILE $proxysettings{'SRC_UNRESTRICTED_IP'};
    close(FILE);

    open(FILE, ">$acl_src_unrestricted_mac");
    flock(FILE, 2);
    print FILE $proxysettings{'SRC_UNRESTRICTED_MAC'};
    close(FILE);

    open(FILE, ">$acl_dst_noauth");
    flock(FILE, 2);
    print FILE $proxysettings{'DST_NOAUTH'};
    close(FILE);

    open(FILE, ">$acl_dst_noauth_net");
    close(FILE);
    open(FILE, ">$acl_dst_noauth_dom");
    close(FILE);
    open(FILE, ">$acl_dst_noauth_url");
    close(FILE);

    @temp = split(/\n/,$proxysettings{'DST_NOAUTH'});
    foreach(@temp)
    {
        unless (/^#/)
        {
            if (/^\*\.\w/)
            {
                s/^\*//;
                open(FILE, ">>$acl_dst_noauth_dom");
                flock(FILE, 2);
                print FILE "$_\n";
                close(FILE);
            }
            elsif (&General::validipormask($_))
            {
                open(FILE, ">>$acl_dst_noauth_net");
                flock(FILE, 2);
                $_ = NetAddr::IP->new ($_);
                s/\/32$//;
                print FILE "$_\n";
                close(FILE);
            }
            elsif (/\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?-\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?/)
            {
                open(FILE, ">>$acl_dst_noauth_net");
                flock(FILE, 2);
                print FILE "$_\n";
                close(FILE);
            }
            else
            {
                open(FILE, ">>$acl_dst_noauth_url");
                flock(FILE, 2);
                if (/^[fh]tt?ps?:\/\//) { print FILE "$_\n"; } else { print FILE "^[fh]tt?ps?://$_\n"; }
                close(FILE);
            }
        }
    }

    open(FILE, ">$acl_dst_nocache");
    flock(FILE, 2);
    print FILE $proxysettings{'DST_NOCACHE'};
    close(FILE);

    open(FILE, ">$acl_dst_nocache_net");
    close(FILE);
    open(FILE, ">$acl_dst_nocache_dom");
    close(FILE);
    open(FILE, ">$acl_dst_nocache_url");
    close(FILE);

    @temp = split(/\n/,$proxysettings{'DST_NOCACHE'});
    foreach(@temp)
    {
        unless (/^#/)
        {
            if (/^\*\.\w/)
            {
                s/^\*//;
                open(FILE, ">>$acl_dst_nocache_dom");
                flock(FILE, 2);
                print FILE "$_\n";
                close(FILE);
            }
            elsif (&General::validipormask($_))
            {
                open(FILE, ">>$acl_dst_nocache_net");
                flock(FILE, 2);
                $_ = NetAddr::IP->new ($_);
                s/\/32$//;
                print FILE "$_\n";
                close(FILE);
            }
            elsif (/\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?-\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?/)
            {
                open(FILE, ">>$acl_dst_nocache_net");
                flock(FILE, 2);
                print FILE "$_\n";
                close(FILE);
            }
            else
            {
                open(FILE, ">>$acl_dst_nocache_url");
                flock(FILE, 2);
                if (/^[fh]tt?ps?:\/\//) { print FILE "$_\n"; } else { print FILE "^[fh]tt?ps?://$_\n"; }
                close(FILE);
            }
        }
    }

    open(FILE, ">$acl_dst_mime_exceptions");
    flock(FILE, 2);
    print FILE $proxysettings{'MIME_EXCEPTIONS'};
    close(FILE);

    open(FILE, ">$acl_dst_mime_exceptions_net");
    close(FILE);
    open(FILE, ">$acl_dst_mime_exceptions_dom");
    close(FILE);
    open(FILE, ">$acl_dst_mime_exceptions_url");
    close(FILE);

    @temp = split(/\n/,$proxysettings{'MIME_EXCEPTIONS'});
    foreach(@temp)
    {
        unless (/^#/)
        {
            if (/^\*\.\w/)
            {
                s/^\*//;
                open(FILE, ">>$acl_dst_mime_exceptions_dom");
                flock(FILE, 2);
                print FILE "$_\n";
                close(FILE);
            }
            elsif (&General::validipormask($_))
            {
                open(FILE, ">>$acl_dst_mime_exceptions_net");
                flock(FILE, 2);
                $_ = NetAddr::IP->new ($_);
                s/\/32$//;
                print FILE "$_\n";
                close(FILE);
            }
            elsif (/\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?-\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?/)
            {
                open(FILE, ">>$acl_dst_mime_exceptions_net");
                flock(FILE, 2);
                print FILE "$_\n";
                close(FILE);
            }
            else
            {
                open(FILE, ">>$acl_dst_mime_exceptions_url");
                flock(FILE, 2);
                if (/^[fh]tt?ps?:\/\//) { print FILE "$_\n"; } else { print FILE "^[fh]tt?ps?://$_\n"; }
                close(FILE);
            }
        }
    }

    open(FILE, ">$acl_ports_safe");
    flock(FILE, 2);
    if (!$proxysettings{'PORTS_SAFE'}) { print FILE $def_ports_safe; } else { print FILE $proxysettings{'PORTS_SAFE'}; }
    close(FILE);

    open(FILE, ">$acl_ports_ssl");
    flock(FILE, 2);
    if (!$proxysettings{'PORTS_SSL'}) { print FILE $def_ports_ssl; } else { print FILE $proxysettings{'PORTS_SSL'}; }
    close(FILE);

    open(FILE, ">$acl_dst_throttle");
    flock(FILE, 2);
    if ($proxysettings{'THROTTLE_BINARY'} eq 'on')
    {
        @temp = split(/\|/,$throttle_binary);
        foreach (@temp) { print FILE "\\.$_\$\n"; }
    }
    if ($proxysettings{'THROTTLE_DSKIMG'} eq 'on')
    {
        @temp = split(/\|/,$throttle_dskimg);
        foreach (@temp) { print FILE "\\.$_\$\n"; }
    }
    if ($proxysettings{'THROTTLE_MMEDIA'} eq 'on')
    {
        @temp = split(/\|/,$throttle_mmedia);
        foreach (@temp) { print FILE "\\.$_\$\n"; }
    }
    if (-s $throttled_urls)
    {
        open(URLFILE, $throttled_urls);
        @temp = <URLFILE>;
        close(URLFILE);
        foreach (@temp) { print FILE; }
    }
    close(FILE);

    open(FILE, ">$mimetypes");
    flock(FILE, 2);
    print FILE $proxysettings{'MIME_TYPES'};
    close(FILE);

    open(FILE, ">$ntlmdir/msntauth.allowusers");
    flock(FILE, 2);
    print FILE $proxysettings{'NTLM_ALLOW_USERS'};
    close(FILE);

    open(FILE, ">$ntlmdir/msntauth.denyusers");
    flock(FILE, 2);
    print FILE $proxysettings{'NTLM_DENY_USERS'};
    close(FILE);

    open(FILE, ">$raddir/radauth.allowusers");
    flock(FILE, 2);
    print FILE $proxysettings{'RADIUS_ALLOW_USERS'};
    close(FILE);

    open(FILE, ">$raddir/radauth.denyusers");
    flock(FILE, 2);
    print FILE $proxysettings{'RADIUS_DENY_USERS'};
    close(FILE);

    open(FILE, ">$identdir/identauth.allowusers");
    flock(FILE, 2);
    print FILE $proxysettings{'IDENT_ALLOW_USERS'};
    close(FILE);

    open(FILE, ">$identdir/identauth.denyusers");
    flock(FILE, 2);
    print FILE $proxysettings{'IDENT_DENY_USERS'};
    close(FILE);

    open(FILE, ">$identhosts");
    flock(FILE, 2);
    print FILE $proxysettings{'IDENT_HOSTS'};
    close(FILE);

    open(FILE, ">$cre_groups");
    flock(FILE, 2);
    print FILE $proxysettings{'CRE_GROUPS'};
    close(FILE);

    open(FILE, ">$cre_svhosts");
    flock(FILE, 2);
    print FILE $proxysettings{'CRE_SVHOSTS'};
    close(FILE);
}

# -------------------------------------------------------------------

sub adduser
{
    my ($str_user, $str_pass, $str_group) = @_;
    my @groupmembers=();

    if ($str_pass eq 'lEaVeAlOnE')
    {
        open(FILE, "$userdb");
        @groupmembers = <FILE>;
        close(FILE);
        foreach $line (@groupmembers) {	if ($line =~ /^$str_user:/i) { $str_pass = substr($line,index($line,":")); } }
        &deluser($str_user);
        open(FILE, ">>$userdb");
        flock FILE,2;
        print FILE "$str_user$str_pass";
        close(FILE);
    } else {
        &deluser($str_user);
        system("/usr/sbin/htpasswd -b $userdb $str_user $str_pass");
    }

    if ($str_group eq 'standard') { open(FILE, ">>$stdgrp");
    } elsif ($str_group eq 'extended') { open(FILE, ">>$extgrp");
    } elsif ($str_group eq 'disabled') { open(FILE, ">>$disgrp"); }
    flock FILE, 2;
    print FILE "$str_user\n";
    close(FILE);

    return;
}

# -------------------------------------------------------------------

sub deluser
{
    my ($str_user) = @_;
    my $groupfile='';
    my @groupmembers=();
    my @templist=();

    foreach $groupfile ($stdgrp, $extgrp, $disgrp)
    {
        undef @templist;
        open(FILE, "$groupfile");
        @groupmembers = <FILE>;
        close(FILE);
        foreach $line (@groupmembers) { if (!($line =~ /^$str_user$/i)) { push(@templist, $line); } }
        open(FILE, ">$groupfile");
        flock FILE, 2;
        print FILE @templist;
        close(FILE);
    }

    undef @templist;
    open(FILE, "$userdb");
    @groupmembers = <FILE>;
    close(FILE);
    foreach $line (@groupmembers) { if (!($line =~ /^$str_user:/i)) { push(@templist, $line); } }
    open(FILE, ">$userdb");
    flock FILE, 2;
    print FILE @templist;
    close(FILE);

    return;
}

# -------------------------------------------------------------------
