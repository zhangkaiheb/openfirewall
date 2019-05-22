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
# (c) 2018-2019 The Openfirewall Team
#

# Add entry in menu
# MENUTHRDLVL "web proxy" 020 "proxy access control" "proxy access control"
#
# Make sure translation exists $Lang::tr{'proxy access control'}

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

    &Header::openbox('100%', 'left', "$Lang::tr{'proxy access control'}", $error_options);

    print <<END
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

#--------------------------------------------------------------------------------


    print <<END
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' align='top' alt='*' />&nbsp;
    <font class='base'>$Lang::tr{'this field may be blank'}</font>
    </td>
    <td class='button2buttons'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'save'}' /></td>
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
        system("/usr/bin/htpasswd -b $userdb $str_user $str_pass");
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
