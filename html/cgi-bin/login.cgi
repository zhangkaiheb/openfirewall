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
# (c) 2017-2020, the Openfirewall Team
#


use strict;

# enable only the following on debugging purpose
use warnings;
use CGI::Carp 'fatalsToBrowser';

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

# Files used
#my $settingsfilename = '/var/ofw/main/settings';


&Header::showhttpheaders();


my $gui_no=13980;


print <<END;
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <meta http-equiv="pragma" content="no-cache">
    <title>$Lang::tr{"please login"}</title><link href="/css/bootstrap.min.css?q=$gui_no" rel="stylesheet" type="text/css">
    <link href="/css/fontawesome.min.css?q=$gui_no" rel="stylesheet" type="text/css">
    <link href="/css/login.css?q=$gui_no" rel="stylesheet" type="text/css">
    <script type="text/javascript" src="/js/jquery-min.js?q=$gui_no"></script>
    <script type="text/javascript" src="/js/bootstrap.min.js?q=$gui_no"></script>
    <script type="text/javascript">
        if (top.location != window.location) top.location.reload();
        if (window.opener) {window.opener.top.location.reload(); self.close();}
    </script>
</head>
END


print <<END;
<body>
    <div class="login-panel">
    <div class="login-head clearfix">
    <div class="logo text-center"><img src="images/logo_login.png"></div>
    </div>
    <div class="login-body">
    <form onsubmit="return false;" class="login-form" method="post" action="cgi-bin/logincheck">
    <div class="form-group pos-rel">
    <i class="fa fa-user"></i>
    <input type="text" id="username" name="username" class="form-control" value="" maxlength="35" placeholder=$Lang::tr{"username"}>
    </div>
    <div class="form-group pos-rel">
    <i class="fa fa-lock"></i>
    <input type="password" id="secretkey" name="secretkey" class="form-control" maxlength="30" placeholder=$Lang::tr{"password"}>
    </div>
    <div class="errors"></div>
    <input type="hidden" name="apw_form_token" value="671875285">
    <button class="btn btn-primary btn-block btn-login" action="login">登录</button>
    </form>
    </div>
    </div>
    
    <script type="text/javascript">
        jQuery("#username").focus();
    </script>
    <script type="text/javascript">
        var Login_Msgs = {};
        Login_Msgs.name_required = $Lang::tr{"Please input username"};
        Login_Msgs.login_failed = $Lang::tr{"failed and retry"};
        Login_Msgs.lockout_msg = $Lang::tr{"too many retries"};
        Login_Msgs.server_unreachable = $Lang::tr{"can not connect server"};
    </script>
    <script type="text/javascript" src="/js/login.js?q=$gui_no"></script>
    <div class="logo-login-company"></div><div class="logo-login-copyright"></div>
</body>
END


