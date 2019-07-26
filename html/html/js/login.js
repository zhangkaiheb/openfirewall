/**
 * login
 */

(function($) {

        $(document).ready(function() {
                $('.btn[action="login"]').click(function() {
                        var $btn = $(this),
                                username = $('#username').val(),
                                secretkey = $('#secretkey').val(),
                                auth_two_factor = $('#auth_two_factor').val(),
                                auth_token = $('#auth_token').val(),
                                $errors = $('.errors'),
                                msg = '',
                                params = {};

                        if($btn.hasClass('disabled')) {
                                return;
                        }

                        // validate
                        if(!username) {
                                $('#username').parents('.form-group').addClass('has-error');
                                msg = Login_Msgs['name_required'];
                        }
                        $('#username').parents('.form-group').removeClass('has-error');

                        // show errors
                        if(msg) {
                                $errors.html(msg);
                                return;
                        }
                        // clear errors
                        $errors.html('');
                        // disable login btn
                        $btn.addClass('disabled');

                        params = {
                                ajax: 1,
                                username: username,
                                secretkey: secretkey
                        };

                        if(auth_two_factor && auth_token) {
                                params['auth_two_factor'] = 1;
                                params['auth_token'] = auth_token;
                        }

                        // login
                        $.ajax({
                                type: 'POST',
                                url: '/logincheck',
                                data: params,
                                // contentType: 'application/json; charset=UTF-8',
                                // processData: false,
                                dataType: 'text'
                        }).done(function(result) {
                                if(!result) {
                                        $errors.html(Login_Msgs['server_unreachable']);
                                        return;
                                }
                                var rv = result.charAt(0),
                                        rv2 = result.substring(1);
                                if(rv == '1') {
                                        eval(rv2); // javascript code
                                } else if(rv == '2') {
                                        $errors.html(Login_Msgs['lockout_msg']);
                                } else {
                                        $errors.html(Login_Msgs['login_failed']);
                                }
                        }).fail(function(result) {
                                $errors.html(Login_Msgs['login_failed']);
                        }).always(function(result) {
                                $btn.removeClass('disabled');
                        });
                });
        });

        $(document).ready(function() {
                // support placeholder
                if(document.createElement('input').placeholder !== '') {
                        $('head').append('<style>.placeholder{color:#aaa;}</style>');
                        $('[placeholder]').focus(function() {
                                var $this = $(this);
                                if($this.val() == $this.attr('placeholder')) {
                                        $this.val('');
                                        $this.removeClass('placeholder');
                                }
                        }).blur(function() {
                                var $this = $(this);
                                if(this.type === 'password') {
                                        return false;
                                }
                                if($this.val() == '' || $this.val() == $this.attr('placeholder')) {
                                        $this.addClass('placeholder');
                                        $this.val($this.attr('placeholder'));
                                }
                        }).blur().parents('form').submit(function() {
                                $(this).find('[placeholder]').each(function() {
                                        var $this = $(this);
                                        if($this.val() == $this.attr('placeholder')) {
                                                $this.val('');
                                        }
                                });
                        });
                }

                $('body').append('<div class="logo-login-company"></div>');
                $('body').append('<div class="logo-login-copyright"></div>');
        });

})(jQuery);

