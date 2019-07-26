




// [Cookie] Sets value in a cookie
dTree.prototype.setCookie = function(cookieName, cookieValue, expires, path, domain, secure)
{
    document.cookie =
        escape(cookieName) + '=' + escape(cookieValue)
        + (expires ? '; expires=' + expires.toGMTString() : '')
        + (path ? '; path=' + path : '')
        + (domain ? '; domain=' + domain : '')
        + (secure ? '; secure' : '');
};

