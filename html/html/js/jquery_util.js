var mixed_state_opacity = 0.3;

// Resolve conflicts
if (typeof jQuery != "undefined") $j = jQuery.noConflict();

jQuery.fn.check = function(checked) {
    if (typeof checked == 'undefined') checked = true;
    return this.each(function() {
        if (typeof this.checked != 'undefined') this.checked = checked;
    });
}

jQuery.fn.uncheck = function() {
    return this.check(false);
}

jQuery.fn.enable = function(enabled) {
    if (typeof enabled == 'undefined') enabled = true;
    return this.each(function() {
        if (typeof this.disabled != 'undefined') this.disabled = !enabled;
    });
}

jQuery.fn.disable = function() {
    return this.enable(false);
}


/* ========================================================================
 * widgets
 * ======================================================================== */
/************** w-tab **************/
;(function($) {

    var Tab = function(element) {
        this.element = $(element);
    }

    Tab.prototype.show = function() {
        var $this = this.element,
        $ul = $this.closest('ul'),
        selector = $this.attr('href');

        selector = selector && selector.replace(/.*(?=#[^\s]*$)/, ''); // strip for ie7
        if ($this.parent('li').hasClass('active')) return;

        var $previous = $ul.find('.active:last a');
        // var hideEvent = $.Event('hide.bs.wtab', {
        //     relatedTarget: $this[0]
        // });
        // var showEvent = $.Event('show.bs.wtab', {
        //     relatedTarget: $previous[0]
        // });
        // $previous.trigger(hideEvent);
        // $this.trigger(showEvent);
        // if(showEvent.isDefaultPrevented() || hideEvent.isDefaultPrevented()) return;
        var $target = $(selector);

        this.activate($this.closest('li'), $ul);
        this.activate($target, $target.parent(),
        function() {
            // $previous.trigger({
            //     type: 'hidden.bs.wtab',
            //     relatedTarget: $this[0]
            // });
            // $this.trigger({
            //     type: 'shown.bs.wtab',
            //     relatedTarget: $previous[0]
            // });
        });
    };

    Tab.prototype.activate = function(element, container, callback) {
        var $active = container.find('> .active');

        function next() {
            $active.removeClass('active');
            element.addClass('active');
            callback && callback();
        }

        next();
    };

    function Plugin(option) {
        return this.each(function() {
            var $this = $(this),
            data = $this.data('bs.wtab');

            if (!data) $this.data('bs.wtab', (data = new Tab(this)));
            if (typeof option == 'string') data[option]();
        });
    }

    var old = $.fn.wtab;

    $.fn.wtab = Plugin;
    $.fn.wtab.Constructor = Tab;

    $.fn.wtab.noConflict = function() {
        $.fn.wtab = old;
        return this;
    };

})(jQuery);
