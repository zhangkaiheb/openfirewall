var IE = window.ActiveXObject,
        FF = navigator.userAgent.indexOf("Gecko") > 0,
        propagate_modal_mask = true,
        modal_op_dialog = 1,
        modal_op_rename = 2,
        modal_op_menu = 3,
        modal_op_auxiliary = 4,
        InlineModal = {
                in_modal_op: false,
                op_type: 0,
                maskdiv_callbacks_init: false,
                mask_div: null,
                dlg_div: null,
                end_contextmenu_cb: null,
                scroll_contextmenu_cb: null,
                end_rename_cb: null,
                aux_target_wnd: null,
                in_rename_op: function() {
                        return (this.in_modal_op && this.op_type == modal_op_rename);
                }
        };

var wij_modal_show_timer = null;
function wij_in_modal_op() {
        return (InlineModal.in_modal_op && InlineModal.op_type == modal_op_dialog);
}

function handle_maskdiv_click() {
        var oModal = InlineModal;
        if (!oModal.in_modal_op) return false;
        if (oModal.op_type == modal_op_rename) {
                wij_end_modal_rename(true);
        } else if (oModal.op_type == modal_op_menu) {
                wij_end_contextmenu_mask();
        } else if (oModal.op_type == modal_op_auxiliary) {
                oModal.aux_target_wnd.handle_maskdiv_click();
        }
}

function wij_align_modal_dlg() {
        if (!InlineModal.in_modal_op) {
                return;
        }
        var dlg_div = InlineModal.dlg_div;
        var bd = document.body;
        var root = document.documentElement;
        var w_dlg = (dlg_div.offsetWidth ? dlg_div.offsetWidth: 400);
        var h_dlg = (dlg_div.offsetHeight ? dlg_div.offsetHeight: 300);
        var w_pg = root.clientWidth;
        var h_pg = root.clientHeight;

        var t = (h_pg - h_dlg) / 2;
        if (t < 10) t = 10;
        var l = (w_pg - w_dlg) / 2;

        dlg_div.style.left = l + 'px';
        dlg_div.style.top = t + 'px';
}

function wij_modal_onresize() {
        var oModal = InlineModal;
        if (!oModal.in_modal_op) return;
        if (oModal.op_type == modal_op_dialog) {
                wij_align_modal_dlg();
        }
}

function setup_maskdiv_callbacks() {
        if (InlineModal.maskdiv_callbacks_init) return;
        addEvent(window, "resize", wij_modal_onresize);
        if (IE) addEvent(document.body.firstChild, 'resize', wij_modal_onresize);
        InlineModal.maskdiv_callbacks_init = true;
}

function setup_mask_div() {
        var mask_div = InlineModal.mask_div;
        if (mask_div) return mask_div;
        var tmp_div = document.createElement("DIV");
        tmp_div.innerHTML = '<div id="maskDiv" style="display: none; background-color: black; position: fixed; left: 0; top: 0; z-index: 10000; height: 100%; width: 100%; -moz-opacity: 0.5; opacity: 0.5; filter: alpha(opacity=50);"  onclick="handle_maskdiv_click()" onmousedown="return false" onmousemove="return false"  onmouseup="return false" ondblclick="return false" onselectstart="return false" oncontextmenu="return false"></div>';
        mask_div = tmp_div.childNodes[0];
        Element.remove(mask_div);
        document.body.appendChild(mask_div);
        InlineModal.mask_div = mask_div;
        return mask_div;
}

function display_mask_div(opacity) {
        var mask_div = InlineModal.mask_div;
        Element.setOpacity(mask_div, opacity);
        mask_div.style.visibility = "hidden";
        mask_div.style.display = "";
        mask_div.style.visibility = "visible";
        setup_maskdiv_callbacks();
        if (propagate_modal_mask && (top != window) && top == window.parent && top.display_auxiliary_mask) {
                var wnd = window.parent;
                if (wnd && wnd.wij_in_modal_op && wnd.wij_in_modal_op()) {
                        return;
                }
                var panels_adjusted = 0;
                top.jQuery(".page-main").each(function() {
                        var elem = jQuery(this);
                        elem.data("zIndex", elem.css("z-index"));
                        elem.css("z-index", 10100);
                        panels_adjusted ++;
                });
                if (panels_adjusted > 0) {
                        top.display_auxiliary_mask(window, opacity);
                }
        }
}

function display_auxiliary_mask(target_wnd, opacity) {
        var oModal = InlineModal;
        if (oModal.in_modal_op || (target_wnd == window)) return;
        oModal.in_modal_op = true;
        oModal.op_type = modal_op_auxiliary;
        oModal.aux_target_wnd = target_wnd;
        var mask_div = setup_mask_div();
        Element.setOpacity(mask_div, opacity);
        mask_div.style.visibility = "hidden";
        mask_div.style.display = "";
        mask_div.style.visibility = "visible";
        setup_maskdiv_callbacks();
}

function hide_mask_div() {
        var mask_div = InlineModal.mask_div;
        mask_div.style.display = "none";
        if (propagate_modal_mask && (top != window) && top.hide_auxiliary_mask) {
                var wnd = window.parent;
                if (wnd && wnd.wij_in_modal_op && wnd.wij_in_modal_op()) {
                        return;
                }
                top.jQuery(".page-main").each(function() {
                        var elem = jQuery(this);
                        elem.css("z-index", elem.data("zIndex"));
                });
                top.hide_auxiliary_mask(window);
        }
}

function hide_auxiliary_mask(target_wnd) {
        if (target_wnd == window) return;
        var mask_div = InlineModal.mask_div;
        mask_div.style.display = "none";
        var oModal = InlineModal;
        if (oModal.in_modal_op && oModal.op_type == modal_op_auxiliary) {
                oModal.in_modal_op = false;
                oModal.op_type = 0;
        }
}

function setup_modal_dlg() {
        var dv_modal = InlineModal.dlg_div;
        if (dv_modal) return dv_modal;
        var tmp_div = document.createElement("DIV");
        tmp_div.innerHTML = '<div id="modal_div" style="position:absolute; overflow:hidden; display:none; visibility:hidden; background-color: white; left: -1000; top: -1000; z-index: 10001"></div>';
        dv_modal = tmp_div.childNodes[0];
        Element.remove(dv_modal);
        document.body.appendChild(dv_modal);
        InlineModal.dlg_div = dv_modal;
        return dv_modal;
}

var aModalIframe_tpl = ['<iframe id="', '', '" name="', '', '" frameBorder=0 scrolling="auto" src="', '', '" style="overflow:auto; width:', '', '; height:', '', '" />'];
function wij_set_modal_options(opts) {
        var oModal = InlineModal;
        oModal.height = "auto";
        oModal.width = 300;
        oModal.close_button = true;
        oModal.callback_handlers = true;
        oModal.bg_color = "#ddd";
        oModal.escape_to_exit = true;
        if (typeof(opts) != "object") return;
        for (var prop in opts) {
                if (prop in oModal) {
                        oModal[prop] = opts[prop];
                }
        }
}

var next_modaldlg_seqno = 1;
function wij_display_modal_content(content, opts) {
        var oModal = InlineModal;
        oModal.in_modal_op = true;
        oModal.op_type = modal_op_dialog;
        wij_set_modal_options(opts);
        var dv_modal = setup_modal_dlg();
        var mask_div = setup_mask_div();
        dv_modal.innerHTML = content;
        dv_modal.style.position = "fixed";
        dv_modal.style.display = "";
        dv_modal.style.visibility = "hidden";
        dv_modal.onmouseover = function() {
                this.focus()
        }
        dv_modal.onmouseout = function() {
                this.blur()
        }
        if (wij_modal_show_timer) clearTimeout(wij_modal_show_timer);
        wij_modal_show_timer = setTimeout(wij_align_and_show_modal_dlg, 500);
        display_mask_div(0.5);
}

function wij_display_modal_dlg(url, opts) {
        var oModal = InlineModal,
                frm_id = "wij_modal_frame_" + next_modaldlg_seqno++,
                arr = aModalIframe_tpl;

        wij_set_modal_options(opts);
        arr[1] = frm_id;
        arr[3] = frm_id;
        arr[5] = url;

        if (oModal.width != "auto") {
                arr[7] = oModal.width + "px";
        }

        if (oModal.height != "auto") {
                arr[9] = oModal.height + "px";
        }

        wij_display_modal_content(arr.join(""), opts);
}

function wij_end_modal_dialog() {
        var oModal = InlineModal;
        oModal.in_modal_op = false;
        oModal.op_type = 0;
        jQuery(oModal.dlg_div).html("");
        hide_mask_div();
        if (oModal.callback_handlers && window.callback_handlers && window.callback_handlers.should_call) {
                callFunctionArray(window.callback_handlers);
        }
}

function on_modal_dialog_keypress(ev) {
        if (!wij_in_modal_op()) return;
        if (!ev) ev = window.event;
        var key_code = crack_kbd_event(ev);
        if (key_code == 27 && InlineModal.escape_to_exit) {
                wij_end_modal_dialog();
        }
        return true;
}

function wij_align_and_show_modal_dlg() {
        var mlist = InlineModal.dlg_div;
        wij_align_modal_dlg();
        mlist.style.visibility = "visible";
}

function crack_kbd_event(evt) {
        if (evt.which) {
                return evt.which;
        } else if (evt.keyCode) {
                return evt.keyCode;
        }
        return 0;
}

function on_rename_keypress(ev) {
        if (!ev) ev = window.event;
        var key_code = crack_kbd_event(ev);
        if (key_code == 13) {
                wij_end_modal_rename(true);
        } else if (key_code == 27) {
                wij_end_modal_rename(false);
        }
        return true;
}

function on_rename_blur(ev) {
        wij_end_modal_rename(true);
}

function wij_end_modal_rename(bCommit) {
        var oModal = InlineModal,
                dv_dialog = oModal.dlg_div,
                edit_ctrl = dv_dialog.firstDescendant();

        oModal.end_rename_cb(edit_ctrl, bCommit);
        oModal.in_modal_op = false;
        oModal.op_type = 0;
        dv_dialog.innerHTML = '';
        dv_dialog.style.display = 'none';
        hide_mask_div();
}

function reposition_top_aligned_menu(oMenu) {
        var bd = oMenu.output_document.documentElement;
        oMenu.element.style.top = bd.scrollTop + 'px';
}

var in_wij_end_contextmenu_mask_cb = false;
function wij_end_contextmenu_mask() {
        if (in_wij_end_contextmenu_mask_cb) return;
        var oModal = InlineModal;
        in_wij_end_contextmenu_mask_cb = true;
        oModal.end_contextmenu_cb();
        in_wij_end_contextmenu_mask_cb = false;
        oModal.in_modal_op = false;
        oModal.op_type = 0;
        hide_mask_div();
}

function wij_display_genericmenu_mask(cb_end, elem) {
        var oModal = InlineModal,
                mask_div;

        oModal.in_modal_op = true;
        oModal.op_type = modal_op_menu;
        oModal.scroll_contextmenu_cb = null;
        oModal.end_contextmenu_cb = cb_end;
        elem.style.position = "absolute";
        propagate_modal_mask = false;

        mask_div = setup_mask_div();
        display_mask_div(0.15);
}

function wij_auto_resize_iframe() {
        if (!InlineModal.in_modal_op) {
                return;
        }

        jQuery("iframe", InlineModal.dlg_div).each(function() {
                this.scrolling = "no";
                if (InlineModal.height == "auto") {
                        update_iframe_height(this.id);
                }
                this.scrolling = "auto";
        });

        wij_align_modal_dlg();
}

function wij_add_close_button() {
        var wnd = window.parent,
                doc_width = jQuery(document).width();

        jQuery("table.header tr td").append('<span id="wij_modal_close_btn_abs" class="modal-header-btn-close"><i class="fa fa-times"></i></span>');
        jQuery("#wij_modal_close_btn_abs").each(function() {
                jQuery(this).css({
                        'right': 'inherit',
                        'left': doc_width - 15 - 7
                });
        }).click(function() {
                wnd.wij_end_modal_dialog();
        });

        jQuery("h1").append('<span id="wij_modal_close_btn_fixed" class="modal-header-btn-close"><i class="fa fa-times"></i></span>');
        jQuery("#wij_modal_close_btn_fixed").click(function() {
                wnd.wij_end_modal_dialog();
        });
}

jQuery(document).ready(function() {
        var wnd = window.parent;
        if (wnd && wnd.wij_in_modal_op && wnd.wij_in_modal_op()) {
                wnd.wij_auto_resize_iframe();
                if (wnd.InlineModal.close_button) {
                        wij_add_close_button();
                }
                jQuery(document).keyup(wnd.on_modal_dialog_keypress);
        } else {
                if (jQuery.browser.msie && jQuery.browser.version < 8) propagate_modal_mask = false;
                if (jQuery.browser.mozilla && jQuery.browser.version < '1.9') propagate_modal_mask = false;
                jQuery(document).keyup(on_modal_dialog_keypress);
        }
});

