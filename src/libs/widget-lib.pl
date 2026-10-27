#
# widget-lib.pl: shared widget CSS, icons, and JavaScript for status pages
#
# This file is part of the Openfirewall.
#

package Widget;

use strict;

sub widget_css {
    return <<'CSS';
<link rel="stylesheet" type="text/css" href="/css/main.css" />
<style>
.status-widget-grid {
    column-count: 2;
    column-gap: 16px;
    padding: 16px;
    width: 100%;
    box-sizing: border-box;
}
.status-widget-grid .widget-card {
    border: 1px solid #D0D0D0;
    border-radius: 2px;
    background: #fff;
    break-inside: avoid;
    margin-bottom: 16px;
    display: inline-block;
    width: 100%;
    box-sizing: border-box;
}
.status-widget-grid .widget-card.widget-collapsed {
    display: none !important;
}
.status-widget-grid .widget-card.widgetFull {
    position: fixed !important;
    top: 60px !important;
    left: 16px !important;
    width: calc(100vw - 32px) !important;
    height: calc(100vh - 76px) !important;
    z-index: 1000 !important;
    background: #fff !important;
    margin: 0 !important;
    display: flex !important;
    flex-direction: column !important;
}
.status-widget-grid .widget-header {
    padding: 10px 12px;
    background: linear-gradient(to bottom, #f8f8f8, #e8e8e8);
    border-bottom: 1px solid #ccc;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-radius: 4px 4px 0 0;
    cursor: grab;
}
.status-widget-grid .widget-header:active {
    cursor: grabbing;
}
.status-widget-grid .widget-title {
    font-weight: bold;
    color: #333;
}
.status-widget-grid .widget-actions {
    display: flex;
    gap: 6px;
}
.widget-action-btn {
    width: 24px;
    height: 24px;
    border: 1px solid #bbb;
    border-radius: 3px;
    background: linear-gradient(to bottom, #fff, #e6e6e6);
    color: #555;
    font-size: 14px;
    line-height: 1;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
    padding: 0;
}
.widget-action-btn:hover {
    background: linear-gradient(to bottom, #f0f0f0, #d6d6d6);
    border-color: #999;
}
.status-widget-grid .widget-action-btn {
    width: 24px;
    height: 24px;
    border: 1px solid #bbb;
    border-radius: 3px;
    background: linear-gradient(to bottom, #fff, #e6e6e6);
    color: #555;
    font-size: 14px;
    line-height: 1;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
    padding: 0;
}
.status-widget-grid .widget-action-btn:hover {
    background: linear-gradient(to bottom, #f0f0f0, #d6d6d6);
    border-color: #999;
}
.status-widget-grid .widget-action-close {
    color: #c04340;
}
.status-widget-grid .widget-action-close:hover {
    color: #a83835;
}
.status-widget-grid .widget-action-expand {
    color: #d49a3e;
}
.status-widget-grid .widget-action-expand:hover {
    color: #b8832f;
}
.status-widget-grid .widget-body {
    padding: 12px;
    overflow-y: auto;
    overflow-x: auto;
    max-height: 450px;
}
.status-widget-grid .widget-body img {
    max-width: 100%;
    height: auto;
}
.status-widget-grid .widget-table {
    width: 100%;
    border-collapse: collapse;
}
.status-widget-grid .widget-table th,
.status-widget-grid .widget-table td {
    padding: 6px 8px;
    text-align: left;
    border-bottom: 1px solid #e0e0e0;
}
.status-widget-grid .widget-table th {
    background: #f5f5f5;
    font-weight: bold;
}
.status-widget-grid .widget-card .ofw_running {
    color: #209040 !important;
    background-color: transparent !important;
}
.status-widget-grid .widget-card .ofw_stopped {
    color: #C00000 !important;
    background-color: transparent !important;
}
.status-widget-grid .widget-wide {
    column-span: all;
}

/* Modal dialog styles */
#addWidgetDialog.ofw_modal_overlay {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0,0,0,0.5);
    z-index: 10000;
}

#addWidgetDialog .ofw_modal_dialog {
    background: white;
    border-radius: 8px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    max-width: 90vw;
    max-height: 90vh;
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 350px;
    z-index: 10001;
    overflow: hidden;
}

#addWidgetDialog .ofw_modal_header {
    padding: 12px 16px;
    background: #5B9BD5;
    color: white;
    border-radius: 8px 8px 0 0;
    border-bottom: none;
    cursor: move;
    user-select: none;
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
    box-sizing: border-box;
}

#addWidgetDialog .ofw_modal_title {
    font-weight: bold;
    font-size: 14px;
}

#addWidgetDialog .ofw_modal_close {
    background: none;
    border: none;
    color: #fff;
    font-size: 20px;
    cursor: pointer;
    padding: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-left: 0;
}

#addWidgetDialog .ofw_modal_close:hover {
    opacity: 0.8;
    background: none;
}

#addWidgetDialog .ofw_modal_body {
    padding: 16px;
}

#addWidgetDialog .ofw_modal_footer {
    padding: 12px 16px;
    border-top: 1px solid #e0e0e0;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
}

.ofw_btn {
    padding: 6px 16px;
    border: 1px solid #ccc;
    border-radius: 4px;
    background: #f5f5f5;
    cursor: pointer;
    font-size: 13px;
}

.ofw_btn:hover {
    background: #e8e8e8;
}

.ofw_btn_primary {
    background: #5B9BD5;
    color: white;
    border-color: #4a8bc4;
}

.ofw_btn_primary:hover {
    background: #4a8bc4;
}
</style>
CSS
}

sub widget_icons {
    my %icons;
    $icons{'close'} = '&times;';
    $icons{'expand'} = '&#x2922;';
    return %icons;
}

sub widget_js {
    return <<'JS';
<script>
function toggleWidget(btn) {
    var card = btn.closest('.widget-card');
    if (card) {
        card.classList.toggle('widget-collapsed');
    }
    checkClosedWidgets();
}

function toggleFullscreen(btn) {
    var card = btn.closest('.widget-card');
    if (card) {
        var title = card.querySelector('.widget-title').textContent;
        var bodyHtml = card.querySelector('.widget-body').innerHTML;
        var w = window.open('', '_blank', 'width=1200,height=800,scrollbars=yes,resizable=yes');
        if (w) {
            w.document.write('<!DOCTYPE html><html><head><title>' + title + '</title>');
            w.document.write('<style>');
            w.document.write('body{font-family:Arial,sans-serif;margin:16px;background:#fff;}');
            w.document.write('h2{margin:0 0 12px 0;color:#333;font-size:18px;}');
            w.document.write('table{width:100%;border-collapse:collapse;font-size:13px;}');
            w.document.write('th,td{border:1px solid #D0D0D0;padding:5px 6px;text-align:left;vertical-align:top;}');
            w.document.write('th{background:#5B9BD5;color:#fff;font-weight:500;}');
            w.document.write('tbody tr:nth-child(even){background:#F5F5F5;}');
            w.document.write('tbody tr:nth-child(odd){background:#fff;}');
            w.document.write('pre{font-family:monospace;font-size:13px;}');
            w.document.write('.boldbase{font-weight:bold;}');
            w.document.write('.table1colour{background:#e8e8e8;}');
            w.document.write('input[type=text]{padding:3px 6px;border:1px solid #ccc;}');
            w.document.write('.commonbuttons{padding:4px 16px;background:#5B9BD5;color:#fff;border:none;cursor:pointer;}');
            w.document.write('</style>');
            w.document.write('</head><body>');
            w.document.write('<h2>' + title + '</h2>');
            w.document.write(bodyHtml);
            w.document.write('</body></html>');
            w.document.close();
        }
    }
}

function checkClosedWidgets() {
    var addBtn = document.getElementById('addWidgetBtn');
    if (addBtn) {
        addBtn.style.display = 'inline-block';
    }
}

function showAddWidgetDialog() {
    var dialog = document.getElementById('addWidgetDialog');
    var select = document.getElementById('widgetSelect');
    var closedWidgets = document.querySelectorAll('.widget-card.widget-collapsed');
    select.innerHTML = '<option value="">-- Select Widget --</option>';
    for (var i = 0; i < closedWidgets.length; i++) {
        var id = closedWidgets[i].getAttribute('data-widget-id');
        var option = document.createElement('option');
        option.value = id;
        option.textContent = id.charAt(0).toUpperCase() + id.slice(1);
        select.appendChild(option);
    }
    // Clear any inline positioning from previous drag
    var dialogEl = dialog.querySelector('.ofw_modal_dialog');
    dialogEl.style.left = '';
    dialogEl.style.top = '';
    dialogEl.style.transform = '';
    _dragStarted = false;
    // Show dialog - CSS will center it
    dialog.style.display = 'block';
    requestAnimationFrame(function() {
        initModalDrag();
    });
}

function closeAddWidgetDialog() {
    var dialog = document.getElementById('addWidgetDialog');
    dialog.style.display = 'none';
    var dialogEl = dialog.querySelector('.ofw_modal_dialog');
    dialogEl.style.left = '';
    dialogEl.style.top = '';
    dialogEl.style.transform = '';
    _dragStarted = false;
}

var _modalDragInited = false;
var _dragStarted = false;
function initModalDrag() {
    if (_modalDragInited) return;
    _modalDragInited = true;
    var modal = document.getElementById('addWidgetDialog');
    if (!modal) return;
    var modalHeader = modal.querySelector('.ofw_modal_header');
    if (!modalHeader) return;
    var isDragging = false;
    var offsetX = 0, offsetY = 0;
    var dialogEl = modal.querySelector('.ofw_modal_dialog');

    modalHeader.addEventListener('mousedown', function(e) {
        if (e.target.classList.contains('ofw_modal_close')) return;
        e.preventDefault();
        var rect = dialogEl.getBoundingClientRect();
        if (!_dragStarted) {
            _dragStarted = true;
            dialogEl.style.left = rect.left + 'px';
            dialogEl.style.top = rect.top + 'px';
            dialogEl.style.transform = 'none';
        }
        isDragging = true;
        offsetX = e.clientX - rect.left;
        offsetY = e.clientY - rect.top;
    });

    document.addEventListener('mousemove', function(e) {
        if (!isDragging) return;
        e.preventDefault();
        dialogEl.style.left = (e.clientX - offsetX) + 'px';
        dialogEl.style.top = (e.clientY - offsetY) + 'px';
    });

    document.addEventListener('mouseup', function() {
        isDragging = false;
    });
}

function addWidget() {
    var select = document.getElementById('widgetSelect');
    var widgetId = select.value;
    if (!widgetId) { alert('Please select a widget'); return; }
    var card = document.querySelector('.widget-card[data-widget-id="' + widgetId + '"]');
    if (card) {
        card.classList.remove('widget-collapsed');
        closeAddWidgetDialog();
        checkClosedWidgets();
    }
}

(function() {
    var dragSrc = null;
    var grid = null;
    function handleDragStart(e) {
        dragSrc = this;
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', this.getAttribute('data-widget-id'));
        this.style.opacity = '0.4';
    }
    function handleDragOver(e) {
        if (e.preventDefault) e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        return false;
    }
    function handleDragEnter(e) {
        this.style.borderTop = '3px solid #4a9e4a';
    }
    function handleDragLeave(e) {
        this.style.borderTop = '';
    }
    function handleDrop(e) {
        if (e.stopPropagation) e.stopPropagation();
        this.style.borderTop = '';
        if (dragSrc !== this) {
            var cards = Array.from(grid.querySelectorAll('.widget-card'));
            var srcIdx = cards.indexOf(dragSrc);
            var dstIdx = cards.indexOf(this);
            if (srcIdx < dstIdx) {
                grid.insertBefore(dragSrc, this.nextSibling);
            } else {
                grid.insertBefore(dragSrc, this);
            }
        }
        return false;
    }
    function handleDragEnd(e) {
        this.style.opacity = '1';
        var cards = grid.querySelectorAll('.widget-card');
        for (var i = 0; i < cards.length; i++) { cards[i].style.borderTop = ''; }
    }
    function initDragAndDrop() {
        grid = document.querySelector('.status-widget-grid');
        if (!grid) return;
        var cards = grid.querySelectorAll('.widget-card');
        for (var i = 0; i < cards.length; i++) {
            cards[i].setAttribute('draggable', 'true');
            cards[i].addEventListener('dragstart', handleDragStart, false);
            cards[i].addEventListener('dragenter', handleDragEnter, false);
            cards[i].addEventListener('dragover', handleDragOver, false);
            cards[i].addEventListener('dragleave', handleDragLeave, false);
            cards[i].addEventListener('drop', handleDrop, false);
            cards[i].addEventListener('dragend', handleDragEnd, false);
        }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDragAndDrop);
    } else {
        initDragAndDrop();
    }
})();

checkClosedWidgets();
</script>
JS
}

sub widget_header_buttons {
    my ($closeIcon, $expandIcon) = @_;
    return <<END;
<div class="widget-actions">
    <button class="widget-action-btn widget-action-close" onclick="toggleWidget(this)" title="Close">$closeIcon</button>
    <button class="widget-action-btn widget-action-expand" onclick="toggleFullscreen(this)" title="Expand">$expandIcon</button>
</div>
END
}

sub widget_add_button {
    return <<'END';
<div style="padding: 16px 16px 0 16px; text-align: left;">
    <button id="addWidgetBtn" class="widget-action-btn" style="display: inline-block; padding: 8px 16px; width: auto; height: auto; background: none; color: #4a9e4a; border: 1px solid #4a9e4a;" onclick="showAddWidgetDialog()">
        + Add Widget
    </button>
</div>
END
}

sub widget_add_dialog {
    my ($tr_cancel, $tr_add) = @_;
    return <<END;
<div id="addWidgetDialog" class="ofw_modal_overlay" style="display: none;">
    <div class="ofw_modal_dialog" style="width:350px;">
        <div class="ofw_modal_header">
            <span class="ofw_modal_title">Add Widget</span>
            <button type="button" class="ofw_modal_close" onclick="closeAddWidgetDialog()">&times;</button>
        </div>
        <div class="ofw_modal_body">
            <div style="margin-bottom: 10px;">
                <label style="display: block; margin-bottom: 5px;">Select widget to add:</label>
                <select id="widgetSelect" style="width: 100%; padding: 5px;">
                    <option value="">-- Select Widget --</option>
                </select>
            </div>
        </div>
        <div class="ofw_modal_footer">
            <button type="button" class="ofw_btn" onclick="closeAddWidgetDialog()">$tr_cancel</button>
            <button type="button" class="ofw_btn ofw_btn_primary" onclick="addWidget()">$tr_add</button>
        </div>
    </div>
</div>
END
}

1;
