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
# (c) 2018-2019, the Openfirewall Team
#

# Add entry in menu
# MENUENTRY status 090 "IPTables" "IPTables"
#
# Do not translate IPTables ?

use strict;

# enable only the following on debugging purpose
use warnings; no warnings 'once';
use CGI::Carp 'fatalsToBrowser';

use LWP::UserAgent;

require '/usr/lib/ofw/general-functions.pl';
require '/usr/lib/ofw/lang.pl';
require '/usr/lib/ofw/header.pl';

my $errormessage = '';

my %cgiparams=();
$cgiparams{'ACTION'} = '';              # refresh
$cgiparams{'CHAIN'} = '';
&General::getcgihash(\%cgiparams);


if ( $cgiparams{'ACTION'} eq $Lang::tr{'refresh'} ) {
}

&Header::showhttpheaders();

# Include main.css for widget styles via extrahead parameter
my $extrahead = <<'CSS';
<link rel="stylesheet" type="text/css" href="/css/main.css" />
<style>
/* Widget Grid Layout - inline to ensure it works */
.status-widget-grid {
    display: flex !important;
    flex-wrap: wrap !important;
    gap: 8px !important;
    padding: 8px !important;
    column-count: auto !important;
    column-gap: auto !important;
    width: 100%;
    box-sizing: border-box;
}
.status-widget-grid .widget-card {
    border: 1px solid #ccc !important;
    border-radius: 4px !important;
    background: #fff !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1) !important;
    display: flex !important;
    flex-direction: column !important;
    flex: 0 0 calc(50% - 4px) !important;
    max-width: calc(50% - 4px) !important;
    width: auto !important;
    break-inside: auto !important;
    margin-bottom: 0 !important;
    max-height: 400px;
    min-height: 200px;
    overflow: hidden;
    box-sizing: border-box;
}
.widget-card.widget-collapsed {
    display: none !important;
}
.widget-card.widgetFull {
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
.widget-header {
    padding: 10px 12px;
    background: linear-gradient(to bottom, #f8f8f8, #e8e8e8);
    border-bottom: 1px solid #ccc;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-radius: 4px 4px 0 0;
    cursor: grab;
}
.widget-header:active {
    cursor: grabbing;
}
.widget-title {
    font-weight: bold;
    color: #333;
}
.widget-actions {
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
.widget-action-close {
    color: #c04340;
}
.widget-action-close:hover {
    color: #a83835;
}
.widget-action-expand {
    color: #d49a3e;
}
.widget-action-expand:hover {
    color: #b8832f;
}
.widget-body {
    padding: 12px;
    overflow-y: scroll;
    overflow-x: auto;
    max-height: 450px;
}
.widget-table {
    width: 100%;
    border-collapse: collapse;
}
.widget-table th,
.widget-table td {
    padding: 6px 8px;
    text-align: left;
    border-bottom: 1px solid #e0e0e0;
}
.widget-table th {
    background: #f5f5f5;
    font-weight: bold;
}
.widget-wide {
    grid-column: span 2;
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

&Header::openpage('IPTables', 1, $extrahead);

# Icons for widget buttons (using Unicode characters for better compatibility)
my $closeIcon = '&times;';
my $expandIcon = '&#x2922;';  # expand icon
my $restoreIcon = '&#x25B2;'; # up triangle - restore

# Add Widget button at top left
print <<END
<div style="padding: 8px 8px 0 8px;">
    <button id="addWidgetBtn" class="widget-action-btn" style="padding: 8px 16px; width: auto; height: auto; background: none; color: #4a9e4a; border: 1px solid #4a9e4a;" onclick="showAddWidgetDialog()">
        + Add Widget
    </button>
</div>

<div class='status-widget-grid'>
END
;

# Filter form widget
print <<END
<div class="widget-card" data-widget-id="filter" style="max-height: 180px; min-height: 120px;">
    <div class="widget-header">
        <span class="widget-title">IPTables Filter</span>
        <div class="widget-actions">
            <button class="widget-action-btn widget-action-close" onclick="toggleWidget(this)" title="Close">$closeIcon</button>
            <button class="widget-action-btn widget-action-expand" onclick="toggleFullscreen(this)" title="Expand">$expandIcon</button>
        </div>
    </div>
    <div class="widget-body" style="overflow-y: scroll; overflow-x: auto; max-height: 140px;">
<form method='post' action='$ENV{'SCRIPT_NAME'}'>
<table width='100%'>
<tr>
    <td width='25%' class='base'>Chain:&nbsp;<img src='/blob.gif' alt='*' /></td>
    <td width='25%'><input type='text' name='CHAIN' value='$cgiparams{'CHAIN'}' size='20' /></td>
    <td width='25%'>&nbsp;$errormessage</td>
    <td width='25%'>&nbsp;</td>
</tr>
</table>
<hr />
<table width='100%'>
<tr>
    <td class='comment1button'><img src='/blob.gif' alt='*' />&nbsp;$Lang::tr{'this field may be blank'}</td>
    <td class='button1button'><input type='submit' class='commonbuttons' name='ACTION' value='$Lang::tr{'refresh'}' /></td>
    <td class='onlinehelp'>
        <a href='${General::adminmanualurl}/status-iptables.html' target='_blank'><img src='/images/web-support.png' alt='$Lang::tr{'online help en'}' title='$Lang::tr{'online help en'}' /></a>
    </td>
</tr>
</table></form>
    </div>
</div>
END
;

if ($cgiparams{'CHAIN'} !~ /^[A-Z_]*$/) {
    $errormessage = $Lang::tr{'invalid input'};
}

# Display four tables: filter, mangle, nat, raw
foreach my $table ( ('filter', 'mangle', 'nat', 'raw') ) {
    my $output = '';
    if (($cgiparams{'CHAIN'} eq '') || $errormessage) {
        $output = `/usr/local/bin/iptableswrapper $table 2>&1`;
    }
    else {
        $output = `/usr/local/bin/iptableswrapper chain $table $cgiparams{'CHAIN'} 2>&1`;
    }
    $output = &Header::cleanhtml($output);

    (my @lines) = split(/\n/, $output);

    print <<END
<div class="widget-card" data-widget-id="$table">
    <div class="widget-header">
        <span class="widget-title">$table</span>
        <div class="widget-actions">
            <button class="widget-action-btn widget-action-close" onclick="toggleWidget(this)" title="Close">$closeIcon</button>
            <button class="widget-action-btn widget-action-expand" onclick="toggleFullscreen(this)" title="Expand">$expandIcon</button>
        </div>
    </div>
    <div class="widget-body" style="overflow-y: scroll; overflow-x: auto; max-height: 450px;">
<table width='100%'>
END
;
    foreach my $line ( @lines )
    {
        if ($line eq '') {
            print "<tr><td colspan='12'>&nbsp;</td></tr>\n"
        }
        elsif ($line =~ m/^Chain ([A-Z_]+) (.*)$/) {
            print "<tr class='table1colour'><td colspan='12' class='boldbase'><a name='$1'>$1</a> $2</td></tr>\n"
        }
        elsif ($line =~ m/^num + pkts/ ) {
            print "<tr><td>&nbsp;</td><td>num</td><td>pkts</td><td>bytes</td><td>target</td><td>prot</td><td>opt</td><td>in</td><td>out</td><td>src</td><td>dest</td><td>&nbsp;</td></tr>\n"
        }
        elsif ($line =~ m/^([0-9]+)\s+([0-9]+[KMGT]?)\s+([0-9]+[KMGT]?)\s+([A-Z_]+)\s+([a-z]+|[0-9]+)+\s+([a-z-]+)\s+([a-z0-9-:.*]+)\s+([a-z0-9-:.*]+)\s+(!{0,1}[0-9.\/]+)\s+(!{0,1}[0-9.\/]+)+(.*)/) {
            print "<tr><td>&nbsp;</td><td>$1</td><td>$2</td><td>$3</td><td>".&formattarget($4)."</td><td>$5</td><td>$6</td><td>".&General::color_devices("$7")."</td><td>".&General::color_devices("$8")."</td><td>$9</td><td>$10</td><td>$11</td></tr>\n"
        }
        else {
            print "<tr><td>&nbsp;</td><td colspan='11'>$line</td></tr>\n";
        }
    }
    print "</table>\n";
    print "    </div>\n</div>\n";
}

print "</div>\n";

# Add Widget Dialog
print <<END
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
            <button type="button" class="ofw_btn" onclick="closeAddWidgetDialog()">$Lang::tr{'cancel'}</button>
            <button type="button" class="ofw_btn ofw_btn_primary" onclick="addWidget()">$Lang::tr{'add'}</button>
        </div>
    </div>
</div>

<script>
// Toggle widget visibility (close/open)
function toggleWidget(btn) {
    var card = btn.closest('.widget-card');
    if (card) {
        card.classList.toggle('widget-collapsed');
    }
    checkClosedWidgets();
}

// Open widget in a new window
function toggleFullscreen(btn) {
    var card = btn.closest('.widget-card');
    if (card) {
        var widgetId = card.getAttribute('data-widget-id');
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

// Check if any widgets are closed
function checkClosedWidgets() {
    var addBtn = document.getElementById('addWidgetBtn');
    if (addBtn) {
        addBtn.style.display = 'inline-block';
    }
}

// Show add widget dialog
function showAddWidgetDialog() {
    var dialog = document.getElementById('addWidgetDialog');
    var select = document.getElementById('widgetSelect');

    // Get closed widgets
    var closedWidgets = document.querySelectorAll('.widget-card.widget-collapsed');

    // Populate select with closed widgets
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

// Close add widget dialog
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

// Add selected widget
function addWidget() {
    var select = document.getElementById('widgetSelect');
    var widgetId = select.value;

    if (!widgetId) {
        alert('Please select a widget');
        return;
    }

    var card = document.querySelector('.widget-card[data-widget-id="' + widgetId + '"]');
    if (card) {
        card.classList.remove('widget-collapsed');
        closeAddWidgetDialog();
        checkClosedWidgets();
    }
}

// Drag and drop for widget reordering
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
        for (var i = 0; i < cards.length; i++) {
            cards[i].style.borderTop = '';
        }
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

// Initialize
checkClosedWidgets();
</script>
END
;

&Header::closepage();


sub formattarget
{
  my $target = shift;

    if ($target eq 'ACCEPT') {
        return "<font class='ofw_iface_green'>$target</font>";
    }
    elsif ($target =~ m/^(DROP|REJECT)$/) {
        return "<font class='ofw_iface_red'>$target</font>";
    }
    elsif ($target =~ m/^(DNAT|SNAT|MASQUERADE|LOG|MARK|RETURN)$/) {
        return $target;
    }
    else {
        if ($cgiparams{'CHAIN'} eq '') {
            return "<a href='#$target'>$target</a>";
        }
        else {
            return "$target";
        }
    }
}
