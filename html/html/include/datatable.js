/**
 * DataTable - Reusable data table component for Openfirewall
 * Features: toolbar buttons, search, filter, column settings, pagination, row selection
 */
(function(global) {
    'use strict';

    class DataTable {
        constructor(container, options) {
            this.container = typeof container === 'string' ? document.querySelector(container) : container;
            this.options = Object.assign({
                columns: [],
                data: [],
                rowKey: 'id',
                selectable: true,
                pageSize: 20,
                actions: ['create', 'edit', 'delete', 'refresh'],
                disabledActions: [],
                loading: false,
                onAction: null,
                onSelectionChange: null,
                onRowClick: null
            }, options);

            this.state = {
                currentPage: 1,
                selectedKeys: new Set(),
                quickFilter: '',
                sortKey: options.defaultSort ? options.defaultSort.key : '',
                sortOrder: options.defaultSort ? options.defaultSort.order : 'asc',
                visibleColumns: this.options.columns.map(c => c.key),
                filterEntries: [],
                filterOpen: false,
                columnSettingOpen: false,
                selectedColumns: [],
                availableColumns: [],
                filterForm: {
                    enabled: true,
                    section: 'contains',
                    not: false,
                    text: '',
                    caseSensitive: false
                },
                selectedFilterField: null
            };

            this.init();
        }

        init() {
            this.loadColumnSettings();
            this.render();
            this.bindEvents();
        }

        loadColumnSettings() {
            const tableKey = this.options.tableKey || 'default';
            const storageKey = `ofw_columns_${tableKey}`;
            try {
                const saved = JSON.parse(localStorage.getItem(storageKey));
                if (Array.isArray(saved) && saved.length) {
                    const valid = saved.filter(k => this.options.columns.some(c => c.key === k));
                    if (valid.length) this.state.visibleColumns = valid;
                }
            } catch (e) {}
        }

        saveColumnSettings() {
            const tableKey = this.options.tableKey || 'default';
            const storageKey = `ofw_columns_${tableKey}`;
            localStorage.setItem(storageKey, JSON.stringify(this.state.visibleColumns));
        }

        get filteredData() {
            let rows = [...this.options.data];

            // Quick filter
            if (this.state.quickFilter) {
                const q = this.state.quickFilter.toLowerCase();
                rows = rows.filter(r => Object.values(r).some(v => String(v).toLowerCase().includes(q)));
            }

            // Advanced filters
            for (const entry of this.state.filterEntries) {
                if (!entry.enabled || !entry.text) continue;
                const { field, section, not: invert, text, caseSensitive } = entry;
                rows = rows.filter(r => {
                    const val = String(r[field] ?? '');
                    const source = caseSensitive ? val : val.toLowerCase();
                    const target = caseSensitive ? text : text.toLowerCase();
                    let match = false;
                    if (section === 'equals') match = source === target;
                    else if (section === 'notEqual') match = source !== target;
                    else if (section === 'contains') match = source.includes(target);
                    else if (section === 'notContains') match = !source.includes(target);
                    else if (section === 'startsWith') match = source.startsWith(target);
                    else if (section === 'endsWith') match = source.endsWith(target);
                    return invert ? !match : match;
                });
            }

            // Sort
            if (this.state.sortKey) {
                rows.sort((a, b) => {
                    const av = a[this.state.sortKey], bv = b[this.state.sortKey];
                    if (av === bv) return 0;
                    if (av === undefined || av === null) return 1;
                    if (bv === undefined || bv === null) return -1;
                    if (av < bv) return this.state.sortOrder === 'asc' ? -1 : 1;
                    if (av > bv) return this.state.sortOrder === 'asc' ? 1 : -1;
                    return 0;
                });
            }

            return rows;
        }

        get pagedData() {
            const start = (this.state.currentPage - 1) * this.options.pageSize;
            return this.filteredData.slice(start, start + this.options.pageSize);
        }

        get totalPages() {
            return Math.max(1, Math.ceil(this.filteredData.length / this.options.pageSize));
        }

        get selectedRows() {
            return this.options.data.filter(r => this.state.selectedKeys.has(r[this.options.rowKey]));
        }

        actionDisabled(action) {
            if (this.options.disabledActions.includes(action)) return true;
            // edit and delete require at least one selection
            const needsSelection = ['edit', 'delete'];
            if (needsSelection.includes(action) && this.state.selectedKeys.size === 0) return true;
            // edit only works with exactly one selection
            if (action === 'edit' && this.state.selectedKeys.size > 1) return true;
            // delete not allowed for physical interfaces (type 0)
            if (action === 'delete' && this.state.selectedKeys.size > 0) {
                const allPhysical = Array.from(this.state.selectedKeys).every(key => {
                    const row = this.options.data.find(r => r[this.options.rowKey] == key);
                    return row && row.typeCode === '0';
                });
                if (allPhysical) return true;
            }
            return false;
        }

        updateToolbarState() {
            // Update button disabled states
            const toolbarBtns = this.container.querySelectorAll('button[data-action]');
            toolbarBtns.forEach(btn => {
                const action = btn.getAttribute('data-action');
                const disabled = this.actionDisabled(action);
                btn.disabled = disabled;
            });
        }

        handleAction(action) {
            if (this.options.onAction) {
                if (action === 'edit') {
                    this.openEditModal(this.selectedRows[0]);
                } else if (action === 'delete') {
                    this.openDeleteConfirm();
                } else if (action === 'create') {
                    this.openAddModal();
                } else {
                    this.options.onAction(action);
                }
            }
        }

        openAddModal() {
            // Prevent duplicate modals
            if (document.querySelector('.ofw_modal_overlay')) return;
            
            const overlay = document.createElement('div');
            overlay.className = 'ofw_modal_overlay';
            overlay.innerHTML = `
                <div class="ofw_modal_dialog" style="width:680px;">
                    <div class="ofw_modal_header">
                        <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
                        <span class="ofw_modal_title">Add Interface</span>
                        <button class="ofw_modal_close">&times;</button>
                    </div>
                    <div class="ofw_modal_body">
                        <form id="addInterfaceForm" method="post" action="/cgi-bin/interfaces.cgi">
                            <input type="hidden" name="ACTION" value="${this.options.addAction || 'add interface'}">
                            <table style="width:100%;border-collapse:collapse;">
                                <tr>
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>Name</label></td>
                                    <td><input type="text" name="IF_NAME" style="width:200px;" required></td>
                                </tr>
                                <tr>
                                    <td style="padding:8px 12px 8px 0;text-align:right;"><label>Description</label></td>
                                    <td><input type="text" name="DESCRIPTION" style="width:200px;"></td>
                                </tr>
                                <tr>
                                    <td style="padding:8px 12px 8px 0;text-align:right;"><label>Type</label></td>
                                    <td>
                                        <select name="TYPE" style="width:200px;" onchange="toggleAddTypeFields(this.value)">
                                            <option value="1" selected>VLAN</option>
                                            <option value="2">BRIDGE</option>
                                            <option value="3">BOND</option>
                                        </select>
                                    </td>
                                </tr>
                                <tr id="vlan_if_row">
                                    <td style="padding:8px 12px 8px 0;text-align:right;"><label>Interface</label></td>
                                    <td>
                                        <select name="IFACE" style="width:200px;" onchange="toggleAddTypeFields(this.value)">
                                            ${this.options.interfaces ? this.options.interfaces.map(i => `<option value="${i}">${i}</option>`).join('') : ''}
                                        </select>
                                    </td>
                                </tr>
                                <tr id="vlan_id_row">
                                    <td style="padding:8px 12px 8px 0;text-align:right;"><label>VLAN ID</label></td>
                                    <td><input type="text" name="VLANID" style="width:200px;" maxlength="5"></td>
                                </tr>
                                <tr id="bond_members_row" style="display:none;">
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>Sub Interfaces</label></td>
                                    <td>
                                        <table style="width:100%;">
                                            <tr>
                                                <td style="width:45%;"><div style="margin-bottom:4px;">Available:</div>
                                                    <select name="bond_avail" id="bond_avail" style="width:100%;" multiple size="5">
                                                        ${this.options.interfaces ? this.options.interfaces.map(i => `<option value="${i}">${i}</option>`).join('') : ''}
                                                    </select>
                                                </td>
                                                <td style="width:10%;text-align:center;vertical-align:middle;">
                                                    <button type="button" onclick="moveOption(document.getElementById('bond_avail'), document.getElementById('bond_selected'))" style="margin:2px;">→</button><br>
                                                    <button type="button" onclick="moveOption(document.getElementById('bond_selected'), document.getElementById('bond_avail'))" style="margin:2px;">←</button>
                                                </td>
                                                <td style="width:45%;"><div style="margin-bottom:4px;">Selected:</div>
                                                    <select name="BOND_MEMBERS" id="bond_selected" style="width:100%;" multiple size="5"></select>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr id="bridge_members_row" style="display:none;">
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>Bridge Slaves</label></td>
                                    <td>
                                        <table style="width:100%;">
                                            <tr>
                                                <td style="width:45%;"><div style="margin-bottom:4px;">Available:</div>
                                                    <select name="bridge_avail" id="bridge_avail" style="width:100%;" multiple size="5">
                                                        ${this.options.interfaces ? this.options.interfaces.map(i => `<option value="${i}">${i}</option>`).join('') : ''}
                                                    </select>
                                                </td>
                                                <td style="width:10%;text-align:center;vertical-align:middle;">
                                                    <button type="button" onclick="moveOption(document.getElementById('bridge_avail'), document.getElementById('bridge_selected'))" style="margin:2px;">→</button><br>
                                                    <button type="button" onclick="moveOption(document.getElementById('bridge_selected'), document.getElementById('bridge_avail'))" style="margin:2px;">←</button>
                                                </td>
                                                <td style="width:45%;"><div style="margin-bottom:4px;">Selected:</div>
                                                    <select name="BR_MEMBERS" id="bridge_selected" style="width:100%;" multiple size="5"></select>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>Address Mode</label></td>
                                    <td>
                                        <input type="radio" name="ADDRESSING_MODE" value="0" id="mode_static" checked onchange="toggleAddressMode()">
                                        <label for="mode_static">Static</label>&nbsp;&nbsp;&nbsp;
                                        <input type="radio" name="ADDRESSING_MODE" value="1" id="mode_dhcp" onchange="toggleAddressMode()">
                                        <label for="mode_dhcp">DHCP</label>
                                    </td>
                                </tr>
                                <tr id="ipaddr_row">
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>IP Address/Netmask</label></td>
                                    <td><input type="text" name="IPADDR_MASK" style="width:200px;" placeholder="192.168.1.1/255.255.255.0"></td>
                                </tr>
                                <tr>
                                    <td style="width:160px;padding:12px 12px 8px 0;text-align:right;">
                                        <input type="checkbox" id="mode_mtu" name="flag_mtu" value="1" onchange="document.getElementById('mtu_input').disabled = !this.checked">
                                        <label for="mode_mtu">MTU</label>
                                    </td>
                                    <td style="padding:12px 0 8px 0;">
                                        <input type="text" id="mtu_input" name="MTU" style="width:200px;" value="1500" disabled>
                                        <span style="margin-left:4px;color:#666;">(bytes)</span>
                                    </td>
                                </tr>
                            </table>
                        </form>
                    </div>
                    <div class="ofw_modal_footer">
                        <button class="ofw_btn ofw_btn_cancel">Cancel</button>
                        <button class="ofw_btn ofw_btn_primary" onclick="prepareAddFormSubmit()">Add</button>
                    </div>
                </div>
            `;

            document.body.appendChild(overlay);

            // Close button
            overlay.querySelector('.ofw_modal_close').addEventListener('click', () => {
                overlay.remove();
            });

            // Cancel button
            overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => {
                overlay.remove();
            });

            // Make modal draggable
            this.makeDraggable(overlay.querySelector('.ofw_modal_dialog'), overlay.querySelector('.ofw_modal_header'));
        }

        openEditModal(rowData) {
            if (!rowData) return;
            
            // Prevent duplicate modals
            if (document.querySelector('.ofw_modal_overlay')) return;
            
            const overlay = document.createElement('div');
            overlay.className = 'ofw_modal_overlay';
            
            // Determine address mode
            const isDhcp = rowData.addressingMode === '1';
            const staticChecked = !isDhcp ? 'checked' : '';
            const dhcpChecked = isDhcp ? 'checked' : '';
            const ipaddrDisabled = isDhcp ? 'disabled' : '';
            const ipaddrDisplay = isDhcp ? 'none' : '';
            
            // Determine type fields visibility
            const type = rowData.typeCode;
            const vlanIfDisplay = type === '1' ? '' : 'none';
            const vlanIdDisplay = type === '1' ? '' : 'none';
            const bondDisplay = type === '3' ? '' : 'none';
            const bridgeDisplay = type === '2' ? '' : 'none';
            
            // Build bridge/bond member options
            let bridgeAvailHtml = '';
            let bridgeSelectedHtml = '';
            let bondAvailHtml = '';
            let bondSelectedHtml = '';
            
            if (this.options.interfaces) {
                const brMembers = rowData.brMembers ? rowData.brMembers.split('#') : [];
                const bondMembers = rowData.bondMembers ? rowData.bondMembers.split('#') : [];
                
                this.options.interfaces.forEach(iface => {
                    const ifaceName = iface.replace(/'/g, '');
                    if (brMembers.includes(ifaceName)) {
                        bridgeSelectedHtml += `<option value="${ifaceName}">${ifaceName}</option>`;
                    } else {
                        bridgeAvailHtml += `<option value="${ifaceName}">${ifaceName}</option>`;
                    }
                    if (bondMembers.includes(ifaceName)) {
                        bondSelectedHtml += `<option value="${ifaceName}">${ifaceName}</option>`;
                    } else {
                        bondAvailHtml += `<option value="${ifaceName}">${ifaceName}</option>`;
                    }
                });
            }
            
            // Build interface options for VLAN
            let vlanIfHtml = '';
            if (this.options.interfaces) {
                vlanIfHtml = this.options.interfaces.map(iface => {
                    const ifaceName = iface.replace(/'/g, '');
                    const selected = ifaceName === rowData.iface ? 'selected' : '';
                    return `<option value="${ifaceName}" ${selected}>${ifaceName}</option>`;
                }).join('');
            }
            
            // MTU handling
            const mtuValue = rowData.mtu || '1500';
            const mtuChecked = mtuValue !== '1500' ? 'checked' : '';
            const mtuDisabled = mtuValue === '1500' ? 'disabled' : '';
            
            overlay.innerHTML = `
                <div class="ofw_modal_dialog" style="width:600px;">
                    <div class="ofw_modal_header">
                        <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
                        <span class="ofw_modal_title">Edit Interface</span>
                        <button class="ofw_modal_close">&times;</button>
                    </div>
                    <div class="ofw_modal_body">
                        <form id="editInterfaceForm" method="post" action="/cgi-bin/interfaces.cgi">
                            <input type="hidden" name="ACTION" value="${this.options.editAction || 'edit'}">
                            <input type="hidden" name="OLD_IF_NAME" value="${rowData.id}">
                            <table style="width:100%;border-collapse:collapse;">
                                <tr>
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>Name</label></td>
                                    <td><input type="text" name="IF_NAME" style="width:200px;" value="${rowData.id}" required readonly></td>
                                </tr>
                                <tr>
                                    <td style="padding:8px 12px 8px 0;text-align:right;"><label>Description</label></td>
                                    <td><input type="text" name="DESCRIPTION" style="width:200px;" value="${rowData.description || ''}"></td>
                                </tr>
                                <tr>
                                    <td style="padding:8px 12px 8px 0;text-align:right;"><label>Type</label></td>
                                    <td>
                                        <select name="TYPE_display" style="width:200px;" disabled>
                                            <option value="0" ${type === '0' ? 'selected' : ''}>PHYSICAL</option>
                                            <option value="1" ${type === '1' ? 'selected' : ''}>VLAN</option>
                                            <option value="2" ${type === '2' ? 'selected' : ''}>BRIDGE</option>
                                            <option value="3" ${type === '3' ? 'selected' : ''}>BOND</option>
                                        </select>
                                        <input type="hidden" name="TYPE" value="${type}">
                                    </td>
                                </tr>
                                <tr id="vlan_if_row" style="display:${vlanIfDisplay};">
                                    <td style="padding:8px 12px 8px 0;text-align:right;"><label>Interface</label></td>
                                    <td>
                                        <select name="IFACE" style="width:200px;">
                                            ${vlanIfHtml}
                                        </select>
                                    </td>
                                </tr>
                                <tr id="vlan_id_row" style="display:${vlanIdDisplay};">
                                    <td style="padding:8px 12px 8px 0;text-align:right;"><label>VLAN ID</label></td>
                                    <td><input type="text" name="VLANID" style="width:200px;" value="${rowData.vlanId || ''}" maxlength="5"></td>
                                </tr>
                                <tr id="bond_members_row" style="display:${bondDisplay};">
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>Sub Interfaces</label></td>
                                    <td>
                                        <table style="width:100%;">
                                            <tr>
                                                <td style="width:45%;"><div style="margin-bottom:4px;">Available:</div>
                                                    <select name="bond_avail" id="bond_avail" style="width:100%;" multiple size="5">
                                                        ${bondAvailHtml}
                                                    </select>
                                                </td>
                                                <td style="width:10%;text-align:center;vertical-align:middle;">
                                                    <button type="button" onclick="move_option(document.getElementById('bond_avail'), document.getElementById('bond_selected'))" style="margin:2px;">→</button><br>
                                                    <button type="button" onclick="move_option(document.getElementById('bond_selected'), document.getElementById('bond_avail'))" style="margin:2px;">←</button>
                                                </td>
                                                <td style="width:45%;"><div style="margin-bottom:4px;">Selected:</div>
                                                    <select name="BOND_MEMBERS" id="bond_selected" style="width:100%;" multiple size="5">${bondSelectedHtml}</select>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr id="bridge_members_row" style="display:${bridgeDisplay};">
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>Bridge Slaves</label></td>
                                    <td>
                                        <table style="width:100%;">
                                            <tr>
                                                <td style="width:45%;"><div style="margin-bottom:4px;">Available:</div>
                                                    <select name="bridge_avail" id="bridge_avail" style="width:100%;" multiple size="5">
                                                        ${bridgeAvailHtml}
                                                    </select>
                                                </td>
                                                <td style="width:10%;text-align:center;vertical-align:middle;">
                                                    <button type="button" onclick="move_option(document.getElementById('bridge_avail'), document.getElementById('bridge_selected'))" style="margin:2px;">→</button><br>
                                                    <button type="button" onclick="move_option(document.getElementById('bridge_selected'), document.getElementById('bridge_avail'))" style="margin:2px;">←</button>
                                                </td>
                                                <td style="width:45%;"><div style="margin-bottom:4px;">Selected:</div>
                                                    <select name="BR_MEMBERS" id="bridge_selected" style="width:100%;" multiple size="5">${bridgeSelectedHtml}</select>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>Address Mode</label></td>
                                    <td>
                                        <input type="radio" name="ADDRESSING_MODE" value="0" id="mode_static" ${staticChecked} onchange="toggleAddressMode()">
                                        <label for="mode_static">Static</label>&nbsp;&nbsp;&nbsp;
                                        <input type="radio" name="ADDRESSING_MODE" value="1" id="mode_dhcp" ${dhcpChecked} onchange="toggleAddressMode()">
                                        <label for="mode_dhcp">DHCP</label>
                                    </td>
                                </tr>
                                <tr id="ipaddr_row" style="display:${ipaddrDisplay};">
                                    <td style="width:160px;padding:8px 12px 8px 0;text-align:right;"><label>IP Address/Netmask</label></td>
                                    <td><input type="text" name="IPADDR_MASK" style="width:200px;" value="${rowData.ipaddress}/${rowData.netmask}" ${ipaddrDisabled}></td>
                                </tr>
                                <tr>
                                    <td style="width:160px;padding:12px 12px 8px 0;text-align:right;">
                                        <input type="checkbox" id="mode_mtu" name="flag_mtu" value="1" ${mtuChecked} onchange="document.getElementById('mtu_input').disabled = !this.checked">
                                        <label for="mode_mtu">MTU</label>
                                    </td>
                                    <td style="padding:12px 0 8px 0;">
                                        <input type="text" id="mtu_input" name="MTU" style="width:200px;" value="${mtuValue}" ${mtuDisabled}>
                                        <span style="margin-left:4px;color:#666;">(bytes)</span>
                                    </td>
                                </tr>
                            </table>
                        </form>
                    </div>
                    <div class="ofw_modal_footer">
                        <button class="ofw_btn ofw_btn_cancel">Cancel</button>
                        <button class="ofw_btn ofw_btn_primary" onclick="prepareEditFormSubmit()">Save</button>
                    </div>
                </div>
            `;

            document.body.appendChild(overlay);

            // Close button
            overlay.querySelector('.ofw_modal_close').addEventListener('click', () => {
                overlay.remove();
            });

            // Cancel button
            overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => {
                overlay.remove();
            });

            // Make modal draggable
            this.makeDraggable(overlay.querySelector('.ofw_modal_dialog'), overlay.querySelector('.ofw_modal_header'));
        }

        openDeleteConfirm() {
            const selectedRows = this.selectedRows;
            const names = selectedRows.map(r => r[this.options.rowKey]);
            const count = names.length;
            const msg = count === 1
                ? 'Are you sure you want to delete the following interface?'
                : 'Are you sure you want to delete the following ' + count + ' interfaces?';
            const namesHtml = names.map(n => '<div style="padding:2px 0;">' + n + '</div>').join('');

            // Create modal overlay
            const overlay = document.createElement('div');
            overlay.className = 'ofw_modal_overlay';
            overlay.innerHTML = `
                <div class="ofw_modal_dialog" style="width:400px;">
                    <div class="ofw_modal_header">
                        <svg class="ofw_modal_icon" viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                        <span class="ofw_modal_title">Confirm Delete</span>
                        <button class="ofw_modal_close">&times;</button>
                    </div>
                    <div class="ofw_modal_body">
                        <div class="ofw_modal_message">${msg}</div>
                        <div style="margin-top:12px;padding:8px 12px;background:#f5f5f5;border-radius:4px;">
                            ${namesHtml}
                        </div>
                    </div>
                    <div class="ofw_modal_footer">
                        <button class="ofw_btn ofw_btn_cancel">Cancel</button>
                        <button class="ofw_btn ofw_btn_primary">Delete</button>
                    </div>
                </div>
            `;

            document.body.appendChild(overlay);

            // Close button
            overlay.querySelector('.ofw_modal_close').addEventListener('click', () => {
                overlay.remove();
            });

            // Cancel button
            overlay.querySelector('.ofw_btn_cancel').addEventListener('click', () => {
                overlay.remove();
            });

            // Delete button
            overlay.querySelector('.ofw_btn_primary').addEventListener('click', () => {
                overlay.remove();
                if (this.options.onAction) {
                    this.options.onAction('delete', Array.from(this.state.selectedKeys));
                }
            });

            // Click overlay to close - disabled
            // overlay.addEventListener('click', (e) => {
            //     if (e.target === overlay) {
            //         overlay.remove();
            //     }
            // });

            // Make modal draggable
            this.makeDraggable(overlay.querySelector('.ofw_modal_dialog'), overlay.querySelector('.ofw_modal_header'));
        }

        makeDraggable(element, handle) {
            let isDragging = false;
            let startX, startY, initialX, initialY;

            handle.addEventListener('mousedown', (e) => {
                isDragging = true;
                startX = e.clientX;
                startY = e.clientY;
                const transform = element.style.transform || 'translate(0px, 0px)';
                const match = transform.match(/translate\(([^,]+)px,\s*([^)]+)px\)/);
                initialX = match ? parseFloat(match[1]) : 0;
                initialY = match ? parseFloat(match[2]) : 0;
                document.body.style.userSelect = 'none';
            });

            document.addEventListener('mousemove', (e) => {
                if (!isDragging) return;
                const dx = e.clientX - startX;
                const dy = e.clientY - startY;
                element.style.transform = `translate(${initialX + dx}px, ${initialY + dy}px)`;
            });

            document.addEventListener('mouseup', () => {
                isDragging = false;
                document.body.style.userSelect = '';
            });
        }

        toggleSelect(key) {
            if (this.state.selectedKeys.has(key)) {
                this.state.selectedKeys.delete(key);
            } else {
                this.state.selectedKeys.add(key);
            }
            this.render();
            if (this.options.onSelectionChange) {
                this.options.onSelectionChange(Array.from(this.state.selectedKeys));
            }
        }

        toggleSelectAll() {
            const pageKeys = this.pagedData.map(r => r[this.options.rowKey]);
            const allSelected = pageKeys.every(k => this.state.selectedKeys.has(k));
            if (allSelected) {
                pageKeys.forEach(k => this.state.selectedKeys.delete(k));
            } else {
                pageKeys.forEach(k => this.state.selectedKeys.add(k));
            }
            this.render();
            if (this.options.onSelectionChange) {
                this.options.onSelectionChange(Array.from(this.state.selectedKeys));
            }
        }

        isSelected(row) {
            return this.state.selectedKeys.has(row[this.options.rowKey]);
        }

        allPageSelected() {
            if (!this.pagedData.length) return false;
            return this.pagedData.every(r => this.state.selectedKeys.has(r[this.options.rowKey]));
        }

        toggleSort(key) {
            if (this.state.sortKey === key) {
                this.state.sortOrder = this.state.sortOrder === 'asc' ? 'desc' : 'asc';
            } else {
                this.state.sortKey = key;
                this.state.sortOrder = 'asc';
            }
            this.render();
        }

        updateData(data) {
            this.options.data = data;
            this.state.currentPage = 1;
            this.render();
        }

        setQuickFilter(value) {
            this.state.quickFilter = value;
            this.state.currentPage = 1;
            this.render();
        }

        render() {
            this.container.innerHTML = this.renderTemplate();
        }

        renderTemplate() {
            return `
                <div class="ofw_datatable">
                    ${this.renderToolbar()}
                    ${this.renderTable()}
                    ${this.renderPagination()}
                    ${this.renderColumnSettingModal()}
                    ${this.renderFilterModal()}
                </div>
            `;
        }

        renderToolbar() {
            const actions = this.options.actions;
            const actionLabels = {
                create: 'Add',
                edit: 'Edit',
                delete: 'Delete',
                refresh: 'Refresh',
                filter: 'Filter',
                columnSetting: 'Columns'
            };
            const actionIcons = {
                create: '＋',
                edit: '✎',
                delete: '✕',
                refresh: '↻',
                filter: '▦',
                columnSetting: '☰'
            };

            let toolbarHtml = '<div class="ofw_toolbar">';
            toolbarHtml += '<div class="ofw_toolbar_left">';
            actions.forEach(action => {
                const disabledAttr = this.actionDisabled(action) ? 'disabled' : '';
                const icon = actionIcons[action] || '';
                const label = actionLabels[action] || action;
                toolbarHtml += `<button class="ofw_btn" data-action="${action}" ${disabledAttr}><span class="ofw_btn_icon">${icon}</span><span class="ofw_btn_label">${label}</span></button>`;
            });
            toolbarHtml += '</div>';
            toolbarHtml += '<div class="ofw_toolbar_right">';
            toolbarHtml += `<input type="text" class="ofw_search" placeholder="Search..." value="${this.state.quickFilter}" />`;
            toolbarHtml += '<button class="ofw_btn" data-action="filter"><span class="ofw_btn_icon">▦</span><span class="ofw_btn_label">Filter</span></button>';
            toolbarHtml += '<button class="ofw_btn" data-action="columnSetting"><span class="ofw_btn_icon">☰</span><span class="ofw_btn_label">Columns</span></button>';
            toolbarHtml += '</div>';
            toolbarHtml += '</div>';
            return toolbarHtml;
        }

        renderTable() {
            const visibleCols = this.options.columns.filter(c => this.state.visibleColumns.includes(c.key));
            let html = '<div class="ofw_table_wrapper">';
            html += '<table class="ofw_data_table">';
            html += '<thead><tr>';

            if (this.options.selectable) {
                const checked = this.allPageSelected() ? 'checked' : '';
                html += `<th style="width:40px;"><input type="checkbox" class="ofw_select_all" ${checked} /></th>`;
            }

            visibleCols.forEach(col => {
                const sortIcon = this.state.sortKey === col.key ? (this.state.sortOrder === 'asc' ? ' ▲' : ' ▼') : '';
                html += `<th class="ofw_sortable" data-key="${col.key}">${col.title}${sortIcon}</th>`;
            });

            html += '</tr></thead><tbody>';

            if (this.pagedData.length === 0) {
                html += `<tr><td colspan="${visibleCols.length + (this.options.selectable ? 1 : 0)}" class="ofw_no_data">No data</td></tr>`;
            } else {
                this.pagedData.forEach(row => {
                    const selected = this.isSelected(row) ? 'selected' : '';
                    html += `<tr class="${selected}" data-key="${row[this.options.rowKey]}">`;

                    if (this.options.selectable) {
                        const checked = this.isSelected(row) ? 'checked' : '';
                        html += `<td><input type="checkbox" class="ofw_row_select" ${checked} /></td>`;
                    }

                    visibleCols.forEach(col => {
                        const value = col.render ? col.render(row[col.key], row) : (row[col.key] || '');
                        html += `<td>${value}</td>`;
                    });

                    html += '</tr>';
                });
            }

            html += '</tbody></table></div>';
            return html;
        }

        renderPagination() {
            if (this.totalPages <= 1) return '';

            let html = '<div class="ofw_pagination">';
            html += `<button class="ofw_page_btn" data-page="1" ${this.state.currentPage === 1 ? 'disabled' : ''}>First</button>`;
            html += `<button class="ofw_page_btn" data-page="${this.state.currentPage - 1}" ${this.state.currentPage === 1 ? 'disabled' : ''}>Prev</button>`;

            const delta = 2;
            const left = Math.max(1, this.state.currentPage - delta);
            const right = Math.min(this.totalPages, this.state.currentPage + delta);

            if (left > 1) html += '<button class="ofw_page_btn" data-page="1">1</button>';
            if (left > 2) html += '<span class="ofw_page_ellipsis">...</span>';

            for (let i = left; i <= right; i++) {
                const active = i === this.state.currentPage ? 'active' : '';
                html += `<button class="ofw_page_btn ${active}" data-page="${i}">${i}</button>`;
            }

            if (right < this.totalPages - 1) html += '<span class="ofw_page_ellipsis">...</span>';
            if (right < this.totalPages) html += `<button class="ofw_page_btn" data-page="${this.totalPages}">${this.totalPages}</button>`;

            html += `<button class="ofw_page_btn" data-page="${this.state.currentPage + 1}" ${this.state.currentPage === this.totalPages ? 'disabled' : ''}>Next</button>`;
            html += `<button class="ofw_page_btn" data-page="${this.totalPages}" ${this.state.currentPage === this.totalPages ? 'disabled' : ''}>Last</button>`;
            html += `<span class="ofw_page_info">Total: ${this.filteredData.length} | Page ${this.state.currentPage} of ${this.totalPages}</span>`;
            html += '</div>';

            return html;
        }

        renderColumnSettingModal() {
            return `
                <div class="ofw_modal ${this.state.columnSettingOpen ? 'open' : ''}" id="ofw_column_modal">
                    <div class="ofw_modal_content">
                        <div class="ofw_modal_header">
                            <h3>Column Settings</h3>
                            <button class="ofw_modal_close">&times;</button>
                        </div>
                        <div class="ofw_modal_body">
                            <div class="ofw_pane_container">
                                <div class="ofw_pane">
                                    <div class="ofw_pane_title">Available Columns</div>
                                    <div class="ofw_pane_list" id="ofw_available_cols">
                                        ${this.state.availableColumns.map(col => `<div class="ofw_pane_item" data-key="${col.key}">${col.title}</div>`).join('')}
                                    </div>
                                </div>
                                <div class="ofw_pane_actions">
                                    <button class="ofw_btn" id="ofw_add_col">▶</button>
                                    <button class="ofw_btn" id="ofw_remove_col">◀</button>
                                </div>
                                <div class="ofw_pane">
                                    <div class="ofw_pane_title">Visible Columns</div>
                                    <div class="ofw_pane_list" id="ofw_visible_cols">
                                        ${this.state.selectedColumns.map(col => `<div class="ofw_pane_item" data-key="${col.key}">${col.title}</div>`).join('')}
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="ofw_modal_footer">
                            <button class="ofw_btn" id="ofw_cancel_col">Cancel</button>
                            <button class="ofw_btn ofw_btn_primary" id="ofw_confirm_col">Confirm</button>
                        </div>
                    </div>
                </div>
            `;
        }

        renderFilterModal() {
            return `
                <div class="ofw_modal ${this.state.filterOpen ? 'open' : ''}" id="ofw_filter_modal">
                    <div class="ofw_modal_content">
                        <div class="ofw_modal_header">
                            <h3>Filter</h3>
                            <button class="ofw_modal_close">&times;</button>
                        </div>
                        <div class="ofw_modal_body">
                            <div class="ofw_filter_form">
                                <div class="ofw_form_row">
                                    <label style="width:80px;text-align:right;display:inline-block;">Field</label>
                                    <select id="ofw_filter_field">
                                        ${this.options.columns.map(col => `<option value="${col.key}">${col.title}</option>`).join('')}
                                    </select>
                                </div>
                                <div class="ofw_form_row">
                                    <label style="width:80px;text-align:right;display:inline-block;">Match</label>
                                    <select id="ofw_filter_section">
                                        <option value="contains">Contains</option>
                                        <option value="equals">Equals</option>
                                        <option value="startsWith">Starts With</option>
                                        <option value="endsWith">Ends With</option>
                                        <option value="notContains">Not Contains</option>
                                        <option value="notEqual">Not Equal</option>
                                    </select>
                                </div>
                                <div class="ofw_form_row">
                                    <label style="width:80px;text-align:right;display:inline-block;"><input type="checkbox" id="ofw_filter_not" /> Negate</label>
                                </div>
                                <div class="ofw_form_row">
                                    <label style="width:80px;text-align:right;display:inline-block;">Text</label>
                                    <input type="text" id="ofw_filter_text" />
                                </div>
                                <div class="ofw_form_row">
                                    <label style="width:80px;text-align:right;display:inline-block;"><input type="checkbox" id="ofw_filter_case" /> Case Sensitive</label>
                                </div>
                                <button class="ofw_btn ofw_btn_primary" id="ofw_add_filter">Add Condition</button>
                            </div>
                            <div class="ofw_filter_list" id="ofw_filter_entries">
                                ${this.state.filterEntries.map((entry, i) => `
                                    <div class="ofw_filter_entry">
                                        <span>${entry.field} ${entry.section} "${entry.text}"</span>
                                        <button class="ofw_btn ofw_btn_danger" data-index="${i}">Remove</button>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                        <div class="ofw_modal_footer">
                            <button class="ofw_btn" id="ofw_clear_filter">Clear All</button>
                            <button class="ofw_btn" id="ofw_cancel_filter">Cancel</button>
                            <button class="ofw_btn ofw_btn_primary" id="ofw_confirm_filter">Confirm</button>
                        </div>
                    </div>
                </div>
            `;
        }

        bindEvents() {
            // Use event delegation on container for all dynamic elements
            this.container.addEventListener('click', (e) => {
                // Toolbar action buttons
                const actionBtn = e.target.closest('[data-action]');
                if (actionBtn) {
                    const action = actionBtn.dataset.action;
                    if (action === 'filter') {
                        this.openFilter();
                    } else if (action === 'columnSetting') {
                        this.openColumnSetting();
                    } else {
                        this.handleAction(action);
                    }
                    return;
                }

                // Sort headers
                const sortableTh = e.target.closest('.ofw_sortable');
                if (sortableTh) {
                    this.toggleSort(sortableTh.dataset.key);
                    return;
                }

                // Pagination buttons
                const pageBtn = e.target.closest('.ofw_page_btn');
                if (pageBtn) {
                    const page = parseInt(pageBtn.dataset.page);
                    if (page >= 1 && page <= this.totalPages) {
                        this.state.currentPage = page;
                        this.render();
                    }
                    return;
                }

                // Modal close buttons
                const closeBtn = e.target.closest('.ofw_modal_close');
                if (closeBtn) {
                    this.state.columnSettingOpen = false;
                    this.state.filterOpen = false;
                    this.render();
                    return;
                }

                // Column setting buttons
                if (e.target.id === 'ofw_add_col') { this.addColumn(); return; }
                if (e.target.id === 'ofw_remove_col') { this.removeColumn(); return; }
                if (e.target.id === 'ofw_confirm_col') { this.confirmColumnSetting(); return; }
                if (e.target.id === 'ofw_cancel_col') { this.cancelColumnSetting(); return; }

                // Filter buttons
                if (e.target.id === 'ofw_add_filter') { this.addFilterEntry(); return; }
                if (e.target.id === 'ofw_clear_filter') { this.clearFilters(); return; }
                if (e.target.id === 'ofw_confirm_filter') { this.confirmFilter(); return; }
                if (e.target.id === 'ofw_cancel_filter') { this.cancelFilter(); return; }

                // Filter entry remove buttons
                const filterRemoveBtn = e.target.closest('.ofw_filter_entry button');
                if (filterRemoveBtn) {
                    const index = parseInt(filterRemoveBtn.dataset.index);
                    this.removeFilterEntry(index);
                    return;
                }

                // Column selection items
                const colItem = e.target.closest('.ofw_pane_item');
                if (colItem) {
                    const parent = colItem.parentElement;
                    parent.querySelectorAll('.ofw_pane_item').forEach(i => i.classList.remove('selected'));
                    colItem.classList.add('selected');
                    return;
                }

                // Row click (not on checkbox)
                const row = e.target.closest('tbody tr');
                if (row && e.target.type !== 'checkbox' && this.options.onRowClick) {
                    const key = row.dataset.key;
                    const rowData = this.options.data.find(r => r[this.options.rowKey] == key);
                    this.options.onRowClick(rowData);
                }
            });

            // Checkbox events - use click with preventDefault to control state manually
            this.container.addEventListener('click', (e) => {
                if (e.target.classList.contains('ofw_row_select')) {
                    e.preventDefault();
                    e.stopPropagation();
                    const row = e.target.closest('tr');
                    const key = row.dataset.key;
                    this.toggleSelect(key);
                } else if (e.target.classList.contains('ofw_select_all')) {
                    e.preventDefault();
                    e.stopPropagation();
                    this.toggleSelectAll();
                }
            });

            // Search input
            this.container.addEventListener('input', (e) => {
                if (e.target.classList.contains('ofw_search')) {
                    this.setQuickFilter(e.target.value);
                }
            });
        }

        openColumnSetting() {
            this.state.selectedColumns = this.options.columns.filter(c => this.state.visibleColumns.includes(c.key));
            this.state.availableColumns = this.options.columns.filter(c => !this.state.visibleColumns.includes(c.key));
            this.state.columnSettingOpen = true;
            this.render();
        }

        closeColumnSetting() {
            this.state.columnSettingOpen = false;
            this.render();
        }

        addColumn() {
            const selected = this.container.querySelector('#ofw_available_cols .ofw_pane_item.selected');
            if (!selected) return;
            const key = selected.dataset.key;
            const col = this.state.availableColumns.find(c => c.key === key);
            if (col) {
                this.state.availableColumns = this.state.availableColumns.filter(c => c.key !== key);
                this.state.selectedColumns.push(col);
                this.render();
            }
        }

        removeColumn() {
            const selected = this.container.querySelector('#ofw_visible_cols .ofw_pane_item.selected');
            if (!selected) return;
            const key = selected.dataset.key;
            const col = this.state.selectedColumns.find(c => c.key === key);
            if (col) {
                this.state.selectedColumns = this.state.selectedColumns.filter(c => c.key !== key);
                this.state.availableColumns.push(col);
                this.render();
            }
        }

        confirmColumnSetting() {
            this.state.visibleColumns = this.state.selectedColumns.map(c => c.key);
            this.saveColumnSettings();
            this.state.columnSettingOpen = false;
            this.render();
        }

        cancelColumnSetting() {
            this.state.columnSettingOpen = false;
            this.render();
        }

        openFilter() {
            this.state.filterOpen = true;
            this.render();
        }

        closeFilter() {
            this.state.filterOpen = false;
            this.render();
        }

        addFilterEntry() {
            const field = this.container.querySelector('#ofw_filter_field').value;
            const section = this.container.querySelector('#ofw_filter_section').value;
            const not = this.container.querySelector('#ofw_filter_not').checked;
            const text = this.container.querySelector('#ofw_filter_text').value;
            const caseSensitive = this.container.querySelector('#ofw_filter_case').checked;

            if (!text) return;

            this.state.filterEntries.push({ field, section, not, text, caseSensitive, enabled: true });
            this.container.querySelector('#ofw_filter_text').value = '';
            this.render();
        }

        removeFilterEntry(index) {
            this.state.filterEntries.splice(index, 1);
            this.render();
        }

        clearFilters() {
            this.state.filterEntries = [];
            this.render();
        }

        confirmFilter() {
            this.state.currentPage = 1;
            this.state.filterOpen = false;
            this.render();
        }

        cancelFilter() {
            this.state.filterOpen = false;
            this.render();
        }
    }

    global.DataTable = DataTable;
})(window);
