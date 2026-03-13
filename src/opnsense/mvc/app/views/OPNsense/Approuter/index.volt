{#
    Copyright (C) 2024 os-app-router contributors
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#}

<style>
    .gw-sortable-list {
        list-style: none;
        padding: 0;
        margin: 5px 0;
    }
    .gw-sortable-list li {
        padding: 6px 10px;
        margin-bottom: 2px;
        border: 1px solid #ddd;
        border-radius: 3px;
        background: #fff;
        cursor: default;
        display: flex;
        align-items: center;
    }
    .gw-sortable-list li.gw-selected {
        background: #f0f8ff;
        border-color: #5bc0de;
    }
    .gw-sortable-list li.gw-selected .gw-handle {
        cursor: grab;
    }
    .gw-sortable-list li .gw-handle {
        margin-right: 8px;
        color: #999;
        font-size: 16px;
        visibility: hidden;
    }
    .gw-sortable-list li.gw-selected .gw-handle {
        visibility: visible;
    }
    .gw-sortable-list li .gw-rank {
        font-weight: bold;
        margin-right: 8px;
        min-width: 20px;
        color: #337ab7;
    }
    .gw-sortable-list li .gw-label {
        flex: 1;
    }
    .gw-sortable-list li input[type="checkbox"] {
        margin-right: 8px;
    }
    .gw-sortable-list .gw-divider {
        border: none;
        padding: 2px 10px;
        margin-bottom: 2px;
        color: #999;
        font-size: 11px;
        text-align: center;
        cursor: default;
    }
    .gw-sortable-list .gw-divider .gw-handle,
    .gw-sortable-list .gw-divider .gw-rank {
        display: none;
    }
    .gw-sortable-list .ui-sortable-helper {
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    }
</style>

<script>
    $( document ).ready(function() {
        // Tab persistence via URL hash
        if (window.location.hash) {
            $('#maintabs a[href="' + window.location.hash + '"]').tab('show');
        }
        $('#maintabs a').on('shown.bs.tab', function (e) {
            window.location.hash = e.target.hash;
        });

        // Both forms share the same model endpoint - load once, populate both
        var data_get_map = {
            'frm_GeneralSettings': "/api/approuter/settings/get",
            'frm_ListSettings': "/api/approuter/settings/get"
        };
        mapDataToFormUI(data_get_map).done(function(data){
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        $("#saveGeneralAct").click(function(){
            saveFormToEndpoint(url="/api/approuter/settings/set", formid='frm_GeneralSettings', callback_ok=function(){
                $("#saveGeneralAct_progress").addClass("fa fa-spinner fa-pulse");
                ajaxCall(url="/api/approuter/service/reconfigure", sendData={}, callback=function(data,status) {
                    $("#saveGeneralAct_progress").removeClass("fa fa-spinner fa-pulse");
                });
            });
        });

        $("#saveListsAct").click(function(){
            saveFormToEndpoint(url="/api/approuter/settings/set", formid='frm_ListSettings', callback_ok=function(){
                $("#saveListsAct_progress").addClass("fa fa-spinner fa-pulse");
                ajaxCall(url="/api/approuter/service/reconfigure", sendData={}, callback=function(data,status) {
                    $("#saveListsAct_progress").removeClass("fa fa-spinner fa-pulse");
                });
            });
        });

        $("#updateListsAct").click(function(){
            $("#updateListsAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall(url="/api/approuter/service/updateLists", sendData={}, callback=function(data,status) {
                $("#updateListsAct_progress").removeClass("fa fa-spinner fa-pulse");
                loadStatus();
            });
        });

        $("#forceUpdateAct").click(function(){
            $("#forceUpdateAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall(url="/api/approuter/service/forceUpdate", sendData={}, callback=function(data,status) {
                $("#forceUpdateAct_progress").removeClass("fa fa-spinner fa-pulse");
                loadStatus();
            });
        });

        // Smart Gateway: show/hide probe fields based on checkbox
        function toggleSmartGatewayFields() {
            var isChecked = $("#rule\\.smartGateway").is(":checked");
            var probeFields = ["#row_rule\\.probeUrl", "#row_rule\\.probeInterval",
                               "#row_rule\\.probeMethod", "#row_rule\\.probePattern"];
            probeFields.forEach(function(sel) {
                if (isChecked) {
                    $(sel).show();
                } else {
                    $(sel).hide();
                }
            });
            // Show/hide probePattern based on probeMethod
            if (isChecked) {
                var method = $("#rule\\.probeMethod").val();
                if (method === "body_match") {
                    $("#row_rule\\.probePattern").show();
                } else {
                    $("#row_rule\\.probePattern").hide();
                }
            }
        }

        $(document).on("change", "#rule\\.smartGateway", toggleSmartGatewayFields);
        $(document).on("change", "#rule\\.probeMethod", toggleSmartGatewayFields);

        // Toggle fields when dialog opens + build gateway sortable
        $(document).on("shown.bs.modal", "#DialogRule", function() {
            toggleSmartGatewayFields();
            buildGatewaySortable();
        });

        // Store gateway_order from getRule API response
        var _lastGatewayOrder = "";
        // Intercept AJAX responses to capture gateway_order from getRule
        $(document).ajaxComplete(function(event, xhr, settings) {
            if (settings.url && settings.url.indexOf('/api/approuter/settings/getRule/') === 0) {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data && data.rule && data.rule.gateway_order) {
                        _lastGatewayOrder = data.rule.gateway_order;
                    } else {
                        _lastGatewayOrder = "";
                    }
                } catch(e) {}
            }
        });

        function buildGatewaySortable() {
            var $selectContainer = $("#row_rule\\.gateway");
            if ($selectContainer.length === 0) return;

            // Remove any previous sortable
            $selectContainer.find(".gw-sortable-container").remove();

            // Read options from the select_multiple generated by OPNsense
            var $select = $selectContainer.find("select");
            if ($select.length === 0) return;

            // Read the saved gateway order
            var gatewayOrder = [];
            if (_lastGatewayOrder) {
                gatewayOrder = _lastGatewayOrder.split(",").map(function(s) { return s.trim(); }).filter(Boolean);
            }

            var options = [];
            $select.find("option").each(function() {
                options.push({
                    value: $(this).val(),
                    label: $(this).text(),
                    selected: $(this).is(":selected")
                });
            });

            if (options.length === 0) return;

            // Sort: selected items first (in gateway_order if available), then unselected
            var selectedMap = {};
            options.forEach(function(o) { if (o.selected) selectedMap[o.value] = o; });

            var selectedItems = [];
            // First add in saved order
            gatewayOrder.forEach(function(val) {
                if (selectedMap[val]) {
                    selectedItems.push(selectedMap[val]);
                    delete selectedMap[val];
                }
            });
            // Then any selected not in saved order
            for (var val in selectedMap) {
                selectedItems.push(selectedMap[val]);
            }
            var unselectedItems = options.filter(function(o) { return !o.selected; });

            // Build the sortable HTML
            var html = '<div class="gw-sortable-container">';
            html += '<ul class="gw-sortable-list" id="gwSortableList">';

            function renderItem(o, isSelected) {
                var cls = isSelected ? ' class="gw-selected"' : '';
                var chk = isSelected ? ' checked' : '';
                return '<li' + cls + ' data-value="' + o.value + '">' +
                    '<span class="gw-handle">&#9776;</span>' +
                    '<span class="gw-rank"></span>' +
                    '<input type="checkbox"' + chk + '>' +
                    '<span class="gw-label">' + $('<span>').text(o.label).html() + '</span>' +
                    '</li>';
            }

            selectedItems.forEach(function(o) { html += renderItem(o, true); });
            html += '<li class="gw-divider" data-value="__divider__">--- {{ lang._("Unselected") }} ---</li>';
            unselectedItems.forEach(function(o) { html += renderItem(o, false); });

            html += '</ul></div>';

            // Hide original select, append our sortable
            $select.hide();
            // Also hide any selectpicker bootstrap container
            $selectContainer.find(".bootstrap-select").hide();
            $selectContainer.find(".col-sm-8, .col-md-9, .col-xs-12").first().append(html);

            var $list = $("#gwSortableList");

            function updateRanksAndValue() {
                var rank = 1;
                var selectedValues = [];
                $list.children("li").each(function() {
                    var val = $(this).data("value");
                    if (val === "__divider__") return;
                    var isChecked = $(this).find("input[type=checkbox]").is(":checked");
                    if (isChecked) {
                        $(this).addClass("gw-selected").find(".gw-rank").text(rank + ".");
                        selectedValues.push(val);
                        rank++;
                    } else {
                        $(this).removeClass("gw-selected").find(".gw-rank").text("");
                    }
                });

                // Reorder <option> elements so selected ones come first in drag order.
                // OPNsense serializes select[multiple] in DOM order.
                var $opts = $select.find("option").detach();
                var optMap = {};
                $opts.each(function() { optMap[$(this).val()] = $(this).prop("selected", false); });
                // Append selected in sortable order, mark selected
                selectedValues.forEach(function(val) {
                    if (optMap[val]) {
                        optMap[val].prop("selected", true);
                        $select.append(optMap[val]);
                        delete optMap[val];
                    }
                });
                // Append remaining unselected
                for (var val in optMap) {
                    $select.append(optMap[val]);
                }
                $select.trigger("change");
            }

            // Make it sortable (only selected items above divider can be reordered)
            $list.sortable({
                items: "li:not(.gw-divider)",
                handle: ".gw-handle",
                placeholder: "ui-state-highlight",
                tolerance: "pointer",
                update: function() {
                    // Move unchecked items below divider, checked above
                    reorderList();
                    updateRanksAndValue();
                }
            });

            function reorderList() {
                var $divider = $list.find(".gw-divider");
                $list.children("li:not(.gw-divider)").each(function() {
                    var isChecked = $(this).find("input[type=checkbox]").is(":checked");
                    if (isChecked) {
                        $divider.before($(this));
                    } else {
                        $list.append($(this));
                    }
                });
            }

            // Checkbox toggle: move item to correct section
            $list.on("change", "input[type=checkbox]", function() {
                var $li = $(this).closest("li");
                var $divider = $list.find(".gw-divider");
                if ($(this).is(":checked")) {
                    $divider.before($li);
                } else {
                    $list.append($li);
                }
                updateRanksAndValue();
            });

            updateRanksAndValue();
        }

        $("#grid-rules").UIBootgrid({
            'search':'/api/approuter/settings/searchRule',
            'get':'/api/approuter/settings/getRule/',
            'set':'/api/approuter/settings/setRule/',
            'add':'/api/approuter/settings/addRule',
            'del':'/api/approuter/settings/delRule/',
            'toggle':'/api/approuter/settings/toggleRule/'
        });

        $("#reconfigureAct").click(function(){
            $("#reconfigureAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall(url="/api/approuter/service/reconfigure", sendData={}, callback=function(data,status) {
                $("#reconfigureAct_progress").removeClass("fa fa-spinner fa-pulse");
                $("#RuleChangeMessage").addClass("hidden");
                updateServiceControlUI('approuter');
            });
        });

        // Service status control (green/red indicator + stop/restart buttons)
        updateServiceControlUI('approuter');

        loadStatus();

        function loadStatus() {
            ajaxGet(url="/api/approuter/service/detailStatus", sendData={}, callback=function(data, status) {
                if (data && data.data) {
                    var info = data.data;
                    var html = '';
                    function esc(s) { return $('<span>').text(s).html(); }

                    // Service status
                    html += '<h4>{{ lang._("Service") }}</h4>';
                    html += '<table class="table table-condensed table-striped">';
                    html += '<tr><td style="width:200px">{{ lang._("Plugin Enabled") }}</td><td>' +
                        (info.enabled === '1' ? '<span class="label label-success">Yes</span>' : '<span class="label label-danger">No</span>') + '</td></tr>';
                    html += '<tr><td>{{ lang._("DNS Resolver") }}</td><td>' + (info.dns_resolver || 'N/A') + '</td></tr>';
                    if (info.dns_watcher) {
                        var watcherLabel = info.dns_watcher.running ?
                            '<span class="label label-success">Running (PID ' + info.dns_watcher.pid + ')</span>' :
                            '<span class="label label-danger">Stopped</span>';
                        html += '<tr><td>{{ lang._("DNS Watcher") }}</td><td>' + watcherLabel + '</td></tr>';
                    }
                    if (info.geo_prober) {
                        var proberLabel = info.geo_prober.running ?
                            '<span class="label label-success">Running (PID ' + info.geo_prober.pid + ')</span>' :
                            '<span class="label label-default">Stopped</span>';
                        html += '<tr><td>{{ lang._("Geo Prober") }}</td><td>' + proberLabel + '</td></tr>';
                    }
                    if (info.last_full_update) {
                        var d = new Date(info.last_full_update * 1000);
                        html += '<tr><td>{{ lang._("Last List Update") }}</td><td>' + d.toLocaleString() + '</td></tr>';
                    }
                    html += '</table>';

                    // List stats
                    html += '<h4>{{ lang._("Lists") }}</h4>';
                    html += '<table class="table table-condensed table-striped">';
                    if (info.china_cidrs_count) {
                        html += '<tr><td style="width:200px">{{ lang._("China CIDRs") }}</td><td>' + info.china_cidrs_count + '</td></tr>';
                    }
                    if (info.china_domains_count) {
                        html += '<tr><td>{{ lang._("China Domains") }}</td><td>' + info.china_domains_count + '</td></tr>';
                    }
                    if (info.categories) {
                        for (var cat in info.categories) {
                            html += '<tr><td>' + cat + '</td><td>' + info.categories[cat] + ' domains</td></tr>';
                        }
                    }
                    html += '</table>';

                    // Smart Gateway status
                    if (info.smart_gateway && info.smart_gateway.length > 0) {
                        html += '<h4>{{ lang._("Smart Gateway") }}</h4>';
                        html += '<table class="table table-condensed table-striped">';
                        html += '<thead><tr><th>{{ lang._("Rule") }}</th><th>{{ lang._("Gateways (Priority Order)") }}</th><th>{{ lang._("Active Gateway") }}</th><th>{{ lang._("Method") }}</th></tr></thead>';
                        for (var s = 0; s < info.smart_gateway.length; s++) {
                            var sg = info.smart_gateway[s];
                            var gwList = '';
                            for (var g = 0; g < sg.gateways.length; g++) {
                                var isActive = (sg.gateways[g] === sg.active_gateway);
                                var isFallback = (g === sg.gateways.length - 1);
                                var badge = isActive ? 'success' : 'default';
                                var suffix = isFallback ? ' (fallback)' : '';
                                gwList += '<span class="label label-' + badge + '" style="margin-right:4px">' +
                                    (g + 1) + '. ' + esc(sg.gateways[g]) + suffix + '</span> ';
                            }
                            // Check gw_tables for entry counts
                            if (sg.gw_tables) {
                                gwList += '<br/><small>';
                                for (var gt = 0; gt < sg.gw_tables.length; gt++) {
                                    var gwt = sg.gw_tables[gt];
                                    var entryBadge = gwt.entries > 0 ?
                                        '<span class="label label-success">' + gwt.entries + '</span>' :
                                        '<span class="label label-warning">0</span>';
                                    gwList += esc(gwt.gateway) + ': ' + entryBadge + ' ';
                                }
                                gwList += '</small>';
                            }
                            var activeLabel = '<span class="label label-primary">' + esc(sg.active_gateway) + '</span>';
                            html += '<tr><td>' + esc(sg.description) + '</td><td>' + gwList + '</td><td>' + activeLabel + '</td><td>' + esc(sg.probe_method) + '</td></tr>';
                        }
                        html += '</table>';
                    }

                    // pf table stats
                    if (info.pf_tables && Object.keys(info.pf_tables).length > 0) {
                        html += '<h4>{{ lang._("PF Tables") }}</h4>';
                        html += '<table class="table table-condensed table-striped">';
                        html += '<thead><tr><th>{{ lang._("Table") }}</th><th>{{ lang._("Entries") }}</th></tr></thead>';
                        for (var tbl in info.pf_tables) {
                            var cnt = info.pf_tables[tbl];
                            var badge = cnt > 0 ? '<span class="label label-success">' + cnt + '</span>' :
                                '<span class="label label-warning">0 (empty)</span>';
                            html += '<tr><td>' + esc(tbl) + '</td><td>' + badge + '</td></tr>';
                        }
                        html += '</table>';
                    }

                    // Rule match stats
                    if (info.rule_stats && info.rule_stats.length > 0) {
                        html += '<h4>{{ lang._("Rule Activity") }}</h4>';
                        html += '<table class="table table-condensed table-striped">';
                        html += '<thead><tr><th>{{ lang._("Rule") }}</th><th>{{ lang._("Packets") }}</th><th>{{ lang._("Bytes") }}</th></tr></thead>';
                        for (var i = 0; i < info.rule_stats.length; i++) {
                            var rs = info.rule_stats[i];
                            var bytes = rs.bytes;
                            var bytesStr = bytes > 1073741824 ? (bytes/1073741824).toFixed(1) + ' GB' :
                                           bytes > 1048576 ? (bytes/1048576).toFixed(1) + ' MB' :
                                           bytes > 1024 ? (bytes/1024).toFixed(1) + ' KB' : bytes + ' B';
                            var pktBadge = rs.packets > 0 ?
                                '<span class="label label-success">' + rs.packets.toLocaleString() + '</span>' :
                                '<span class="label label-default">0</span>';
                            html += '<tr><td>' + rs.rule.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</td><td>' + pktBadge + '</td><td>' + bytesStr + '</td></tr>';
                        }
                        html += '</table>';
                    }

                    // Recent logs
                    if (info.recent_logs && info.recent_logs.length > 0) {
                        html += '<h4>{{ lang._("Recent Logs") }}</h4>';
                        html += '<pre style="max-height:300px;overflow-y:auto;font-size:11px">';
                        for (var i = info.recent_logs.length - 1; i >= 0; i--) {
                            html += info.recent_logs[i].replace(/</g, '&lt;').replace(/>/g, '&gt;') + '\n';
                        }
                        html += '</pre>';
                    }

                    $("#statusInfo").html(html);
                }
            });
        }

        $("#refreshStatusAct").click(function() {
            loadStatus();
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#rules">{{ lang._('Routing Rules') }}</a></li>
    <li><a data-toggle="tab" href="#lists">{{ lang._('List Sources') }}</a></li>
    <li><a data-toggle="tab" href="#status">{{ lang._('Status') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="general" class="tab-pane fade in active">
        <div class="content-box" style="padding-bottom: 1.5em;">
            {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_GeneralSettings'])}}
            <div class="col-md-12">
                <hr />
                <button class="btn btn-primary" id="saveGeneralAct" type="button">
                    <b>{{ lang._('Save') }}</b> <i id="saveGeneralAct_progress"></i>
                </button>
            </div>
        </div>
    </div>

    <div id="rules" class="tab-pane fade in">
        <table id="grid-rules" class="table table-condensed table-hover table-striped" data-editDialog="DialogRule" data-editAlert="RuleChangeMessage">
            <thead>
                <tr>
                    <th data-column-id="uuid" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="enabled" data-width="6em" data-type="string" data-formatter="rowtoggle">{{ lang._('Enabled') }}</th>
                    <th data-column-id="description" data-type="string">{{ lang._('Description') }}</th>
                    <th data-column-id="sourceNets" data-type="string">{{ lang._('Source') }}</th>
                    <th data-column-id="categories" data-type="string">{{ lang._('Categories') }}</th>
                    <th data-column-id="customDomains" data-type="string">{{ lang._('Custom Domains') }}</th>
                    <th data-column-id="gateway" data-type="string">{{ lang._('Gateway') }}</th>
                    <th data-column-id="smartGateway" data-width="6em" data-type="string" data-formatter="boolean" data-visible="false">{{ lang._('Smart') }}</th>
                    <th data-column-id="interface" data-type="string">{{ lang._('Interface') }}</th>
                    <th data-column-id="commands" data-width="7em" data-formatter="commands" data-sortable="false">{{ lang._('Commands') }}</th>
                </tr>
            </thead>
            <tbody>
            </tbody>
            <tfoot>
                <tr>
                    <td></td>
                    <td>
                        <button data-action="add" type="button" class="btn btn-xs btn-primary">
                            <span class="fa fa-fw fa-plus"></span>
                        </button>
                        <button data-action="deleteSelected" type="button" class="btn btn-xs btn-default">
                            <span class="fa fa-fw fa-trash-o"></span>
                        </button>
                    </td>
                </tr>
            </tfoot>
        </table>
        <div class="col-md-12">
            <div id="RuleChangeMessage" class="alert alert-info" style="display: none" role="alert">
                {{ lang._('After changing settings, please remember to apply them.') }}
            </div>
            <hr />
            <button class="btn btn-primary" id="reconfigureAct" type="button">
                <b>{{ lang._('Apply') }}</b> <i id="reconfigureAct_progress"></i>
            </button>
        </div>
    </div>

    <div id="lists" class="tab-pane fade in">
        <div class="content-box" style="padding-bottom: 1.5em;">
            {{ partial("layout_partials/base_form",['fields':listsForm,'id':'frm_ListSettings'])}}
            <div class="col-md-12">
                <hr />
                <button class="btn btn-primary" id="saveListsAct" type="button">
                    <b>{{ lang._('Save') }}</b> <i id="saveListsAct_progress"></i>
                </button>
                <button class="btn btn-default" id="updateListsAct" type="button">
                    <b>{{ lang._('Update Lists Now') }}</b> <i id="updateListsAct_progress"></i>
                </button>
                <button class="btn btn-default" id="forceUpdateAct" type="button">
                    <b>{{ lang._('Force Full Update') }}</b> <i id="forceUpdateAct_progress"></i>
                </button>
            </div>
        </div>
    </div>

    <div id="status" class="tab-pane fade in">
        <div class="content-box" style="padding-bottom: 1.5em;">
            <div class="col-md-12">
                <h3>{{ lang._('AppRouter Status') }}</h3>
                <div id="statusInfo">
                    <p>{{ lang._('Loading...') }}</p>
                </div>
                <hr />
                <button class="btn btn-default" id="refreshStatusAct" type="button">
                    <b>{{ lang._('Refresh') }}</b> <i class="fa fa-refresh"></i>
                </button>
            </div>
        </div>
    </div>
</div>

{{ partial("layout_partials/base_dialog",['fields':
    [
        {'id': 'rule.enabled', 'label': lang._('Enabled'), 'type': 'checkbox'},
        {'id': 'rule.description', 'label': lang._('Description'), 'type': 'text'},
        {'id': 'rule.interface', 'label': lang._('Interface'), 'type': 'dropdown', 'help': lang._('Inbound interface')},
        {'id': 'rule.sourceNets', 'label': lang._('Source'), 'type': 'text', 'help': lang._('Enter "any" or comma-separated IPs/subnets (e.g. 192.168.1.0/24, 10.0.0.5)')},
        {'id': 'rule.categories', 'label': lang._('App Categories'), 'type': 'select_multiple', 'help': lang._('Search and select app categories or individual apps')},
        {'id': 'rule.customDomains', 'label': lang._('Custom Domains'), 'type': 'text', 'help': lang._('Comma-separated domains (e.g. example.com, cdn.test.org). All subdomains matched automatically.')},
        {'id': 'rule.gateway', 'label': lang._('Gateway'), 'type': 'select_multiple', 'help': lang._('Select gateways in priority order (first = highest priority, last = fallback)')},
        {'id': 'rule.smartGateway', 'label': lang._('Smart Gateway'), 'type': 'checkbox', 'help': lang._('Enable automatic gateway probing and failover (requires 2+ gateways)')},
        {'id': 'rule.probeUrl', 'label': lang._('Probe URL'), 'type': 'text', 'help': lang._('URL to probe for gateway availability (e.g. https://www.iqiyi.com/)')},
        {'id': 'rule.probeInterval', 'label': lang._('Probe Interval'), 'type': 'text', 'help': lang._('Probe interval in seconds (30-3600, default: 300)')},
        {'id': 'rule.probeMethod', 'label': lang._('Probe Method'), 'type': 'dropdown', 'help': lang._('How to test gateway availability')},
        {'id': 'rule.probePattern', 'label': lang._('Probe Pattern'), 'type': 'text', 'help': lang._('Regex pattern for body_match method (match = geo-restricted)')}
    ],
    'id':'DialogRule',
    'label':lang._('Edit Routing Rule')
])}}
