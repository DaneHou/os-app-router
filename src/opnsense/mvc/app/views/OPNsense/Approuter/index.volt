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

<script>
    $( document ).ready(function() {
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

        $("#grid-rules").UIBootgrid({
            'search':'/api/approuter/settings/searchRule',
            'get':'/api/approuter/settings/getRule',
            'set':'/api/approuter/settings/setRule',
            'add':'/api/approuter/settings/addRule',
            'del':'/api/approuter/settings/delRule',
            'toggle':'/api/approuter/settings/toggleRule'
        });

        $("#reconfigureAct").click(function(){
            $("#reconfigureAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall(url="/api/approuter/service/reconfigure", sendData={}, callback=function(data,status) {
                $("#reconfigureAct_progress").removeClass("fa fa-spinner fa-pulse");
                $("#RuleChangeMessage").addClass("hidden");
            });
        });

        loadStatus();

        function loadStatus() {
            ajaxGet(url="/api/approuter/service/status", sendData={}, callback=function(data, status) {
                if (data && data.data) {
                    var info = data.data;
                    var html = '';

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

                    // pf table stats
                    if (info.pf_tables && Object.keys(info.pf_tables).length > 0) {
                        html += '<h4>{{ lang._("PF Tables") }}</h4>';
                        html += '<table class="table table-condensed table-striped">';
                        html += '<thead><tr><th>{{ lang._("Table") }}</th><th>{{ lang._("Entries") }}</th></tr></thead>';
                        for (var tbl in info.pf_tables) {
                            var cnt = info.pf_tables[tbl];
                            var badge = cnt > 0 ? '<span class="label label-success">' + cnt + '</span>' :
                                '<span class="label label-warning">0 (empty)</span>';
                            html += '<tr><td>' + tbl + '</td><td>' + badge + '</td></tr>';
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
                            var shortRule = rs.rule.replace(/pass in quick on \S+ route-to \([^)]+\) inet from /, 'from ');
                            var bytes = rs.bytes;
                            var bytesStr = bytes > 1073741824 ? (bytes/1073741824).toFixed(1) + ' GB' :
                                           bytes > 1048576 ? (bytes/1048576).toFixed(1) + ' MB' :
                                           bytes > 1024 ? (bytes/1024).toFixed(1) + ' KB' : bytes + ' B';
                            var pktBadge = rs.packets > 0 ?
                                '<span class="label label-success">' + rs.packets.toLocaleString() + '</span>' :
                                '<span class="label label-default">0</span>';
                            html += '<tr><td style="font-size:12px;word-break:break-all">' + shortRule + '</td><td>' + pktBadge + '</td><td>' + bytesStr + '</td></tr>';
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
                    <th data-column-id="gateway" data-type="string">{{ lang._('Gateway') }}</th>
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
                <button class="btn btn-default" id="refreshStatusAct" type="button" onclick="loadStatus()">
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
        {'id': 'rule.gateway', 'label': lang._('Gateway'), 'type': 'dropdown', 'help': lang._('Target gateway for routing')}
    ],
    'id':'DialogRule',
    'label':lang._('Edit Routing Rule')
])}}
