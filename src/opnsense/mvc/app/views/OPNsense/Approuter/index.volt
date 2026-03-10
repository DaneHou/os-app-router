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
        // Cache gateway and category options for dialog population
        var gatewayOptions = [];
        var categoryOptions = [];

        // Fetch gateways
        ajaxGet(url="/api/approuter/settings/getGateways", sendData={}, callback=function(data, status) {
            if (data && data.rows) {
                gatewayOptions = data.rows;
            }
        });

        // Fetch categories
        ajaxGet(url="/api/approuter/settings/getCategories", sendData={}, callback=function(data, status) {
            if (data && data.rows) {
                categoryOptions = data.rows;
            }
        });

        // Populate gateway dropdown and categories tokenizer before dialog opens
        $('#DialogRule').on('opnsense_bootgrid_mapped', function(e) {
            // Populate gateway dropdown
            var $gw = $('#rule\\.gateway');
            var currentVal = $gw.val();
            $gw.empty();
            $gw.append($('<option>').val('').text('--- Select Gateway ---'));
            $.each(gatewayOptions, function(idx, gw) {
                var label = gw.name;
                if (gw.descr) label += ' (' + gw.descr + ')';
                if (gw.gateway && gw.gateway !== 'group') label += ' [' + gw.gateway + ']';
                $gw.append($('<option>').val(gw.name).text(label));
            });
            if (currentVal) {
                $gw.val(currentVal);
            }
            $gw.selectpicker('refresh');

            // Populate categories tokenizer
            var $cat = $('#rule\\.categories');
            var currentCats = $cat.val();
            $cat.empty();
            $.each(categoryOptions, function(idx, opt) {
                $cat.append($('<option>').val(opt.value).text(opt.label));
            });
            if (currentCats) {
                $cat.val(currentCats);
            }
            $cat.selectpicker('refresh');
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
                    var html = '<table class="table table-condensed">';
                    if (info.last_full_update) {
                        var d = new Date(info.last_full_update * 1000);
                        html += '<tr><td>Last Update</td><td>' + d.toLocaleString() + '</td></tr>';
                    }
                    if (info.china_cidrs_count) {
                        html += '<tr><td>China CIDRs</td><td>' + info.china_cidrs_count + '</td></tr>';
                    }
                    if (info.china_domains_count) {
                        html += '<tr><td>China Domains</td><td>' + info.china_domains_count + '</td></tr>';
                    }
                    if (info.categories) {
                        for (var cat in info.categories) {
                            html += '<tr><td>Category: ' + cat + '</td><td>' + info.categories[cat] + ' domains</td></tr>';
                        }
                    }
                    html += '</table>';
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
                    <th data-column-id="sourceNets" data-type="string">{{ lang._('Source Networks') }}</th>
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
            </div>
        </div>
    </div>
</div>

{{ partial("layout_partials/base_dialog",['fields':
    [
        {'id': 'rule.enabled', 'label': lang._('Enabled'), 'type': 'checkbox'},
        {'id': 'rule.description', 'label': lang._('Description'), 'type': 'text'},
        {'id': 'rule.sourceNets', 'label': lang._('Source Networks'), 'type': 'select_multiple', 'help': lang._('Type IP addresses or subnets (e.g. 192.168.1.0/24) and press Enter')},
        {'id': 'rule.categories', 'label': lang._('App Categories'), 'type': 'select_multiple', 'help': lang._('Search and select app categories or individual apps (e.g. type "爱" to find iQIYI)')},
        {'id': 'rule.gateway', 'label': lang._('Gateway'), 'type': 'dropdown', 'help': lang._('Select target gateway for routing')},
        {'id': 'rule.interface', 'label': lang._('Interface'), 'type': 'dropdown', 'help': lang._('Inbound interface (usually LAN)')}
    ],
    'id':'DialogRule',
    'label':lang._('Edit Routing Rule')
])}}
