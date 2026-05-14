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

        // Toggle fields when dialog opens (sortable built after data loads)
        $(document).on("shown.bs.modal", "#DialogRule", function() {
            toggleSmartGatewayFields();
        });

        // After getRule loads data, refresh selectpicker and build priority panel
        var _gwOrder = "";
        $(document).ajaxComplete(function(event, xhr, settings) {
            if (settings.url && settings.url.indexOf('/api/approuter/settings/getRule') === 0) {
                try {
                    var d = JSON.parse(xhr.responseText);
                    _gwOrder = (d && d.rule && d.rule.gateway_order) ? d.rule.gateway_order : "";
                } catch(e) { _gwOrder = ""; }
                setTimeout(function() {
                    if ($("#DialogRule").is(":visible")) {
                        $("#rule\\.gateway").selectpicker('refresh');
                        toggleSmartGatewayFields();
                        buildGwPriority();
                    }
                }, 300);
            }
        });

        // When user changes gateway selection, rebuild priority panel
        $(document).on("change", "#rule\\.gateway", function() {
            buildGwPriority();
        });

        function buildGwPriority() {
            var $select = $("#rule\\.gateway");
            if ($select.length === 0) return;

            // Remove old panel
            $("#gwPriorityPanel").remove();

            // Get selected values
            var selected = $select.val() || [];
            if (selected.length < 2) return; // No ordering needed for 0-1 gateways

            // Restore saved order: reorder selected to match _gwOrder
            if (_gwOrder) {
                var orderArr = _gwOrder.split(",").map(function(s){return s.trim();}).filter(Boolean);
                var ordered = [];
                orderArr.forEach(function(v) {
                    if (selected.indexOf(v) >= 0) ordered.push(v);
                });
                // Add any selected not in saved order
                selected.forEach(function(v) {
                    if (ordered.indexOf(v) < 0) ordered.push(v);
                });
                selected = ordered;
            }

            // Get labels from select options
            var labelMap = {};
            $select.find("option").each(function() {
                labelMap[$(this).val()] = $(this).text();
            });

            // Build panel HTML
            var html = '<div id="gwPriorityPanel" style="margin-top:8px;padding:8px;border:1px solid #ddd;border-radius:4px;background:#fafafa">';
            html += '<small style="color:#888"><i class="fa fa-sort"></i> {{ lang._("Priority Order") }} ({{ lang._("first = highest") }}):</small>';
            html += '<table style="width:100%;margin-top:4px">';
            for (var i = 0; i < selected.length; i++) {
                var v = selected[i];
                var lbl = $('<span>').text(labelMap[v] || v).html();
                var isFallback = (i === selected.length - 1);
                var badge = isFallback ? '<span class="label label-default" style="margin-left:6px">fallback</span>' : '';
                html += '<tr data-gw="' + v + '">';
                html += '<td style="width:30px;font-weight:bold;color:#337ab7">' + (i+1) + '.</td>';
                html += '<td>' + lbl + badge + '</td>';
                html += '<td style="width:60px;text-align:right">';
                if (i > 0) {
                    html += '<button type="button" class="btn btn-xs btn-default gw-mv-up" title="Move up"><i class="fa fa-arrow-up"></i></button> ';
                }
                if (i < selected.length - 1) {
                    html += '<button type="button" class="btn btn-xs btn-default gw-mv-down" title="Move down"><i class="fa fa-arrow-down"></i></button>';
                }
                html += '</td></tr>';
            }
            html += '</table></div>';

            // Insert after the bootstrap-select container
            $select.closest(".form-group, div").find(".bootstrap-select").first().after(html);
            // Fallback: if bootstrap-select not found, append to select's parent
            if ($("#gwPriorityPanel").length === 0) {
                $select.parent().append(html);
            }

            // Button handlers
            $("#gwPriorityPanel").on("click", ".gw-mv-up", function(e) {
                e.preventDefault();
                var $tr = $(this).closest("tr");
                $tr.prev("tr").before($tr);
                syncGwOrder();
            });
            $("#gwPriorityPanel").on("click", ".gw-mv-down", function(e) {
                e.preventDefault();
                var $tr = $(this).closest("tr");
                $tr.next("tr").after($tr);
                syncGwOrder();
            });
        }

        function syncGwOrder() {
            var $select = $("#rule\\.gateway");
            var newOrder = [];
            $("#gwPriorityPanel tr[data-gw]").each(function() {
                newOrder.push($(this).data("gw"));
            });
            // Reorder <option> DOM so OPNsense serializes CSV in this order
            var $opts = $select.find("option").detach();
            var optMap = {};
            $opts.each(function() { optMap[$(this).val()] = $(this); });
            // Selected in priority order first
            newOrder.forEach(function(v) {
                if (optMap[v]) { $select.append(optMap[v]); delete optMap[v]; }
            });
            // Remaining unselected
            for (var k in optMap) $select.append(optMap[k]);
            // Update saved order for next rebuild
            _gwOrder = newOrder.join(",");
            // Rebuild panel to update numbers and buttons
            buildGwPriority();
        }

        // ── Custom Categories ────────────────────────────────────────────
        var _editCatUuid = null;

        function loadCustomCategories() {
            ajaxGet("/api/approuter/settings/searchCustomCategory", {}, function(data) {
                var $tbody = $("#custom-cat-tbody");
                $tbody.empty();
                if (data && data.rows && data.rows.length) {
                    data.rows.forEach(function(row) {
                        var domParts = (row.domains || "").split(",").filter(Boolean);
                        var domPreview = domParts.slice(0, 3).map(function(d){return d.trim();}).join(", ");
                        if (domParts.length > 3) domPreview += " …+" + (domParts.length - 3);
                        var cidrParts = (row.cidrs || "").split(",").filter(Boolean);
                        var cidrPreview = cidrParts.slice(0, 2).map(function(c){return c.trim();}).join(", ");
                        if (cidrParts.length > 2) cidrPreview += " …+" + (cidrParts.length - 2);
                        var $tr = $("<tr>")
                            .append($("<td>").text(row.slug || ""))
                            .append($("<td>").text(row.label || ""))
                            .append($("<td>").text(domPreview))
                            .append($("<td>").text(cidrPreview))
                            .append($("<td>").html(
                                '<button class="btn btn-xs btn-default btn-edit-cat" data-uuid="' + row.uuid + '" title="{{ lang._("Edit") }}"><i class="fa fa-pencil"></i></button> ' +
                                '<button class="btn btn-xs btn-danger btn-del-cat" data-uuid="' + row.uuid + '" data-slug="' + (row.slug||"") + '" title="{{ lang._("Delete") }}"><i class="fa fa-trash-o"></i></button>'
                            ));
                        $tbody.append($tr);
                    });
                } else {
                    $tbody.append('<tr><td colspan="5" class="text-center text-muted">{{ lang._("No custom categories defined yet.") }}</td></tr>');
                }
            });
        }

        function openCatDialog(uuid) {
            _editCatUuid = uuid || null;
            $("#customcat_uuid").val("");
            $("#customcat_slug").val("").prop("disabled", false);
            $("#customcat_label").val("");
            $("#customcat_domains").val("");
            $("#customcat_cidrs").val("");
            $("#DialogCustomCategory .modal-title").text(uuid ? "{{ lang._('Edit Custom Category') }}" : "{{ lang._('Add Custom Category') }}");

            if (uuid) {
                ajaxGet("/api/approuter/settings/getCustomCategory/" + uuid, {}, function(data) {
                    if (data && data.category) {
                        var c = data.category;
                        $("#customcat_uuid").val(uuid);
                        $("#customcat_slug").val(c.slug || "").prop("disabled", true);
                        $("#customcat_label").val(c.label || "");
                        // Convert comma-separated to one-per-line for textarea
                        $("#customcat_domains").val((c.domains || "").split(",").map(function(d){return d.trim();}).filter(Boolean).join("\n"));
                        $("#customcat_cidrs").val((c.cidrs || "").split(",").map(function(d){return d.trim();}).filter(Boolean).join("\n"));
                    }
                });
            }
            $("#DialogCustomCategory").modal("show");
        }

        $("#addCustomCatBtn").click(function() { openCatDialog(null); });

        $(document).on("click", ".btn-edit-cat", function() {
            openCatDialog($(this).data("uuid"));
        });

        $(document).on("click", ".btn-del-cat", function() {
            var uuid = $(this).data("uuid");
            var slug = $(this).data("slug");
            if (!confirm('{{ lang._("Delete custom category") }} "' + slug + '"?')) return;
            ajaxCall("/api/approuter/settings/delCustomCategory/" + uuid, {}, function(data) {
                loadCustomCategories();
                $("#CustomCatChangeMessage").removeClass("hidden");
            });
        });

        $("#saveCustomCategoryAct").click(function() {
            var uuid = $("#customcat_uuid").val();
            // Normalise textarea values: newlines → comma-separated
            var domains = $("#customcat_domains").val().replace(/\s*[\r\n]+\s*/g, ",").replace(/,+/g, ",").replace(/^,|,$/g, "");
            var cidrs   = $("#customcat_cidrs").val().replace(/\s*[\r\n]+\s*/g, ",").replace(/,+/g, ",").replace(/^,|,$/g, "");
            var payload = {
                category: {
                    slug:    $("#customcat_slug").val().trim(),
                    label:   $("#customcat_label").val().trim(),
                    domains: domains,
                    cidrs:   cidrs
                }
            };
            var url = uuid
                ? "/api/approuter/settings/setCustomCategory/" + uuid
                : "/api/approuter/settings/addCustomCategory";
            ajaxCall(url, payload, function(data) {
                if (data && data.result && data.result !== "failed") {
                    $("#DialogCustomCategory").modal("hide");
                    loadCustomCategories();
                    $("#CustomCatChangeMessage").removeClass("hidden");
                } else {
                    var msg = (data && data.validations) ? JSON.stringify(data.validations) : "{{ lang._('Save failed — check field values.') }}";
                    alert(msg);
                }
            });
        });

        loadCustomCategories();
        // ── End Custom Categories ─────────────────────────────────────────

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
    <li><a data-toggle="tab" href="#categories">{{ lang._('Custom Categories') }}</a></li>
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

    <div id="categories" class="tab-pane fade in">
        <div class="content-box" style="padding-bottom: 1.5em;">
            <div class="col-md-12" style="padding-top: 1em;">
                <p class="text-muted">
                    {{ lang._('Define your own routing categories with custom domains and CIDRs. Each category appears in the Routing Rules editor alongside built-in categories.') }}
                    {{ lang._('Domains match all subdomains automatically (e.g. "amazonaws-us-gov.com" catches s3.us-gov-west-1.amazonaws-us-gov.com).') }}
                </p>
            </div>
            <table class="table table-condensed table-hover table-striped">
                <thead>
                    <tr>
                        <th style="width:140px">{{ lang._('Slug (ID)') }}</th>
                        <th>{{ lang._('Label') }}</th>
                        <th>{{ lang._('Domains') }}</th>
                        <th style="width:180px">{{ lang._('Static CIDRs') }}</th>
                        <th style="width:80px">{{ lang._('Actions') }}</th>
                    </tr>
                </thead>
                <tbody id="custom-cat-tbody">
                </tbody>
            </table>
            <div class="col-md-12">
                <div id="CustomCatChangeMessage" class="alert alert-info hidden" role="alert">
                    {{ lang._('Category saved. Click Apply on the Routing Rules tab to activate changes.') }}
                </div>
                <hr />
                <button class="btn btn-primary" id="addCustomCatBtn" type="button">
                    <i class="fa fa-plus"></i> {{ lang._('Add Category') }}
                </button>
            </div>
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

<!-- Custom Category Dialog -->
<div class="modal fade" id="DialogCustomCategory" tabindex="-1" role="dialog">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title">{{ lang._('Add Custom Category') }}</h4>
            </div>
            <div class="modal-body">
                <input type="hidden" id="customcat_uuid">
                <div class="form-group">
                    <label>{{ lang._('Slug') }} <span class="text-danger">*</span></label>
                    <input type="text" id="customcat_slug" class="form-control" placeholder="e.g. ba_work">
                    <span class="help-block">{{ lang._('Lowercase letters, numbers, underscores. Used as pf table suffix. Cannot be changed after creation.') }}</span>
                </div>
                <div class="form-group">
                    <label>{{ lang._('Label') }} <span class="text-danger">*</span></label>
                    <input type="text" id="customcat_label" class="form-control" placeholder="e.g. BA Work Traffic">
                </div>
                <div class="form-group">
                    <label>{{ lang._('Domains') }}</label>
                    <textarea id="customcat_domains" class="form-control" rows="7"
                        placeholder="One per line — subdomains matched automatically&#10;e.g.&#10;amazonaws-us-gov.com&#10;benchmarkanalytics.atlassian.net&#10;benchmarkonline.app"></textarea>
                    <span class="help-block">{{ lang._('Do not prefix with *.  All subdomains are caught automatically.') }}</span>
                </div>
                <div class="form-group">
                    <label>{{ lang._('Static CIDRs') }}</label>
                    <textarea id="customcat_cidrs" class="form-control" rows="4"
                        placeholder="One per line&#10;e.g.&#10;203.0.113.0/24&#10;198.51.100.5"></textarea>
                    <span class="help-block">{{ lang._('Optional fixed IP/subnet entries added to the pf table immediately (no DNS needed).') }}</span>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
                <button type="button" class="btn btn-primary" id="saveCustomCategoryAct">{{ lang._('Save') }}</button>
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
        {'id': 'rule.probeUrl', 'label': lang._('Probe URL'), 'type': 'text', 'help': lang._('URL to test through each gateway. Leave empty to use https://www.google.com. Examples: https://www.iqiyi.com/ (video), https://music.163.com/ (music)')},
        {'id': 'rule.probeInterval', 'label': lang._('Probe Interval'), 'type': 'text', 'help': lang._('Seconds between probes (30-3600, default 300). Lower = faster failover but more traffic')},
        {'id': 'rule.probeMethod', 'label': lang._('Probe Method'), 'type': 'dropdown', 'help': lang._('Connect: TCP reachability. Status Code: HTTP 403/451 = blocked. Body Match: regex on response body. Latency: pick fastest gateway')},
        {'id': 'rule.probePattern', 'label': lang._('Probe Pattern'), 'type': 'text', 'help': lang._('Regex to detect geo-restriction in response body. Match = blocked. Example: 地区限制|not available|geo.restricted')}
    ],
    'id':'DialogRule',
    'label':lang._('Edit Routing Rule')
])}}
