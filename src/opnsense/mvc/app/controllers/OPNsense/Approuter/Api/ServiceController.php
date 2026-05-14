<?php

/**
 *    Copyright (C) 2024 os-app-router contributors
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Approuter\Api;

use OPNsense\Approuter\Approuter;
use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Approuter\Approuter';
    protected static $internalServiceTemplate = 'OPNsense/Approuter';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'approuter';

    public function reconfigureAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            session_write_close();
            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/Approuter');
            $backend->configdRun('approuter generate_dns');

            // Restart dns_watcher early (before filter reload which can be slow
            // and cause PHP timeout). dns_watcher loads mappings at startup.
            $backend->configdRun('approuter dns_watcher_stop');
            $backend->configdRun('approuter dns_watcher_start');

            // Stop geo_prober before filter reload (will restart after if needed)
            $backend->configdRun('approuter geo_prober_stop');

            // filter reload can be slow — run async to avoid PHP timeout
            $backend->configdpRun('filter reload');

            // Explicitly load client tables from files (OPNsense registerTable
            // creates persist tables but doesn't always load file contents).
            // Small delay to let async filter reload register the tables.
            sleep(2);
            $clientsDir = '/usr/local/etc/app-router/clients';
            if (is_dir($clientsDir)) {
                foreach (glob($clientsDir . '/*.txt') as $clientFile) {
                    $tableName = basename($clientFile, '.txt');
                    exec("/sbin/pfctl -t " . escapeshellarg($tableName) . " -T replace -f " . escapeshellarg($clientFile));
                }
            }

            // Trigger list update in background (non-blocking) if lists don't exist yet
            if (!file_exists('/usr/local/etc/app-router/cidrs/china_all.txt')) {
                $backend->configdpRun('approuter update_lists');
            }

            // Start geo_prober if any smart gateway rules exist
            $mdl = new Approuter();
            $hasSmartRules = false;
            foreach ($mdl->rules->rule->iterateItems() as $uuid => $rule) {
                if ((string)$rule->enabled === '1' && (string)$rule->smartGateway === '1') {
                    $gateways = array_filter(array_map('trim', explode(',', (string)$rule->gateway)));
                    if (count($gateways) > 1) {
                        $hasSmartRules = true;
                        break;
                    }
                }
            }
            if ($hasSmartRules) {
                $backend->configdRun('approuter geo_prober_start');
            }

            // Reload dns_watcher domain mappings now that pf tables are registered.
            // dns_watcher started earlier (before filter reload), so its initial
            // resolution ran before the tables existed. SIGHUP triggers a fresh
            // load_domain_mappings + resolve_and_update with tables now in place.
            $backend->configdRun('approuter dns_watcher_reload');

            $status = "ok";
        }
        return ['status' => $status];
    }

    public function updateListsAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            session_write_close();
            $backend = new Backend();
            $backend->configdpRun('approuter update_lists');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function forceUpdateAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            session_write_close();
            $backend = new Backend();
            $backend->configdpRun('approuter force_update');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function statusAction()
    {
        $backend = new Backend();
        $watcherResponse = trim($backend->configdRun('approuter dns_watcher_status'));
        $watcherData = json_decode($watcherResponse, true);
        $running = is_array($watcherData) && !empty($watcherData['running']);
        return [
            'status' => $running ? 'running' : 'stopped',
            'widget' => [
                'caption_restart' => gettext('Restart'),
                'caption_start' => gettext('Start'),
                'caption_stop' => gettext('Stop'),
            ],
        ];
    }

    public function startAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('approuter dns_watcher_start');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function stopAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('approuter dns_watcher_stop');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function restartAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('approuter dns_watcher_stop');
            $backend->configdRun('approuter dns_watcher_start');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function detailStatusAction()
    {
        $backend = new Backend();

        // Basic status from list_updater
        $response = trim($backend->configdRun('approuter status'));
        $data = json_decode($response, true) ?: [];

        // DNS watcher status
        $watcherResponse = trim($backend->configdRun('approuter dns_watcher_status'));
        $watcherData = json_decode($watcherResponse, true);
        $data['dns_watcher'] = $watcherData ?: ['running' => false];

        // DNS resolver mode
        $mdl = new Approuter();
        $data['dns_resolver'] = (string)$mdl->general->dnsResolver ?: 'dnsmasq';
        $data['enabled'] = (string)$mdl->general->enabled;

        // Build rule description lookup: hash(uuid) => description
        $ruleDescriptions = [];
        $tablePrefix = (string)$mdl->general->tablePrefix ?: 'approuter';
        foreach ($mdl->rules->rule->iterateItems() as $uuid => $rule) {
            $hash = substr(md5($uuid), 0, 8);
            $ruleDescriptions[$hash] = (string)$rule->description ?: 'Rule ' . $hash;
        }

        // pf table stats — count entries in each approuter table, hide clients_* tables
        $tables = [];
        $tableLines = [];
        exec("/sbin/pfctl -s Tables 2>/dev/null", $tableLines);
        foreach ($tableLines as $line) {
            $tbl = trim($line);
            if (strpos($tbl, $tablePrefix . '_') === 0 && strpos($tbl, $tablePrefix . '_clients_') !== 0) {
                $count = 0;
                $entries = [];
                exec("/sbin/pfctl -t " . escapeshellarg($tbl) . " -T show 2>/dev/null", $entries);
                $count = count(array_filter($entries, function ($e) {
                    return trim($e) !== '';
                }));
                $tables[$tbl] = $count;
            }
        }
        $data['pf_tables'] = $tables;

        // Rule match stats with human-readable descriptions
        $ruleStats = [];
        $ruleLines = [];
        exec("/sbin/pfctl -s rules -v 2>/dev/null", $ruleLines);
        $currentRule = '';
        foreach ($ruleLines as $line) {
            if (strpos($line, 'approuter') !== false && strpos($line, 'route-to') !== false) {
                $currentRule = trim($line);
            } elseif (!empty($currentRule) && preg_match('/\[\s*Evaluations:\s*(\d+)\s*Packets:\s*(\d+)\s*Bytes:\s*(\d+)/', $line, $m)) {
                // Extract human-readable description from pf rule label
                $description = $currentRule;
                // Try to extract table names and gateway from the rule
                if (preg_match('/route-to\s+\((\S+)\s+([^)]+)\)/', $currentRule, $gm)) {
                    $gwName = $gm[1];
                }
                // Extract destination table name to get category
                $destTable = '';
                if (preg_match('/to\s+<(' . preg_quote($tablePrefix, '/') . '_[^>]+)>/', $currentRule, $dm)) {
                    $destTable = $dm[1];
                }
                // Build readable description: "RuleDesc -> category (gateway)"
                $readable = $destTable;
                // Try to match rule UUID hash from client table or label
                foreach ($ruleDescriptions as $hash => $desc) {
                    if (strpos($currentRule, $hash) !== false) {
                        $readable = $desc;
                        if (!empty($destTable)) {
                            // Strip prefix for cleaner display
                            $shortDest = str_replace($tablePrefix . '_', '', $destTable);
                            $readable .= ' -> ' . $shortDest;
                        }
                        break;
                    }
                }
                if (isset($gwName) && !empty($gwName)) {
                    $readable .= ' via ' . $gwName;
                }

                $ruleStats[] = [
                    'rule' => $readable,
                    'evaluations' => (int)$m[1],
                    'packets' => (int)$m[2],
                    'bytes' => (int)$m[3],
                ];
                $currentRule = '';
                unset($gwName);
            }
        }
        $data['rule_stats'] = $ruleStats;

        // Geo prober status
        $geoProberResponse = trim($backend->configdRun('approuter geo_prober_status'));
        $geoProberData = json_decode($geoProberResponse, true);
        $data['geo_prober'] = $geoProberData ?: ['running' => false];

        // Smart gateway rule details
        $smartGwStatus = [];
        foreach ($mdl->rules->rule->iterateItems() as $uuid => $rule) {
            if ((string)$rule->enabled === '1' && (string)$rule->smartGateway === '1') {
                $gateways = array_filter(array_map('trim', explode(',', (string)$rule->gateway)));
                if (count($gateways) > 1) {
                    $ruleStatus = [
                        'description' => (string)$rule->description ?: 'Rule ' . substr(md5($uuid), 0, 8),
                        'gateways' => $gateways,
                        'probe_method' => (string)$rule->probeMethod ?: 'connect_only',
                        'probe_url' => (string)$rule->probeUrl ?: '',
                        'active_gateway' => end($gateways),  // default: fallback
                    ];

                    // Check which _gwN tables have entries to determine active gateway
                    $categories = array_filter(array_map('trim', explode(',', (string)$rule->categories)));
                    if (!empty($categories)) {
                        $firstCat = $categories[0];
                        $catTable = $tablePrefix . '_' . str_replace('.', '_', $firstCat);
                        for ($i = 0; $i < count($gateways) - 1; $i++) {
                            $gwTable = $catTable . '_gw' . $i;
                            $gwEntries = [];
                            exec("/sbin/pfctl -t " . escapeshellarg($gwTable) . " -T show 2>/dev/null", $gwEntries);
                            $gwCount = count(array_filter($gwEntries, function ($e) {
                                return trim($e) !== '';
                            }));
                            $ruleStatus['gw_tables'][] = [
                                'table' => $gwTable,
                                'entries' => $gwCount,
                                'gateway' => $gateways[$i],
                            ];
                            if ($gwCount > 0) {
                                $ruleStatus['active_gateway'] = $gateways[$i];
                                break;  // Highest priority active gateway wins
                            }
                        }
                    }

                    $smartGwStatus[] = $ruleStatus;
                }
            }
        }
        $data['smart_gateway'] = $smartGwStatus;

        // Recent log entries: syslog + dns_watcher log
        $logs = [];
        $syslogLines = [];
        exec("grep -i 'approuter' /var/log/system/latest.log 2>/dev/null | tail -20", $syslogLines);
        foreach ($syslogLines as $line) {
            $logs[] = $line;
        }
        $snifferLogs = [];
        exec("tail -20 /var/log/approuter_dns_watcher.log 2>/dev/null", $snifferLogs);
        foreach ($snifferLogs as $line) {
            if (!empty(trim($line))) {
                $logs[] = '[sniffer] ' . $line;
            }
        }
        $data['recent_logs'] = $logs;

        return ['status' => 'ok', 'data' => $data];
    }
}
