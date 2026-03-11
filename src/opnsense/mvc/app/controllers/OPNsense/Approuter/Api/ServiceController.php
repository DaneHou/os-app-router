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

            $backend->configdRun('filter reload');

            // Explicitly load client tables from files (OPNsense registerTable
            // creates persist tables but doesn't always load file contents)
            $clientsDir = '/usr/local/etc/app-router/clients';
            if (is_dir($clientsDir)) {
                foreach (glob($clientsDir . '/*.txt') as $clientFile) {
                    $tableName = basename($clientFile, '.txt');
                    exec("/sbin/pfctl -t " . escapeshellarg($tableName) . " -T replace -f " . escapeshellarg($clientFile));
                }
            }

            // Restart dns_watcher: stop first to clear stale PID, then start fresh.
            // After start, signal SIGHUP to reload domain mappings immediately.
            $backend->configdRun('approuter dns_watcher_stop');
            $backend->configdRun('approuter dns_watcher_start');
            $backend->configdRun('approuter dns_watcher_reload');

            // Trigger list update in background (non-blocking) if lists don't exist yet
            if (!file_exists('/usr/local/etc/app-router/cidrs/china_all.txt')) {
                $backend->configdpRun('approuter update_lists');
            }

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
