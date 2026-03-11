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
            // Auto-update lists if they don't exist yet
            if (!file_exists('/usr/local/etc/app-router/cidrs/china_all.txt')) {
                $backend->configdRun('approuter update_lists');
            }

            // Reload Unbound if in unbound mode (picks up log-replies config)
            $mdl = new Approuter();
            if ((string)$mdl->general->dnsResolver === 'unbound') {
                $backend->configdRun('dns reload');
            }

            $backend->configdRun('filter reload');

            // Always start dns_watcher (warmup_tables works in both DNS modes)
            $backend->configdRun('approuter dns_watcher_start');

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
            $backend->configdRun('approuter update_lists');
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
            $backend->configdRun('approuter force_update');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function statusAction()
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

        // pf table stats — count entries in each approuter table
        $tablePrefix = (string)$mdl->general->tablePrefix ?: 'approuter';
        $tables = [];
        exec("/sbin/pfctl -s Tables 2>/dev/null", $tableLines);
        foreach ($tableLines as $line) {
            $tbl = trim($line);
            if (strpos($tbl, $tablePrefix . '_') === 0) {
                $count = 0;
                exec("/sbin/pfctl -t " . escapeshellarg($tbl) . " -T show 2>/dev/null", $entries);
                $count = count(array_filter($entries, function ($e) {
                    return trim($e) !== '';
                }));
                $tables[$tbl] = $count;
                unset($entries);
            }
        }
        $data['pf_tables'] = $tables;

        // Rule match stats — how many packets/bytes each approuter rule has matched
        $ruleStats = [];
        exec("/sbin/pfctl -s rules -v 2>/dev/null", $ruleLines);
        $currentRule = '';
        foreach ($ruleLines as $line) {
            if (strpos($line, 'approuter') !== false && strpos($line, 'route-to') !== false) {
                $currentRule = trim($line);
            } elseif (!empty($currentRule) && preg_match('/\[\s*Evaluations:\s*(\d+)\s*Packets:\s*(\d+)\s*Bytes:\s*(\d+)/', $line, $m)) {
                $ruleStats[] = [
                    'rule' => $currentRule,
                    'evaluations' => (int)$m[1],
                    'packets' => (int)$m[2],
                    'bytes' => (int)$m[3],
                ];
                $currentRule = '';
            }
        }
        $data['rule_stats'] = $ruleStats;

        // Recent dns_watcher log entries
        $logs = [];
        exec("grep -i 'approuter' /var/log/system.log 2>/dev/null | tail -30", $logLines);
        foreach ($logLines as $line) {
            $logs[] = $line;
        }
        $data['recent_logs'] = $logs;

        return ['status' => 'ok', 'data' => $data];
    }
}
