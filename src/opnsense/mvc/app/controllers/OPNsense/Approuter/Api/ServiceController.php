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
use OPNsense\Approuter\MacAliases;
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
            // Device (MAC) sources: create/update/delete the App Router
            // managed MAC aliases before the filter reload below, which
            // regenerates the alias definitions (template OPNsense/Filter)
            // and runs `filter refresh_aliases` to resolve them via ARP.
            MacAliases::sync();
            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/Approuter');
            $backend->configdRun('approuter generate_dns');

            // Restart dns_watcher early (before filter reload which can be slow
            // and cause PHP timeout). dns_watcher loads mappings at startup.
            $backend->configdRun('approuter dns_watcher_stop');
            $backend->configdRun('approuter dns_watcher_start');

            // Stop geo_prober before filter reload (will restart after if needed).
            // It only runs for Smart Gateway rules with 2+ gateways.
            if (is_file('/var/run/approuter_geo_prober.pid')) {
                $backend->configdRun('approuter geo_prober_stop');
            }

            // Synchronous (configdpRun waits for the reload to finish)
            $backend->configdpRun('filter reload');

            // Explicitly load client tables from files (OPNsense registerTable
            // creates persist tables but doesn't always load file contents).
            // Small delay to let async filter reload register the tables.
            // Only IP/CIDR sources live in these files; alias sources are
            // referenced as <alias> in the rules and kept current by core.
            sleep(2);
            $clientsDir = '/usr/local/etc/app-router/clients';
            $pfTables = [];
            exec('/sbin/pfctl -s Tables 2>/dev/null', $pfTables);
            $pfTables = array_map('trim', $pfTables);
            if (is_dir($clientsDir)) {
                foreach (glob($clientsDir . '/*_clients_*.txt') as $clientFile) {
                    $tableName = basename($clientFile, '.txt');
                    if (!in_array($tableName, $pfTables, true)) {
                        // stale file of a deleted rule: don't recreate its table
                        continue;
                    }
                    $pfOut = [];
                    $pfRet = 0;
                    exec("/sbin/pfctl -t " . escapeshellarg($tableName) . " -T replace -f " . escapeshellarg($clientFile) . " 2>&1", $pfOut, $pfRet);
                    if ($pfRet !== 0) {
                        syslog(LOG_ERR, "approuter: pfctl replace failed for {$tableName}: " . implode(' ', $pfOut));
                    }
                }
            }

            // Trigger list update in background (non-blocking) if lists don't exist yet
            if (!file_exists('/usr/local/etc/app-router/cidrs/china_all.txt')) {
                $backend->configdpRun('approuter update_lists');
            }

            // Merge static CIDR lists (china_all, custom categories) into
            // their category tables. Never `pfctl -T replace` these: that
            // drops every IP dns_watcher learned from DNS answers, and clients
            // keep their DNS cache, so the traffic would leave via the default
            // gateway until the TTL runs out. static_sync.py adds missing
            // static entries and deletes only those removed from the list,
            // and skips tables no rule uses.
            $backend->configdRun('approuter reload_tables');
            $mdl = new Approuter();

            // Start geo_prober if any smart gateway rules exist
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

            // "Resolve DNS via gateway": during the filter reload Unbound's
            // queries to the forward server time out, and it would answer
            // SERVFAIL for the forward zones for about a minute. Clear the
            // failures (infra + zone cache of App Router's zones only) once
            // the route is back. Detached and best effort: never delays or
            // fails Apply; no-op without forward zones.
            $backend->configdRun('approuter unbound_flush', true);

            // AdGuard Home on port 53: keep its upstreams sending the "via gateway"
            // domains to Unbound (no-op when unchanged, AdGuard Home absent or sync off).
            $backend->configdRun('approuter agh_resync', true);

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

    /**
     * Problems with enabled rules that the firewall hook would silently skip.
     * A rule bound to a missing or disabled interface gets no pf rule at all.
     */
    public static function ruleWarnings($mdl)
    {
        $warnings = [];
        $ifaces = \OPNsense\Core\Config::getInstance()->object()->interfaces;
        foreach ($mdl->rules->rule->iterateItems() as $uuid => $rule) {
            if ((string)$rule->enabled !== '1') {
                continue;
            }
            $name = (string)$rule->description ?: $uuid;
            $if = (string)$rule->interface;
            if ($if === '' || !isset($ifaces->$if)) {
                $warnings[] = sprintf(gettext('Rule "%s": interface "%s" does not exist, the rule is not active.'), $name, $if);
            } elseif (empty((string)$ifaces->$if->enable) && $if !== 'lan') {
                $warnings[] = sprintf(gettext('Rule "%s": interface "%s" is disabled, the rule is not active.'), $name, $if);
            }
        }
        // "Resolve DNS via gateway": result of dns_forward.php's check through port 53
        $st = json_decode((string)@file_get_contents('/usr/local/etc/app-router/dns_forward_status.json'), true);
        if (is_array($st) && !empty($st['zones']) && empty($st['reaches_unbound'])) {
            $warnings[] = sprintf(
                gettext('Resolve DNS via gateway: DNS queries on port 53 (answered by %s) do not reach Unbound, so it has no effect. Forward the domains in /usr/local/etc/app-router/dns_via_gateway.txt to Unbound (127.0.0.1:%d) in that DNS server.'),
                $st['port53'] ?: gettext('another DNS server'), (int)($st['unbound_port'] ?? 53)
            );
        }
        return $warnings;
    }

    /**
     * GET /api/approuter/service/leakCheck
     * Connections of rule clients to rule domains that did not go through the rule's gateway.
     */
    public function leakCheckAction()
    {
        $backend = new Backend();
        $result = json_decode(trim($backend->configdRun('approuter leak_check')), true);
        if (!is_array($result)) {
            return ['status' => 'error', 'message' => gettext('Leak check failed')];
        }
        return $result;
    }

    /**
     * Route inspector: GET /api/approuter/service/inspect?action=trace&client=IP&domain=NAME
     * action=connections&client=IP lists a client's live connections, action=clients the rule clients.
     */
    public function inspectAction()
    {
        $action = (string)$this->request->get('action');
        $client = trim((string)$this->request->get('client'));
        $domain = strtolower(trim((string)$this->request->get('domain')));
        $domain = preg_replace('#^[a-z]+://#', '', $domain);
        $domain = explode('/', $domain)[0];
        $domain = explode(':', $domain)[0];
        $backend = new Backend();
        if ($action === 'clients') {
            $out = $backend->configdRun('approuter inspect_clients');
        } else {
            if (!filter_var($client, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return ['status' => 'error', 'message' => gettext('Enter the client\'s IPv4 address')];
            }
            if ($action === 'trace') {
                if (!preg_match('/^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/', $domain)) {
                    return ['status' => 'error', 'message' => gettext('Enter a domain name such as m.iqiyi.com')];
                }
                $out = $backend->configdpRun('approuter inspect_trace', [$client, $domain]);
            } elseif ($action === 'connections') {
                $out = $backend->configdpRun('approuter inspect_connections', [$client]);
            } else {
                return ['status' => 'error', 'message' => 'unknown action'];
            }
        }
        $result = json_decode(trim($out), true);
        return is_array($result) ? $result : ['status' => 'error', 'message' => gettext('Inspection failed')];
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

        $mdl = new Approuter();
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
                $gateways = array_values(array_filter(array_map('trim', explode(',', (string)$rule->gateway))));
                if (count($gateways) > 1) {
                    $ruleStatus = [
                        'description' => (string)$rule->description ?: 'Rule ' . substr(md5($uuid), 0, 8),
                        'gateways' => $gateways,
                        'probe_method' => (string)$rule->probeMethod ?: 'connect_only',
                        'probe_url' => (string)$rule->probeUrl ?: '',
                        'active_gateway' => end($gateways),  // default: fallback
                    ];

                    // Check which _gwN tables have entries to determine active gateway
                    // array_values: array_filter keeps keys, so [0] may not exist
                    $categories = array_values(array_filter(array_map('trim', explode(',', (string)$rule->categories))));
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

        $data['warnings'] = self::ruleWarnings($mdl);
        return ['status' => 'ok', 'data' => $data];
    }
}
