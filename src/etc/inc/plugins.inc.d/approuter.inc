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

use OPNsense\Approuter\Approuter;
use OPNsense\Approuter\MacAliases;
use OPNsense\Approuter\Sources;

/**
 * Register AppRouter firewall rules and pf tables
 */
function approuter_firewall(\OPNsense\Firewall\Plugin $fw)
{
    $mdl = new Approuter();

    if ((string)$mdl->general->enabled !== '1') {
        return;
    }

    $tablePrefix = (string)$mdl->general->tablePrefix ?: 'approuter';
    $clientsDir = '/usr/local/etc/app-router/clients';
    if (!is_dir($clientsDir)) {
        mkdir($clientsDir, 0750, true);
    }

    $rules = [];
    foreach ($mdl->rules->rule->iterateItems() as $uuid => $rule) {
        if ((string)$rule->enabled !== '1') {
            continue;
        }
        $rules[] = [
            'uuid' => $uuid,
            'description' => (string)$rule->description,
            'sourceNets' => (string)$rule->sourceNets,
            'categories' => explode(',', (string)$rule->categories),
            'customDomains' => (string)$rule->customDomains,
            'gateway' => (string)$rule->gateway,
            'interface' => (string)$rule->interface,
        ];
    }

    $valid = approuter_register_rules(
        $fw,
        $rules,
        $tablePrefix,
        $clientsDir,
        approuter_alias_names(),
        MacAliases::ownedNames()
    );
    approuter_cleanup_orphan_tables($tablePrefix, $valid);
}

/**
 * Names of firewall aliases that resolve to addresses (every type but "port").
 * Core keeps each of them in a pf table of the same name; MAC aliases are
 * filled with the IPs currently seen for those MACs (ARP/NDP).
 * Returns null when the Alias model can't be read: names are then accepted
 * on syntax only (an unknown table in a rule is simply empty in pf).
 */
function approuter_alias_names()
{
    try {
        $names = [];
        foreach ((new \OPNsense\Firewall\Alias())->aliases->alias->iterateItems() as $alias) {
            if ((string)$alias->type !== 'port') {
                $names[] = (string)$alias->name;
            }
        }
        return $names;
    } catch (\Throwable $e) {
        syslog(LOG_WARNING, 'approuter: cannot read firewall aliases: ' . $e->getMessage());
        return null;
    }
}

/**
 * IP address or CIDR (v4 or v6)?
 */
function approuter_is_net($entry)
{
    return Sources::isNet($entry);
}

/**
 * Split a rule's source list into "any", plain IPs/CIDRs, alias names and
 * device MACs ("mac:aa:bb:cc:dd:ee:ff" or a raw MAC, normalised).
 * @param string $sourceNets comma separated source list
 * @param array|null $aliasNames known address aliases (null = don't check existence)
 * @return array ['any' => bool, 'nets' => [], 'aliases' => [], 'macs' => [], 'invalid' => []]
 */
function approuter_parse_sources($sourceNets, $aliasNames = null)
{
    $result = ['any' => false, 'nets' => [], 'aliases' => [], 'macs' => [], 'invalid' => []];
    foreach (explode(',', (string)$sourceNets) as $entry) {
        $entry = trim($entry);
        if ($entry === '') {
            continue;
        }
        $mac = Sources::normalizeMac($entry);
        if (strtolower($entry) === 'any') {
            $result['any'] = true;
        } elseif ($mac !== null) {
            if (!in_array($mac, $result['macs'], true)) {
                $result['macs'][] = $mac;
            }
        } elseif (approuter_is_net($entry)) {
            if (!in_array($entry, $result['nets'], true)) {
                $result['nets'][] = $entry;
            }
        } elseif (
            preg_match('/^[A-Za-z0-9_]{1,32}$/', $entry) &&
            ($aliasNames === null || in_array($entry, $aliasNames, true))
        ) {
            if (!in_array($entry, $result['aliases'], true)) {
                $result['aliases'][] = $entry;
            }
        } else {
            $result['invalid'][] = $entry;
        }
    }
    return $result;
}

/**
 * Register one App Router rule: pass with route-to the rule's gateway, then
 * the same match as block. The exit is the point of the rule, so traffic must
 * never leave by another way when it is gone:
 * - skip_rules_gw_down drops the pass rule when core has no usable gateway of
 *   that name (gateway disabled or deleted, its interface gone, every member
 *   of a gateway group down); without it core would emit the rule without
 *   route-to and the traffic would leave by the default route.
 * - the block right behind it then catches that traffic. While the pass rule
 *   is there (quick) the block is never reached.
 * A single gateway that is only marked down keeps its route-to (core leaves
 * it in place), so its traffic goes nowhere either way.
 */
function approuter_register_route($fw, $priority, array $conf, array $defaults)
{
    $fw->registerFilterRule($priority, $conf + ['skip_rules_gw_down' => true], $defaults);
    $rule = $conf;
    unset($rule['gateway']);
    $rule['type'] = 'block';
    $rule['descr'] = $conf['descr'] . ' (blocked while the exit is down)';
    $rule['#ref'] = $conf['#ref'] . ':block';
    $fw->registerFilterRule($priority, $rule, $defaults);
}

/**
 * Register tables and route-to rules for the given (enabled) rules.
 * Plain IPs/CIDRs of a rule go into a file-backed <prefix>_clients_<hash>
 * table; alias sources are referenced directly as <alias> so pf follows the
 * alias contents (e.g. MAC aliases re-resolved via ARP) without a reload.
 * Device (MAC) sources use the rule's App Router managed MAC alias
 * (Sources::macAliasName(), kept in sync by MacAliases::sync()).
 * @param array|null $ownedMacAliases managed alias names that exist (null = don't check)
 * @return array valid client files/tables and custom tables
 */
function approuter_register_rules($fw, array $rules, $tablePrefix, $clientsDir, $aliasNames = null, $ownedMacAliases = null)
{
    $categoriesNeeded = [];
    foreach ($rules as $rule) {
        foreach ($rule['categories'] as $cat) {
            $cat = trim($cat);
            if (!empty($cat)) {
                $categoriesNeeded[$cat] = true;
            }
        }
    }

    // Register pf tables for each needed category (supports dotted notation: "video.bilibili")
    foreach (array_keys($categoriesNeeded) as $category) {
        // Convert dots to underscores for pf table name
        $tableName = $tablePrefix . '_' . str_replace('.', '_', $category);
        // Contents come from `pfctl -T replace` (table_manager.sh / Apply) and
        // dns_watcher; a `file` clause would reset learned IPs on every filter
        // reload, so declare the table persistent without a file.
        $fw->registerTable($tableName, true);
    }

    // Track valid client files/tables and custom table names for orphan cleanup
    $validClientFiles = [];
    $validClientTables = [];
    $validCustomTables = [];

    // Defaults required by OPNsense's FilterRule compiler (type, ipprotocol, etc.)
    $filterDefaults = [
        'type' => 'pass',
        'quick' => true,
        'ipprotocol' => 'inet',
        'statetype' => 'keep',
    ];

    // Generate pf filter rules
    $priority = 1;
    foreach ($rules as $rule) {
        $label = $rule['description'] ?: $rule['uuid'];
        $sources = approuter_parse_sources($rule['sourceNets'], $aliasNames);
        foreach ($sources['invalid'] as $bad) {
            syslog(LOG_WARNING, "approuter: rule '{$label}': source '{$bad}' is not an IP/subnet or address alias, ignored");
        }

        $sourceAliases = $sources['aliases'];
        if (!empty($sources['macs'])) {
            $macAlias = Sources::macAliasName($rule['uuid']);
            if ($ownedMacAliases === null || in_array($macAlias, $ownedMacAliases, true)) {
                $sourceAliases[] = $macAlias;
            } else {
                syslog(LOG_WARNING, "approuter: rule '{$label}': device alias {$macAlias} missing, devices ignored (save the rule or Apply)");
            }
        }

        $fromClause = 'any';
        if (!$sources['any']) {
            $clientTableName = $tablePrefix . '_clients_' . substr(md5($rule['uuid']), 0, 8);
            $froms = [];
            if (!empty($sources['nets'])) {
                $clientFile = $clientsDir . '/' . $clientTableName . '.txt';
                $written = file_put_contents($clientFile, implode("\n", $sources['nets']) . "\n");
                if ($written === false) {
                    syslog(LOG_ERR, "approuter: failed to write client file $clientFile");
                }
                // core signature is registerTable($name, $persist, $file)
                $fw->registerTable($clientTableName, true, $clientFile);
                $validClientFiles[] = $clientTableName . '.txt';
                $validClientTables[] = $clientTableName;
                $froms[] = '<' . $clientTableName . '>';
            }
            if (!empty($sourceAliases)) {
                // alias names for dns_watcher (state kills); pf reads the alias tables itself
                $aliasFile = $clientsDir . '/' . $clientTableName . '.aliases';
                if (file_put_contents($aliasFile, implode("\n", $sourceAliases) . "\n") === false) {
                    syslog(LOG_ERR, "approuter: failed to write alias file $aliasFile");
                }
                $validClientFiles[] = $clientTableName . '.aliases';
                foreach ($sourceAliases as $alias) {
                    $froms[] = '<' . $alias . '>';
                }
            }
            if (empty($froms)) {
                // never fall back to "any" for a rule whose sources are all invalid
                syslog(LOG_WARNING, "approuter: rule '{$label}' has no valid source, skipped");
                continue;
            }
            // core expands a comma separated "from" into one pf rule per source
            $fromClause = implode(',', $froms);
        }

        // a rule has one gateway; older configs could list several: use the first
        $gateways = array_values(array_filter(array_map('trim', explode(',', $rule['gateway']))));
        if (empty($gateways)) {
            continue;
        }
        $gateway = $gateways[0];

        // Register custom domains table if rule has customDomains
        if (!empty($rule['customDomains'])) {
            $customTableName = $tablePrefix . '_custom_' . substr(md5($rule['uuid']), 0, 8);
            $fw->registerTable($customTableName, true);
            $validCustomTables[] = $customTableName;

            $description = 'AppRouter: ' . ($rule['description'] ?: 'custom domains') . ' via ' . $gateway;
            approuter_register_route(
                $fw,
                $priority,
                [
                    'from' => $fromClause,
                    'to' => '<' . $customTableName . '>',
                    'gateway' => $gateway,
                    'direction' => 'in',
                    'interface' => $rule['interface'],
                    'descr' => $description,
                    '#ref' => 'approuter:' . $rule['uuid'] . ':custom',
                ],
                $filterDefaults
            );
            $priority++;
        }

        foreach ($rule['categories'] as $category) {
            $category = trim($category);
            if (empty($category)) {
                continue;
            }

            $tableName = $tablePrefix . '_' . str_replace('.', '_', $category);

            $description = 'AppRouter: ' . ($rule['description'] ?: $category) . ' via ' . $gateway;
            approuter_register_route(
                $fw,
                $priority,
                [
                    'from' => $fromClause,
                    'to' => '<' . $tableName . '>',
                    'gateway' => $gateway,
                    'direction' => 'in',
                    'interface' => $rule['interface'],
                    'descr' => $description,
                    '#ref' => 'approuter:' . $rule['uuid'],
                ],
                $filterDefaults
            );
            $priority++;
        }
    }

    // Clean up orphaned client table / alias files from deleted rules
    $clientFiles = array_merge(
        glob($clientsDir . '/' . $tablePrefix . '_clients_*.txt') ?: [],
        glob($clientsDir . '/' . $tablePrefix . '_clients_*.aliases') ?: []
    );
    foreach ($clientFiles as $file) {
        if (!in_array(basename($file), $validClientFiles)) {
            @unlink($file);
        }
    }

    return [
        'clientFiles' => $validClientFiles,
        'clientTables' => $validClientTables,
        'customTables' => $validCustomTables,
    ];
}

/**
 * pf tables App Router no longer uses: client and custom tables of deleted
 * rules, and every <prefix>_..._gwN table (left over from the removed Smart
 * Gateway feature). Only tables with App Router's own prefix are considered.
 */
function approuter_orphan_tables($tablePrefix, array $valid, array $pfTables)
{
    $own = '/^' . preg_quote($tablePrefix . '_', '/');
    $orphans = [];
    foreach ($pfTables as $t) {
        $t = trim($t);
        if (preg_match($own . '[a-z0-9_]+_gw\d+$/', $t)
            || (preg_match($own . 'custom_[0-9a-f]{8}$/', $t) && !in_array($t, $valid['customTables'], true))
            || (preg_match($own . 'clients_[0-9a-f]{8}$/', $t) && !in_array($t, $valid['clientTables'], true))) {
            $orphans[] = $t;
        }
    }
    return $orphans;
}

/**
 * Remove the pf tables approuter_orphan_tables() finds.
 */
function approuter_cleanup_orphan_tables($tablePrefix, array $valid)
{
    $pfTables = [];
    exec('/sbin/pfctl -s Tables 2>/dev/null', $pfTables);
    foreach (approuter_orphan_tables($tablePrefix, $valid, $pfTables) as $t) {
        exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T flush 2>/dev/null');
        exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T kill 2>/dev/null');
        syslog(LOG_NOTICE, "approuter: removed orphaned table $t");
    }
}

/**
 * Register AppRouter services
 */
function approuter_services()
{
    $services = [];
    $mdl = new Approuter();

    if ((string)$mdl->general->enabled === '1') {
        $services[] = [
            'description' => gettext('AppRouter DNS Watcher'),
            'configd' => [
                'restart' => ['approuter dns_watcher_start'],
                'start' => ['approuter dns_watcher_start'],
                'stop' => ['approuter dns_watcher_stop'],
            ],
            'name' => 'approuter_dns_watcher',
            'pidfile' => '/var/run/approuter_dns_watcher.pid',
        ];

    }

    return $services;
}

/**
 * Boot: pf comes up with empty category tables and nothing else starts the
 * DNS watcher, so routing by domain would stay off until someone pressed
 * Apply (or a health job repaired it). Start the plugin's services here and
 * merge the static lists back in; the watcher re-adds the IPs it learned
 * before the reboot (ip_seen.json). Runs after the filter and DNS are up.
 */
function approuter_configure()
{
    return [
        'bootup' => ['approuter_boot:20'],
    ];
}

function approuter_boot($verbose = false)
{
    $services = approuter_services();   /* empty unless App Router is enabled */
    if (empty($services)) {
        return;
    }
    service_log('Starting App Router...', $verbose);
    /* large lists: merge in the background, do not hold up the boot */
    configd_run('approuter reload_tables', true);
    foreach ($services as $service) {
        foreach ($service['configd']['start'] ?? [] as $cmd) {
            configd_run($cmd);
        }
    }
    service_log("done.\n", $verbose);
}

/**
 * Register syslog targets
 */
function approuter_syslog()
{
    $logfacilities = [];
    $logfacilities['approuter'] = [
        'facility' => ['approuter', 'approuter-dns'],
    ];
    return $logfacilities;
}

/**
 * Register cron jobs for list updates
 */
function approuter_cron()
{
    $jobs = [];
    $mdl = new Approuter();

    if ((string)$mdl->general->enabled === '1') {
        $interval = (string)$mdl->general->updateInterval ?: 'daily';

        $cmd = '/usr/local/opnsense/scripts/OPNsense/Approuter/list_updater.py update';

        switch ($interval) {
            case 'hourly':
                $jobs[] = [
                    'description' => 'AppRouter list update',
                    'autocron' => [$cmd, '15'],
                ];
                break;
            case 'weekly':
                $jobs[] = [
                    'description' => 'AppRouter list update',
                    'autocron' => [$cmd, '30', '3', '*', '*', '1'],
                ];
                break;
            default:
                $jobs[] = [
                    'description' => 'AppRouter list update',
                    'autocron' => [$cmd, '30', '3'],
                ];
                break;
        }
        // daily leak check (read-only: pf states vs. rules); the result feeds
        // "Last leak check" in configctl approuter healthcheck
        $jobs[] = [
            'description' => 'AppRouter leak check',
            'autocron' => ['/usr/local/opnsense/scripts/OPNsense/Approuter/leak_check.py > /dev/null', '45', '4'],
        ];
    }

    return $jobs;
}
