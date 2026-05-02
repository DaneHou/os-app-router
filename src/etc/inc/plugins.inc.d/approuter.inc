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
    $cidrsDir = '/usr/local/etc/app-router/cidrs';
    $clientsDir = '/usr/local/etc/app-router/clients';
    if (!is_dir($clientsDir)) {
        mkdir($clientsDir, 0750, true);
    }

    $categoriesNeeded = [];
    $rules = [];

    foreach ($mdl->rules->rule->iterateItems() as $uuid => $rule) {
        if ((string)$rule->enabled !== '1') {
            continue;
        }
        $ruleCategories = explode(',', (string)$rule->categories);
        foreach ($ruleCategories as $cat) {
            $cat = trim($cat);
            if (!empty($cat)) {
                $categoriesNeeded[$cat] = true;
            }
        }
        $rules[] = [
            'uuid' => $uuid,
            'description' => (string)$rule->description,
            'sourceNets' => (string)$rule->sourceNets,
            'categories' => $ruleCategories,
            'customDomains' => (string)$rule->customDomains,
            'gateway' => (string)$rule->gateway,
            'interface' => (string)$rule->interface,
            'smartGateway' => (string)$rule->smartGateway,
        ];
    }

    // Collect smart gateway info per category for registering _gwN tables
    $smartGwPerCategory = [];
    foreach ($rules as $rule) {
        $gateways = array_filter(array_map('trim', explode(',', $rule['gateway'])));
        $isSmart = ($rule['smartGateway'] === '1' && count($gateways) > 1);
        if ($isSmart) {
            foreach ($rule['categories'] as $cat) {
                $cat = trim($cat);
                if (!empty($cat)) {
                    $smartGwPerCategory[$cat] = count($gateways);
                }
            }
        }
    }

    // Register pf tables for each needed category (supports dotted notation: "video.bilibili")
    foreach (array_keys($categoriesNeeded) as $category) {
        // Convert dots to underscores for pf table name
        $tableName = $tablePrefix . '_' . str_replace('.', '_', $category);
        // Try dotted filename first (e.g. video.bilibili.txt), then underscored
        $cidrFile = $cidrsDir . '/' . $category . '.txt';
        if (!file_exists($cidrFile)) {
            $cidrFile = $cidrsDir . '/' . str_replace('.', '_', $category) . '.txt';
        }

        if (file_exists($cidrFile)) {
            $fw->registerTable($tableName, [
                'file' => $cidrFile,
                'persist' => true,
            ]);
        } else {
            $fw->registerTable($tableName, [
                'persist' => true,
            ]);
        }

        // Register _gwN tables for smart gateway categories
        if (isset($smartGwPerCategory[$category])) {
            $gwCount = $smartGwPerCategory[$category];
            // Register _gw0 through _gw(N-2) (last gateway uses main table)
            for ($i = 0; $i < $gwCount - 1; $i++) {
                $gwTableName = $tableName . '_gw' . $i;
                $fw->registerTable($gwTableName, [
                    'persist' => true,
                ]);
            }
        }
    }

    // Track valid client file basenames and custom table names for orphan cleanup
    $validClientFiles = [];
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
        $sourceNets = array_filter(array_map('trim', explode(',', $rule['sourceNets'])));
        if (empty($sourceNets)) {
            continue;
        }

        // Check if source is "any"
        $isAny = (count($sourceNets) === 1 && strtolower($sourceNets[0]) === 'any');

        $fromClause = 'any';
        if (!$isAny) {
            $clientTableName = $tablePrefix . '_clients_' . substr(md5($rule['uuid']), 0, 8);
            $clientFile = $clientsDir . '/' . $clientTableName . '.txt';
            $written = file_put_contents($clientFile, implode("\n", $sourceNets) . "\n");
            if ($written === false) {
                syslog(LOG_ERR, "approuter: failed to write client file $clientFile");
            }
            $fw->registerTable($clientTableName, [
                'file' => $clientFile,
                'persist' => true,
            ]);
            $validClientFiles[] = $clientTableName . '.txt';
            $fromClause = '<' . $clientTableName . '>';
        }

        $gateways = array_filter(array_map('trim', explode(',', $rule['gateway'])));
        $isSmart = ($rule['smartGateway'] === '1' && count($gateways) > 1);

        // Register custom domains table if rule has customDomains
        if (!empty($rule['customDomains'])) {
            $customTableName = $tablePrefix . '_custom_' . substr(md5($rule['uuid']), 0, 8);
            $fw->registerTable($customTableName, [
                'persist' => true,
            ]);
            $validCustomTables[] = $customTableName;

            if ($isSmart) {
                // Smart mode: register _gwN tables and N rules for custom domains
                for ($i = 0; $i < count($gateways) - 1; $i++) {
                    $gwCustomTable = $customTableName . '_gw' . $i;
                    $fw->registerTable($gwCustomTable, ['persist' => true]);
                    $description = 'AppRouter: ' . ($rule['description'] ?: 'custom domains') . ' via ' . trim($gateways[$i]) . ' [smart gw' . $i . ']';
                    $fw->registerFilterRule(
                        $priority,
                        [
                            'from' => $fromClause,
                            'to' => '<' . $gwCustomTable . '>',
                            'gateway' => trim($gateways[$i]),
                            'direction' => 'in',
                            'interface' => $rule['interface'],
                            'descr' => $description,
                            '#ref' => 'approuter:' . $rule['uuid'] . ':custom:gw' . $i,
                        ],
                        $filterDefaults
                    );
                    $priority++;
                }
                // Fallback: last gateway uses main custom table
                $description = 'AppRouter: ' . ($rule['description'] ?: 'custom domains') . ' via ' . trim(end($gateways)) . ' [fallback]';
                $fw->registerFilterRule(
                    $priority,
                    [
                        'from' => $fromClause,
                        'to' => '<' . $customTableName . '>',
                        'gateway' => trim(end($gateways)),
                        'direction' => 'in',
                        'interface' => $rule['interface'],
                        'descr' => $description,
                        '#ref' => 'approuter:' . $rule['uuid'] . ':custom',
                    ],
                    $filterDefaults
                );
                $priority++;
            } else {
                // Non-smart: single rule with first gateway
                $description = 'AppRouter: ' . ($rule['description'] ?: 'custom domains') . ' via ' . trim($gateways[0]);
                $fw->registerFilterRule(
                    $priority,
                    [
                        'from' => $fromClause,
                        'to' => '<' . $customTableName . '>',
                        'gateway' => trim($gateways[0]),
                        'direction' => 'in',
                        'interface' => $rule['interface'],
                        'descr' => $description,
                        '#ref' => 'approuter:' . $rule['uuid'] . ':custom',
                    ],
                    $filterDefaults
                );
                $priority++;
            }
        }

        foreach ($rule['categories'] as $category) {
            $category = trim($category);
            if (empty($category)) {
                continue;
            }

            $tableName = $tablePrefix . '_' . str_replace('.', '_', $category);

            if ($isSmart) {
                // Smart mode: N rules with priority ordering
                // GW0..GWn-2 use _gwN tables (empty by default, filled by prober)
                for ($i = 0; $i < count($gateways) - 1; $i++) {
                    $gwTableName = $tableName . '_gw' . $i;
                    $description = 'AppRouter: ' . ($rule['description'] ?: $category) . ' via ' . trim($gateways[$i]) . ' [smart gw' . $i . ']';
                    $fw->registerFilterRule(
                        $priority,
                        [
                            'from' => $fromClause,
                            'to' => '<' . $gwTableName . '>',
                            'gateway' => trim($gateways[$i]),
                            'direction' => 'in',
                            'interface' => $rule['interface'],
                            'descr' => $description,
                            '#ref' => 'approuter:' . $rule['uuid'] . ':gw' . $i,
                        ],
                        $filterDefaults
                    );
                    $priority++;
                }
                // Last gateway: fallback using main table (always has IPs)
                $description = 'AppRouter: ' . ($rule['description'] ?: $category) . ' via ' . trim(end($gateways)) . ' [fallback]';
                $fw->registerFilterRule(
                    $priority,
                    [
                        'from' => $fromClause,
                        'to' => '<' . $tableName . '>',
                        'gateway' => trim(end($gateways)),
                        'direction' => 'in',
                        'interface' => $rule['interface'],
                        'descr' => $description,
                        '#ref' => 'approuter:' . $rule['uuid'],
                    ],
                    $filterDefaults
                );
                $priority++;
            } else {
                // Non-smart: single rule with first gateway (existing behavior)
                $description = 'AppRouter: ' . ($rule['description'] ?: $category) . ' via ' . trim($gateways[0]);
                $fw->registerFilterRule(
                    $priority,
                    [
                        'from' => $fromClause,
                        'to' => '<' . $tableName . '>',
                        'gateway' => trim($gateways[0]),
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
    }

    // Clean up orphaned client table files from deleted rules
    foreach (glob($clientsDir . '/' . $tablePrefix . '_clients_*.txt') as $file) {
        if (!in_array(basename($file), $validClientFiles)) {
            @unlink($file);
        }
    }

    // Build set of valid _gwN table names from smart gateway rules
    $validGwTables = [];
    foreach ($rules as $rule) {
        $gateways = array_filter(array_map('trim', explode(',', $rule['gateway'])));
        $isSmart = ($rule['smartGateway'] === '1' && count($gateways) > 1);
        if (!$isSmart) {
            continue;
        }
        foreach ($rule['categories'] as $cat) {
            $cat = trim($cat);
            if (empty($cat)) {
                continue;
            }
            $tableName = $tablePrefix . '_' . str_replace('.', '_', $cat);
            for ($i = 0; $i < count($gateways) - 1; $i++) {
                $validGwTables[] = $tableName . '_gw' . $i;
            }
        }
        if (!empty($rule['customDomains'])) {
            $customTableName = $tablePrefix . '_custom_' . substr(md5($rule['uuid']), 0, 8);
            for ($i = 0; $i < count($gateways) - 1; $i++) {
                $validGwTables[] = $customTableName . '_gw' . $i;
            }
        }
    }

    // Clean up orphaned custom/client/gw pf tables from deleted rules
    $pfTables = [];
    exec('/sbin/pfctl -s Tables 2>/dev/null', $pfTables);
    foreach ($pfTables as $t) {
        $t = trim($t);
        if (preg_match('/_custom_[0-9a-f]{8}(_gw\d+)?$/', $t)) {
            // Custom table or custom _gwN table
            $baseCustom = preg_replace('/_gw\d+$/', '', $t);
            if (strpos($t, '_gw') !== false) {
                if (!in_array($t, $validGwTables)) {
                    exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T flush 2>/dev/null');
                    exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T kill 2>/dev/null');
                    syslog(LOG_NOTICE, "approuter: removed orphaned table $t");
                }
            } elseif (!in_array($t, $validCustomTables)) {
                exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T flush 2>/dev/null');
                exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T kill 2>/dev/null');
                syslog(LOG_NOTICE, "approuter: removed orphaned table $t");
            }
        } elseif (preg_match('/_clients_[0-9a-f]{8}$/', $t) && !in_array($t . '.txt', $validClientFiles)) {
            exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T flush 2>/dev/null');
            exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T kill 2>/dev/null');
            syslog(LOG_NOTICE, "approuter: removed orphaned table $t");
        } elseif (preg_match('/_gw\d+$/', $t) && strpos($t, $tablePrefix . '_') === 0 && !in_array($t, $validGwTables)) {
            // Orphaned _gwN table from category rules
            exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T flush 2>/dev/null');
            exec('/sbin/pfctl -t ' . escapeshellarg($t) . ' -T kill 2>/dev/null');
            syslog(LOG_NOTICE, "approuter: removed orphaned table $t");
        }
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

        // Register geo_prober service if any rule has smartGateway enabled
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
            $services[] = [
                'description' => gettext('AppRouter Geo Prober'),
                'configd' => [
                    'restart' => ['approuter geo_prober_start'],
                    'start' => ['approuter geo_prober_start'],
                    'stop' => ['approuter geo_prober_stop'],
                ],
                'name' => 'approuter_geo_prober',
                'pidfile' => '/var/run/approuter_geo_prober.pid',
            ];
        }
    }

    return $services;
}

/**
 * Register syslog targets
 */
function approuter_syslog()
{
    $logfacilities = [];
    $logfacilities['approuter'] = [
        'facility' => ['approuter', 'approuter-dns', 'approuter-geo'],
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
    }

    return $jobs;
}
