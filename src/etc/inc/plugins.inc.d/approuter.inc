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
            'gateway' => (string)$rule->gateway,
            'interface' => (string)$rule->interface,
        ];
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
    }

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
            $fw->registerTable($clientTableName, [
                'content' => $sourceNets,
                'persist' => true,
            ]);
            $fromClause = '<' . $clientTableName . '>';
        }

        foreach ($rule['categories'] as $category) {
            $category = trim($category);
            if (empty($category)) {
                continue;
            }

            $tableName = $tablePrefix . '_' . str_replace('.', '_', $category);
            $description = 'AppRouter: ' . ($rule['description'] ?: $category) . ' via ' . $rule['gateway'];

            $fw->registerFilterRule(
                $priority,
                [
                    'from' => $fromClause,
                    'to' => '<' . $tableName . '>',
                    'gateway' => $rule['gateway'],
                    'direction' => 'in',
                    'interface' => $rule['interface'],
                    'descr' => $description,
                    'quick' => true,
                    'log' => false,
                    '#ref' => 'approuter:' . $rule['uuid'],
                ]
            );
            $priority++;
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
        if ((string)$mdl->general->dnsResolver === 'unbound') {
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

        switch ($interval) {
            case 'hourly':
                $jobs[] = [
                    'description' => 'AppRouter list update',
                    'autocron' => [
                        'minutes' => '15',
                        'hours' => '*',
                    ],
                    'origin' => 'approuter',
                    'command' => '/usr/local/opnsense/scripts/OPNsense/Approuter/list_updater.py update',
                ];
                break;
            case 'weekly':
                $jobs[] = [
                    'description' => 'AppRouter list update',
                    'autocron' => [
                        'minutes' => '30',
                        'hours' => '3',
                        'days' => '1',
                    ],
                    'origin' => 'approuter',
                    'command' => '/usr/local/opnsense/scripts/OPNsense/Approuter/list_updater.py update',
                ];
                break;
            default:
                $jobs[] = [
                    'description' => 'AppRouter list update',
                    'autocron' => [
                        'minutes' => '30',
                        'hours' => '3',
                    ],
                    'origin' => 'approuter',
                    'command' => '/usr/local/opnsense/scripts/OPNsense/Approuter/list_updater.py update',
                ];
                break;
        }
    }

    return $jobs;
}
