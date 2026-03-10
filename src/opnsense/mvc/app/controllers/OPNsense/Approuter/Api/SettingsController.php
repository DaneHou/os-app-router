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

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'approuter';
    protected static $internalModelClass = 'OPNsense\Approuter\Approuter';

    // getAction() and setAction() are auto-provided by the base class
    // They handle the full model (general + lists sections)
    // API: GET /api/approuter/settings/get
    //      POST /api/approuter/settings/set

    public function searchRuleAction()
    {
        return $this->searchBase(
            'rules.rule',
            ['enabled', 'description', 'sourceNets', 'categories', 'gateway', 'interface'],
            'description'
        );
    }

    public function getRuleAction($uuid = null)
    {
        $result = $this->getBase('rule', 'rules.rule', $uuid);

        if (isset($result['rule'])) {
            // Augment gateway: TextField → dropdown options
            $gwValue = is_string($result['rule']['gateway']) ? $result['rule']['gateway'] : '';
            $gateways = $this->getGatewaysAction();
            $gwOptions = ['' => ['value' => '', 'selected' => empty($gwValue) ? 1 : 0]];
            foreach ($gateways['rows'] as $gw) {
                $label = $gw['name'];
                if (!empty($gw['descr'])) {
                    $label .= ' (' . $gw['descr'] . ')';
                }
                if (!empty($gw['gateway']) && $gw['gateway'] !== 'group') {
                    $label .= ' [' . $gw['gateway'] . ']';
                }
                $gwOptions[$gw['name']] = [
                    'value' => $label,
                    'selected' => ($gw['name'] === $gwValue) ? 1 : 0,
                ];
            }
            $result['rule']['gateway'] = $gwOptions;

            // Augment categories: CSVListField → select_multiple options
            $catValue = is_string($result['rule']['categories']) ? $result['rule']['categories'] : '';
            $catSelected = array_filter(array_map('trim', explode(',', $catValue)));
            $categories = $this->getCategoriesAction();
            $catOptions = [];
            foreach ($categories['rows'] as $cat) {
                $catOptions[$cat['value']] = [
                    'value' => $cat['label'],
                    'selected' => in_array($cat['value'], $catSelected) ? 1 : 0,
                ];
            }
            $result['rule']['categories'] = $catOptions;

            // sourceNets: plain text field, no augmentation needed
        }

        return $result;
    }

    public function addRuleAction()
    {
        return $this->addBase('rule', 'rules.rule');
    }

    public function setRuleAction($uuid)
    {
        return $this->setBase('rule', 'rules.rule', $uuid);
    }

    public function delRuleAction($uuid)
    {
        return $this->delBase('rules.rule', $uuid);
    }

    public function toggleRuleAction($uuid, $enabled = null)
    {
        return $this->toggleBase('rules.rule', $uuid, $enabled);
    }

    public function getCategoriesAction()
    {
        $result = ['rows' => []];
        $categoriesFile = '/usr/local/opnsense/scripts/OPNsense/Approuter/app_categories.json';
        if (file_exists($categoriesFile)) {
            $data = json_decode(file_get_contents($categoriesFile), true);
            if (is_array($data)) {
                foreach ($data as $catId => $catData) {
                    $catName = $catData['name'] ?? $catId;
                    $result['rows'][] = [
                        'value' => $catId,
                        'label' => $catName . ' (All)',
                    ];
                    if (isset($catData['apps']) && is_array($catData['apps'])) {
                        foreach ($catData['apps'] as $appId => $appData) {
                            $result['rows'][] = [
                                'value' => $catId . '.' . $appId,
                                'label' => $appData['label'] ?? $appId,
                            ];
                        }
                    }
                }
            }
        }
        return $result;
    }

    public function getNetworksAction()
    {
        $result = ['rows' => []];

        // "any" = all traffic (always shown regardless of interface)
        $result['rows'][] = ['value' => 'any', 'label' => 'any', 'iface' => '*'];

        $config = Config::getInstance()->object();
        if (isset($config->interfaces)) {
            foreach ($config->interfaces->children() as $ifname => $iface) {
                $enabled = (string)$iface->enable;
                if (empty($enabled) && !in_array($ifname, ['lan', 'wan'])) {
                    continue;
                }
                $descr = !empty((string)$iface->descr) ? (string)$iface->descr : strtoupper($ifname);
                $ipaddr = (string)$iface->ipaddr;
                $subnet = (string)$iface->subnet;

                // Static IP interface
                if (!empty($ipaddr) && !empty($subnet) && filter_var($ipaddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $netLong = ip2long($ipaddr) & ((-1 << (32 - (int)$subnet)));
                    $network = long2ip($netLong) . '/' . $subnet;
                    $result['rows'][] = [
                        'value' => $network,
                        'label' => '[' . $descr . '] net (' . $network . ')',
                        'iface' => $ifname,
                    ];
                    $result['rows'][] = [
                        'value' => $ipaddr,
                        'label' => '[' . $descr . '] address (' . $ipaddr . ')',
                        'iface' => $ifname,
                    ];
                } elseif (in_array($ipaddr, ['dhcp', 'pppoe', 'pptp', 'ppp'])) {
                    // Dynamic interface — try to read actual IP from system
                    $realif = (string)$iface->if;
                    $actualIp = '';
                    $ipFile = '/tmp/' . $realif . '_ip';
                    if (!empty($realif) && file_exists($ipFile)) {
                        $actualIp = trim(file_get_contents($ipFile));
                    }
                    if (!empty($actualIp) && filter_var($actualIp, FILTER_VALIDATE_IP)) {
                        $result['rows'][] = [
                            'value' => $actualIp,
                            'label' => '[' . $descr . '] address (' . $actualIp . ' / ' . $ipaddr . ')',
                            'iface' => $ifname,
                        ];
                    }
                }
            }
        }

        // Firewall aliases (shown for all interfaces)
        if (isset($config->OPNsense->Firewall->Alias->aliases->alias)) {
            foreach ($config->OPNsense->Firewall->Alias->aliases->alias as $alias) {
                $atype = (string)$alias->type;
                if (in_array($atype, ['host', 'network'])) {
                    $aname = (string)$alias->name;
                    $adescr = (string)$alias->description;
                    $label = $aname;
                    if ($adescr) {
                        $label .= ' (' . $adescr . ')';
                    }
                    $result['rows'][] = [
                        'value' => $aname,
                        'label' => $label,
                        'iface' => '*',
                    ];
                }
            }
        }

        return $result;
    }

    public function getGatewaysAction()
    {
        $result = ['rows' => []];

        // Use configd backend — same method OPNsense core uses
        $backend = new Backend();
        $response = trim($backend->configdpRun('interface routes gateways status'));
        $gateways = json_decode($response, true);

        if (is_array($gateways)) {
            foreach ($gateways as $gwName => $gwData) {
                if (is_array($gwData) && !empty($gwName)) {
                    $result['rows'][] = [
                        'name' => $gwData['name'] ?? $gwName,
                        'interface' => $gwData['interface'] ?? '',
                        'gateway' => $gwData['address'] ?? $gwData['gateway'] ?? '',
                        'descr' => $gwData['descr'] ?? '',
                    ];
                }
            }
        }

        return $result;
    }

    /**
     * Debug endpoint — shows raw gateway data from all sources.
     * Access via browser: /api/approuter/settings/debug
     * DELETE THIS after debugging.
     */
    public function debugAction()
    {
        $debug = [];

        // 1. configd backend
        try {
            $backend = new Backend();
            $raw = trim($backend->configdpRun('interface routes gateways status'));
            $debug['configd_raw'] = $raw;
            $debug['configd_parsed'] = json_decode($raw, true);
        } catch (\Throwable $e) {
            $debug['configd_error'] = $e->getMessage();
        }

        // 2. Routing model
        try {
            $gwModel = new \OPNsense\Routing\Gateways();
            $items = [];
            foreach ($gwModel->gateway_item->iterateItems() as $uuid => $gw) {
                $items[$uuid] = [
                    'name' => (string)$gw->name,
                    'interface' => (string)$gw->interface,
                    'gateway' => (string)$gw->gateway,
                    'descr' => (string)$gw->descr,
                    'disabled' => (string)$gw->disabled,
                ];
            }
            $debug['routing_model'] = $items;
        } catch (\Throwable $e) {
            $debug['routing_model_error'] = $e->getMessage();
        }

        // 3. Config XML paths
        $config = Config::getInstance()->object();
        $debug['has_gateways_node'] = isset($config->gateways);
        $debug['has_gateways_gateway_item'] = isset($config->gateways->gateway_item);
        $debug['has_opnsense_gateways'] = isset($config->OPNsense->Gateways);
        $debug['has_opnsense_gateways_item'] = isset($config->OPNsense->Gateways->gateway_item);

        // Dump legacy gateway items if they exist
        if (isset($config->gateways->gateway_item)) {
            $legacy = [];
            foreach ($config->gateways->gateway_item as $gw) {
                $item = [];
                foreach ($gw->children() as $child) {
                    $item[$child->getName()] = (string)$child;
                }
                $legacy[] = $item;
            }
            $debug['legacy_gateways'] = $legacy;
        }

        // Dump OPNsense MVC gateway items if they exist
        if (isset($config->OPNsense->Gateways)) {
            $mvc = [];
            foreach ($config->OPNsense->Gateways->children() as $section) {
                $sectionName = $section->getName();
                if ($sectionName === 'gateway_item') {
                    $item = [];
                    foreach ($section->children() as $child) {
                        $item[$child->getName()] = (string)$child;
                    }
                    $mvc[] = $item;
                }
            }
            $debug['mvc_gateways'] = $mvc;
        }

        // 4. Interfaces
        $ifaces = [];
        if (isset($config->interfaces)) {
            foreach ($config->interfaces->children() as $ifname => $iface) {
                $ifaces[$ifname] = [
                    'descr' => (string)$iface->descr,
                    'enable' => (string)$iface->enable,
                    'ipaddr' => (string)$iface->ipaddr,
                    'subnet' => (string)$iface->subnet,
                    'if' => (string)$iface->if,
                ];
            }
        }
        $debug['interfaces'] = $ifaces;

        return $debug;
    }
}
