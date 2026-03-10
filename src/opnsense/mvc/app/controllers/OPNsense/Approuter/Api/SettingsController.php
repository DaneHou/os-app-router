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
        return $this->getBase('rule', 'rules.rule', $uuid);
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

        // "any" = all traffic
        $result['rows'][] = ['value' => 'any', 'label' => 'any'];

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
                if (!empty($ipaddr) && !empty($subnet) && filter_var($ipaddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $netLong = ip2long($ipaddr) & ((-1 << (32 - (int)$subnet)));
                    $network = long2ip($netLong) . '/' . $subnet;
                    $result['rows'][] = [
                        'value' => $network,
                        'label' => $descr . ' net (' . $network . ')',
                    ];
                    // Also add single interface address
                    $result['rows'][] = [
                        'value' => $ipaddr . '/32',
                        'label' => $descr . ' address (' . $ipaddr . ')',
                    ];
                }
            }
        }

        // Firewall aliases
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
                    ];
                }
            }
        }

        return $result;
    }

    public function getGatewaysAction()
    {
        $result = ['rows' => []];
        $seen = [];
        $config = Config::getInstance()->object();

        // OPNsense 24.7+ MVC gateway model
        if (isset($config->OPNsense->Gateways->gateway_item)) {
            foreach ($config->OPNsense->Gateways->gateway_item as $gw) {
                $name = (string)$gw->name;
                if (!empty($name) && !isset($seen[$name])) {
                    $seen[$name] = true;
                    $result['rows'][] = [
                        'name' => $name,
                        'interface' => (string)$gw->interface,
                        'gateway' => (string)$gw->gateway,
                        'descr' => (string)$gw->descr,
                    ];
                }
            }
        }

        // Legacy gateway format (pre-24.7)
        if (isset($config->gateways->gateway_item)) {
            foreach ($config->gateways->gateway_item as $gw) {
                $name = (string)$gw->name;
                if (!empty($name) && !isset($seen[$name])) {
                    $seen[$name] = true;
                    $result['rows'][] = [
                        'name' => $name,
                        'interface' => (string)$gw->interface,
                        'gateway' => (string)$gw->gateway,
                        'descr' => (string)$gw->descr,
                    ];
                }
            }
        }

        // Gateway groups
        if (isset($config->gateways->gateway_group)) {
            foreach ($config->gateways->gateway_group as $gwg) {
                $name = (string)$gwg->name;
                if (!empty($name) && !isset($seen[$name])) {
                    $seen[$name] = true;
                    $result['rows'][] = [
                        'name' => $name,
                        'interface' => '',
                        'gateway' => 'group',
                        'descr' => (string)$gwg->descr . ' (group)',
                    ];
                }
            }
        }

        return $result;
    }
}
