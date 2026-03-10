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
            // Augment gateway: TextField → dropdown options (lightweight, no configd)
            try {
                $gwValue = is_string($result['rule']['gateway']) ? $result['rule']['gateway'] : '';
                $gwOptions = ['' => ['value' => '(none)', 'selected' => empty($gwValue) ? 1 : 0]];
                // Use Routing model directly — fast PHP-only call, no configd socket
                $gwModel = new \OPNsense\Routing\Gateways();
                foreach ($gwModel->gateway_item->iterateItems() as $gwUuid => $gw) {
                    if ((string)$gw->disabled === '1') {
                        continue;
                    }
                    $name = (string)$gw->name;
                    if (empty($name)) {
                        continue;
                    }
                    $label = $name;
                    $descr = (string)$gw->descr;
                    $addr = (string)$gw->gateway;
                    if (!empty($descr)) {
                        $label .= ' (' . $descr . ')';
                    }
                    if (!empty($addr)) {
                        $label .= ' [' . $addr . ']';
                    }
                    $gwOptions[$name] = [
                        'value' => $label,
                        'selected' => ($name === $gwValue) ? 1 : 0,
                    ];
                }
                // If the currently selected gateway isn't in the model (e.g. dynamic gateway),
                // add it so it still shows as selected
                if (!empty($gwValue) && !isset($gwOptions[$gwValue])) {
                    $gwOptions[$gwValue] = [
                        'value' => $gwValue,
                        'selected' => 1,
                    ];
                }
                $result['rule']['gateway'] = $gwOptions;
            } catch (\Throwable $e) {
                // Keep gateway as plain text if augmentation fails
            }

            // Augment categories: CSVListField → select_multiple options
            try {
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
            } catch (\Throwable $e) {
                // Keep categories as plain text if augmentation fails
            }

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

    public function getGatewaysAction()
    {
        $result = ['rows' => []];
        $seen = [];

        // Primary: configd 'interface gateways status' — returns all gateways
        // including dynamic/auto-created ones (e.g. FRP_GW from tunnel interfaces)
        try {
            $backend = new Backend();
            $response = trim($backend->configdRun('interface gateways status'));
            $gateways = json_decode($response, true);
            if (is_array($gateways)) {
                foreach ($gateways as $gwData) {
                    if (!is_array($gwData)) {
                        continue;
                    }
                    $name = $gwData['name'] ?? '';
                    if (!empty($name) && !isset($seen[$name])) {
                        $seen[$name] = true;
                        $result['rows'][] = [
                            'name' => $name,
                            'interface' => $gwData['interface'] ?? '',
                            'gateway' => $gwData['address'] ?? '',
                            'descr' => $gwData['status_translated'] ?? '',
                        ];
                    }
                }
            }
        } catch (\Throwable $e) {
            // ignore
        }

        // Fallback: Routing model (if configd didn't return results)
        if (empty($result['rows'])) {
            try {
                $gwModel = new \OPNsense\Routing\Gateways();
                foreach ($gwModel->gateway_item->iterateItems() as $uuid => $gw) {
                    if ((string)$gw->disabled === '1') {
                        continue;
                    }
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
            } catch (\Throwable $e) {
                // ignore
            }
        }

        return $result;
    }
}
