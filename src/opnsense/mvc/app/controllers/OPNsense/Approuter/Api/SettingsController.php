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
            ['enabled', 'description', 'sourceNets', 'categories', 'customDomains', 'gateway', 'interface', 'smartGateway'],
            'description'
        );
    }

    public function getRuleAction($uuid = null)
    {
        $result = $this->getBase('rule', 'rules.rule', $uuid);

        if (isset($result['rule'])) {
            // CSVListField may return an array of {value, selected} entries
            // instead of a plain string. Normalize text fields to strings.
            $result['rule']['sourceNets'] = $this->extractCsvValue($result['rule']['sourceNets'] ?? '');
            $result['rule']['customDomains'] = $this->extractCsvValue($result['rule']['customDomains'] ?? '');

            // Augment gateway: CSVListField → multi-select with ordering
            $gwValue = $this->extractCsvValue($result['rule']['gateway'] ?? '');
            $gwSelected = array_filter(array_map('trim', explode(',', $gwValue)));
            $gwOptions = [];
            $gateways = null;
            // Method 1: exec with timeout (fast, non-blocking)
            try {
                $gwLines = [];
                exec('/usr/bin/timeout 3 /usr/local/sbin/configctl interface gateways status 2>/dev/null', $gwLines);
                $gwJson = implode('', $gwLines);
                if (!empty($gwJson)) {
                    $gateways = json_decode($gwJson, true);
                }
            } catch (\Throwable $e) {
                // fall through to method 2
            }
            // Method 2: Backend class (may be slower but more reliable)
            if (!is_array($gateways) || empty($gateways)) {
                try {
                    $backend = new Backend();
                    $response = trim($backend->configdRun('interface gateways status'));
                    if (!empty($response)) {
                        $gateways = json_decode($response, true);
                    }
                } catch (\Throwable $e) {
                    // both methods failed
                }
            }
            if (is_array($gateways)) {
                foreach ($gateways as $gwData) {
                    if (!is_array($gwData)) {
                        continue;
                    }
                    $name = $gwData['name'] ?? '';
                    if (empty($name)) {
                        continue;
                    }
                    $label = $name;
                    if (!empty($gwData['status_translated'])) {
                        $label .= ' (' . $gwData['status_translated'] . ')';
                    }
                    if (!empty($gwData['address'])) {
                        $label .= ' [' . $gwData['address'] . ']';
                    }
                    $gwOptions[$name] = [
                        'value' => $label,
                        'selected' => in_array($name, $gwSelected) ? 1 : 0,
                    ];
                }
            }
            // Always ensure saved gateways appear as options (even if configctl failed)
            foreach ($gwSelected as $gw) {
                if (!empty($gw) && !isset($gwOptions[$gw])) {
                    $gwOptions[$gw] = [
                        'value' => $gw,
                        'selected' => 1,
                    ];
                }
            }
            // gateway MUST be an options object for select_multiple, never a string
            $result['rule']['gateway'] = $gwOptions;
            $result['rule']['gateway_order'] = $gwValue;

            // Augment categories: CSVListField → select_multiple options
            try {
                $catValue = $this->extractCsvValue($result['rule']['categories'] ?? '');
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
        }

        return $result;
    }

    /**
     * Extract a string value from a field that may be returned as either
     * a plain string or a CSVListField array of {value, selected} entries.
     */
    private function extractCsvValue($field)
    {
        if (is_string($field)) {
            return $field;
        }
        if (is_array($field)) {
            $selected = [];
            foreach ($field as $key => $data) {
                if (is_array($data) && !empty($data['selected'])) {
                    $selected[] = $key;
                }
            }
            return implode(',', $selected);
        }
        return '';
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

        // Note: no Routing model fallback — its constructor can hang via configd

        return $result;
    }
}
