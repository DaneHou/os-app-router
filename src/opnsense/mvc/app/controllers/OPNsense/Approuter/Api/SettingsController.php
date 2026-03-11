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
            ['enabled', 'description', 'sourceNets', 'categories', 'customDomains', 'gateway', 'interface'],
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

            // Augment gateway: TextField → dropdown options
            // Uses configctl with timeout to prevent hanging (configd socket can block)
            try {
                $gwValue = $this->extractCsvValue($result['rule']['gateway'] ?? '');
                $gwOptions = ['' => ['value' => '(none)', 'selected' => empty($gwValue) ? 1 : 0]];
                $gwLines = [];
                exec('timeout 3 configctl interface gateways status 2>/dev/null', $gwLines);
                $gateways = json_decode(implode('', $gwLines), true);
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
                            'selected' => ($name === $gwValue) ? 1 : 0,
                        ];
                    }
                }
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
