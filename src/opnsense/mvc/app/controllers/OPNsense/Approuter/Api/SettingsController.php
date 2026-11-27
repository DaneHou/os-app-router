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

use OPNsense\Approuter\MacAliases;
use OPNsense\Approuter\Sources;
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
            $result['rule']['sourceNets'] = $this->sourceOptions(
                $this->extractCsvValue($result['rule']['sourceNets'] ?? '')
            );
            $result['rule']['customDomains'] = $this->extractCsvValue($result['rule']['customDomains'] ?? '');

            // Augment gateway: CSVListField → dropdown of the configured gateways
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
            // gateway MUST be an options object for the dropdown, never a string
            $result['rule']['gateway'] = $gwOptions;

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
     * Options for the source tokenizer, keys are what gets stored:
     * "any" and the rule's current entries (IPs/CIDRs are free text,
     * allownew), "Devices" (mac:<MAC> tokens from the DHCP leases + ARP
     * table) and "Aliases" (every address alias, all types but port, except
     * the MAC aliases App Router manages itself).
     */
    private function sourceOptions($value)
    {
        $selected = Sources::split($value);
        $options = [];
        foreach ($selected as $entry) {
            $label = $entry;
            $mac = Sources::normalizeMac($entry);
            if ($mac !== null) {
                $label = $mac . ' (device not seen now)';
            }
            $options[$entry] = ['value' => $label, 'selected' => 1];
        }
        if (!isset($options['any'])) {
            $options['any'] = ['value' => 'any', 'selected' => 0];
        }
        try {
            foreach (Sources::deviceOptions(MacAliases::devices()) as $token => $label) {
                if (isset($options[$token])) {
                    $options[$token]['value'] = $label;
                    $options[$token]['optgroup'] = 'Devices';
                } else {
                    $options[$token] = ['value' => $label, 'selected' => 0, 'optgroup' => 'Devices'];
                }
            }
        } catch (\Throwable $e) {
            // leases/ARP unavailable: MACs can still be typed
        }
        try {
            foreach ((new \OPNsense\Firewall\Alias())->aliases->alias->iterateItems() as $alias) {
                $name = (string)$alias->name;
                $type = (string)$alias->type;
                if ($name === '' || $type === 'port' || Sources::aliasOwner($name, (string)$alias->description) !== null) {
                    continue;
                }
                $label = $name . ' (' . $type . ')';
                if (isset($options[$name])) {
                    $options[$name]['value'] = $label;
                    $options[$name]['optgroup'] = 'Aliases';
                } else {
                    $options[$name] = ['value' => $label, 'selected' => 0, 'optgroup' => 'Aliases'];
                }
            }
        } catch (\Throwable $e) {
            // alias model unavailable: keep current entries only
        }
        return $options;
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

    /**
     * Store typed MACs (aa:bb:.., aa-bb-..) as mac:aa:bb:cc:dd:ee:ff
     * (called after validation, before the config is written).
     */
    protected function setBaseHook($node)
    {
        if (isset($node->sourceNets)) {
            $node->sourceNets->setValue(Sources::normalizeList((string)$node->sourceNets));
        }
    }

    /** update the managed MAC aliases after a rule change, report problems */
    private function withMacAliases(array $result)
    {
        if (in_array($result['result'] ?? '', ['saved', 'deleted'], true)) {
            $sync = MacAliases::sync();
            if (!empty($sync['errors'])) {
                $result['mac_alias_errors'] = $sync['errors'];
            }
        }
        return $result;
    }

    public function addRuleAction()
    {
        return $this->withMacAliases($this->addBase('rule', 'rules.rule'));
    }

    public function setRuleAction($uuid)
    {
        return $this->withMacAliases($this->setBase('rule', 'rules.rule', $uuid));
    }

    public function delRuleAction($uuid)
    {
        return $this->withMacAliases($this->delBase('rules.rule', $uuid));
    }

    /** rules as [uuid => [description, sourceNets]] */
    private function ruleSources()
    {
        $rules = [];
        foreach ($this->getModel()->rules->rule->iterateItems() as $uuid => $rule) {
            $rules[$uuid] = ['description' => (string)$rule->description, 'sourceNets' => (string)$rule->sourceNets];
        }
        return $rules;
    }

    /**
     * "Convert IP sources to devices", step 1: which rule IPs map to exactly
     * one MAC in the DHCP leases / ARP table. Changes nothing.
     */
    public function macMigrationPreviewAction()
    {
        return ['rules' => Sources::migrationPreview($this->ruleSources(), MacAliases::devices())];
    }

    /**
     * Step 2 (POST {selection: {ruleUuid: [ip entry, ..]}}): replace the
     * confirmed entries by their device. The mapping is checked again;
     * entries that no longer map one-to-one are left alone.
     */
    public function macMigrationApplyAction()
    {
        $result = ['result' => 'failed', 'changed' => []];
        if (!$this->request->isPost()) {
            return $result;
        }
        $selection = $this->request->getPost('selection');
        if (!is_array($selection)) {
            return $result;
        }
        $devices = MacAliases::devices();
        \OPNsense\Core\Config::getInstance()->lock();
        $mdl = $this->getModel();
        foreach ($selection as $uuid => $entries) {
            $node = $mdl->getNodeByReference('rules.rule.' . $uuid);
            if ($node === null || !is_array($entries)) {
                continue;
            }
            $old = (string)$node->sourceNets;
            $new = Sources::applyMigration($old, array_map('strval', $entries), $devices);
            if ($new !== $old) {
                $node->sourceNets->setValue($new);
                $result['changed'][$uuid] = $new;
            }
        }
        if (!empty($result['changed'])) {
            $this->save();
        } else {
            \OPNsense\Core\Config::getInstance()->unlock();
        }
        return $this->withMacAliases(['result' => 'saved'] + $result);
    }

    public function toggleRuleAction($uuid, $enabled = null)
    {
        return $this->toggleBase('rules.rule', $uuid, $enabled);
    }

    public function searchCustomCategoryAction()
    {
        return $this->searchBase(
            'customCategories.category',
            ['slug', 'label', 'domains', 'cidrs'],
            'label'
        );
    }

    public function getCustomCategoryAction($uuid = null)
    {
        return $this->getBase('category', 'customCategories.category', $uuid);
    }

    public function addCustomCategoryAction()
    {
        return $this->addBase('category', 'customCategories.category');
    }

    public function setCustomCategoryAction($uuid)
    {
        return $this->setBase('category', 'customCategories.category', $uuid);
    }

    public function delCustomCategoryAction($uuid)
    {
        return $this->delBase('customCategories.category', $uuid);
    }

    public function getCategoriesAction()
    {
        // IP based category: all mainland China networks from the China CIDR
        // list (List Sources tab), loaded into <prefix>_china_all by
        // list_updater. Matches destinations regardless of domain or DNS.
        $result = ['rows' => [[
            'value' => 'china_all',
            'label' => gettext('China Mainland IPs (CIDR list)'),
        ]]];
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
        // Append user-defined custom categories
        $mdl = $this->getModel();
        foreach ($mdl->customCategories->category->iterateItems() as $uuid => $cat) {
            $slug = (string)$cat->slug;
            $label = (string)$cat->label;
            if (!empty($slug) && !empty($label)) {
                $result['rows'][] = [
                    'value' => $slug,
                    'label' => $label . ' [Custom]',
                ];
            }
        }
        return $result;
    }

    public function getGatewaysAction()
    {
        $result = ['rows' => []];
        $seen = [];

        // Primary: configd 'interface gateways status' — returns all gateways
        // including dynamic/auto-created ones (e.g. gateways of tunnel interfaces)
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
