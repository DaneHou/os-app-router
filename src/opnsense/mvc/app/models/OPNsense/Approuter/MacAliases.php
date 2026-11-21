<?php

/**
 *    Copyright (C) 2026 os-app-router contributors
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

namespace OPNsense\Approuter;

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;

/**
 * Keeps one "MAC address" firewall alias per rule with device (MAC) sources
 * (see Sources). Only aliases whose name and description mark them as owned
 * by App Router are ever changed or deleted.
 */
class MacAliases
{
    /**
     * Bring the managed aliases in line with the rules.
     * @param Approuter|null $mdl rules to use (default: as saved in config)
     * @return array ['changed' => bool, 'errors' => [..]]
     */
    public static function sync($mdl = null)
    {
        $mdl = $mdl ?? new Approuter();
        $rules = [];
        foreach ($mdl->rules->rule->iterateItems() as $uuid => $rule) {
            $rules[$uuid] = ['description' => (string)$rule->description, 'sourceNets' => (string)$rule->sourceNets];
        }

        Config::getInstance()->lock();
        $aliasMdl = new Alias();
        $aliases = [];
        foreach ($aliasMdl->aliases->alias->iterateItems() as $auuid => $a) {
            $aliases[] = [
                'uuid' => $auuid, 'name' => (string)$a->name, 'type' => (string)$a->type,
                'content' => (string)$a->content, 'description' => (string)$a->description,
            ];
        }
        $plan = Sources::planAliases($rules, $aliases);
        $errors = [];
        foreach ($plan['conflicts'] as $name => $reason) {
            $errors[] = "$name: $reason";
            syslog(LOG_ERR, "approuter: MAC alias $name not managed: $reason");
        }
        if (empty($plan['add']) && empty($plan['update']) && empty($plan['delete'])) {
            Config::getInstance()->unlock();
            return ['changed' => false, 'errors' => $errors];
        }
        foreach ($plan['add'] as [$name, $content, $descr]) {
            $node = $aliasMdl->aliases->alias->Add();
            $node->setNodes(['enabled' => '1', 'name' => $name, 'type' => 'mac',
                             'content' => $content, 'description' => $descr]);
        }
        foreach ($plan['update'] as $auuid => [$name, $content, $descr]) {
            $node = $aliasMdl->getNodeByReference('aliases.alias.' . $auuid);
            if ($node !== null) {
                $node->setNodes(['enabled' => '1', 'type' => 'mac', 'content' => $content, 'description' => $descr]);
            }
        }
        foreach ($plan['delete'] as $auuid) {
            $aliasMdl->aliases->alias->del($auuid);
        }
        try {
            $aliasMdl->serializeToConfig();
            Config::getInstance()->save();
            Config::getInstance()->unlock();
        } catch (\Throwable $e) {
            Config::getInstance()->unlock();
            $errors[] = $e->getMessage();
            syslog(LOG_ERR, 'approuter: saving MAC aliases failed: ' . $e->getMessage());
            return ['changed' => false, 'errors' => $errors];
        }
        syslog(LOG_NOTICE, sprintf(
            'approuter: MAC aliases synced (+%d ~%d -%d)',
            count($plan['add']),
            count($plan['update']),
            count($plan['delete'])
        ));
        return ['changed' => true, 'errors' => $errors];
    }

    /** names of the aliases App Router owns, null when the Alias model can't be read */
    public static function ownedNames()
    {
        try {
            $names = [];
            foreach ((new Alias())->aliases->alias->iterateItems() as $a) {
                if (Sources::aliasOwner((string)$a->name, (string)$a->description) !== null) {
                    $names[] = (string)$a->name;
                }
            }
            return $names;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** devices from the dnsmasq leases and the ARP table, see Sources::buildDevices() */
    public static function devices()
    {
        $leases = @file_get_contents('/var/db/dnsmasq.leases');
        $arp = [];
        exec('/usr/bin/timeout 3 /usr/sbin/arp -an 2>/dev/null', $arp);
        return Sources::buildDevices(Sources::parseLeases($leases ?: ''), Sources::parseArp(implode("\n", $arp)));
    }
}
