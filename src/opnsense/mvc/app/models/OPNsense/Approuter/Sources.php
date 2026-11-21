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

/**
 * Rule source helpers without OPNsense dependencies (unit tested in
 * tests/php/test_firewall.php).
 *
 * Source entries: "any", IP/CIDR, firewall alias name or a device MAC stored
 * as "mac:aa:bb:cc:dd:ee:ff". The "mac:" prefix can't be confused with an
 * alias name (no ":" allowed) or IPv6. A typed raw MAC (aa:bb:.., aa-bb-..)
 * is accepted and normalised to the token on save.
 *
 * Each rule with MAC entries gets one firewall alias of type "MAC address"
 * named ar_<first 8 hex of the rule uuid>_mac; core resolves it to the IPs
 * currently seen for those MACs (ARP/NDP).
 */
class Sources
{
    const MAC_PREFIX = 'mac:';
    const MARKER = 'Managed by App Router';

    /** canonical lowercase aa:bb:cc:dd:ee:ff, null when not a full MAC */
    public static function normalizeMac($entry)
    {
        $entry = trim((string)$entry);
        if (stripos($entry, self::MAC_PREFIX) === 0) {
            $entry = substr($entry, strlen(self::MAC_PREFIX));
        }
        if (!preg_match('/^[0-9a-f]{1,2}([:-])[0-9a-f]{1,2}(\1[0-9a-f]{1,2}){4}$/i', $entry, $m)) {
            return null;
        }
        $parts = array_map(function ($p) {
            return str_pad(strtolower($p), 2, '0', STR_PAD_LEFT);
        }, explode($m[1], $entry));
        return implode(':', $parts);
    }

    /** token as stored in sourceNets */
    public static function macToken($mac)
    {
        return self::MAC_PREFIX . $mac;
    }

    /** locally administered ("private"/randomised) MAC */
    public static function isRandomMac($mac)
    {
        return (hexdec(substr($mac, 0, 2)) & 0x02) !== 0;
    }

    public static function isNet($entry)
    {
        $parts = explode('/', $entry, 2);
        if (filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
            return false;
        }
        if (count($parts) === 1) {
            return true;
        }
        $max = strpos($parts[0], ':') !== false ? 128 : 32;
        return ctype_digit($parts[1]) && (int)$parts[1] <= $max;
    }

    public static function isAliasName($entry)
    {
        return preg_match('/^[A-Za-z0-9_]{1,32}$/', $entry) === 1;
    }

    /** any | mac | net | alias | invalid */
    public static function classify($entry)
    {
        $entry = trim((string)$entry);
        if (strtolower($entry) === 'any') {
            return 'any';
        }
        if (self::normalizeMac($entry) !== null) {
            return 'mac';
        }
        if (self::isNet($entry)) {
            return 'net';
        }
        if (self::isAliasName($entry)) {
            return 'alias';
        }
        return 'invalid';
    }

    public static function split($csv)
    {
        return array_values(array_filter(array_map('trim', explode(',', (string)$csv)), 'strlen'));
    }

    /** validation messages for a source list (empty = valid) */
    public static function validate($csv)
    {
        $errors = [];
        foreach (self::split($csv) as $entry) {
            if (self::classify($entry) !== 'invalid') {
                continue;
            }
            if (stripos($entry, self::MAC_PREFIX) === 0 || preg_match('/^[0-9a-f]{1,2}[:-][0-9a-f]{1,2}[:-]/i', $entry)) {
                $errors[] = sprintf('"%s" is not a valid MAC address (use aa:bb:cc:dd:ee:ff).', $entry);
            } else {
                $errors[] = sprintf('"%s" is not "any", an IP/subnet, an alias name or a MAC address.', $entry);
            }
        }
        return $errors;
    }

    /** MAC entries as "mac:aa:bb:..", duplicates removed, order kept */
    public static function normalizeList($csv)
    {
        $out = [];
        foreach (self::split($csv) as $entry) {
            $mac = self::normalizeMac($entry);
            $entry = $mac !== null ? self::macToken($mac) : $entry;
            if (!in_array($entry, $out, true)) {
                $out[] = $entry;
            }
        }
        return implode(',', $out);
    }

    /** normalised MACs of a source list */
    public static function macs($csv)
    {
        $macs = [];
        foreach (self::split($csv) as $entry) {
            $mac = self::normalizeMac($entry);
            if ($mac !== null && !in_array($mac, $macs, true)) {
                $macs[] = $mac;
            }
        }
        return $macs;
    }

    /* ---- managed MAC aliases ---- */

    public static function macAliasName($ruleUuid)
    {
        $hex = preg_replace('/[^0-9a-f]/', '', strtolower((string)$ruleUuid));
        return 'ar_' . substr($hex, 0, 8) . '_mac';
    }

    public static function aliasDescription($ruleUuid, $ruleDescription)
    {
        $d = sprintf('%s (rule %s), do not edit: %s', self::MARKER, $ruleUuid, $ruleDescription);
        return mb_substr(preg_replace('/[\x00-\x1f\x7f]/', ' ', $d), 0, 255);
    }

    /** rule uuid an alias belongs to, null when App Router doesn't own it */
    public static function aliasOwner($name, $description)
    {
        if (!preg_match('/^ar_[0-9a-f]{8}_mac$/', (string)$name)) {
            return null;
        }
        $re = '/^' . preg_quote(self::MARKER, '/') . ' \(rule ([0-9a-f-]{36})\)/';
        if (!preg_match($re, (string)$description, $m)) {
            return null;
        }
        return self::macAliasName($m[1]) === $name ? $m[1] : null;
    }

    /**
     * What to do to the firewall aliases.
     * @param array $rules ruleUuid => ['description' => .., 'sourceNets' => ..] (all rules, enabled or not)
     * @param array $aliases list of ['uuid','name','type','content','description'] (content "\n" separated)
     * @return array add: [[name,content,description]], update: [aliasUuid => [name,content,description]],
     *               delete: [aliasUuid], conflicts: [name => reason]
     */
    public static function planAliases(array $rules, array $aliases)
    {
        $plan = ['add' => [], 'update' => [], 'delete' => [], 'conflicts' => []];
        $byName = [];
        foreach ($aliases as $a) {
            $byName[(string)$a['name']] = $a;
        }
        $wanted = [];
        foreach ($rules as $ruleUuid => $rule) {
            $macs = self::macs($rule['sourceNets'] ?? '');
            if (empty($macs)) {
                continue;
            }
            $name = self::macAliasName($ruleUuid);
            $content = implode("\n", $macs);
            $descr = self::aliasDescription($ruleUuid, $rule['description'] ?? '');
            if (isset($wanted[$name])) {
                $plan['conflicts'][$name] = "uuid prefix shared by rules {$wanted[$name]} and $ruleUuid";
                continue;
            }
            $wanted[$name] = $ruleUuid;
            if (!isset($byName[$name])) {
                $plan['add'][] = [$name, $content, $descr];
                continue;
            }
            $cur = $byName[$name];
            if (self::aliasOwner($cur['name'], $cur['description']) !== $ruleUuid) {
                $plan['conflicts'][$name] = 'an alias with this name exists and is not managed by App Router';
                continue;
            }
            $curContent = implode("\n", array_filter(array_map('trim', preg_split('/[\n,]/', (string)$cur['content']))));
            if ($cur['type'] !== 'mac' || $curContent !== $content || $cur['description'] !== $descr) {
                $plan['update'][$cur['uuid']] = [$name, $content, $descr];
            }
        }
        foreach ($aliases as $a) {
            if (self::aliasOwner($a['name'], $a['description']) !== null && !isset($wanted[$a['name']])) {
                $plan['delete'][] = $a['uuid'];
            }
        }
        return $plan;
    }

    /* ---- devices from DHCP leases + ARP ---- */

    /** dnsmasq.leases: "<expiry> <mac> <ip> <hostname|*> <client-id|*>" */
    public static function parseLeases($text)
    {
        $out = [];
        foreach (preg_split('/\r?\n/', (string)$text) as $line) {
            $p = preg_split('/\s+/', trim($line));
            if (count($p) < 4) {
                continue;
            }
            $mac = self::normalizeMac($p[1]);
            if ($mac === null || filter_var($p[2], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                continue;
            }
            $out[] = ['mac' => $mac, 'ip' => $p[2], 'hostname' => $p[3] === '*' ? '' : $p[3]];
        }
        return $out;
    }

    /**
     * `arp -an`: "? (192.168.1.5) at aa:bb:cc:dd:ee:ff on igc1 expires in 1199 seconds [ethernet]".
     * Skips incomplete and permanent (the firewall's own) entries and
     * non-private addresses (upstream gateways).
     */
    public static function parseArp($text)
    {
        $out = [];
        foreach (preg_split('/\r?\n/', (string)$text) as $line) {
            if (!preg_match('/\(([0-9.]+)\) at (\S+) on (\S+)(.*)$/', $line, $m)) {
                continue;
            }
            $mac = self::normalizeMac($m[2]);
            if ($mac === null || strpos($m[4], 'permanent') !== false) {
                continue;
            }
            $ip = $m[1];
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false ||
                filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) !== false) {
                continue;
            }
            $out[] = ['mac' => $mac, 'ip' => $ip, 'interface' => $m[3]];
        }
        return $out;
    }

    /** mac => [mac, hostname, ips[], random] */
    public static function buildDevices(array $leases, array $arp)
    {
        $dev = [];
        foreach (array_merge($leases, $arp) as $e) {
            $mac = $e['mac'];
            if (!isset($dev[$mac])) {
                $dev[$mac] = ['mac' => $mac, 'hostname' => '', 'ips' => [], 'random' => self::isRandomMac($mac)];
            }
            if (!empty($e['hostname']) && $dev[$mac]['hostname'] === '') {
                $dev[$mac]['hostname'] = $e['hostname'];
            }
            if (!in_array($e['ip'], $dev[$mac]['ips'], true)) {
                $dev[$mac]['ips'][] = $e['ip'];
            }
        }
        uasort($dev, function ($a, $b) {
            return [strtolower($a['hostname']) === '' ? 1 : 0, strtolower($a['hostname']), ip2long($a['ips'][0])]
                <=> [strtolower($b['hostname']) === '' ? 1 : 0, strtolower($b['hostname']), ip2long($b['ips'][0])];
        });
        return $dev;
    }

    public static function deviceLabel(array $d)
    {
        $label = implode(' · ', [$d['hostname'] !== '' ? $d['hostname'] : 'unknown', $d['mac'], implode(', ', $d['ips'])]);
        return $d['random'] ? $label . ' · private (random) MAC' : $label;
    }

    /** token => label */
    public static function deviceOptions(array $devices)
    {
        $out = [];
        foreach ($devices as $d) {
            $out[self::macToken($d['mac'])] = self::deviceLabel($d);
        }
        return $out;
    }

    /** ip => [macs] */
    public static function ipToMacs(array $devices)
    {
        $map = [];
        foreach ($devices as $d) {
            foreach ($d['ips'] as $ip) {
                $map[$ip][] = $d['mac'];
            }
        }
        return $map;
    }

    /** single IPv4 host entry ("1.2.3.4" or "1.2.3.4/32") => address, else null */
    private static function hostIp($entry)
    {
        $parts = explode('/', $entry, 2);
        if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return null;
        }
        return (count($parts) === 1 || $parts[1] === '32') ? $parts[0] : null;
    }

    /**
     * Rule IP sources that map to exactly one known MAC.
     * @param array $rules ruleUuid => ['description','sourceNets']
     * @return array list of [uuid, description, replace: [[entry, mac, label, random]], keep: [entries]]
     */
    public static function migrationPreview(array $rules, array $devices)
    {
        $map = self::ipToMacs($devices);
        $out = [];
        foreach ($rules as $uuid => $rule) {
            $replace = [];
            $keep = [];
            foreach (self::split($rule['sourceNets'] ?? '') as $entry) {
                if (self::classify($entry) !== 'net') {
                    continue;
                }
                $ip = self::hostIp($entry);
                if ($ip !== null && isset($map[$ip]) && count(array_unique($map[$ip])) === 1) {
                    $mac = $map[$ip][0];
                    $replace[] = ['entry' => $entry, 'mac' => $mac, 'label' => self::deviceLabel($devices[$mac]),
                                  'random' => $devices[$mac]['random']];
                } else {
                    $keep[] = $entry;
                }
            }
            if (!empty($replace)) {
                $out[] = ['uuid' => $uuid, 'description' => $rule['description'] ?? '',
                          'replace' => $replace, 'keep' => $keep];
            }
        }
        return $out;
    }

    /**
     * Replace the confirmed IP entries by their MAC token (re-checked against
     * the current mapping; entries no longer one-to-one are kept).
     */
    public static function applyMigration($csv, array $confirmed, array $devices)
    {
        $preview = self::migrationPreview(['x' => ['sourceNets' => $csv]], $devices);
        $repl = [];
        foreach ($preview[0]['replace'] ?? [] as $r) {
            if (in_array($r['entry'], $confirmed, true)) {
                $repl[$r['entry']] = self::macToken($r['mac']);
            }
        }
        $out = [];
        foreach (self::split($csv) as $entry) {
            $entry = $repl[$entry] ?? $entry;
            if (!in_array($entry, $out, true)) {
                $out[] = $entry;
            }
        }
        return implode(',', $out);
    }
}
