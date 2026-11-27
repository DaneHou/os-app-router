<?php
/*
 * Checks for src/etc/inc/plugins.inc.d/approuter.inc (rule generation).
 * Driven by tests/test_php_hook.py; prints {"case": [failed checks...]} as JSON.
 * OPNsense's firewall plugin class is replaced by a recorder.
 */

namespace OPNsense\Firewall {
    class Plugin
    {
        public $tables = [];
        public $rules = [];     // pass (route-to) rules, as before
        public $blocks = [];    // the kill-switch block behind each of them
        public $order = [];     // everything in registration order
        public function registerTable($name, $persist = false, $file = null)
        {
            $this->tables[$name] = ['persist' => $persist, 'file' => $file];
        }
        public function registerFilterRule($prio, $conf, $defaults = null)
        {
            $r = ['prio' => $prio] + array_merge($defaults ?? [], $conf);
            $this->order[] = $r;
            if (($r['type'] ?? '') === 'block') {
                $this->blocks[] = $r;
            } else {
                $this->rules[] = $r;
            }
        }
    }
}

namespace {
    use OPNsense\Approuter\Sources;

    require __DIR__ . '/../../src/opnsense/mvc/app/models/OPNsense/Approuter/Sources.php';
    require __DIR__ . '/../../src/etc/inc/plugins.inc.d/approuter.inc';

    const ALIASES = ['Kids_MAC', 'Family', '__lan_network'];
    const UUID = '700da3ee-0000-4000-8000-000000000001';

    function mkrule(array $over = [])
    {
        return array_merge([
            'uuid' => UUID, 'description' => 'my-mbp', 'sourceNets' => '192.168.70.124/32',
            'categories' => ['video.iqiyi'], 'customDomains' => '', 'gateway' => 'FRP_GW',
            'interface' => 'opt1',
        ], $over);
    }

    function client_table($uuid = UUID)
    {
        return 'approuter_clients_' . substr(md5($uuid), 0, 8);
    }

    function fresh_dir()
    {
        $dir = sys_get_temp_dir() . '/approuter-test-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);
        return $dir;
    }

    /** run the hook core on $rules, return [fw, clientsDir, valid] */
    function hook(array $rules, $aliases = ALIASES, $dir = null, $ownedMacAliases = null)
    {
        $fw = new \OPNsense\Firewall\Plugin();
        $dir = $dir ?? fresh_dir();
        $valid = approuter_register_rules($fw, $rules, 'approuter', $dir, $aliases, $ownedMacAliases);
        return [$fw, $dir, $valid];
    }

    $results = [];
    function run_case($name, callable $fn)
    {
        global $results;
        $failed = [];
        $check = function ($label, $cond) use (&$failed) {
            if (!$cond) {
                $failed[] = $label;
            }
        };
        try {
            $fn($check);
        } catch (\Throwable $e) {
            $failed[] = 'exception: ' . $e->getMessage();
        }
        $results[$name] = $failed;
    }

    run_case('parse_sources_kinds', function ($check) {
        $r = approuter_parse_sources(' 192.168.70.124/32, 10.10.0.4 ,Kids_MAC,fd00::1/64,Kids_MAC', ALIASES);
        $check('nets', $r['nets'] === ['192.168.70.124/32', '10.10.0.4', 'fd00::1/64']);
        $check('aliases deduped', $r['aliases'] === ['Kids_MAC']);
        $check('not any', $r['any'] === false && $r['invalid'] === []);
        $r = approuter_parse_sources('any', ALIASES);
        $check('any', $r['any'] === true && $r['nets'] === [] && $r['aliases'] === []);
    });

    run_case('parse_sources_rejects_garbage', function ($check) {
        $r = approuter_parse_sources('Unknown_Alias,1.2.3.4/33,<x>,a b,x;y,999.1.1.1,10.0.0.0/abc', ALIASES);
        $check('nothing accepted', $r['nets'] === [] && $r['aliases'] === [] && !$r['any']);
        $check('all invalid', count($r['invalid']) === 7);
        $check('too long alias name', approuter_parse_sources(str_repeat('a', 33), null)['invalid'] !== []);
    });

    run_case('parse_sources_without_alias_model', function ($check) {
        $r = approuter_parse_sources('SomeAlias,10.0.0.1', null);
        $check('syntax-valid name accepted', $r['aliases'] === ['SomeAlias'] && $r['nets'] === ['10.0.0.1']);
    });

    run_case('rule_ip_only_unchanged', function ($check) {
        [$fw, $dir] = hook([mkrule()]);
        $t = client_table();
        $check('one rule', count($fw->rules) === 1);
        $r = $fw->rules[0];
        $check('from client table', $r['from'] === "<$t>");
        $check('to category table', $r['to'] === '<approuter_video_iqiyi>');
        $check('via FRP_GW on opt1 inbound', $r['gateway'] === 'FRP_GW' && $r['interface'] === 'opt1' && $r['direction'] === 'in');
        $check('inet pass quick', $r['type'] === 'pass' && $r['ipprotocol'] === 'inet' && $r['quick'] === true);
        $check('client table file-backed', ($fw->tables[$t]['file'] ?? null) === "$dir/$t.txt");
        $check('client file content', @file_get_contents("$dir/$t.txt") === "192.168.70.124/32\n");
        $check('no alias sidecar', !file_exists("$dir/$t.aliases"));
    });

    run_case('rule_alias_only', function ($check) {
        [$fw, $dir] = hook([mkrule(['sourceNets' => 'Kids_MAC'])]);
        $t = client_table();
        $check('one rule', count($fw->rules) === 1);
        $check('from alias table directly', ($fw->rules[0]['from'] ?? null) === '<Kids_MAC>');
        $check('no client table registered', !isset($fw->tables[$t]));
        $check('no client file', !file_exists("$dir/$t.txt"));
        $check('alias sidecar for dns_watcher', @file_get_contents("$dir/$t.aliases") === "Kids_MAC\n");
        $check('alias table not re-registered', !isset($fw->tables['Kids_MAC']));
    });

    run_case('rule_mixed_ip_and_aliases', function ($check) {
        [$fw, $dir] = hook([mkrule(['sourceNets' => '10.10.0.4/32,Kids_MAC,192.168.70.124,Family'])]);
        $t = client_table();
        $check('one registration, comma separated from', count($fw->rules) === 1);
        $check('from = client table + aliases', ($fw->rules[0]['from'] ?? null) === "<$t>,<Kids_MAC>,<Family>");
        $check('only IPs in client file', @file_get_contents("$dir/$t.txt") === "10.10.0.4/32\n192.168.70.124\n");
        $check('aliases in sidecar', @file_get_contents("$dir/$t.aliases") === "Kids_MAC\nFamily\n");
    });

    run_case('rule_invalid_sources_skipped_not_any', function ($check) {
        [$fw] = hook([mkrule(['sourceNets' => 'Nope_Alias,1.2.3.4/40'])]);
        $check('no rule generated', $fw->rules === []);
        [$fw] = hook([mkrule(['sourceNets' => 'Nope_Alias,10.0.0.9'])]);
        $check('valid part kept', count($fw->rules) === 1 && $fw->rules[0]['from'] === '<' . client_table() . '>');
    });

    run_case('rule_any', function ($check) {
        [$fw, $dir] = hook([mkrule(['sourceNets' => 'any'])]);
        $check('from any', ($fw->rules[0]['from'] ?? null) === 'any');
        $check('no client table', !isset($fw->tables[client_table()]) && glob("$dir/*") === []);
    });

    run_case('category_tables_stay_fileless', function ($check) {
        [$fw] = hook([mkrule(['sourceNets' => '10.0.0.1,Family', 'customDomains' => 'example.com'])]);
        foreach (['approuter_video_iqiyi', 'approuter_custom_' . substr(md5(UUID), 0, 8)] as $t) {
            $check("$t persistent without file", ($fw->tables[$t] ?? null) === ['persist' => true, 'file' => null]);
        }
        $check('client table has file', !empty($fw->tables[client_table()]['file']));
        $check('no _gwN tables', preg_grep('/_gw\d+$/', array_keys($fw->tables)) === []);
    });

    run_case('rule_uses_first_gateway', function ($check) {
        // configs from before 1.5.0 could list several gateways (Smart Gateway): the first is used
        [$fw, , $valid] = hook([mkrule(['sourceNets' => 'Kids_MAC', 'gateway' => 'WAN_DHCP,FRP_GW', 'smartGateway' => '1',
                                        'customDomains' => 'example.org'])]);
        $check('one route per table', count($fw->rules) === 2);
        $check('all via the first gateway', array_unique(array_column($fw->rules, 'gateway')) === ['WAN_DHCP']);
        $check('category and custom tables', array_column($fw->rules, 'to') === ['<approuter_custom_' . substr(md5(UUID), 0, 8) . '>', '<approuter_video_iqiyi>']);
        $check('from alias', $fw->rules[0]['from'] === '<Kids_MAC>');
        $check('no gwTables key', !isset($valid['gwTables']));
    });

    run_case('orphan_tables_removed', function ($check) {
        $valid = ['clientTables' => ['approuter_clients_aaaaaaaa'], 'customTables' => ['approuter_custom_bbbbbbbb']];
        $pf = ['   approuter_clients_aaaaaaaa', '   approuter_clients_deadbeef', '   approuter_custom_bbbbbbbb',
               '   approuter_custom_cafebabe', '   approuter_video_iqiyi', '   approuter_video_iqiyi_gw0',
               '   approuter_custom_bbbbbbbb_gw1', '   other_custom_cafebabe', '   other_video_gw0', '   bogons'];
        $check('orphans: deleted rules and every _gwN of our prefix', approuter_orphan_tables('approuter', $valid, $pf) === [
            'approuter_clients_deadbeef', 'approuter_custom_cafebabe', 'approuter_video_iqiyi_gw0', 'approuter_custom_bbbbbbbb_gw1',
        ]);
    });

    run_case('orphan_client_files_removed', function ($check) {
        $dir = fresh_dir();
        $stale = 'approuter_clients_deadbeef';
        file_put_contents("$dir/$stale.txt", "10.9.9.9\n");
        file_put_contents("$dir/$stale.aliases", "Family\n");
        $t = client_table();
        file_put_contents("$dir/$t.aliases", "Old\n");   // rule switched from alias to IP-only
        [, , $valid] = hook([mkrule()], ALIASES, $dir);
        $check('stale files removed', !file_exists("$dir/$stale.txt") && !file_exists("$dir/$stale.aliases"));
        $check('outdated sidecar removed', !file_exists("$dir/$t.aliases"));
        $check('current file kept', file_exists("$dir/$t.txt"));
        $check('valid client tables', $valid['clientTables'] === [$t]);
    });


    const MAC1 = 'a8:bb:cc:00:11:22';
    const MAC2 = '3c:22:fb:01:02:03';
    function mac_alias($uuid = UUID)
    {
        return 'ar_' . substr(str_replace('-', '', $uuid), 0, 8) . '_mac';
    }

    run_case('mac_token_parsing', function ($check) {
        $check('canonical', Sources::normalizeMac('mac:A8:BB:CC:00:11:22') === MAC1);
        $check('raw colon', Sources::normalizeMac('a8:bb:cc:00:11:22') === MAC1);
        $check('raw dash', Sources::normalizeMac('A8-BB-CC-00-11-22') === MAC1);
        $check('short groups padded (arp style)', Sources::normalizeMac('a:bb:c:0:11:22') === '0a:bb:0c:00:11:22');
        $check('mixed separators rejected', Sources::normalizeMac('aa:bb-cc:00:11:22') === null);
        $check('partial rejected', Sources::normalizeMac('mac:aa:bb:cc') === null);
        $check('7 groups rejected', Sources::normalizeMac('a8:bb:cc:00:11:22:33') === null);
        foreach (['fe80::1', '2001:db8::/32', '::1', 'fd00:aa:bb:cc:dd:ee::1', '1:2:3:4:5:6:7:8'] as $v6) {
            $check("$v6 is net", Sources::classify($v6) === 'net');
        }
        $check('alias', Sources::classify('Kids_MAC') === 'alias');
        $check('managed alias name is alias syntax', Sources::classify(mac_alias()) === 'alias');
        $check('mac token', Sources::classify('mac:' . MAC1) === 'mac');
        $check('raw mac', Sources::classify(MAC1) === 'mac');
        $check('any', Sources::classify('ANY') === 'any');
        $check('random mac', Sources::isRandomMac('3e:22:fb:01:02:03') && Sources::isRandomMac('da:00:00:00:00:01'));
        $check('burned-in mac', !Sources::isRandomMac(MAC2) && !Sources::isRandomMac('00:11:22:33:44:55'));
    });

    run_case('mac_validation', function ($check) {
        $check('valid list', Sources::validate('any,10.0.0.1/32,Kids_MAC,mac:' . MAC1 . ',' . MAC2 . ',fe80::1') === []);
        $e = Sources::validate('mac:aa:bb:cc,aa:bb:cc:dd:ee:gg,bad name,1.2.3.4/33');
        $check('4 errors', count($e) === 4);
        $check('mac message for mac-like', strpos($e[0], 'not a valid MAC') !== false && strpos($e[1], 'not a valid MAC') !== false);
        $check('generic message', strpos($e[2], 'not "any"') !== false);
        $check('normalise list', Sources::normalizeList(' 10.0.0.1 , A8-BB-CC-00-11-22,mac:a8:bb:cc:00:11:22,Kids_MAC')
            === '10.0.0.1,mac:' . MAC1 . ',Kids_MAC');
        $check('macs', Sources::macs('mac:' . MAC1 . ',' . strtoupper(MAC2) . ',10.0.0.1') === [MAC1, MAC2]);
    });

    run_case('parse_sources_macs', function ($check) {
        $r = approuter_parse_sources('mac:' . MAC1 . ',10.0.0.1,' . MAC1 . ',Kids_MAC,mac:zz', ALIASES);
        $check('macs deduped', $r['macs'] === [MAC1]);
        $check('others unchanged', $r['nets'] === ['10.0.0.1'] && $r['aliases'] === ['Kids_MAC']);
        $check('bad token invalid', $r['invalid'] === ['mac:zz']);
    });

    function alias_row($uuid, $name, $content, $descr, $type = 'mac')
    {
        return ['uuid' => $uuid, 'name' => $name, 'type' => $type, 'content' => $content, 'description' => $descr];
    }

    run_case('managed_alias_plan', function ($check) {
        $u2 = 'c3e29e49-087e-4fb2-83b4-c1b07f61223c';
        $u3 = 'e7ba9c24-8577-4188-9b13-bacbb9bc5733';
        $gone = 'deadbeef-0000-4000-8000-000000000000';
        $rules = [
            UUID => ['description' => 'my-mbp', 'sourceNets' => 'mac:' . MAC1 . ',10.0.0.1'],
            $u2 => ['description' => 'my-studio', 'sourceNets' => 'mac:' . MAC1 . ',mac:' . MAC2],
            $u3 => ['description' => 'my-iMac', 'sourceNets' => 'mac:' . MAC2],
            '11111111-0000-4000-8000-000000000000' => ['description' => 'ip only', 'sourceNets' => '10.0.0.9'],
        ];
        $name = mac_alias();
        $check('name format', preg_match('/^ar_[0-9a-f]{8}_mac$/', $name) === 1 && strlen($name) < 32);
        $check('owner parsed', Sources::aliasOwner($name, Sources::aliasDescription(UUID, 'x')) === UUID);
        $check('no marker, not owned', Sources::aliasOwner($name, 'my own alias') === null);
        $check('marker of other rule, not owned', Sources::aliasOwner($name, Sources::aliasDescription($u2, 'x')) === null);
        $aliases = [
            // current, unchanged
            alias_row('a1', mac_alias($u2), MAC1 . "\n" . MAC2, Sources::aliasDescription($u2, 'my-studio')),
            // owned, content changed -> update
            alias_row('a2', mac_alias($u3), MAC1, Sources::aliasDescription($u3, 'my-iMac')),
            // owned, rule deleted -> delete
            alias_row('a3', mac_alias($gone), MAC1, Sources::aliasDescription($gone, 'old')),
            // user aliases: never touched, even with a look-alike name
            alias_row('a4', 'ar_12345678_mac', MAC1, 'my own alias'),
            alias_row('a5', 'Kids_MAC', MAC2, 'Managed by App Router (rule ' . $gone . ') fake'),
        ];
        $p = Sources::planAliases($rules, $aliases);
        $check('add for new rule', $p['add'] === [[$name, MAC1, Sources::aliasDescription(UUID, 'my-mbp')]]);
        $check('update changed', array_keys($p['update']) === ['a2'] && $p['update']['a2'][1] === MAC2);
        $check('delete orphan only', $p['delete'] === ['a3']);
        $check('no conflicts', $p['conflicts'] === []);
        // a foreign alias already uses the rule's name: reported, left alone
        $p = Sources::planAliases([UUID => $rules[UUID]], [alias_row('f1', $name, '10.0.0.0/8', 'mine', 'network')]);
        $check('conflict reported', isset($p['conflicts'][$name]));
        $check('foreign alias untouched', $p['add'] === [] && $p['update'] === [] && $p['delete'] === []);
        // MACs removed from the rule -> its alias is deleted
        $p = Sources::planAliases([$u3 => ['description' => 'my-iMac', 'sourceNets' => '192.168.70.171/32']], $aliases);
        $check('delete when MACs removed', $p["delete"] === ["a1", "a2", "a3"] && $p["add"] === []);
    });

    run_case('rule_mac_only', function ($check) {
        [$fw, $dir] = hook([mkrule(['sourceNets' => 'mac:' . MAC1])], ALIASES, null, [mac_alias()]);
        $t = client_table();
        $check('one rule', count($fw->rules) === 1);
        $check('from managed alias', ($fw->rules[0]['from'] ?? null) === '<' . mac_alias() . '>');
        $check('no client table', !isset($fw->tables[$t]) && !file_exists("$dir/$t.txt"));
        $check('alias sidecar for dns_watcher', @file_get_contents("$dir/$t.aliases") === mac_alias() . "\n");
    });

    run_case('rule_mixed_mac_ip_alias', function ($check) {
        [$fw, $dir] = hook([mkrule(['sourceNets' => '10.10.0.4/32,mac:' . MAC1 . ',Kids_MAC,' . MAC2])], ALIASES, null, [mac_alias()]);
        $t = client_table();
        $check('from = clients, alias, managed alias',
            ($fw->rules[0]['from'] ?? null) === "<$t>,<Kids_MAC>,<" . mac_alias() . '>');
        $check('only IPs in client file', @file_get_contents("$dir/$t.txt") === "10.10.0.4/32\n");
        $check('sidecar', @file_get_contents("$dir/$t.aliases") === "Kids_MAC\n" . mac_alias() . "\n");
        [$fw] = hook([mkrule(['sourceNets' => 'Kids_MAC,mac:' . MAC1])], ALIASES, null, [mac_alias()]);
        $check('mac + alias', ($fw->rules[0]['from'] ?? null) === '<Kids_MAC>,<' . mac_alias() . '>');
    });

    run_case('rule_mac_alias_missing', function ($check) {
        [$fw] = hook([mkrule(['sourceNets' => 'mac:' . MAC1])], ALIASES, null, []);
        $check('MAC-only rule skipped, never any', $fw->rules === []);
        [$fw] = hook([mkrule(['sourceNets' => 'mac:' . MAC1 . ',10.0.0.1'])], ALIASES, null, []);
        $check('IP part kept', count($fw->rules) === 1 && $fw->rules[0]['from'] === '<' . client_table() . '>');
        [$fw] = hook([mkrule(['sourceNets' => 'mac:' . MAC1])], ALIASES, null, null);
        $check('alias model unreadable: referenced by name', ($fw->rules[0]['from'] ?? null) === '<' . mac_alias() . '>');
    });

    run_case('kill_switch_block_behind_every_route', function ($check) {
        [$fw] = hook([mkrule(['customDomains' => 'example.cn']),
                      mkrule(['uuid' => '700da3ee-0000-4000-8000-000000000002',
                              'gateway' => 'WAN_DHCP', 'customDomains' => 'example.org',
                              'sourceNets' => 'Kids_MAC'])]);
        $check('some routes', count($fw->rules) >= 4);
        $check('as many blocks as routes', count($fw->blocks) === count($fw->rules));
        $ok = true;
        for ($i = 0; $i < count($fw->order); $i += 2) {
            $p = $fw->order[$i];
            $b = $fw->order[$i + 1] ?? [];
            $ok = $ok && ($p['type'] ?? '') === 'pass' && !empty($p['skip_rules_gw_down']) && !empty($p['gateway'])
                && ($b['type'] ?? '') === 'block' && !isset($b['gateway']) && !empty($b['quick'])
                && $b['from'] === $p['from'] && $b['to'] === $p['to'] && $b['interface'] === $p['interface']
                && $b['direction'] === $p['direction'] && $b['prio'] === $p['prio']
                && $b['#ref'] === $p['#ref'] . ':block';
        }
        $check('each pass(route-to, skipped when its gateway is gone) is followed by the same match as block', $ok);
    });

    run_case('existing_rules_identical_output', function ($check) {
        $rules = json_decode(file_get_contents(__DIR__ . '/fixtures/existing_rules.json'), true);
        $expected = json_decode(file_get_contents(__DIR__ . '/fixtures/existing_rules_expected.json'), true);
        $dir = fresh_dir();
        $fw = new \OPNsense\Firewall\Plugin();
        approuter_register_rules($fw, $rules, 'approuter', $dir, ['Kids_MAC'], ['ar_00000000_mac']);
        $files = [];
        foreach (glob("$dir/*") as $f) {
            $files[basename($f)] = file_get_contents($f);
        }
        $got = json_decode(str_replace($dir, '@DIR@', json_encode(
            ['rules' => $fw->rules, 'tables' => $fw->tables, 'files' => $files],
            JSON_UNESCAPED_SLASHES
        )), true);
        $check('pf rules identical to 3f051c9 (plus skip_rules_gw_down)', $got['rules'] == $expected['rules']);
        $check('tables identical', $got['tables'] === $expected['tables']);
        $check('client files identical', $got['files'] === $expected['files']);
        $check('my-mbp via FRP_GW', $got['rules'][0]['gateway'] === 'FRP_GW'
            && file_get_contents("$dir/approuter_clients_a6a42fca.txt") === "192.168.70.124/32\n");
    });

    const LEASES = "1795354775 a8:bb:cc:00:11:22 192.168.70.124 dane-mbp 01:a8:bb:cc:00:11:22\n"
        . "1795302208 3e:22:fb:01:02:03 192.168.70.130 iPhone *\n"
        . "1795302209 00:11:22:33:44:55 192.168.70.140 * *\n"
        . "duid 00:01:00:01:2a:2b:2c:2d\n"
        . "garbage line\n";
    const ARP = "? (192.168.70.1) at 64:62:66:18:39:1d on igc1 permanent [ethernet]\n"
        . "? (192.168.70.90) at 3c:22:fb:1:2:3 on igc1 expires in 1199 seconds [ethernet]\n"
        . "? (192.168.70.124) at a8:bb:cc:00:11:22 on igc1 expires in 600 seconds [ethernet]\n"
        . "? (192.168.70.200) at (incomplete) on igc1 expired [ethernet]\n"
        . "? (198.18.0.1) at 64:62:66:b2:49:0c on igc0 expires in 122 seconds [ethernet]\n"
        . "? (192.168.70.150) at 00:11:22:33:44:55 on igc1 expires in 30 seconds [ethernet]\n";

    function fixture_devices()
    {
        return Sources::buildDevices(Sources::parseLeases(LEASES), Sources::parseArp(ARP));
    }

    run_case('device_options', function ($check) {
        $leases = Sources::parseLeases(LEASES);
        $check('3 v4 leases', count($leases) === 3 && $leases[2]['hostname'] === '');
        $arp = Sources::parseArp(ARP);
        $check('arp: no permanent/incomplete/public', array_column($arp, 'ip') === ['192.168.70.90', '192.168.70.124', '192.168.70.150']);
        $opts = Sources::deviceOptions(fixture_devices());
        $check('keys are mac tokens', array_keys($opts) === [
            'mac:a8:bb:cc:00:11:22', 'mac:3e:22:fb:01:02:03', 'mac:3c:22:fb:01:02:03', 'mac:00:11:22:33:44:55']);
        $check('label', $opts['mac:a8:bb:cc:00:11:22'] === 'dane-mbp · a8:bb:cc:00:11:22 · 192.168.70.124');
        $check('random marked', $opts['mac:3e:22:fb:01:02:03'] === 'iPhone · 3e:22:fb:01:02:03 · 192.168.70.130 · private (random) MAC');
        $check('arp-only device', $opts['mac:3c:22:fb:01:02:03'] === 'unknown · 3c:22:fb:01:02:03 · 192.168.70.90');
        $check('lease + arp ips merged', $opts['mac:00:11:22:33:44:55'] === 'unknown · 00:11:22:33:44:55 · 192.168.70.140, 192.168.70.150');
    });

    run_case('migration_preview', function ($check) {
        $devices = fixture_devices();
        // 192.168.70.90 also claimed by a second MAC: ambiguous, kept
        $amb = $devices + Sources::buildDevices([], Sources::parseArp("? (192.168.70.90) at 00:aa:00:aa:00:aa on igc1 expires in 9 seconds [ethernet]\n"));
        $rules = json_decode(file_get_contents(__DIR__ . '/fixtures/existing_rules.json'), true);
        $byUuid = [];
        foreach ($rules as $r) {
            $byUuid[$r['uuid']] = ['description' => $r['description'], 'sourceNets' => $r['sourceNets']];
        }
        $byUuid['x'] = ['description' => 'mixed', 'sourceNets' => '192.168.70.0/24,192.168.70.124,10.10.0.4/32,Kids_MAC,mac:' . MAC2];
        $p = Sources::migrationPreview($byUuid, $amb);
        $check('only rules with a 1:1 IP', array_column($p, 'description') === ['my-mbp', 'mixed']);
        $check('my-mbp -> its MAC', $p[0]['replace'][0]['entry'] === '192.168.70.124/32' && $p[0]['replace'][0]['mac'] === MAC1);
        $check('subnet, WireGuard IP kept', $p[1]['keep'] === ['192.168.70.0/24', '10.10.0.4/32']);
        $check('no WireGuard rule offered', !in_array('wg-flyer', array_column($p, 'description'), true));
        $new = Sources::applyMigration('192.168.70.124/32,10.10.0.4/32', ['192.168.70.124/32', '10.10.0.4/32'], $devices);
        $check('apply replaces confirmed 1:1 only', $new === 'mac:' . MAC1 . ',10.10.0.4/32');
        $check('apply ignores unconfirmed', Sources::applyMigration('192.168.70.124', [], $devices) === '192.168.70.124');
        $check('apply rechecks ambiguity', Sources::applyMigration('192.168.70.90', ['192.168.70.90'], $amb) === '192.168.70.90');
        $check('apply dedupes', Sources::applyMigration('mac:' . MAC1 . ',192.168.70.124', ['192.168.70.124'], $devices) === 'mac:' . MAC1);
    });

    echo json_encode($results), "\n";
    exit(0);
}
