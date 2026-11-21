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
        public $rules = [];
        public function registerTable($name, $persist = false, $file = null)
        {
            $this->tables[$name] = ['persist' => $persist, 'file' => $file];
        }
        public function registerFilterRule($prio, $conf, $defaults = null)
        {
            $this->rules[] = ['prio' => $prio] + array_merge($defaults ?? [], $conf);
        }
    }
}

namespace {
    require __DIR__ . '/../../src/etc/inc/plugins.inc.d/approuter.inc';

    const ALIASES = ['Kids_MAC', 'Family', '__lan_network'];
    const UUID = '700da3ee-0000-4000-8000-000000000001';

    function mkrule(array $over = [])
    {
        return array_merge([
            'uuid' => UUID, 'description' => 'my-mbp', 'sourceNets' => '192.168.70.124/32',
            'categories' => ['video.iqiyi'], 'customDomains' => '', 'gateway' => 'FRP_GW',
            'interface' => 'opt1', 'smartGateway' => '0',
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
    function hook(array $rules, $aliases = ALIASES, $dir = null)
    {
        $fw = new \OPNsense\Firewall\Plugin();
        $dir = $dir ?? fresh_dir();
        $valid = approuter_register_rules($fw, $rules, 'approuter', $dir, $aliases);
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
        [$fw] = hook([mkrule(['sourceNets' => '10.0.0.1,Family', 'gateway' => 'WAN_DHCP,FRP_GW', 'smartGateway' => '1',
                              'customDomains' => 'example.com'])]);
        foreach (['approuter_video_iqiyi', 'approuter_video_iqiyi_gw0', 'approuter_custom_' . substr(md5(UUID), 0, 8)] as $t) {
            $check("$t persistent without file", ($fw->tables[$t] ?? null) === ['persist' => true, 'file' => null]);
        }
        $check('client table has file', !empty($fw->tables[client_table()]['file']));
    });

    run_case('smart_gateway_rules_use_alias_sources', function ($check) {
        [$fw, , $valid] = hook([mkrule(['sourceNets' => 'Kids_MAC', 'gateway' => 'WAN_DHCP,FRP_GW', 'smartGateway' => '1'])]);
        $check('gw rule + fallback rule', count($fw->rules) === 2);
        $check('gw0 rule', $fw->rules[0]['to'] === '<approuter_video_iqiyi_gw0>' && $fw->rules[0]['gateway'] === 'WAN_DHCP');
        $check('fallback rule', $fw->rules[1]['to'] === '<approuter_video_iqiyi>' && $fw->rules[1]['gateway'] === 'FRP_GW');
        $check('both from alias', $fw->rules[0]['from'] === '<Kids_MAC>' && $fw->rules[1]['from'] === '<Kids_MAC>');
        $check('valid gw tables', $valid['gwTables'] === ['approuter_video_iqiyi_gw0']);
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

    echo json_encode($results), "\n";
    exit(0);
}
