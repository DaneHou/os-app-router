<?php
/*
 * Checks for src/opnsense/scripts/OPNsense/Approuter/dns_forward.php (planning + rendering).
 * Driven by tests/test_dns_forward.py; prints {"case": [failed checks...]} as JSON.
 */
ob_start();   // the script's shebang line is echoed when it is included
require __DIR__ . '/../../src/opnsense/scripts/OPNsense/Approuter/dns_forward.php';
ob_end_clean();

$results = [];
function run_case($name, $fn)
{
    global $results;
    $failed = [];
    $fn(function ($label, $ok) use (&$failed) {
        if (!$ok) {
            $failed[] = $label;
        }
    });
    $results[$name] = $failed;
}

const U1 = '700da3ee-0000-4000-8000-000000000001';
const U2 = '700da3ee-0000-4000-8000-000000000002';

function rule(array $over = [])
{
    return array_merge([
        'uuid' => U1, 'description' => 'wg-iphone', 'categories' => ['video.iqiyi'],
        'customDomains' => false, 'gateway' => 'FRP_GW', 'dnsServer' => '223.6.6.6',
    ], $over);
}

$GW = [
    'FRP_GW' => ['if' => 'pgw_China', 'gateway' => '172.31.175.170', 'fargw' => true],
    'WAN2' => ['if' => 'igc3', 'gateway' => '10.0.0.1', 'fargw' => false],
];
$MAP = [
    'approuter_video_iqiyi' => ['iqiyi.com', 'qy.net', '*.iqiyipic.com', 'bad domain!', 'IQIYI.COM.'],
    'approuter_video_youku' => ['youku.com', 'qy.net'],
    'approuter_custom_' . substr(md5(U2), 0, 8) => ['example.cn'],
];

run_case('basic_plan', function ($check) use ($GW, $MAP) {
    $p = ar_plan([rule()], $MAP, $GW);
    $check('zones', array_keys($p['zones']) === ['iqiyi.com', 'iqiyipic.com', 'qy.net']);
    $check('dns', array_values(array_unique($p['zones'])) === ['223.6.6.6']);
    $check('route', $p['routes'] === [['dns' => '223.6.6.6', 'interface' => 'pgw_China', 'gateway' => '172.31.175.170', 'far' => true]]);
    $check('no warnings', $p['warnings'] === []);
});

run_case('custom_domains_and_china_all', function ($check) use ($GW, $MAP) {
    $p = ar_plan([rule(['uuid' => U2, 'categories' => ['china_all'], 'customDomains' => true])], $MAP, $GW);
    $check('custom table used', array_keys($p['zones']) === ['example.cn']);
    $check('china_all warned', count(preg_grep('/china_all/', $p['warnings'])) === 1);
});

run_case('first_rule_wins', function ($check) use ($GW, $MAP) {
    $p = ar_plan([
        rule(),
        rule(['uuid' => U2, 'description' => 'other', 'categories' => ['video.youku'], 'gateway' => 'WAN2', 'dnsServer' => '1.1.1.1']),
    ], $MAP, $GW);
    $check('qy.net stays with first rule', $p['zones']['qy.net'] === '223.6.6.6');
    $check('youku via second', $p['zones']['youku.com'] === '1.1.1.1');
    $check('two routes', count($p['routes']) === 2);
    $check('overlap warned', count(preg_grep('/qy\.net already resolved/', $p['warnings'])) === 1);
});

run_case('shared_domains_same_dns', function ($check) use ($GW, $MAP) {
    $p = ar_plan([rule(), rule(['uuid' => U2, 'description' => 'wg-mbp'])], $MAP, $GW);
    $check('no warnings', $p['warnings'] === []);
    $check('one route', count($p['routes']) === 1);
});

run_case('dns_server_gateway_conflict', function ($check) use ($GW, $MAP) {
    $p = ar_plan([rule(), rule(['uuid' => U2, 'description' => 'other', 'categories' => ['video.youku'], 'gateway' => 'WAN2'])], $MAP, $GW);
    $check('second rule skipped', !isset($p['zones']['youku.com']));
    $check('one route', count($p['routes']) === 1);
    $check('conflict warned', count(preg_grep('/already routed via another gateway/', $p['warnings'])) === 1);
});

run_case('invalid_inputs', function ($check) use ($GW, $MAP) {
    $p = ar_plan([rule(['dnsServer' => 'x']), rule(['gateway' => 'NOPE']), rule(['categories' => ['video.none']])], $MAP, $GW);
    $check('nothing planned', $p['zones'] === [] && $p['routes'] === []);
    $check('three warnings', count($p['warnings']) === 3);
});

run_case('domain_cap', function ($check) use ($GW) {
    $many = [];
    for ($i = 0; $i < 20; $i++) {
        $many[] = "d{$i}.cn";
    }
    $p = ar_plan([rule()], ['approuter_video_iqiyi' => $many], $GW, 'approuter', 5);
    $check('capped', count($p['zones']) === 5);
    $check('cap warned', count(preg_grep('/more than 5 domains/', $p['warnings'])) === 1);
});

run_case('render', function ($check) {
    $check('empty', ar_render_unbound([]) === '');
    $c = ar_render_unbound(['iqiyi.com' => '223.6.6.6']);
    $check('zone', strpos($c, "forward-zone:\n    name: \"iqiyi.com.\"\n    forward-addr: 223.6.6.6\n    forward-tcp-upstream: yes\n") !== false);
});

echo json_encode($results), "\n";
exit(0);
