#!/usr/local/bin/php
<?php
/*
 * dns_forward.php - "Resolve DNS via gateway" for App Router rules.
 *
 * Some CDNs answer by the location of the resolver: a China site resolved from
 * abroad returns an overseas edge, which may redirect to an international site
 * or refuse service, even when the traffic itself is routed through a China
 * gateway. For rules with dnsViaGateway=1 this script makes the domains of the
 * rule's categories resolve through the rule's (first) gateway:
 *
 *   - Unbound forward-zones (TCP) to the rule's DNS server
 *     -> /usr/local/etc/unbound.opnsense.d/approuter_dns.conf
 *   - a host route DNS server -> rule gateway, applied by dns_routes.py and
 *     kept in place by dns_watcher (tunnel interfaces get recreated)
 *     -> /usr/local/etc/app-router/dns_routes.json
 *   - the domain list, for DNS servers in front of Unbound (e.g. AdGuard Home)
 *     -> /usr/local/etc/app-router/dns_via_gateway.txt
 *
 * Unbound is restarted only when its file changed and the new file passes
 * unbound-checkconf. Disabled plugin / no such rules: everything is removed.
 */

const AR_DIR = '/usr/local/etc/app-router';
const AR_MAPPING_DIR = AR_DIR . '/unbound.d';
const AR_UNBOUND_FILE = '/usr/local/etc/unbound.opnsense.d/approuter_dns.conf';
const AR_UNBOUND_CHROOT_FILE = '/var/unbound/etc/approuter_dns.conf';
const AR_ROUTES_FILE = AR_DIR . '/dns_routes.json';
const AR_EXPORT_FILE = AR_DIR . '/dns_via_gateway.txt';
const AR_MAX_DOMAINS = 5000;
const AR_STATUS_FILE = AR_DIR . '/dns_forward_status.json';
const AR_CHECK_LABEL = '_approuter-check';

/**
 * Build table name => domains from the mapping files written by list_updater.
 */
function ar_load_mappings($dir)
{
    $tables = [];
    foreach (glob($dir . '/*.json') ?: [] as $file) {
        $data = json_decode((string)@file_get_contents($file), true);
        if (!is_array($data) || empty($data['table']) || !is_array($data['domains'] ?? null)) {
            continue;
        }
        $tables[$data['table']] = array_merge($tables[$data['table']] ?? [], $data['domains']);
    }
    return $tables;
}

function ar_clean_domain($d)
{
    $d = strtolower(trim((string)$d));
    if (strpos($d, '*.') === 0) {
        $d = substr($d, 2);
    }
    $d = rtrim($d, '.');
    return preg_match('/^[a-z0-9_]([a-z0-9_\-]*\.)*[a-z0-9\-]+$/', $d) ? $d : null;
}

/**
 * Pure planning step (unit tested).
 *
 * $rules:    list of ['uuid','description','categories'(array),'customDomains'(bool),
 *            'gateway'(first gateway name),'dnsServer']
 * $mappings: table => domains
 * $gateways: name => ['if' => device, 'gateway' => ip, 'fargw' => bool]
 *
 * Returns ['zones' => domain => dnsServer, 'routes' => [...], 'warnings' => [...]]
 */
function ar_plan(array $rules, array $mappings, array $gateways, $prefix = 'approuter', $maxDomains = AR_MAX_DOMAINS)
{
    $zones = [];
    $routes = [];      // dnsServer => route
    $warnings = [];
    foreach ($rules as $rule) {
        $name = $rule['description'] !== '' ? $rule['description'] : $rule['uuid'];
        $dns = trim((string)$rule['dnsServer']);
        if (!filter_var($dns, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $warnings[] = "rule {$name}: invalid DNS server '{$dns}', skipped";
            continue;
        }
        $gw = $gateways[$rule['gateway']] ?? null;
        if ($gw === null || !filter_var($gw['gateway'] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || empty($gw['if'])) {
            $warnings[] = "rule {$name}: gateway '{$rule['gateway']}' not found or has no IPv4 address, skipped";
            continue;
        }
        $route = ['dns' => $dns, 'interface' => $gw['if'], 'gateway' => $gw['gateway'], 'far' => !empty($gw['fargw'])];
        if (isset($routes[$dns]) && $routes[$dns] != $route) {
            $warnings[] = "rule {$name}: DNS server {$dns} is already routed via another gateway, skipped (use a different DNS server)";
            continue;
        }

        $tables = [];
        foreach ($rule['categories'] as $cat) {
            $cat = trim($cat);
            if ($cat === '') {
                continue;
            }
            if ($cat === 'china_all') {
                $warnings[] = "rule {$name}: china_all is an IP list, it has no domains to resolve";
                continue;
            }
            $tables[] = $prefix . '_' . str_replace('.', '_', $cat);
        }
        if (!empty($rule['customDomains'])) {
            $tables[] = $prefix . '_custom_' . substr(md5($rule['uuid']), 0, 8);
        }

        $added = 0;
        foreach ($tables as $table) {
            foreach ($mappings[$table] ?? [] as $d) {
                $d = ar_clean_domain($d);
                if ($d === null) {
                    continue;
                }
                if (isset($zones[$d])) {
                    if ($zones[$d] !== $dns) {
                        $warnings[] = "rule {$name}: {$d} already resolved via {$zones[$d]} by an earlier rule";
                    } else {
                        $added++;   // same domain, same DNS server: covered by an earlier rule
                    }
                    continue;
                }
                if (count($zones) >= $maxDomains) {
                    $warnings[] = "more than {$maxDomains} domains, the rest is not forwarded";
                    break 3;
                }
                $zones[$d] = $dns;
                $added++;
            }
        }
        if ($added > 0) {
            $routes[$dns] = $route;
        } else {
            $warnings[] = "rule {$name}: no domains to resolve via gateway";
        }
    }
    ksort($zones);
    return ['zones' => $zones, 'routes' => array_values($routes), 'warnings' => array_values(array_unique($warnings))];
}

function ar_render_unbound(array $zones)
{
    if (empty($zones)) {
        return '';
    }
    $out = "# Generated by App Router (rules with \"Resolve DNS via gateway\"). Do not edit.\n";
    // marker record: a TXT query for it through port 53 shows whether queries reach Unbound
    $out .= "server:\n    local-data: \"" . ar_check_name($zones) . ". 60 IN TXT approuter\"\n";
    foreach ($zones as $domain => $dns) {
        $out .= "forward-zone:\n    name: \"{$domain}.\"\n    forward-addr: {$dns}\n    forward-tcp-upstream: yes\n";
    }
    return $out;
}

function ar_check_name(array $zones)
{
    $domains = array_keys($zones);
    sort($domains);
    return AR_CHECK_LABEL . '.' . $domains[0];
}

/**
 * Do clients' DNS queries (port 53) reach Unbound? Another DNS server on port 53
 * (AdGuard Home, dnsmasq, ...) has to forward the zones to Unbound, otherwise the
 * forward-zones have no effect. Asks port 53 for the marker TXT record.
 */
function ar_dns_check(array $zones, $unboundPort)
{
    $owner = '';
    exec('/usr/bin/sockstat -46 -l -p 53 2>/dev/null', $lines);
    foreach (array_slice($lines, 1) as $line) {
        $cols = preg_split('/\s+/', trim($line));
        if (count($cols) > 5 && preg_match('/[.:*]53$/', $cols[5])) {
            $owner = $cols[1];
            break;
        }
    }
    $name = ar_check_name($zones);
    $ok = false;
    for ($i = 0; $i < 5 && !$ok; $i++) {
        if ($i > 0) {
            sleep(1);       // Unbound may still be starting
        }
        $out = [];
        exec('/usr/bin/drill -Q ' . escapeshellarg($name) . ' TXT @127.0.0.1 2>/dev/null', $out);
        $ok = strpos(implode("\n", $out), 'approuter') !== false;
    }
    return ['checked' => time(), 'zones' => count($zones), 'port53' => $owner,
            'unbound_port' => (int)$unboundPort, 'reaches_unbound' => $ok];
}

function ar_write_if_changed($file, $content)
{
    if (is_file($file) && (string)file_get_contents($file) === $content) {
        return false;
    }
    if ($content === '') {
        if (is_file($file)) {
            unlink($file);
            return true;
        }
        return false;
    }
    @mkdir(dirname($file), 0755, true);
    file_put_contents($file . '.tmp', $content);
    rename($file . '.tmp', $file);
    return true;
}

/* Syntax check of our file alone (the full Unbound config needs its chroot and python module). */
function ar_unbound_check($content)
{
    $dir = sys_get_temp_dir() . '/approuter-unbound-check-' . getmypid();
    @mkdir($dir, 0700);
    file_put_contents("$dir/zones.conf", $content);
    file_put_contents("$dir/unbound.conf", "server:\n    chroot: \"\"\n    username: \"\"\n    directory: \"$dir\"\n    module-config: \"iterator\"\ninclude: \"$dir/zones.conf\"\n");
    exec('/usr/local/sbin/unbound-checkconf ' . escapeshellarg("$dir/unbound.conf") . ' 2>&1', $out, $rc);
    @unlink("$dir/zones.conf");
    @unlink("$dir/unbound.conf");
    @rmdir($dir);
    return [$rc === 0, implode(' ', $out)];
}

function ar_log($msg, $prio = LOG_INFO)
{
    syslog($prio, 'approuter: dns_forward: ' . $msg);
    echo $msg . "\n";
}

function ar_main()
{
    require_once 'script/load_phalcon.php';
    openlog('approuter', LOG_PID, LOG_DAEMON);

    $mdl = new \OPNsense\Approuter\Approuter();
    $prefix = (string)$mdl->general->tablePrefix ?: 'approuter';
    $rules = [];
    if ((string)$mdl->general->enabled === '1') {
        foreach ($mdl->rules->rule->iterateItems() as $uuid => $r) {
            if ((string)$r->enabled !== '1' || (string)$r->dnsViaGateway !== '1') {
                continue;
            }
            $gws = array_values(array_filter(array_map('trim', explode(',', (string)$r->gateway))));
            $rules[] = [
                'uuid' => $uuid,
                'description' => (string)$r->description,
                'categories' => explode(',', (string)$r->categories),
                'customDomains' => trim((string)$r->customDomains) !== '',
                'gateway' => $gws[0] ?? '',
                'dnsServer' => (string)$r->dnsServer,
            ];
        }
    }

    $gateways = [];
    if (!empty($rules)) {
        foreach ((new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(false) as $name => $g) {
            $gateways[$name] = ['if' => $g['if'] ?? '', 'gateway' => $g['gateway'] ?? '', 'fargw' => !empty($g['fargw'])];
        }
    }

    $plan = ar_plan($rules, ar_load_mappings(AR_MAPPING_DIR), $gateways, $prefix);
    foreach ($plan['warnings'] as $w) {
        ar_log($w, LOG_WARNING);
    }

    // routes first, so Unbound can reach the DNS server once it restarts
    ar_write_if_changed(AR_ROUTES_FILE, json_encode(['routes' => $plan['routes']], JSON_PRETTY_PRINT) . "\n");
    exec('/usr/local/opnsense/scripts/OPNsense/Approuter/dns_routes.py sync 2>&1', $out);
    foreach ($out as $line) {
        ar_log($line);
    }

    ar_write_if_changed(AR_EXPORT_FILE, empty($plan['zones']) ? '' : implode("\n", array_keys($plan['zones'])) . "\n");

    $conf = ar_render_unbound($plan['zones']);
    $unbound = new \OPNsense\Unbound\Unbound();
    if ($conf !== '' && (string)$unbound->general->enabled !== '1') {
        ar_log('Unbound is disabled: forward-zones not installed (see ' . AR_EXPORT_FILE . ')', LOG_WARNING);
        $conf = '';
    }
    if ($conf !== '') {
        list($ok, $msg) = ar_unbound_check($conf);
        if (!$ok) {
            ar_log("generated Unbound config rejected by unbound-checkconf, not installed: {$msg}", LOG_ERR);
            return 1;
        }
    }
    if (ar_write_if_changed(AR_UNBOUND_FILE, $conf)) {
        if ($conf === '') {
            // Unbound's start copies unbound.opnsense.d into its chroot, it doesn't remove stale copies
            @unlink(AR_UNBOUND_CHROOT_FILE);
        }
        exec('/usr/local/sbin/configctl unbound restart 2>&1');
        ar_log(sprintf('Unbound forward-zones updated: %d domains, restarted Unbound', count($plan['zones'])));
    } else {
        ar_log(sprintf('Unbound forward-zones unchanged (%d domains)', count($plan['zones'])));
    }

    $status = ['checked' => time(), 'zones' => 0];
    if ($conf !== '') {
        $status = ar_dns_check($plan['zones'], (string)$unbound->general->port ?: 53);
        if (!$status['reaches_unbound']) {
            ar_log(sprintf('DNS queries on port 53 (%s) do not reach Unbound: forward the domains in %s to Unbound (127.0.0.1:%d)',
                $status['port53'] ?: 'unknown server', AR_EXPORT_FILE, $status['unbound_port']), LOG_WARNING);
        }
    }
    file_put_contents(AR_STATUS_FILE, json_encode($status) . "\n");
    return 0;
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    exit(ar_main());
}
