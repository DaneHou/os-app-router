#!/bin/sh
# AppRouter Diagnostic Script
# Run on the OPNsense firewall: sh diagnose.sh [domain]
# Example: sh diagnose.sh iqiyi.com

DOMAIN="${1:-iqiyi.com}"
CONFIG_DIR="/usr/local/etc/app-router"
UNBOUND_DIR="$CONFIG_DIR/unbound.d"

echo "========================================"
echo " AppRouter Diagnostics: $DOMAIN"
echo "========================================"

# 1. Config check
echo ""
echo "--- 1. Config ---"
if [ -f "$CONFIG_DIR/config.json" ]; then
    echo "config.json exists"
    python3 -c "
import json
with open('$CONFIG_DIR/config.json') as f:
    cfg = json.load(f)
print(f\"  enabled: {cfg.get('enabled')}\")
print(f\"  dns_resolver: {cfg.get('dns_resolver')}\")
rules = cfg.get('rules', [])
print(f\"  rules: {len(rules)}\")
for i, r in enumerate(rules):
    cats = r.get('categories', '')
    custom = r.get('custom_domains', '')
    print(f\"    [{i}] gw={r.get('gateway')} cats={cats} custom={custom}\")
"
else
    echo "ERROR: config.json not found!"
fi

# 2. Domain mapping check
echo ""
echo "--- 2. Domain Mappings for '$DOMAIN' ---"
python3 -c "
import json, os
from pathlib import Path
domain = '$DOMAIN'.lower()
found = False
for f in sorted(Path('$UNBOUND_DIR').glob('approuter_*.json')):
    with open(f) as fh:
        data = json.load(fh)
    table = data.get('table', '')
    domains = [d.lower() for d in data.get('domains', [])]
    if domain in domains:
        print(f'  {f.name}: {domain} -> {table}')
        found = True
if not found:
    print(f'  WARNING: {domain} not found in any mapping file!')
    print(f'  Available files:')
    for f in sorted(Path('$UNBOUND_DIR').glob('approuter_*.json')):
        with open(f) as fh:
            data = json.load(fh)
        count = len(data.get('domains', []))
        print(f'    {f.name}: {data.get(\"table\",\"\")} ({count} domains)')
"

# 3. pf tables check
echo ""
echo "--- 3. PF Tables (approuter_*) ---"
/sbin/pfctl -s Tables 2>/dev/null | grep "^approuter_" | while read table; do
    count=$(/sbin/pfctl -t "$table" -T show 2>/dev/null | wc -l | tr -d ' ')
    echo "  $table: $count entries"
done

# 4. Check if domain's IPs are in any table
echo ""
echo "--- 4. DNS Resolution + Table Lookup for '$DOMAIN' ---"
echo "  Resolving $DOMAIN via Unbound..."
IPS=$(/usr/bin/drill @127.0.0.1 -p 53530 "$DOMAIN" A 2>/dev/null | awk '/^;; ANSWER/{f=1;next} /^;;/{f=0} f && /\tA\t/{print $5}')
if [ -z "$IPS" ]; then
    # Try default port
    IPS=$(/usr/bin/drill @127.0.0.1 "$DOMAIN" A 2>/dev/null | awk '/^;; ANSWER/{f=1;next} /^;;/{f=0} f && /\tA\t/{print $5}')
fi
if [ -z "$IPS" ]; then
    echo "  WARNING: Could not resolve $DOMAIN"
else
    echo "  Resolved IPs: $IPS"
    for ip in $IPS; do
        echo "  Checking which tables contain $ip..."
        /sbin/pfctl -s Tables 2>/dev/null | grep "^approuter_" | while read table; do
            if /sbin/pfctl -t "$table" -T test "$ip" 2>/dev/null | grep -q "1/1"; then
                echo "    FOUND in $table"
            fi
        done
    done
fi

# 5. Also check www subdomain
echo ""
echo "  Resolving www.$DOMAIN..."
WWW_IPS=$(/usr/bin/drill @127.0.0.1 "www.$DOMAIN" A 2>/dev/null | awk '/^;; ANSWER/{f=1;next} /^;;/{f=0} f && /\tA\t/{print $5}')
if [ -n "$WWW_IPS" ]; then
    echo "  Resolved IPs: $WWW_IPS"
fi

# 6. pf rules check
echo ""
echo "--- 5. PF Filter Rules (approuter) ---"
/sbin/pfctl -s rules 2>/dev/null | grep -i "approuter" | head -20

# 7. dns_watcher status
echo ""
echo "--- 6. DNS Watcher Status ---"
if pgrep -f 'dns_watcher.py' > /dev/null 2>&1; then
    PID=$(pgrep -f 'dns_watcher.py')
    echo "  Running (PID: $PID)"
else
    echo "  NOT RUNNING"
fi
if pgrep -f 'tcpdump.*src port 53' > /dev/null 2>&1; then
    echo "  tcpdump sniffer: running"
    pgrep -af 'tcpdump.*src port 53' | sed 's/^/    /'
else
    echo "  tcpdump sniffer: NOT RUNNING"
fi

# 8. Recent dns_watcher logs
echo ""
echo "--- 7. Recent DNS Watcher Logs ---"
if [ -f /var/log/approuter_dns_watcher.log ]; then
    tail -20 /var/log/approuter_dns_watcher.log
else
    echo "  No log file found"
fi

# 9. Live sniff test
echo ""
echo "--- 8. Live Sniff Test (10 seconds) ---"
echo "  Sniffing DNS responses matching '$DOMAIN' for 10s..."
echo "  (Open $DOMAIN in browser NOW)"
IFACE=$(ifconfig -a | grep -B1 "inet " | grep -v "lo0" | grep -v "127\." | head -1 | cut -d: -f1)
if [ -n "$IFACE" ]; then
    timeout 10 /usr/sbin/tcpdump -l -n -i "$IFACE" "udp and src port 53" -vv 2>/dev/null | grep -i "$DOMAIN" || echo "  No DNS responses captured for $DOMAIN"
else
    echo "  Could not detect interface for sniffing"
fi

echo ""
echo "========================================"
echo " Done"
echo "========================================"
