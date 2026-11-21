#!/bin/sh
#
# AppRouter pf table manager
# Handles atomic updates of pf tables with merged DNS + CIDR data
#

APPROUTER_DIR="/usr/local/etc/app-router"
CIDRS_DIR="${APPROUTER_DIR}/cidrs"
WORKDIR=""
PFCTL="/sbin/pfctl"
LOGGER="/usr/bin/logger"

# Use the configured table prefix (must match the PHP firewall hook)
TABLE_PREFIX=$(sed -n 's/^[[:space:]]*"table_prefix":[[:space:]]*"\([a-z][a-z0-9_]*\)".*/\1/p' \
    "${APPROUTER_DIR}/config.json" 2>/dev/null | head -n 1)
TABLE_PREFIX="${TABLE_PREFIX:-approuter}"

log_info() {
    ${LOGGER} -t approuter -p daemon.info "$1"
}

log_err() {
    ${LOGGER} -t approuter -p daemon.err "$1"
}

ensure_dirs() {
    # private per-run directory; a fixed /tmp path could be pre-created
    # (or symlinked) by another local user and is written to as root
    if [ -z "${WORKDIR}" ]; then
        WORKDIR=$(mktemp -d -t approuter) || exit 1
        trap 'rm -rf "${WORKDIR}"' EXIT
    fi
}

SYNC="/usr/local/opnsense/scripts/OPNsense/Approuter/static_sync.py"

# Static CIDR lists are merged into the category tables by static_sync.py:
# never `pfctl -T replace` a category table, that drops the IPs dns_watcher
# learned from DNS answers (clients keep their DNS cache, so they would not be
# relearned for a while and the traffic leaves via the default gateway).
reload_table() {
    "${SYNC}" "$1"
}

reload_all() {
    if "${SYNC}" all; then
        log_info "All static lists merged into pf tables"
        return 0
    fi
    log_err "Static list merge failed"
    return 1
}

show_table() {
    local category="$1"
    local table_name="${TABLE_PREFIX}_${category}"
    ${PFCTL} -t "${table_name}" -T show 2>/dev/null
}

show_all() {
    ${PFCTL} -s Tables 2>/dev/null | grep "^${TABLE_PREFIX}_" | while read -r table; do
        echo "=== ${table} ==="
        ${PFCTL} -t "${table}" -T show 2>/dev/null | wc -l | xargs echo "  Entries:"
    done
}

flush_all() {
    ${PFCTL} -s Tables 2>/dev/null | grep "^${TABLE_PREFIX}_" | while read -r table; do
        ${PFCTL} -t "${table}" -T flush 2>/dev/null
        log_info "Flushed table ${table}"
    done
}

add_to_table() {
    local table_name="$1"
    shift
    for ip in "$@"; do
        ${PFCTL} -t "${table_name}" -T add "${ip}" 2>/dev/null
    done
}

sync_gw() {
    local base_table="$1"
    local gw_index="$2"
    local gw_table="${base_table}_gw${gw_index}"

    # Copy all IPs from main table to gateway table
    local ips
    ips=$(${PFCTL} -t "${base_table}" -T show 2>/dev/null)
    if [ -z "${ips}" ]; then
        log_info "sync_gw: main table ${base_table} is empty, nothing to copy"
        return 0
    fi

    # Use replace to atomically set the gw table contents
    ensure_dirs
    local tmpfile="${WORKDIR}/sync_gw_${gw_table}.txt"
    ${PFCTL} -t "${base_table}" -T show 2>/dev/null | sed 's/^ *//' > "${tmpfile}"
    ${PFCTL} -t "${gw_table}" -T replace -f "${tmpfile}" 2>/dev/null
    local count
    count=$(wc -l < "${tmpfile}" | tr -d ' ')
    rm -f "${tmpfile}"
    log_info "sync_gw: copied ${count} entries from ${base_table} to ${gw_table}"
    return 0
}

flush_gw() {
    local base_table="$1"
    local gw_index="$2"
    local gw_table="${base_table}_gw${gw_index}"

    ${PFCTL} -t "${gw_table}" -T flush 2>/dev/null
    log_info "flush_gw: flushed ${gw_table}"
    return 0
}

case "$1" in
    reload)
        if [ -n "$2" ]; then
            ensure_dirs
            reload_table "$2"
        else
            echo "Usage: $0 reload <category>"
            exit 1
        fi
        ;;
    reload_all)
        reload_all
        ;;
    show)
        if [ -n "$2" ]; then
            show_table "$2"
        else
            show_all
        fi
        ;;
    stats)
        show_all
        ;;
    flush)
        flush_all
        ;;
    add)
        if [ -n "$2" ] && [ -n "$3" ]; then
            shift
            add_to_table "$@"
        else
            echo "Usage: $0 add <table_name> <ip> [ip...]"
            exit 1
        fi
        ;;
    sync_gw)
        if [ -n "$2" ] && [ -n "$3" ]; then
            sync_gw "$2" "$3"
        else
            echo "Usage: $0 sync_gw <base_table> <gw_index>"
            exit 1
        fi
        ;;
    flush_gw)
        if [ -n "$2" ] && [ -n "$3" ]; then
            flush_gw "$2" "$3"
        else
            echo "Usage: $0 flush_gw <base_table> <gw_index>"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {reload|reload_all|show|stats|flush|add|sync_gw|flush_gw}"
        exit 1
        ;;
esac
