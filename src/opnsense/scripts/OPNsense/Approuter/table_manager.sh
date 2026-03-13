#!/bin/sh
#
# AppRouter pf table manager
# Handles atomic updates of pf tables with merged DNS + CIDR data
#

APPROUTER_DIR="/usr/local/etc/app-router"
CIDRS_DIR="${APPROUTER_DIR}/cidrs"
TMPDIR="/tmp/approuter"
TABLE_PREFIX="approuter"
PFCTL="/sbin/pfctl"
LOGGER="/usr/bin/logger"

log_info() {
    ${LOGGER} -t approuter -p daemon.info "$1"
}

log_err() {
    ${LOGGER} -t approuter -p daemon.err "$1"
}

ensure_dirs() {
    mkdir -p "${TMPDIR}"
    chmod 750 "${TMPDIR}"
}

reload_table() {
    local category="$1"
    local table_name="${TABLE_PREFIX}_${category}"
    local cidr_file="${CIDRS_DIR}/${category}.txt"
    local merged_file="${TMPDIR}/${category}_merged.txt"

    if [ -f "${cidr_file}" ]; then
        cp "${cidr_file}" "${merged_file}"
    else
        : > "${merged_file}"
    fi

    ${PFCTL} -t "${table_name}" -T show > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        ${PFCTL} -t "${table_name}" -T replace -f "${merged_file}" 2>/dev/null
        if [ $? -eq 0 ]; then
            local count
            count=$(${PFCTL} -t "${table_name}" -T show | wc -l | tr -d ' ')
            log_info "Table ${table_name} reloaded: ${count} entries"
        else
            log_err "Failed to reload table ${table_name}"
            return 1
        fi
    else
        log_info "Table ${table_name} not yet in pf, skipping reload"
    fi

    rm -f "${merged_file}"
    return 0
}

reload_all() {
    ensure_dirs
    local errors=0

    if [ -d "${CIDRS_DIR}" ]; then
        for cidr_file in "${CIDRS_DIR}"/*.txt; do
            [ -f "${cidr_file}" ] || continue
            local category
            category=$(basename "${cidr_file}" .txt)
            reload_table "${category}" || errors=$((errors + 1))
        done
    fi

    if [ ${errors} -gt 0 ]; then
        log_err "Table reload completed with ${errors} errors"
        return 1
    fi

    log_info "All tables reloaded successfully"
    return 0
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
    local tmpfile="${TMPDIR}/sync_gw_${gw_table}.txt"
    ensure_dirs
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
