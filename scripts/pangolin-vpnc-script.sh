#!/bin/sh
# Minimal vpnc-compatible script for Pangolin.
#
# libopenconnect invokes this with `reason=connect|disconnect|pre-init|…`
# and a pile of environment variables (TUNDEV, INTERNAL_IP4_*, etc.).
#
# This script intentionally does very little:
#   1. bring the tun device up + assign the GP-provided IP and MTU
#   2. add any routes listed in $PANGOLIN_ROUTES (space-separated CIDRs)
#   3. do NOT touch the default route, /etc/resolv.conf, or
#      CISCO_SPLIT_INC_* — those are left for a future native
#      gp-route / gp-dns implementation.
#
# The upshot: if PANGOLIN_ROUTES is unset, the tunnel comes up but
# routes nothing (safe for iterative testing over SSH). If it's set,
# we install exactly those routes and nothing else — yielding a
# clean client-controlled split tunnel regardless of what the server
# pushed.

set -e

log() { echo "pangolin-vpnc: $*" >&2; }

case "${reason:-}" in
    pre-init)
        # No-op. On distros where /dev/net/tun needs loading, the
        # kernel usually auto-loads it when libopenconnect opens it.
        ;;
    connect)
        : "${TUNDEV:?TUNDEV not set}"
        log "connect dev=$TUNDEV ip=${INTERNAL_IP4_ADDRESS:-?} mtu=${INTERNAL_IP4_MTU:-?}"

        ip link set dev "$TUNDEV" up
        if [ -n "${INTERNAL_IP4_MTU:-}" ]; then
            ip link set dev "$TUNDEV" mtu "$INTERNAL_IP4_MTU"
        fi
        if [ -n "${INTERNAL_IP4_ADDRESS:-}" ]; then
            # /32 on a point-to-point tun is the standard openconnect
            # pattern; remote peer gets picked up from the tunnel itself.
            ip addr add "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV" 2>/dev/null \
                || ip addr replace "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV"
        fi

        if [ -n "${PANGOLIN_ROUTES:-}" ]; then
            for route in $PANGOLIN_ROUTES; do
                log "add route $route via $TUNDEV"
                ip route add "$route" dev "$TUNDEV" 2>/dev/null \
                    || ip route replace "$route" dev "$TUNDEV"
            done
        else
            log "PANGOLIN_ROUTES unset — interface up, no routes installed"
        fi
        ;;
    disconnect)
        log "disconnect dev=${TUNDEV:-?}"
        # libopenconnect tears the interface down for us when the
        # main loop returns; explicit cleanup here would just race it.
        ;;
    reconnect|attempt-reconnect)
        log "reconnect dev=${TUNDEV:-?}"
        ;;
    *)
        log "ignoring reason=${reason:-<unset>}"
        ;;
esac

exit 0
