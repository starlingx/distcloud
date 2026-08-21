#!/bin/bash
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# pre-factory-install-clone.sh — Run on the source system before capturing
# a golden image.
# Prepares the system so the clone boots cleanly on target hardware
# without any post-clone manual intervention, then powers the system off
# gracefully so the captured image is filesystem-consistent.
#
# This script is idempotent — safe to run multiple times.

set -euo pipefail

SCRIPT_NAME=$(basename "$0")

# Seconds to wait before powering off, allowing the operator to abort.
# Set POWEROFF_DELAY=0 for unattended use.
POWEROFF_DELAY="${POWEROFF_DELAY:-10}"

# Whether to power the system off once preparation completes.
# Disabled by the --no-poweroff option.
POWEROFF="true"

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Prepare this system for golden image capture (factory installed machine).

Run this on the SOURCE system immediately before capturing the image.
It performs the following steps:

  1. Stage the LUKS data.
  2. Remove the encrypted vault and its state file.
  3. Create the /etc/platform/.cloned_install flag, required by the
     restored machine.
  4. Remove the DRBD resize flag, so DRBD is resized on the restored
     machine.
  5. Cordon and drain the Kubernetes node, so the restored machine does
     not come up with pods in Error state.
  6. Power off gracefully, unless --no-poweroff is given.

This script is idempotent and may be run more than once.

Options:
  -n, --no-poweroff   Run all preparation steps but leave the system
                      running. Power it off manually before capturing
                      the image.
  -h, --help          Show this help text and exit.

Environment:
  POWEROFF_DELAY      Seconds to wait before powering off, to allow
                      aborting with Ctrl-C. Defaults to 10.
                      Ignored with --no-poweroff.

Examples:
  # Standard factory flow: prepare, then power off after a 10s grace period.
  sudo ${SCRIPT_NAME}

  # Prepare only, then inspect the system and shut it down manually.
  sudo ${SCRIPT_NAME} --no-poweroff

  # Unattended run with no abort window.
  sudo POWEROFF_DELAY=0 ${SCRIPT_NAME}
EOF
}

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ${SCRIPT_NAME}: $*"
}

die() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] ${SCRIPT_NAME}: $*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--no-poweroff)
            POWEROFF="false"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "${SCRIPT_NAME}: unknown option '$1'" >&2
            echo "Try '${SCRIPT_NAME} --help' for more information." >&2
            exit 1
            ;;
    esac
done

[[ $(id -u) -eq 0 ]] || die "Must be run as root"

log_info "Starting pre-clone preparation"

log_info "Stage LUKS data"
if [[ -d /var/luks/stx/luks_fs/ && ! -d /var/luks/stx/.clone_staging/ ]]; then
    cp -a /var/luks/stx/luks_fs/ /var/luks/stx/.clone_staging/ \
        || die "Failed to stage LUKS data"
else
    log_info "LUKS data already staged or source missing, skipping"
fi

log_info "Remove encrypted vault and state file"
rm -f /var/luks/stx/luks_volume.img
rm -f /etc/luks-fs-mgr.d/created_luks.json

log_info "Touch golden image flag"
touch /etc/platform/.cloned_install || die "Failed to touch .cloned_install"

log_info "Remove DRBD resize flag"
rm -f /etc/platform/.cfs_drbdadm_reconfigured

# Drain the node to avoid dead/zombie pods (Error state) on the target
# after image restore. This leverages the same cordon+drain mechanism
# used during host-unlock (force_pod_drain). On first boot, the
# k8s-pod-recovery service will uncordon the node and all pods will
# be freshly recreated by their controllers.
log_info "Drain node to prevent zombie pods on target"
KUBECONFIG="--kubeconfig=/etc/kubernetes/admin.conf"
if [[ ! -f /etc/platform/.reboot_cordoned ]]; then
    kubectl drain "$(hostname)" ${KUBECONFIG} \
        --ignore-daemonsets --delete-emptydir-data --force \
        --disable-eviction=true --timeout=120s || true
    touch /etc/platform/.reboot_cordoned
    log_info "Node drained and cordoned"
else
    log_info "Node already cordoned, skipping drain"
fi

log_info "Pre-clone preparation complete"

if [[ "${POWEROFF}" != "true" ]]; then
    log_info "Skipping poweroff as requested (--no-poweroff)"
    log_info "Power the system off before capturing the image:"
    log_info "    sudo systemctl poweroff"
    exit 0
fi

# Graceful shutdown so the captured image has consistent filesystem state.
# This lets systemd stop services in order, unmount/detach DRBD cleanly and
# flush etcd, avoiding journal replay or a DRBD resync on the target's
# first boot.
log_info "Flushing filesystem buffers"
sync

log_info "Powering off gracefully in ${POWEROFF_DELAY}s (Ctrl-C to abort)"
sleep "${POWEROFF_DELAY}"

log_info "Initiating graceful poweroff"
systemctl poweroff
