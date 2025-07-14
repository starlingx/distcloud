#!/usr/bin/env bash

#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Subcloud auto-restore script that orchestrates platform restoration across
# system reboots. Executed by systemd when /opt/platform-backup/auto-restore
# directory is present after subcloud installation.
#
# Restore workflow:
# - First boot: Send install success IPMI event, discover backup file,
#   execute restore playbook, and unlock controller
# - Second boot: Run system restore-complete and send restore complete IPMI event
#
# The auto-restore directory is removed after the script is executed to stop
# the systemd service from triggering again after reboot.

set -euo pipefail

readonly CONFIG_DIR="/opt/platform-backup/auto-restore"
readonly RESTORE_CONFIG="${CONFIG_DIR}/backup_restore_values.yml"
readonly RESTORE_PLAYBOOK_COMPLETE_FLAG="${CONFIG_DIR}/.restore_playbook_complete"
readonly LOG_FILE="/var/log/auto-restore.log"
readonly OPENRC_FILE="/etc/platform/openrc"
readonly ANSIBLE_PLAYBOOK="/usr/share/ansible/stx-ansible/playbooks/restore_platform.yml"

log() {
    local level="${2:-INFO}"
    printf "%(%F %T)T [%s] %s\n" -1 "$level" "$1" | tee -a "$LOG_FILE"
}

send_ipmi_event() {
    local event_type="$1"
    local event_data

    case "$event_type" in
        "install_success")
            event_data="0x04 0xF0 0x01 0x6f 0xff 0xff 0xff # \"Install Completed\""
            ;;
        "restore_complete")
            event_data="0x04 0xF0 0x01 0x6f 0xff 0xff 0xfe # \"Restore Completed\""
            ;;
        "restore_failed")
            event_data="0x04 0xF0 0x01 0x6f 0xff 0xff 0xfd # \"Restore Failed\""
            ;;
        *)
            log "Unknown IPMI event type: $event_type" "ERROR"
            return 1
            ;;
    esac

    temp_file=$(mktemp /tmp/ipmi_event_XXXXXX.txt)

    echo "$event_data" > "$temp_file"

    if retry "send IPMI event ($event_type)" 3 5 "_send_ipmi_command"; then
        log "IPMI event sent successfully: $event_type"
        rm -f "$temp_file"
        return 0
    else
        log "Failed to send IPMI event after retries: $event_type" "ERROR"
        rm -f "$temp_file"
        return 1
    fi
}

cleanup() {
    log "Removing auto-restore directory to prevent future triggers"
    rm -rf "$CONFIG_DIR" || log "Failed to remove auto-restore directory" "WARN"
}

retry() {
    local -r operation="$1" max_attempts="$2" delay="$3"
    local -r command_func="$4"

    local attempt=1

    while (( attempt <= max_attempts )); do
        log "Attempting $operation (attempt $attempt/$max_attempts)"

        if "$command_func"; then
            log "$operation completed successfully"
            return 0
        fi

        log "$operation failed (attempt $attempt)" "WARN"
        if (( attempt < max_attempts )); then
            log "Retrying in ${delay}s..."
            sleep "$delay"
        fi
        ((attempt++))
    done

    log "$operation failed after $max_attempts attempts" "ERROR"
    return 1
}

_source_openrc() {
    # shellcheck disable=SC1090
    source "$OPENRC_FILE" || {
        log "Failed to source openrc" "ERROR"
        return 1
    }
}

_unlock_host() {
    if system host-unlock controller-0 >> "$LOG_FILE" 2>&1; then
        return 0
    fi
    log "Host unlock failed" "ERROR"
    return 1
}

_restore_complete() {
    local output

    # restore-complete doesn't return a non-zero exit code if the command fails
    # because the restore is still in progress, so we need to parse its output instead
    output=$(system restore-complete 2>&1)
    local exit_code=$?

    if [[ -n "$output" ]]; then
        echo "$output" >> "$LOG_FILE"
    fi

    if [[ $exit_code -eq 0 ]] && echo "$output" | grep -q "Restore procedure completed"; then
        return 0
    else
        if [[ $exit_code -ne 0 ]]; then
            log "system restore-complete command failed with exit code $exit_code" "ERROR"
        fi
        return 1
    fi
}

_send_ipmi_command() {
    if ipmitool sel add "$temp_file" 2>&1 | tee -a "$LOG_FILE" > /dev/null; then
        return 0
    fi
    return 1
}

run_restore_playbook() {
    log "Starting automatic restore process"
    export HOME=/home/sysadmin

    if ! ansible-playbook "$ANSIBLE_PLAYBOOK" \
        -e "@${RESTORE_CONFIG}" \
        -e "override_files_dir=${HOME}" >> "$LOG_FILE" 2>&1; then
        log "Restore playbook failed" "ERROR"
        send_ipmi_event "restore_failed"
        return 1
    fi
    return 0
}

find_and_set_backup_filename() {
    log "Checking if backup_filename is already set in config..."

    if grep -q "^backup_filename:" "$RESTORE_CONFIG"; then
        local existing_filename
        existing_filename=$(grep "^backup_filename:" "$RESTORE_CONFIG" | sed 's/backup_filename: *//' | tr -d '"' | tr -d "'")
        log "backup_filename already set to: $existing_filename"
        return 0
    fi

    log "backup_filename not found in config, scanning for backup file..."

    # Get and validate backup directory
    local backup_dir
    if ! backup_dir=$(get_backup_directory); then
        return 1
    fi

    log "Scanning backup directory: $backup_dir"

    # Find backup files matching the pattern *_platform_backup_*.tgz
    local backup_files
    mapfile -t backup_files < <(find "$backup_dir" -maxdepth 1 -name "*_platform_backup_*.tgz" -type f)

    if [[ ${#backup_files[@]} -eq 0 ]]; then
        log "No backup files found matching pattern *_platform_backup_*.tgz in $backup_dir" "ERROR"
        return 1
    elif [[ ${#backup_files[@]} -gt 1 ]]; then
        log "Multiple backup files found in $backup_dir:" "ERROR"
        for file in "${backup_files[@]}"; do
            log "  - $(basename "$file")" "ERROR"
        done
        return 1
    fi

    # Set backup_filename in the config file
    local backup_filename
    backup_filename=$(basename "${backup_files[0]}")
    log "Found backup file: $backup_filename"

    set_config_value "backup_filename" "\"$backup_filename\"" "$RESTORE_CONFIG"

    return 0
}

set_config_value() {
    local key="$1"
    local value="$2"
    local config_file="$3"

    if grep -q "^${key}:" "$config_file"; then
        # Update existing value
        sed -i "s/^${key}:.*/${key}: ${value}/" "$config_file"
        log "Updated ${key} to ${value} in config"
    else
        # Add new value
        echo "${key}: ${value}" >> "$config_file"
        log "Added ${key}: ${value} to config"
    fi
}

get_backup_directory() {
    # Extract initial_backup_dir from the config
    local backup_dir
    backup_dir=$(grep "^initial_backup_dir:" "$RESTORE_CONFIG" | sed 's/initial_backup_dir: *//' | tr -d '"' | tr -d "'")

    if [[ -z "$backup_dir" ]]; then
        log "initial_backup_dir not found in config" "ERROR"
        return 1
    fi

    if [[ ! -d "$backup_dir" ]]; then
        log "Backup directory does not exist: $backup_dir" "ERROR"
        return 1
    fi

    echo "$backup_dir"
    return 0
}

check_and_set_registry_restore() {
    log "Checking for image registry backup file..."

    # Get and validate backup directory
    local backup_dir
    if ! backup_dir=$(get_backup_directory); then
        return 1
    fi

    log "Scanning backup directory for image registry backup: $backup_dir"

    # Find image registry backup files matching the pattern *_image_registry_backup_*.tgz
    local registry_backup_files
    mapfile -t registry_backup_files < <(find "$backup_dir" -maxdepth 1 -name "*_image_registry_backup_*.tgz" -type f)

    if [[ ${#registry_backup_files[@]} -gt 0 ]]; then
        log "Found ${#registry_backup_files[@]} image registry backup file(s):"
        for file in "${registry_backup_files[@]}"; do
            log "  - $(basename "$file")"
        done
        set_config_value "restore_registry_filesystem" "true" "$RESTORE_CONFIG"
    else
        log "No image registry backup files found matching pattern *_image_registry_backup_*.tgz"
        # We set restore_registry_filesystem to false so the restore playbook attempts
        # to use the prestaged registry data instead of the registry backup file.
        set_config_value "restore_registry_filesystem" "false" "$RESTORE_CONFIG"
    fi

    return 0
}

handle_first_boot() {
    send_ipmi_event "install_success"

    # The IPMI monitor scripts polls every 30s, and initially it's looking for
    # the install_success event, so we add a 60s pause so the system controller
    # has time to detect the install_success and start to look for the restore
    # events, otherwise, if the restore events are sent too soon, there's a
    # possibility the system controller would miss the event.
    log "Waiting 60 seconds for IPMI monitoring transition..."
    sleep 60

    if ! find_and_set_backup_filename; then
        log "Failed to find or set backup filename" "ERROR"
        send_ipmi_event "restore_failed"
        cleanup
        exit 1
    fi

    if ! check_and_set_registry_restore; then
        log "Failed to check and set registry restore file option" "ERROR"
        send_ipmi_event "restore_failed"
        cleanup
        exit 1
    fi

    if ! run_restore_playbook; then
        cleanup
        exit 1
    fi

    log "Restore playbook completed successfully"
    rm -f "$RESTORE_CONFIG" || log "Failed to remove config file" "WARN"
    touch "$RESTORE_PLAYBOOK_COMPLETE_FLAG" || log "Failed to create flag" "WARN"

    if retry "source openrc" 10 10 "_source_openrc" &&
       retry "host unlock" 10 30 "_unlock_host"; then
        log "Host unlock process completed successfully"
    else
        exit 1
    fi
}

handle_second_boot() {
    log "Detected post-unlock boot, running 'system restore-complete'..."
    if retry "source openrc" 10 10 "_source_openrc" &&
       retry "system restore-complete" 15 10 "_restore_complete"; then
        log "System restore-complete executed successfully"
        send_ipmi_event "restore_complete"
        cleanup
        systemctl disable dc-auto-restore.service
    else
        send_ipmi_event "restore_failed"
        exit 1
    fi
}

main() {
    trap 'log "Script exited with code $?."' EXIT
    trap 'log "An error occurred on line $LINENO." "ERROR"' ERR

    log "===== Starting auto-restore script ====="

    if [[ -f "$RESTORE_CONFIG" ]]; then
        handle_first_boot
    elif [[ -f "$RESTORE_PLAYBOOK_COMPLETE_FLAG" ]]; then
        handle_second_boot
    else
        log "No auto-restore config or flag found - nothing to do"
        cleanup
    fi

    log "===== Auto-restore script completed successfully ====="
}

main "$@"
