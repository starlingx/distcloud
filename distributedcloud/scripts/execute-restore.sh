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
            event_data="0x04 0xF0 0x01 0x6f 0xff 0xff 0xfd # \"Restore Completed\""
            ;;
        "restore_failed")
            event_data="0x04 0xF0 0x01 0x6f 0xff 0xff 0xfc # \"Restore Failed\""
            ;;
        "restore_failed_backup_missing")
            event_data="0x04 0xF0 0x01 0x6f 0xff 0xff 0xfb # \"Restore Failed: missing backup file\""
            ;;
        "restore_failed_images_missing")
            event_data="0x04 0xF0 0x01 0x6f 0xff 0xff 0xfa # \"Restore Failed: missing container images backup file\""
            ;;
        "restore_failed_both_missing")
            event_data="0x04 0xF0 0x01 0x6f 0xff 0xff 0xf9 # \"Restore Failed: missing backup and container images backup files\""
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

    local auto_restore_mode
    auto_restore_mode=$(grep "^auto_restore_mode:" "$RESTORE_CONFIG" 2>/dev/null | sed 's/auto_restore_mode: *//' | tr -d '"' | tr -d "'")

    # For factory auto-restore, we need to look for a backup file matching
    # the *factory_backup*.tgz pattern
    local backup_pattern
    if [[ "$auto_restore_mode" == "factory" ]]; then
        backup_pattern="*factory_backup*.tgz"
        log "Factory auto-restore mode, searching for pattern: $backup_pattern"
    else
        backup_pattern="*_platform_backup_*.tgz"
        log "Standard auto-restore mode, searching for pattern: $backup_pattern"
    fi

    log "Scanning backup directory: $backup_dir"

    local backup_files
    mapfile -t backup_files < <(find "$backup_dir" -maxdepth 1 -name "$backup_pattern" -type f)

    if [[ ${#backup_files[@]} -eq 0 ]]; then
        log "No backup files found matching pattern $backup_pattern in $backup_dir" "ERROR"
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

get_software_version() {
    local version
    version=$(grep "^SW_VERSION=" /etc/build.info | cut -d'=' -f2 | tr -d '"')
    echo "$version"
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

    if [[ ${#registry_backup_files[@]} -eq 1 ]]; then
        local registry_backup_filename
        registry_backup_filename=$(basename "${registry_backup_files[0]}")
        log "Found image registry backup file: $registry_backup_filename"
        set_config_value "restore_registry_filesystem" "true" "$RESTORE_CONFIG"
        set_config_value "registry_backup_filename" "$registry_backup_filename" "$RESTORE_CONFIG"
    elif [[ ${#registry_backup_files[@]} -gt 1 ]]; then
        log "Multiple image registry backup files found in $backup_dir:" "ERROR"
        for file in "${registry_backup_files[@]}"; do
            log "  - $(basename "$file")" "ERROR"
        done
        return 1
    else
        log "No image registry backup files found matching pattern *_image_registry_backup_*.tgz"
        # We set restore_registry_filesystem to false so the restore playbook attempts
        # to use the prestaged registry data instead of the registry backup file.
        set_config_value "restore_registry_filesystem" "false" "$RESTORE_CONFIG"
    fi

    return 0
}

check_prestaged_images() {
    log "Checking for prestaged container images..."

    local auto_restore_mode
    auto_restore_mode=$(grep "^auto_restore_mode:" "$RESTORE_CONFIG" 2>/dev/null | sed 's/auto_restore_mode: *//' | tr -d '"' | tr -d "'")

    # Factory auto-restore prestaged data is stored in the factory backup directory
    local prestage_dir
    if [[ "$auto_restore_mode" == "factory" ]]; then
        if ! prestage_dir=$(get_backup_directory); then
            return 1
        fi
        log "Factory auto-restore mode: checking for prestaged images in: $prestage_dir"
    else
        local software_version
        software_version=$(get_software_version)
        prestage_dir="/opt/platform-backup/${software_version}"
        log "Standard auto-restore mode: checking for prestaged images in: $prestage_dir"
    fi

    # Check for prestaged registry filesystem file
    local prestaged_registry_file="${prestage_dir}/local_registry_filesystem.tgz"
    local registry_found=false
    if [[ -f "$prestaged_registry_file" ]]; then
        log "Found prestaged registry file: $prestaged_registry_file"
        registry_found=true
    fi

    # Check for container image files
    local container_images
    mapfile -t container_images < <(find "$prestage_dir" -maxdepth 1 -name "container-image*.tar.gz" -type f 2>/dev/null)
    local containers_found=false
    if [[ ${#container_images[@]} -gt 0 ]]; then
        log "Found ${#container_images[@]} container image file(s):"
        for file in "${container_images[@]}"; do
            log "  - $(basename "$file")"
        done
        containers_found=true
    fi

    if [[ "$registry_found" == true || "$containers_found" == true ]]; then
        return 0
    else
        log "No prestaged images found in: $prestage_dir"
        return 1
    fi
}

validate_restore_prerequisites() {
    log "Validating restore prerequisites..."

    # Check backup file availability
    local backup_available=false
    if find_and_set_backup_filename; then
        backup_available=true
        log "Platform backup file validation: PASSED"
    else
        log "Platform backup file validation: FAILED" "ERROR"
    fi

    # Check registry restore options
    local registry_available=false
    # First, we check that check_and_set_registry_restore returns 0, indicating
    # that backup_dir exists and the registry backup was either found or not.
    if check_and_set_registry_restore; then
        if grep -q "^restore_registry_filesystem: true" "$RESTORE_CONFIG"; then
            # check_and_set_registry_restore sets restore_registry_filesystem
            # to true if it finds the container images backup file
            registry_available=true
            log "Registry backup file validation: PASSED"
        elif check_prestaged_images; then
            # if the registry backup was not found, we check if the prestaged registry data is available
            registry_available=true
            log "Prestaged images validation: PASSED"
        else
            log "Registry backup and prestaged images validation: FAILED" "ERROR"
        fi
    else
        # This means check_and_set_registry_restore exited with a return code of 1,
        # indicating it failed to check if registry backup exists or not.
        log "Registry restore validation: FAILED" "ERROR"
    fi

    # Send the correct failure event
    if [[ "$backup_available" == false && "$registry_available" == false ]]; then
        log "Both platform backup and container images are missing" "ERROR"
        send_ipmi_event "restore_failed_both_missing"
        return 1
    elif [[ "$backup_available" == false ]]; then
        log "Platform backup file is missing" "ERROR"
        send_ipmi_event "restore_failed_backup_missing"
        return 1
    elif [[ "$registry_available" == false ]]; then
        log "Container images (backup file and prestaged) are missing" "ERROR"
        send_ipmi_event "restore_failed_images_missing"
        return 1
    fi

    log "All restore prerequisites validated successfully"
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

    if ! validate_restore_prerequisites; then
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
