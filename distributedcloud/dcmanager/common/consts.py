# Copyright (c) 2016 Ericsson AB.

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

RPC_API_VERSION = "1.0"

TOPIC_DC_MANAGER = "dcmanager"

TOPIC_DC_MANAGER_AUDIT = "dcmanager-audit"

TOPIC_DC_MANAGER_AUDIT_WORKER = "dcmanager-audit-worker"

TOPIC_DC_MANAGER_ORCHESTRATOR = "dcmanager-orchestrator"

LOADS_VAULT_DIR = "/opt/dc-vault/loads"

PATCH_VAULT_DIR = "/opt/dc-vault/patches"

# Well known region names
SYSTEM_CONTROLLER_NAME = "SystemController"
DEFAULT_REGION_NAME = "RegionOne"

# Subcloud management state
MANAGEMENT_UNMANAGED = "unmanaged"
MANAGEMENT_MANAGED = "managed"

# Subcloud availability status
AVAILABILITY_OFFLINE = "offline"
AVAILABILITY_ONLINE = "online"

# Admin status for hosts
ADMIN_LOCKED = 'locked'
ADMIN_UNLOCKED = 'unlocked'

# operational status for hosts
OPERATIONAL_ENABLED = 'enabled'
OPERATIONAL_DISABLED = 'disabled'

# Availability status for hosts
AVAILABILITY_AVAILABLE = 'available'
AVAILABILITY_DEGRADED = 'degraded'

# Personality of hosts
PERSONALITY_CONTROLLER_ACTIVE = 'Controller-Active'
PERSONALITY_CONTROLLER_STANDBY = 'Controller-Standby'

# Subcloud sync status
SYNC_STATUS_UNKNOWN = "unknown"
SYNC_STATUS_IN_SYNC = "in-sync"
SYNC_STATUS_OUT_OF_SYNC = "out-of-sync"

# Subcloud endpoint related database fields
ENDPOINT_SYNC_STATUS = "endpoint_sync_status"
SYNC_STATUS = "sync_status"
ENDPOINT_TYPE = "endpoint_type"

# Service group status
SERVICE_GROUP_STATUS_ACTIVE = "active"

# Availability fail count
# we don't want to alarm first failure since there are
# cases where we expect a transient failure in the
# subcloud (e.g. haproxy process restart to update
# certificates)
AVAIL_FAIL_COUNT_TO_ALARM = 2
AVAIL_FAIL_COUNT_MAX = 9999

# Software update strategy types
SW_UPDATE_TYPE_FIRMWARE = "firmware"
SW_UPDATE_TYPE_KUBERNETES = "kubernetes"
SW_UPDATE_TYPE_PATCH = "patch"
SW_UPDATE_TYPE_UPGRADE = "upgrade"

# Software update states
SW_UPDATE_STATE_INITIAL = "initial"
SW_UPDATE_STATE_APPLYING = "applying"
SW_UPDATE_STATE_ABORT_REQUESTED = "abort requested"
SW_UPDATE_STATE_ABORTING = "aborting"
SW_UPDATE_STATE_COMPLETE = "complete"
SW_UPDATE_STATE_ABORTED = "aborted"
SW_UPDATE_STATE_FAILED = "failed"
SW_UPDATE_STATE_DELETING = "deleting"
SW_UPDATE_STATE_DELETED = "deleted"

# Software update actions
SW_UPDATE_ACTION_APPLY = "apply"
SW_UPDATE_ACTION_ABORT = "abort"

# Subcloud apply types
SUBCLOUD_APPLY_TYPE_PARALLEL = "parallel"
SUBCLOUD_APPLY_TYPE_SERIAL = "serial"

# Values for the Default Subcloud Group
DEFAULT_SUBCLOUD_GROUP_ID = 1
DEFAULT_SUBCLOUD_GROUP_NAME = 'Default'
DEFAULT_SUBCLOUD_GROUP_DESCRIPTION = 'Default Subcloud Group'
DEFAULT_SUBCLOUD_GROUP_UPDATE_APPLY_TYPE = SUBCLOUD_APPLY_TYPE_PARALLEL
DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS = 2

# Strategy step states
STRATEGY_STATE_INITIAL = "initial"
STRATEGY_STATE_UPDATING_PATCHES = "updating patches"
STRATEGY_STATE_CREATING_STRATEGY = "creating strategy"
STRATEGY_STATE_APPLYING_STRATEGY = "applying strategy"
STRATEGY_STATE_FINISHING = "finishing"
STRATEGY_STATE_COMPLETE = "complete"
STRATEGY_STATE_ABORTED = "aborted"
STRATEGY_STATE_FAILED = "failed"

STRATEGY_STATE_PRE_CHECK = "pre check"
STRATEGY_STATE_INSTALLING_LICENSE = "installing license"
STRATEGY_STATE_IMPORTING_LOAD = "importing load"
STRATEGY_STATE_UPDATING_PATCHES = "updating patches"
STRATEGY_STATE_FINISHING_PATCH_STRATEGY = "finishing patch strategy"
STRATEGY_STATE_STARTING_UPGRADE = "starting upgrade"
STRATEGY_STATE_LOCKING_CONTROLLER_0 = "locking controller-0"
STRATEGY_STATE_LOCKING_CONTROLLER_1 = "locking controller-1"
STRATEGY_STATE_UPGRADING_SIMPLEX = "upgrading simplex"
STRATEGY_STATE_UPGRADING_DUPLEX = "upgrading duplex"
STRATEGY_STATE_MIGRATING_DATA = "migrating data"
STRATEGY_STATE_UNLOCKING_CONTROLLER_0 = "unlocking controller-0"
STRATEGY_STATE_UNLOCKING_CONTROLLER_1 = "unlocking controller-1"
STRATEGY_STATE_SWACTING_TO_CONTROLLER_0 = "swacting to controller-0"
STRATEGY_STATE_SWACTING_TO_CONTROLLER_1 = "swacting to controller-1"
STRATEGY_STATE_ACTIVATING_UPGRADE = "activating upgrade"
STRATEGY_STATE_COMPLETING_UPGRADE = "completing upgrade"
STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY = "creating VIM upgrade strategy"
STRATEGY_STATE_APPLYING_VIM_UPGRADE_STRATEGY = "applying VIM upgrade strategy"
STRATEGY_STATE_DELETING_LOAD = "deleting load"

# Firmware update orchestration states
STRATEGY_STATE_IMPORTING_FIRMWARE = "importing firmware"
STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY = "creating fw update strategy"
STRATEGY_STATE_APPLYING_FW_UPDATE_STRATEGY = "applying fw update strategy"
STRATEGY_STATE_FINISHING_FW_UPDATE = "finishing fw update"

# Kubernetes update orchestration states
STRATEGY_STATE_KUBE_UPDATING_PATCHES = \
    "kube updating patches"
STRATEGY_STATE_KUBE_CREATING_VIM_PATCH_STRATEGY = \
    "kube creating vim patch strategy"
STRATEGY_STATE_KUBE_APPLYING_VIM_PATCH_STRATEGY = \
    "kube applying vim patch strategy"
STRATEGY_STATE_KUBE_DELETING_VIM_PATCH_STRATEGY = \
    "kube deleting vim patch strategy"
STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY = \
    "kube creating vim kube upgrade strategy"
STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY = \
    "kube applying vim kube upgrade strategy"

# Subcloud deploy status states
DEPLOY_STATE_NONE = 'not-deployed'
DEPLOY_STATE_PRE_DEPLOY = 'pre-deploy'
DEPLOY_STATE_DEPLOY_PREP_FAILED = 'deploy-prep-failed'
DEPLOY_STATE_PRE_INSTALL = 'pre-install'
DEPLOY_STATE_PRE_INSTALL_FAILED = 'pre-install-failed'
DEPLOY_STATE_INSTALLING = 'installing'
DEPLOY_STATE_INSTALL_FAILED = 'install-failed'
DEPLOY_STATE_INSTALLED = 'installed'
DEPLOY_STATE_BOOTSTRAPPING = 'bootstrapping'
DEPLOY_STATE_BOOTSTRAP_FAILED = 'bootstrap-failed'
DEPLOY_STATE_DEPLOYING = 'deploying'
DEPLOY_STATE_DEPLOY_FAILED = 'deploy-failed'
DEPLOY_STATE_MIGRATING_DATA = 'migrating-data'
DEPLOY_STATE_DATA_MIGRATION_FAILED = 'data-migration-failed'
DEPLOY_STATE_MIGRATED = 'migrated'
DEPLOY_STATE_PRE_RESTORE = 'pre-restore'
DEPLOY_STATE_RESTORE_PREP_FAILED = 'restore-prep-failed'
DEPLOY_STATE_RESTORING = 'restoring'
DEPLOY_STATE_RESTORE_FAILED = 'restore-failed'
DEPLOY_STATE_DONE = 'complete'


# Upgrades States
UPGRADE_STATE_DATA_MIGRATION_COMPLETE = 'data-migration-complete'
UPGRADE_STATE_DATA_MIGRATION_FAILED = 'data-migration-failed'
UPGRADE_STATE_UPGRADING_CONTROLLERS = 'upgrading-controllers'
UPGRADE_STATE_UPGRADING_HOSTS = 'upgrading-hosts'
UPGRADE_STATE_ACTIVATION_FAILED = 'activation-failed'
UPGRADE_STATE_ACTIVATION_COMPLETE = 'activation-complete'

# Alarm aggregation
ALARMS_DISABLED = "disabled"
ALARM_OK_STATUS = "OK"
ALARM_DEGRADED_STATUS = "degraded"
ALARM_CRITICAL_STATUS = "critical"

# subcloud deploy file options
ANSIBLE_OVERRIDES_PATH = '/opt/dc/ansible'
DEPLOY_PLAYBOOK = "deploy_playbook"
DEPLOY_OVERRIDES = "deploy_overrides"
DEPLOY_CHART = "deploy_chart"
DEPLOY_CONFIG = 'deploy_config'

DEPLOY_COMMON_FILE_OPTIONS = [
    DEPLOY_PLAYBOOK,
    DEPLOY_OVERRIDES,
    DEPLOY_CHART
]


DC_LOG_DIR = '/var/log/dcmanager/'
DC_ANSIBLE_LOG_DIR = DC_LOG_DIR + 'ansible'
INVENTORY_FILE_POSTFIX = '_inventory.yml'

# The following password is just a temporary and internal password that is used
# after a remote install as part of the upgrade. The real sysadmin password
# will be restored af the subcloud is re-managed at the end of the upgrade.
TEMP_SYSADMIN_PASSWORD = 'St8rlingX*'

# System mode
SYSTEM_MODE_DUPLEX = "duplex"
SYSTEM_MODE_SIMPLEX = "simplex"
SYSTEM_MODE_DUPLEX_DIRECT = "duplex-direct"

# Load states
ACTIVE_LOAD_STATE = 'active'
IMPORTING_LOAD_STATE = 'importing'
IMPORTED_LOAD_STATE = 'imported'
IMPORTED_METADATA_LOAD_STATE = 'imported-metadata'
ERROR_LOAD_STATE = 'error'
DELETING_LOAD_STATE = 'deleting'
IMPORTED_LOAD_STATES = [
    IMPORTED_LOAD_STATE,
    IMPORTED_METADATA_LOAD_STATE
]
