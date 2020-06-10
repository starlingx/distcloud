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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

RPC_API_VERSION = "1.0"

TOPIC_DC_MANAGER = "dcmanager"

TOPIC_DC_MANAGER_AUDIT = "dcmanager-audit"

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
AVAIL_FAIL_COUNT_TO_ALARM = 2
AVAIL_FAIL_COUNT_MAX = 9999

# Software update strategy types
SW_UPDATE_TYPE_FIRMWARE = "firmware"
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

STRATEGY_STATE_INSTALLING_LICENSE = "installing license"
STRATEGY_STATE_IMPORTING_LOAD = "importing load"
STRATEGY_STATE_STARTING_UPGRADE = "starting upgrade"
STRATEGY_STATE_LOCKING_CONTROLLER = "locking controller"
STRATEGY_STATE_UPGRADING_SIMPLEX = "upgrading simplex"
STRATEGY_STATE_MIGRATING_DATA = "migrating data"
STRATEGY_STATE_UNLOCKING_CONTROLLER = "unlocking controller"
STRATEGY_STATE_ACTIVATING_UPGRADE = "activating upgrade"
STRATEGY_STATE_COMPLETING_UPGRADE = "completing upgrade"

# Subcloud deploy status states
DEPLOY_STATE_NONE = 'not-deployed'
DEPLOY_STATE_PRE_DEPLOY = 'pre-deploy'
DEPLOY_STATE_DEPLOY_PREP_FAILED = 'deploy-prep-failed'
DEPLOY_STATE_PRE_INSTALL = 'pre-install'
DEPLOY_STATE_PRE_INSTALL_FAILED = 'pre-install-failed'
DEPLOY_STATE_INSTALLING = 'installing'
DEPLOY_STATE_INSTALL_FAILED = 'install-failed'
DEPLOY_STATE_BOOTSTRAPPING = 'bootstrapping'
DEPLOY_STATE_BOOTSTRAP_FAILED = 'bootstrap-failed'
DEPLOY_STATE_DEPLOYING = 'deploying'
DEPLOY_STATE_DEPLOY_FAILED = 'deploy-failed'
DEPLOY_STATE_DONE = 'complete'

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
