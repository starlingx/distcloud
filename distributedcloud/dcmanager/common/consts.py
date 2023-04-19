# Copyright (c) 2016 Ericsson AB.
# Copyright (c) 2017-2023 Wind River Systems, Inc.
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

RPC_API_VERSION = "1.0"
RPC_SUBCLOUD_BACKUP_TIMEOUT = 120

TOPIC_DC_MANAGER = "dcmanager"
TOPIC_DC_MANAGER_STATE = "dcmanager-state"
TOPIC_DC_MANAGER_AUDIT = "dcmanager-audit"
TOPIC_DC_MANAGER_AUDIT_WORKER = "dcmanager-audit-worker"
TOPIC_DC_MANAGER_ORCHESTRATOR = "dcmanager-orchestrator"

CERTS_VAULT_DIR = "/opt/dc-vault/certs"
LOADS_VAULT_DIR = "/opt/dc-vault/loads"
PATCH_VAULT_DIR = "/opt/dc-vault/patches"

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
SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE = "kube-rootca-update"
SW_UPDATE_TYPE_KUBERNETES = "kubernetes"
SW_UPDATE_TYPE_PATCH = "patch"
SW_UPDATE_TYPE_PRESTAGE = "prestage"
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

# Common strategy step states
STRATEGY_STATE_INITIAL = "initial"
STRATEGY_STATE_COMPLETE = "complete"
STRATEGY_STATE_ABORTED = "aborted"
STRATEGY_STATE_FAILED = "failed"

# Patch orchestrations states
STRATEGY_STATE_CREATING_VIM_PATCH_STRATEGY = "creating VIM patch strategy"
STRATEGY_STATE_DELETING_VIM_PATCH_STRATEGY = "deleting VIM patch strategy"
STRATEGY_STATE_APPLYING_VIM_PATCH_STRATEGY = "applying VIM patch strategy"

# Upgrade orchestration states
STRATEGY_STATE_PRE_CHECK = "pre check"
STRATEGY_STATE_INSTALLING_LICENSE = "installing license"
STRATEGY_STATE_IMPORTING_LOAD = "importing load"
STRATEGY_STATE_UPDATING_PATCHES = "updating patches"
STRATEGY_STATE_FINISHING_PATCH_STRATEGY = "finishing patch strategy"
STRATEGY_STATE_STARTING_UPGRADE = "starting upgrade"
STRATEGY_STATE_TRANSFERRING_CA_CERTIFICATE = "transferring CA certificate"
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

# Kubernetes update orchestration states (ordered)
STRATEGY_STATE_KUBE_UPGRADE_PRE_CHECK = \
    "kube upgrade pre check"
STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY = \
    "kube creating vim kube upgrade strategy"
STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY = \
    "kube applying vim kube upgrade strategy"

# Kube Root CA Update orchestration states (ordered)
STRATEGY_STATE_KUBE_ROOTCA_UPDATE_PRE_CHECK = \
    "kube rootca update pre check"
STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START = \
    "kube rootca update start"
STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT = \
    "kube rootca update upload cert"
STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY = \
    "creating vim kube rootca update strategy"
STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY = \
    "applying vim kube rootca update strategy"

# Prestage orchestration states (ordered)
STRATEGY_STATE_PRESTAGE_PRE_CHECK = "prestage-precheck"
STRATEGY_STATE_PRESTAGE_PACKAGES = "prestaging-packages"
STRATEGY_STATE_PRESTAGE_IMAGES = "prestaging-images"

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
DEPLOY_STATE_PRE_REHOME = 'pre-rehome'
DEPLOY_STATE_REHOMING = 'rehoming'
DEPLOY_STATE_REHOME_FAILED = 'rehome-failed'
DEPLOY_STATE_REHOME_PREP_FAILED = 'rehome-prep-failed'
DEPLOY_STATE_DONE = 'complete'
DEPLOY_STATE_RECONFIGURING_NETWORK = 'reconfiguring-network'
DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED = 'network-reconfiguration-failed'
# Subcloud errors
ERROR_DESC_EMPTY = 'No errors present'
ERROR_DESC_CMD = 'dcmanager subcloud errors <subcloud-name>'

# Static content for error messages
BOOTSTRAP_ERROR_MSG = DEPLOY_STATE_BOOTSTRAP_FAILED
DEPLOY_ERROR_MSG = DEPLOY_STATE_DEPLOY_FAILED

ERR_MSG_DICT = {

    BOOTSTRAP_ERROR_MSG: "For bootstrap failures, please delete and re-add "
                         "the subcloud after the cause of failure has been "
                         "resolved.",

    DEPLOY_ERROR_MSG: "For deployment failures, please use dcmanager subcloud "
                      "reconfig command to reconfigure the subcloud after the "
                      "cause of failure has been resolved.",

    "bmc_cred": "Check BMC credentials in install-values.yml. Check basic "
                "authenticacion to the BMC: curl -u <<user:pass>> "
                "<<BMC_URL>>",

    "ping_bmc": "Check reachability to the BMC: ping <<BMC_URL>>",

    "dm_pod_failed": """-  Ensure you are using the correct tarball that \
corresponds to the image.
-  Check helm overrides files, ensure the deployment manager images exist in \
the specified registry and you can manually pull them from the registry.
-  Ensure you have installed the correct certificate.
-  Ensure you have logged in: sudo docker login registry.local:9001 \
-u <<registry_user>> -p <<registry_password>>""",

    "dm_apply_failed": "Check deployment yaml file and ensure the content is "
                       "syntactically and semantically correct.",

    "images_download_failure": "Check docker_registries and docker proxy "
                               "configurations in bootstrap values yaml "
                               "file. Ensure you can manually log into the "
                               "registry e.g. sudo docker login "
                               "registry.local:9001 -u <registry-user> "
                               "-p <registry-password>",

    "failed_ssl_cert": "Check if the right certificate was installed."
}

# error_description max length
ERROR_DESCRIPTION_LENGTH = 2048

# Subcloud backup status states
BACKUP_STATE_INITIAL = 'initial'
BACKUP_STATE_VALIDATING = 'validating'
BACKUP_STATE_VALIDATE_FAILED = 'validate-failed'
BACKUP_STATE_PRE_BACKUP = 'pre-backup'
BACKUP_STATE_PREP_FAILED = 'backup-prep-failed'
BACKUP_STATE_IN_PROGRESS = 'backing-up'
BACKUP_STATE_FAILED = 'failed'
BACKUP_STATE_UNKNOWN = 'unknown'
BACKUP_STATE_COMPLETE_LOCAL = 'complete-local'
BACKUP_STATE_COMPLETE_CENTRAL = 'complete-central'

# Upgrades States
UPGRADE_STATE_DATA_MIGRATION = 'data-migration'
UPGRADE_STATE_DATA_MIGRATION_COMPLETE = 'data-migration-complete'
UPGRADE_STATE_DATA_MIGRATION_FAILED = 'data-migration-failed'
UPGRADE_STATE_UPGRADING_CONTROLLERS = 'upgrading-controllers'
UPGRADE_STATE_UPGRADING_HOSTS = 'upgrading-hosts'
UPGRADE_STATE_ACTIVATION_FAILED = 'activation-failed'
UPGRADE_STATE_ACTIVATION_COMPLETE = 'activation-complete'

# Prestage States
PRESTAGE_STATE_PACKAGES = STRATEGY_STATE_PRESTAGE_PACKAGES
PRESTAGE_STATE_IMAGES = STRATEGY_STATE_PRESTAGE_IMAGES
PRESTAGE_STATE_FAILED = 'prestage-failed'
PRESTAGE_STATE_COMPLETE = 'prestage-complete'

# Alarm aggregation
ALARMS_DISABLED = "disabled"
ALARM_OK_STATUS = "OK"
ALARM_DEGRADED_STATUS = "degraded"
ALARM_CRITICAL_STATUS = "critical"

# subcloud deploy file options
ANSIBLE_OVERRIDES_PATH = '/var/opt/dc/ansible'
DEPLOY_PLAYBOOK = "deploy_playbook"
DEPLOY_OVERRIDES = "deploy_overrides"
DEPLOY_CHART = "deploy_chart"
DEPLOY_CONFIG = 'deploy_config'
DEPLOY_PRESTAGE = "prestage_images"

DEPLOY_COMMON_FILE_OPTIONS = [
    DEPLOY_PLAYBOOK,
    DEPLOY_OVERRIDES,
    DEPLOY_CHART,
    DEPLOY_PRESTAGE
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
INACTIVE_LOAD_STATE = 'inactive'
IMPORTING_LOAD_STATE = 'importing'
IMPORTED_LOAD_STATE = 'imported'
IMPORTED_METADATA_LOAD_STATE = 'imported-metadata'
ERROR_LOAD_STATE = 'error'
DELETING_LOAD_STATE = 'deleting'
IMPORTED_LOAD_STATES = [
    IMPORTED_LOAD_STATE,
    IMPORTED_METADATA_LOAD_STATE
]

# extra_args for kube upgrade
EXTRA_ARGS_TO_VERSION = 'to-version'
# extra_args for kube rootca update
EXTRA_ARGS_CERT_FILE = 'cert-file'
EXTRA_ARGS_EXPIRY_DATE = 'expiry-date'
EXTRA_ARGS_SUBJECT = 'subject'
EXTRA_ARGS_SYSADMIN_PASSWORD = 'sysadmin_password'
EXTRA_ARGS_FORCE = 'force'

# extra_args for patching
EXTRA_ARGS_UPLOAD_ONLY = 'upload-only'

# http request/response arguments for prestage
PRESTAGE_SOFTWARE_VERSION = 'prestage-software-version'
PRESTAGE_REQUEST_RELEASE = 'release'

# Device Image Bitstream Types
BITSTREAM_TYPE_ROOT_KEY = 'root-key'
BITSTREAM_TYPE_FUNCTIONAL = 'functional'
BITSTREAM_TYPE_KEY_REVOCATION = 'key-revocation'

# Platform Backup size default in MB
DEFAULT_PERSISTENT_SIZE = 30000

# Retry values to be used when platform requests fail due to temporary unavailability, which
# may occur during some orchestration steps. The sleep duration and number of retries are shorter,
# since these should only occur if a service is being restarted
PLATFORM_RETRY_MAX_ATTEMPTS = 5
PLATFORM_RETRY_SLEEP_MILLIS = 5000

# States to reject when processing a subcloud-backup create request
VALID_DEPLOY_STATES_FOR_BACKUP = [DEPLOY_STATE_DONE,
                                  PRESTAGE_STATE_COMPLETE]

# States to reject when processing a subcloud-backup restore request
INVALID_DEPLOY_STATES_FOR_RESTORE = [DEPLOY_STATE_INSTALLING,
                                     DEPLOY_STATE_BOOTSTRAPPING,
                                     DEPLOY_STATE_DEPLOYING,
                                     DEPLOY_STATE_REHOMING,
                                     DEPLOY_STATE_PRE_RESTORE,
                                     DEPLOY_STATE_RESTORING]

# States to indicate if a backup operation is currently in progress
STATES_FOR_ONGOING_BACKUP = [BACKUP_STATE_INITIAL,
                             BACKUP_STATE_VALIDATING,
                             BACKUP_STATE_PRE_BACKUP,
                             BACKUP_STATE_IN_PROGRESS]

# The k8s secret that holds openldap CA certificate
OPENLDAP_CA_CERT_SECRET_NAME = "system-local-ca"

CERT_NAMESPACE_PLATFORM_CA_CERTS = 'cert-manager'

# The ansible playbook base directories
ANSIBLE_CURRENT_VERSION_BASE_PATH = '/usr/share/ansible/stx-ansible/playbooks'
ANSIBLE_PREVIOUS_VERSION_BASE_PATH = '/opt/dc-vault/playbooks'
