# Copyright (c) 2016 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

RPC_API_VERSION = "1.0"
RPC_SUBCLOUD_BACKUP_TIMEOUT = 120

TOPIC_DC_MANAGER = "dcmanager"
TOPIC_DC_MANAGER_STATE = "dcmanager-state"
TOPIC_DC_MANAGER_AUDIT = "dcmanager-audit"
TOPIC_DC_MANAGER_AUDIT_WORKER = "dcmanager-audit-worker"
TOPIC_DC_MANAGER_ORCHESTRATOR = "dcmanager-orchestrator"
TOPIC_DC_NOTIFICATION = "DCMANAGER-NOTIFICATION"
TOPIC_DC_MANAGER_ORCHESTRATOR_WORKER = "dcmanager-orchestrator-worker"

CERTS_VAULT_DIR = "/opt/dc-vault/certs"

BOOTSTRAP_VALUES = "bootstrap_values"
BOOTSTRAP_ADDRESS = "bootstrap-address"
INSTALL_VALUES = "install_values"

# Deploy phases
DEPLOY_PHASE_CREATE = "create"
DEPLOY_PHASE_INSTALL = "install"
DEPLOY_PHASE_BOOTSTRAP = "bootstrap"
DEPLOY_PHASE_CONFIG = "configure"
DEPLOY_PHASE_COMPLETE = "complete"
DEPLOY_PHASE_ABORT = "abort"
DEPLOY_PHASE_RESUME = "resume"
DEPLOY_PHASE_ENROLL = "enroll"

# Admin status for hosts
ADMIN_LOCKED = "locked"
ADMIN_UNLOCKED = "unlocked"

# operational status for hosts
OPERATIONAL_ENABLED = "enabled"
OPERATIONAL_DISABLED = "disabled"

# Availability status for hosts
AVAILABILITY_AVAILABLE = "available"
AVAILABILITY_DEGRADED = "degraded"

# Personality of hosts
PERSONALITY_CONTROLLER_ACTIVE = "Controller-Active"
PERSONALITY_CONTROLLER_STANDBY = "Controller-Standby"

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
SW_UPDATE_TYPE_PRESTAGE = "prestage"
SW_UPDATE_TYPE_SOFTWARE = "sw-deploy"

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

# Software misc info
ISO_VERSION = "0"

# Software update actions
SW_UPDATE_ACTION_APPLY = "apply"
SW_UPDATE_ACTION_ABORT = "abort"

# Stage states
STAGE_SUBCLOUD_ORCHESTRATION_CREATED = 1
STAGE_SUBCLOUD_ORCHESTRATION_STARTED = 2
STAGE_SUBCLOUD_ORCHESTRATION_PROCESSED = 3

# Stage map
STAGE_MAP = {"1": "Create", "2": "Apply", "3": "Complete"}

# Subcloud apply types
SUBCLOUD_APPLY_TYPE_PARALLEL = "parallel"
SUBCLOUD_APPLY_TYPE_SERIAL = "serial"

# Values for the Default Subcloud Group
DEFAULT_SUBCLOUD_GROUP_ID = 1
DEFAULT_SUBCLOUD_GROUP_NAME = "Default"
DEFAULT_SUBCLOUD_GROUP_DESCRIPTION = "Default Subcloud Group"
DEFAULT_SUBCLOUD_GROUP_UPDATE_APPLY_TYPE = SUBCLOUD_APPLY_TYPE_PARALLEL
DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS = 2

# Common strategy step states
STRATEGY_STATE_INITIAL = "initial"
STRATEGY_STATE_COMPLETE = "complete"
STRATEGY_STATE_ABORTED = "aborted"
STRATEGY_STATE_FAILED = "failed"
STRATEGY_STATE_PRE_CHECK = "pre check"

# Software orchestration states
STRATEGY_STATE_SW_PRE_CHECK = "sw-deploy pre-check"
STRATEGY_STATE_SW_INSTALL_LICENSE = "sw-deploy install license"
STRATEGY_STATE_SW_CREATE_VIM_STRATEGY = "create VIM sw-deploy strategy"
STRATEGY_STATE_SW_APPLY_VIM_STRATEGY = "apply VIM sw-deploy strategy"
STRATEGY_STATE_SW_FINISH_STRATEGY = "finish sw-deploy strategy"

# Firmware update orchestration states
STRATEGY_STATE_IMPORTING_FIRMWARE = "importing firmware"
STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY = "creating fw update strategy"
STRATEGY_STATE_APPLYING_FW_UPDATE_STRATEGY = "applying fw update strategy"
STRATEGY_STATE_FINISHING_FW_UPDATE = "finishing fw update"

# Kubernetes update orchestration states (ordered)
STRATEGY_STATE_KUBE_UPGRADE_PRE_CHECK = "kube upgrade pre check"
STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY = (
    "kube creating vim kube upgrade strategy"
)
STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY = (
    "kube applying vim kube upgrade strategy"
)

# Kube Root CA Update orchestration states (ordered)
STRATEGY_STATE_KUBE_ROOTCA_UPDATE_PRE_CHECK = "kube rootca update pre check"
STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START = "kube rootca update start"
STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT = "kube rootca update upload cert"
STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY = (
    "creating vim kube rootca update strategy"
)
STRATEGY_STATE_APPLYING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY = (
    "applying vim kube rootca update strategy"
)

# Prestage orchestration states (ordered)
STRATEGY_STATE_PRESTAGE_PRE_CHECK = "prestage-precheck"
STRATEGY_STATE_PRESTAGE_PACKAGES = "prestaging-packages"
STRATEGY_STATE_PRESTAGE_IMAGES = "prestaging-images"

# Subcloud deploy status states
DEPLOY_STATE_NONE = "not-deployed"
DEPLOY_STATE_PRE_DEPLOY = "pre-deploy"
DEPLOY_STATE_DEPLOY_PREP_FAILED = "deploy-prep-failed"
DEPLOY_STATE_CREATING = "creating"
DEPLOY_STATE_CREATE_FAILED = "create-failed"
DEPLOY_STATE_CREATED = "create-complete"
DEPLOY_STATE_PRE_INSTALL = "pre-install"
DEPLOY_STATE_PRE_INSTALL_FAILED = "pre-install-failed"
DEPLOY_STATE_INSTALLING = "installing"
DEPLOY_STATE_INSTALL_FAILED = "install-failed"
DEPLOY_STATE_INSTALLED = "install-complete"
DEPLOY_STATE_PRE_BOOTSTRAP = "pre-bootstrap"
DEPLOY_STATE_PRE_BOOTSTRAP_FAILED = "pre-bootstrap-failed"
DEPLOY_STATE_BOOTSTRAPPING = "bootstrapping"
DEPLOY_STATE_BOOTSTRAP_FAILED = "bootstrap-failed"
DEPLOY_STATE_BOOTSTRAP_ABORTED = "bootstrap-aborted"
DEPLOY_STATE_BOOTSTRAPPED = "bootstrap-complete"
DEPLOY_STATE_PRE_CONFIG = "pre-config"
DEPLOY_STATE_PRE_CONFIG_FAILED = "pre-config-failed"
DEPLOY_STATE_CONFIGURING = "configuring"
DEPLOY_STATE_CONFIG_FAILED = "config-failed"
DEPLOY_STATE_DEPLOYING = "deploying"
DEPLOY_STATE_DEPLOY_FAILED = "deploy-failed"
DEPLOY_STATE_ABORTING_INSTALL = "aborting-install"
DEPLOY_STATE_INSTALL_ABORTED = "install-aborted"
DEPLOY_STATE_ABORTING_BOOTSTRAP = "aborting-bootstrap"
DEPLOY_STATE_ABORTING_CONFIG = "aborting-config"
DEPLOY_STATE_CONFIG_ABORTED = "config-aborted"
DEPLOY_STATE_ENROLLED = "enroll-complete"
DEPLOY_STATE_ENROLLING = "enrolling"
DEPLOY_STATE_ENROLL_FAILED = "enroll-failed"
DEPLOY_STATE_PRE_RESTORE = "pre-restore"
DEPLOY_STATE_RESTORE_PREP_FAILED = "restore-prep-failed"
DEPLOY_STATE_RESTORING = "restoring"
DEPLOY_STATE_RESTORE_FAILED = "restore-failed"
# TODO(gherzmann): Add support for enrolling an existing subcloud
# that is in the DEPLOY_STATE_FACTORY_RESTORE_COMPLETE state.
DEPLOY_STATE_FACTORY_RESTORE_COMPLETE = "factory-restore-complete"
DEPLOY_STATE_PRE_REHOME = "pre-rehome"
DEPLOY_STATE_PRE_ENROLL = "pre-enroll"
DEPLOY_STATE_PRE_ENROLL_FAILED = "pre-enroll-failed"
DEPLOY_STATE_PRE_ENROLL_COMPLETE = "pre-enroll-complete"
DEPLOY_STATE_PRE_INIT_ENROLL = "pre-init-enroll"
DEPLOY_STATE_PRE_INIT_ENROLL_FAILED = "pre-init-enroll-failed"
DEPLOY_STATE_INITIATING_ENROLL = "initiating-enroll"
DEPLOY_STATE_INIT_ENROLL_FAILED = "init-enroll-failed"
DEPLOY_STATE_INIT_ENROLL_COMPLETE = "init-enroll-complete"
DEPLOY_STATE_SW_DEPLOY_APPLY_STRATEGY_FAILED = "sw-deploy-apply-strategy-failed"
DEPLOY_STATE_SW_DEPLOY_IN_PROGRESS = "sw-deploy-in-progress"
# If any of the following rehoming or secondary statuses
# are modified, cert-mon code will need to be updated.
DEPLOY_STATE_REHOMING = "rehoming"
DEPLOY_STATE_REHOME_FAILED = "rehome-failed"
DEPLOY_STATE_REHOME_PREP_FAILED = "rehome-prep-failed"
DEPLOY_STATE_REHOME_PENDING = "rehome-pending"
DEPLOY_STATE_SECONDARY = "secondary"
DEPLOY_STATE_SECONDARY_FAILED = "secondary-failed"
DEPLOY_STATE_DONE = "complete"
DEPLOY_STATE_RECONFIGURING_NETWORK = "reconfiguring-network"
DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED = "network-reconfiguration-failed"
# Subcloud errors
ERROR_DESC_EMPTY = "No errors present"
ERROR_DESC_FAILED = "Failed to get error message. Please check sysinv log"
ERROR_DESC_CMD = "dcmanager subcloud errors <subcloud-name>"

# Static content for error messages
BOOTSTRAP_ERROR_MSG = DEPLOY_STATE_BOOTSTRAP_FAILED
CONFIG_ERROR_MSG = DEPLOY_STATE_CONFIG_FAILED

ERR_MSG_DICT = {
    BOOTSTRAP_ERROR_MSG: "For bootstrap failures, please use 'dcmanager subcloud "
    "deploy resume' after the cause of failure has been resolved.",
    CONFIG_ERROR_MSG: "For configuration failures, please use dcmanager subcloud "
    "deploy config command to reconfigure the subcloud after "
    "the cause of failure has been resolved.",
    "bmc_cred": "Check BMC credentials in install-values.yml. Check basic "
    "authenticacion to the BMC: curl -u <<user:pass>> <<BMC_URL>>",
    "ping_bmc": "Check reachability to the BMC: ping <<BMC_URL>>",
    "rvmc_process": "Ensure the previous RVMC process is terminated.",
    "rvmc_timeout": "Please check the dcmanager ansible log for details.",
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
    "configurations in bootstrap values yaml file. Ensure you can manually log into "
    "the registry e.g. sudo docker login registry.local:9001 -u <registry-user> "
    "-p <registry-password>",
    "failed_ssl_cert": "Check if the right certificate was installed.",
}

# error_description max length
ERROR_DESCRIPTION_LENGTH = 2048

# Subcloud backup status states
BACKUP_STATE_INITIAL = "initial"
BACKUP_STATE_VALIDATING = "validating"
BACKUP_STATE_VALIDATE_FAILED = "validate-failed"
BACKUP_STATE_PRE_BACKUP = "pre-backup"
BACKUP_STATE_PREP_FAILED = "backup-prep-failed"
BACKUP_STATE_IN_PROGRESS = "backing-up"
BACKUP_STATE_FAILED = "failed"
BACKUP_STATE_UNKNOWN = "unknown"
BACKUP_STATE_COMPLETE_LOCAL = "complete-local"
BACKUP_STATE_COMPLETE_CENTRAL = "complete-central"

# Prestage States
PRESTAGE_STATE_PRESTAGING = "prestaging"
PRESTAGE_STATE_FAILED = "failed"
PRESTAGE_STATE_COMPLETE = "complete"

# States to indicate if a prestage operation is currently in progress
STATES_FOR_ONGOING_PRESTAGE = [
    STRATEGY_STATE_PRESTAGE_PACKAGES,
    STRATEGY_STATE_PRESTAGE_IMAGES,
]

# Alarm aggregation
ALARMS_DISABLED = "disabled"
ALARM_OK_STATUS = "OK"
ALARM_DEGRADED_STATUS = "degraded"
ALARM_CRITICAL_STATUS = "critical"

DEPLOY_PLAYBOOK = "deploy_playbook"
DEPLOY_OVERRIDES = "deploy_overrides"
DEPLOY_CHART = "deploy_chart"
DEPLOY_CONFIG = "deploy_config"
DEPLOY_PRESTAGE = "prestage_images"

REQUIRED_DEPLOY_FILE_OPTIONS = [
    DEPLOY_PLAYBOOK,
    DEPLOY_CHART,
]
DEPLOY_COMMON_FILE_OPTIONS = [
    DEPLOY_PLAYBOOK,
    DEPLOY_OVERRIDES,
    DEPLOY_CHART,
    DEPLOY_PRESTAGE,
]


DC_LOG_DIR = "/var/log/dcmanager/"
DC_ANSIBLE_LOG_DIR = DC_LOG_DIR + "ansible"
INVENTORY_FILE_POSTFIX = "_inventory.yml"

# System mode
SYSTEM_MODE_DUPLEX = "duplex"
SYSTEM_MODE_SIMPLEX = "simplex"
SYSTEM_MODE_DUPLEX_DIRECT = "duplex-direct"

# extra_args for kube upgrade
EXTRA_ARGS_TO_VERSION = "to-version"
# extra_args for kube rootca update
EXTRA_ARGS_CERT_FILE = "cert-file"
EXTRA_ARGS_EXPIRY_DATE = "expiry-date"
EXTRA_ARGS_SUBJECT = "subject"
EXTRA_ARGS_SYSADMIN_PASSWORD = "sysadmin_password"
EXTRA_ARGS_FORCE = "force"

# extra_args for software
EXTRA_ARGS_RELEASE_ID = "release_id"
EXTRA_ARGS_SNAPSHOT = "snapshot"

# http request/response arguments for prestage
PRESTAGE_SOFTWARE_VERSION = "prestage-software-version"
PRESTAGE_REQUEST_RELEASE = "release"
PRESTAGE_FOR_INSTALL = "for_install"
PRESTAGE_FOR_SW_DEPLOY = "for_sw_deploy"

# Device Image Bitstream Types
BITSTREAM_TYPE_ROOT_KEY = "root-key"
BITSTREAM_TYPE_FUNCTIONAL = "functional"
BITSTREAM_TYPE_KEY_REVOCATION = "key-revocation"

# Platform Backup size default in MB
DEFAULT_PERSISTENT_SIZE = 30000

# Retry values to be used when platform requests fail due to temporary
# unavailability, which may occur during some orchestration steps. The sleep
# duration and number of retries are shorter, since these should only occur if a
# service is being restarted
PLATFORM_RETRY_MAX_ATTEMPTS = 5
PLATFORM_RETRY_SLEEP_MILLIS = 5000

# States to reject when processing a subcloud-backup restore request
INVALID_DEPLOY_STATES_FOR_RESTORE = [
    DEPLOY_STATE_CREATING,
    DEPLOY_STATE_PRE_INSTALL,
    DEPLOY_STATE_INSTALLING,
    DEPLOY_STATE_PRE_BOOTSTRAP,
    DEPLOY_STATE_BOOTSTRAPPING,
    DEPLOY_STATE_PRE_CONFIG,
    DEPLOY_STATE_CONFIGURING,
    DEPLOY_STATE_PRE_REHOME,
    DEPLOY_STATE_REHOMING,
    DEPLOY_STATE_PRE_RESTORE,
    DEPLOY_STATE_RESTORING,
    DEPLOY_STATE_PRE_INIT_ENROLL,
    DEPLOY_STATE_INITIATING_ENROLL,
    DEPLOY_STATE_PRE_ENROLL,
    DEPLOY_STATE_ENROLLING,
]

# States to reject when processing a subcloud delete request
INVALID_DEPLOY_STATES_FOR_DELETE = [
    DEPLOY_STATE_PRE_DEPLOY,
    DEPLOY_STATE_CREATING,
    DEPLOY_STATE_PRE_INSTALL,
    DEPLOY_STATE_INSTALLING,
    DEPLOY_STATE_PRE_BOOTSTRAP,
    DEPLOY_STATE_BOOTSTRAPPING,
    DEPLOY_STATE_PRE_CONFIG,
    DEPLOY_STATE_CONFIGURING,
    DEPLOY_STATE_DEPLOYING,
    DEPLOY_STATE_ABORTING_INSTALL,
    DEPLOY_STATE_ABORTING_BOOTSTRAP,
    DEPLOY_STATE_ABORTING_CONFIG,
    DEPLOY_STATE_PRE_RESTORE,
    DEPLOY_STATE_RESTORING,
    DEPLOY_STATE_PRE_REHOME,
    DEPLOY_STATE_REHOMING,
    DEPLOY_STATE_REHOME_PENDING,
    DEPLOY_STATE_RECONFIGURING_NETWORK,
    DEPLOY_STATE_PRE_INIT_ENROLL,
    DEPLOY_STATE_INITIATING_ENROLL,
    DEPLOY_STATE_PRE_ENROLL,
    DEPLOY_STATE_ENROLLING,
]

# States to indicate if a backup operation is currently in progress
STATES_FOR_ONGOING_BACKUP = [
    BACKUP_STATE_INITIAL,
    BACKUP_STATE_VALIDATING,
    BACKUP_STATE_PRE_BACKUP,
    BACKUP_STATE_IN_PROGRESS,
]

# The k8s secret that holds openldap CA certificate
OPENLDAP_CA_CERT_SECRET_NAME = "system-local-ca"

CERT_NAMESPACE_PLATFORM_CA_CERTS = "cert-manager"

# The ansible playbook base directories
ANSIBLE_CURRENT_VERSION_BASE_PATH = "/usr/share/ansible/stx-ansible/playbooks"
ANSIBLE_PREVIOUS_VERSION_BASE_PATH = "/opt/dc-vault/playbooks"

# Subcloud backup locations
CENTRAL_BACKUP_DIR = "/opt/dc-vault/backups"
SUBCLOUD_LOCAL_BACKUP_DIR = "/opt/platform-backup/backups"
SUBCLOUD_AUTO_RESTORE_DIR = "/opt/platform-backup/auto-restore"
SUBCLOUD_FACTORY_BACKUP_DIR = "/opt/platform-backup/factory"

# Maximum allowed size of subcloud home directory for central backups
DEFAULT_SUBCLOUD_CENTRAL_BACKUP_MAX_HOME_DIR_SIZE_MB = 100

# The deployment manager artifacts usr directories
ALTERNATE_DEPLOY_FILES_DIR = "/usr/local/share/applications"

ALTERNATE_HELM_CHART_DIR = ALTERNATE_DEPLOY_FILES_DIR + "/helm"
HELM_CHART_POSTFIX = "deployment-manager"

ALTERNATE_DEPLOY_PLAYBOOK_DIR = ALTERNATE_DEPLOY_FILES_DIR + "/playbooks"
DEPLOY_PLAYBOOK_POSTFIX = "deployment-manager.yaml"

SUPPORTED_UPGRADES_METADATA_FILE_PATH = "/usr/rootdirs/opt/upgrades/metadata.xml"

# Required for subcloud name configuration
CERT_MON_HTTP_AGENT = "cert-mon/1.0"
OS_REGION_NAME = "OS_REGION_NAME"

# Required for GEO-redundancy
# User-Agent check for subcloud by region_name request.
DCMANAGER_V1_HTTP_AGENT = "dcmanager/1.0"

# batch rehome manage state wait timeout
BATCH_REHOME_MGMT_STATES_TIMEOUT = 900

# System peer availability state
SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE = "available"
SYSTEM_PEER_AVAILABILITY_STATE_UNAVAILABLE = "unavailable"

# Peer group migration status
PEER_GROUP_MIGRATING = "migrating"
PEER_GROUP_MIGRATION_COMPLETE = "complete"
PEER_GROUP_MIGRATION_NONE = "none"

PEER_GROUP_PRIMARY_PRIORITY = 0

# Peer group association type
ASSOCIATION_TYPE_PRIMARY = "primary"
ASSOCIATION_TYPE_NON_PRIMARY = "non-primary"

# Peer group association sync status
ASSOCIATION_SYNC_STATUS_SYNCING = "syncing"
ASSOCIATION_SYNC_STATUS_IN_SYNC = "in-sync"
ASSOCIATION_SYNC_STATUS_FAILED = "failed"
ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC = "out-of-sync"
ASSOCIATION_SYNC_STATUS_UNKNOWN = "unknown"

# Peer monitor heartbeat policy
HEARTBEAT_FAILURE_POLICY_ALARM = "alarm"

SOFTWARE_VERSION_24_09 = "24.09"

# The maximum number of parallel subclouds in an orchestration process
MAX_PARALLEL_SUBCLOUDS_LIMIT = 5000
