# Copyright (c) 2020-2024 Wind River Systems, Inc.
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

SECONDS_IN_HOUR = 3600

KS_ENDPOINT_ADMIN = "admin"
KS_ENDPOINT_INTERNAL = "internal"
KS_ENDPOINT_PUBLIC = "public"
KS_ENDPOINT_DEFAULT = KS_ENDPOINT_ADMIN

KS_ENDPOINT_USER_DOMAIN_DEFAULT = "Default"
KS_ENDPOINT_PROJECT_DEFAULT = "admin"
KS_ENDPOINT_PROJECT_DOMAIN_DEFAULT = "Default"

ENDPOINT_TYPE_IDENTITY_OS = "identity_openstack"

# openstack endpoint types
ENDPOINT_TYPES_LIST_OS = [ENDPOINT_TYPE_IDENTITY_OS]

# distributed Cloud constants
# TODO(gherzmann) Remove the following constants in favor of the
# SYSTEM_CONTROLLER_NAME and DEFAULT_REGION_NAME constants
CLOUD_0 = "RegionOne"
VIRTUAL_MASTER_CLOUD = "SystemController"

SW_UPDATE_DEFAULT_TITLE = "all clouds default"
ANSIBLE_OVERRIDES_PATH = "/opt/dc-vault/ansible"
SOFTWARE_VAULT_DIR = "/opt/dc-vault/software"
SOFTWARE_VAULT_METADATA = ".metadata"
DEPLOY_DIR = "/opt/platform/deploy"

USER_HEADER_VALUE = "distcloud"
USER_HEADER = {"User-Header": USER_HEADER_VALUE}

ADMIN_USER_NAME = "admin"
ADMIN_PROJECT_NAME = "admin"
SYSINV_USER_NAME = "sysinv"
DCMANAGER_USER_NAME = "dcmanager"
SERVICES_USER_NAME = "services"

NOVA_QUOTA_FIELDS = (
    "metadata_items",
    "cores",
    "instances",
    "ram",
    "key_pairs",
    "injected_files",
    "injected_file_path_bytes",
    "injected_file_content_bytes",
    "server_group_members",
    "server_groups",
)

CINDER_QUOTA_FIELDS = (
    "volumes",
    "volumes_iscsi",
    "volumes_ceph",
    "per_volume_gigabytes",
    "groups",
    "snapshots",
    "snapshots_iscsi",
    "snapshots_ceph",
    "gigabytes",
    "gigabytes_iscsi",
    "gigabytes_ceph",
    "backups",
    "backup_gigabytes",
)

NEUTRON_QUOTA_FIELDS = (
    "network",
    "subnet",
    "subnetpool",
    "rbac_policy",
    "trunk",
    "port",
    "router",
    "floatingip",
    "security_group",
    "security_group_rule",
)

# Endpoint services names
ENDPOINT_NAME_DCAGENT = "dcagent"
ENDPOINT_NAME_FM = "fm"
ENDPOINT_NAME_KEYSTONE = "keystone"
ENDPOINT_NAME_SYSINV = "sysinv"
ENDPOINT_NAME_USM = "usm"
ENDPOINT_NAME_VIM = "vim"

# Endpoint services types
ENDPOINT_TYPE_DCAGENT = "dcagent"
ENDPOINT_TYPE_DC_CERT = "dc-cert"
ENDPOINT_TYPE_FIRMWARE = "firmware"
ENDPOINT_TYPE_IDENTITY = "identity"
ENDPOINT_TYPE_KUBERNETES = "kubernetes"
ENDPOINT_TYPE_KUBE_ROOTCA = "kube-rootca"
ENDPOINT_TYPE_USM = "usm"
ENDPOINT_TYPE_PLATFORM = "platform"
ENDPOINT_TYPE_FM = "faultmanagement"
ENDPOINT_TYPE_NFV = "nfv"
# TODO(nicodemos): Remove patching/load after patching is no longer supported
ENDPOINT_TYPE_LOAD = "load"
ENDPOINT_TYPE_PATCHING = "patching"

# TODO(nicodemos): Rename all other audit to use AUDIT_TYPE_
AUDIT_TYPE_SOFTWARE = "software"

# All endpoint types
# TODO(nicodemos): Remove patching after is no longer supported
ENDPOINT_TYPES_LIST = [
    ENDPOINT_TYPE_PLATFORM,
    ENDPOINT_TYPE_PATCHING,
    ENDPOINT_TYPE_IDENTITY,
    ENDPOINT_TYPE_USM,
]

# TODO(nicodemos): Remove patching/load after is no longer supported
AUDIT_TYPES_LIST = [
    ENDPOINT_TYPE_PLATFORM,
    ENDPOINT_TYPE_PATCHING,
    ENDPOINT_TYPE_IDENTITY,
    ENDPOINT_TYPE_LOAD,
    ENDPOINT_TYPE_DC_CERT,
    ENDPOINT_TYPE_FIRMWARE,
    ENDPOINT_TYPE_KUBERNETES,
    ENDPOINT_TYPE_KUBE_ROOTCA,
    AUDIT_TYPE_SOFTWARE,
]


# All endpoint audit requests
# TODO(nicodemos): Remove patching/load after is no longer supported
# TODO(nicodemos): The AUDIT_TYPE_SOFTWARE will use the 'spare_audit_requested'
# temporarily until the USM feature is fully complete. Afterward, the software audit
# will replace the patch audit.
ENDPOINT_AUDIT_REQUESTS = {
    ENDPOINT_TYPE_FIRMWARE: "firmware_audit_requested",
    ENDPOINT_TYPE_KUBERNETES: "kubernetes_audit_requested",
    ENDPOINT_TYPE_KUBE_ROOTCA: "kube_rootca_update_audit_requested",
    ENDPOINT_TYPE_LOAD: "load_audit_requested",
    ENDPOINT_TYPE_PATCHING: "patch_audit_requested",
    AUDIT_TYPE_SOFTWARE: "spare_audit_requested",
}

# TODO(nicodemos): Remove patching/load after is no longer supported
ENDPOINT_URLS = {
    ENDPOINT_NAME_DCAGENT: "https://{}:8326",
    ENDPOINT_NAME_FM: "https://{}:18003",
    ENDPOINT_NAME_KEYSTONE: "https://{}:5001/v3",
    ENDPOINT_TYPE_PATCHING: "https://{}:5492",
    ENDPOINT_NAME_SYSINV: "https://{}:6386/v1",
    ENDPOINT_NAME_USM: "https://{}:5498",
    ENDPOINT_NAME_VIM: "https://{}:4546",
}

BASE_AUDIT = "base_audit"
FIRMWARE_AUDIT = "firmware_audit"
KUBERNETES_AUDIT = "kubernetes_audit"
KUBE_ROOTCA_AUDIT = "kube_rootca_audit"
SOFTWARE_AUDIT = "software_audit"
SKIP_AUDIT = "skip"

DCAGENT_ENDPOINT_TYPE_MAP = {
    FIRMWARE_AUDIT: ENDPOINT_TYPE_FIRMWARE,
    KUBERNETES_AUDIT: ENDPOINT_TYPE_KUBERNETES,
    KUBE_ROOTCA_AUDIT: ENDPOINT_TYPE_KUBE_ROOTCA,
    SOFTWARE_AUDIT: AUDIT_TYPE_SOFTWARE,
}

MIN_VERSION_FOR_DCAGENT = "24.09"

# Well known region names
SYSTEM_CONTROLLER_NAME = "SystemController"
DEFAULT_REGION_NAME = "RegionOne"

# Subcloud management state
MANAGEMENT_UNMANAGED = "unmanaged"
MANAGEMENT_MANAGED = "managed"

# Subcloud availability status
AVAILABILITY_OFFLINE = "offline"
AVAILABILITY_ONLINE = "online"

# Subcloud sync status
SYNC_STATUS_UNKNOWN = "unknown"
SYNC_STATUS_IN_SYNC = "in-sync"
SYNC_STATUS_OUT_OF_SYNC = "out-of-sync"
SYNC_STATUS_NOT_AVAILABLE = "not-available"

# Subcloud deploy configuration status
DEPLOY_CONFIG_UP_TO_DATE = "Deployment: configurations up-to-date"
DEPLOY_CONFIG_OUT_OF_DATE = "Deployment: configurations out-of-date"
MONITORED_ALARM_ENTITIES = [
    "host.starlingx.windriver.com",
]

# OS type
OS_RELEASE_FILE = "/etc/os-release"
OS_CENTOS = "centos"
OS_DEBIAN = "debian"
SUPPORTED_OS_TYPES = [OS_CENTOS, OS_DEBIAN]

# SSL cert
CERT_CA_FILE_CENTOS = "ca-cert.pem"
CERT_CA_FILE_DEBIAN = "ca-cert.crt"
SSL_CERT_CA_DIR = "/etc/pki/ca-trust/source/anchors/"

# RVMC
RVMC_NAME_PREFIX = "rvmc"
RVMC_CONFIG_FILE_NAME = "rvmc-config.yaml"

# Required for GEO-redundancy
# User-Agent check for subcloud by region_name request.
DCMANAGER_V1_HTTP_AGENT = "dcmanager/1.0"

# Subcloud installation values
BMC_INSTALL_VALUES = [
    "bmc_username",
    "bmc_address",
    "bmc_password",
]

OPTIONAL_BMC_INSTALL_VALUES = [
    "bmc_ciphersuite",
]

MANDATORY_INSTALL_VALUES = [
    "bootstrap_interface",
    "bootstrap_address",
    "bootstrap_address_prefix",
    "install_type",
] + BMC_INSTALL_VALUES

MANDATORY_ENROLL_INIT_VALUES = [
    "bootstrap_interface",
    "external_oam_subnet",
    "external_oam_gateway_address",
    "external_oam_floating_address",
    "admin_password",
    "system_mode",
    "software_version",
] + BMC_INSTALL_VALUES

OPTIONAL_INSTALL_VALUES = [
    "nexthop_gateway",
    "network_address",
    "network_mask",
    "console_type",
    "bootstrap_vlan",
    "rootfs_device",
    "boot_device",
    "rd.net.timeout.ipv6dad",
    "no_check_certificate",
    "persistent_size",
    "hw_settle",
    "extra_boot_params",
]

GEN_ISO_OPTIONS = {
    "bootstrap_interface": "--boot-interface",
    "bootstrap_address": "--boot-ip",
    "bootstrap_address_prefix": "--boot-netmask",
    "install_type": "--default-boot",
    "nexthop_gateway": "--boot-gateway",
    "rootfs_device": "--param",
    "boot_device": "--param",
    "rd.net.timeout.ipv6dad": "--param",
    "bootstrap_vlan": "--param",
    "no_check_certificate": "--param",
    "persistent_size": "--param",
    "hw_settle": "--param",
    "extra_boot_params": "--param",
}

SUPPORTED_INSTALL_TYPES = 6
ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/install.yml"
)

ENROLL_INIT_SEED_ISO_NAME = "seed.iso"

ANSIBLE_SUBCLOUD_ENROLL_PLAYBOOK = (
    "/usr/share/ansible/stx-ansible/playbooks/enroll_subcloud.yml"
)

# Sysinv client default timeout
SYSINV_CLIENT_REST_DEFAULT_TIMEOUT = 600

SUBCLOUD_ISO_PATH = "/opt/platform/iso"
SUBCLOUD_FEED_PATH = "/var/www/pages/feed"
