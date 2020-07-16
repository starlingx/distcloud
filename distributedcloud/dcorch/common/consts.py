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


NOVA_QUOTA_FIELDS = ("metadata_items",
                     "cores",
                     "instances",
                     "ram",
                     "key_pairs",
                     "injected_files",
                     "injected_file_path_bytes",
                     "injected_file_content_bytes",
                     "server_group_members",
                     "server_groups",)

CINDER_QUOTA_FIELDS = ("volumes",
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
                       "backup_gigabytes")

NEUTRON_QUOTA_FIELDS = ("network",
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

JOB_PROGRESS = "IN_PROGRESS"

RPC_API_VERSION = "1.0"

TOPIC_ORCH_ENGINE = "dcorch-engine"

# SyncRequest States
ORCH_REQUEST_NONE = None
ORCH_REQUEST_QUEUED = "queued"  # in database, not in thread
ORCH_REQUEST_IN_PROGRESS = "in-progress"
ORCH_REQUEST_COMPLETED = "completed"
ORCH_REQUEST_FAILED = "failed"
ORCH_REQUEST_TIMED_OUT = "timed-out"
ORCH_REQUEST_ABORTED = "aborted"

# SysInv Resources
RESOURCE_TYPE_SYSINV_CERTIFICATE = "certificates"
RESOURCE_TYPE_SYSINV_DNS = "idns"
RESOURCE_TYPE_SYSINV_SNMP_COMM = "icommunity"
RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST = "itrapdest"
RESOURCE_TYPE_SYSINV_USER = "iuser"
RESOURCE_TYPE_SYSINV_FERNET_REPO = "fernet_repo"
RESOURCE_TYPE_SYSINV_LOAD = "loads"
RESOURCE_TYPE_SYSINV_DEVICE_IMAGE = "device_image"

# Compute Resources
RESOURCE_TYPE_COMPUTE_FLAVOR = "flavor"
RESOURCE_TYPE_COMPUTE_KEYPAIR = "keypair"
RESOURCE_TYPE_COMPUTE_QUOTA_SET = "compute_quota_set"
RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET = "quota_class_set"

# Volume Resources
RESOURCE_TYPE_VOLUME_QUOTA_SET = "volume_quota_set"
RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET = "quota_class_set"

# These are quota items that control resources that are managed
# by dcorch.  It doesn't make sense to count the usage in the
# various subclouds since they're all essentially duplicates
# of what's in the master cloud.
QUOTAS_FOR_MANAGED_RESOURCES = ['key_pairs',
                                'security_group',
                                'security_group_rule']

# Neutron Resources
RESOURCE_TYPE_NETWORK_QUOTA_SET = "network_quota_set"
RESOURCE_TYPE_NETWORK_SECURITY_GROUP = "security_group"
RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE = "security_group_rule"
RESOURCE_TYPE_QOS_POLICY = "qos"

# Identity Resources
RESOURCE_TYPE_IDENTITY_USERS = "users"
RESOURCE_TYPE_IDENTITY_USERS_PASSWORD = "users_password"
RESOURCE_TYPE_IDENTITY_ROLES = "roles"
RESOURCE_TYPE_IDENTITY_PROJECTS = "projects"
RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS = "project_role_assignments"
RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS = "revoke_events"
RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS_FOR_USER = "revoke_events_for_user"

KEYPAIR_ID_DELIM = "/"

SHARED_CONFIG_STATE_MANAGED = "managed"
SHARED_CONFIG_STATE_UNMANAGED = "unmanaged"

ENDPOINT_TYPE_PLATFORM = "platform"
ENDPOINT_TYPE_VOLUME = "volume"
ENDPOINT_TYPE_COMPUTE = "compute"
ENDPOINT_TYPE_NETWORK = "network"
ENDPOINT_TYPE_PATCHING = "patching"
ENDPOINT_TYPE_IDENTITY = "identity"
ENDPOINT_TYPE_FM = "faultmanagement"
ENDPOINT_TYPE_NFV = "nfv"
ENDPOINT_TYPE_LOAD = "load"
ENDPOINT_TYPE_DC_CERT = 'dc-cert'

# All endpoint types
ENDPOINT_TYPES_LIST = [ENDPOINT_TYPE_PLATFORM,
                       ENDPOINT_TYPE_PATCHING,
                       ENDPOINT_TYPE_IDENTITY,
                       ENDPOINT_TYPE_LOAD,
                       ENDPOINT_TYPE_DC_CERT]

# Dcorch sync endpoint types
SYNC_ENDPOINT_TYPES_LIST = [ENDPOINT_TYPE_PLATFORM,
                            ENDPOINT_TYPE_IDENTITY]

ENDPOINT_QUOTA_MAPPING = {
    ENDPOINT_TYPE_COMPUTE: NOVA_QUOTA_FIELDS,
    ENDPOINT_TYPE_NETWORK: NEUTRON_QUOTA_FIELDS,
    ENDPOINT_TYPE_VOLUME: CINDER_QUOTA_FIELDS,
}

# DB sync agent endpoint
DBS_ENDPOINT_INTERNAL = "internal"
DBS_ENDPOINT_ADMIN = "admin"
DBS_ENDPOINT_DEFAULT = DBS_ENDPOINT_INTERNAL

# Do we need separate patch/put operations or could we just use
# create/update/delete and have the sync code know which HTTP
# operation to use?
OPERATION_TYPE_CREATE = "create"
OPERATION_TYPE_POST = "post"
OPERATION_TYPE_PATCH = "patch"
OPERATION_TYPE_PUT = "put"
OPERATION_TYPE_DELETE = "delete"
OPERATION_TYPE_ACTION = "action"
OPERATION_TYPE_GET = "get"

ORCH_REQUEST_STATE_NONE = None
ORCH_REQUEST_STATE_IN_PROGRESS = "in-progress"
ORCH_REQUEST_STATE_COMPLETED = "completed"
ORCH_REQUEST_STATE_FAILED = "failed"
ORCH_REQUEST_STATE_TIMED_OUT = "timed-out"
ORCH_REQUEST_STATE_ABORTED = "aborted"

# Flavor Actions
ACTION_ADDTENANTACCESS = "addTenantAccess"
ACTION_REMOVETENANTACCESS = "removeTenantAccess"
ACTION_EXTRASPECS_POST = "extra_specs"
ACTION_EXTRASPECS_DELETE = "extra_specs_delete"

# Subcloud initial sync state
INITIAL_SYNC_STATE_NONE = "none"
INITIAL_SYNC_STATE_REQUESTED = "requested"
INITIAL_SYNC_STATE_IN_PROGRESS = "in-progress"
INITIAL_SYNC_STATE_COMPLETED = "completed"
INITIAL_SYNC_STATE_FAILED = "failed"

# Active load state
LOAD_STATE_ACTIVE = 'active'
