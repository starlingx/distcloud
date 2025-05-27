# Copyright 2017-2025 Wind River
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from dccommon import consts as dccommon_consts
from dcorch.common import consts

# Version could be any of the following: /, /v1, /v1/
# but must deny regular paths such as /v1/isystems
VERSION_ROOT = "/{version:[^/]*?(\/$)?}"

# Compute
FLAVOR_RESOURCE_TAG = "flavors"
FLAVOR_ACCESS_RESOURCE_TAG = "action"
FLAVOR_EXTRA_SPECS_RESOURCE_TAG = "os-extra_specs"
KEYPAIRS_RESOURCE_TAG = "os-keypairs"
QUOTA_RESOURCE_TAG = "os-quota-sets"
QUOTA_CLASS_RESOURCE_TAG = "os-quota-class-sets"

FLAVOR_PATHS = [
    "/v2.1/{project_id:.*?}/flavors",
    "/v2.1/{project_id:.*?}/flavors/{flavor_id}",
]

FLAVOR_ACCESS_PATHS = ["/v2.1/{project_id:.*?}/flavors/{flavor_id}/action"]

EXTRA_SPECS_PATHS = [
    "/v2.1/{project_id:.*?}/flavors/{flavor_id}/os-extra_specs",
    "/v2.1/{project_id:.*?}/flavors/{flavor_id}/os-extra_specs/{extra_spec}",
]

KEYPAIRS_PATHS = [
    "/v2.1/{project_id:.*?}/os-keypairs",
    "/v2.1/{project_id:.*?}/os-keypairs/{keypair}",
]

QUOTA_PATHS = [
    "/v2.1/{project_id:.*?}/os-quota-sets/{tenant_id}",
]

QUOTA_DETAIL_PATHS = [
    "/v2.1/{project_id:.*?}/os-quota-sets/{tenant_id}/detail",
]

QUOTA_CLASS_PATHS = [
    "/v2.1/{project_id:.*?}/os-quota-class-sets/{id}",
]

COMPUTE_PATH_MAP = {
    consts.RESOURCE_TYPE_COMPUTE_FLAVOR: {
        FLAVOR_RESOURCE_TAG: FLAVOR_PATHS,
        FLAVOR_ACCESS_RESOURCE_TAG: FLAVOR_ACCESS_PATHS,
        FLAVOR_EXTRA_SPECS_RESOURCE_TAG: EXTRA_SPECS_PATHS,
    },
    consts.RESOURCE_TYPE_COMPUTE_KEYPAIR: {KEYPAIRS_RESOURCE_TAG: KEYPAIRS_PATHS},
    consts.RESOURCE_TYPE_COMPUTE_QUOTA_SET: {
        QUOTA_RESOURCE_TAG: QUOTA_PATHS,
    },
    consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET: {
        QUOTA_CLASS_RESOURCE_TAG: QUOTA_CLASS_PATHS
    },
}

# Sysinv
CERTIFICATE_PATHS = ["/v1/certificate/certificate_install", "/v1/certificate/{uuid}"]

USER_PATHS = ["/v1/iuser/{uuid}"]

RELEASE_PATHS = ["/v1/release", "/v1/release/{rel_id}"]

DEVICE_IMAGE_PATHS = ["/v1/device_images", "/v1/device_images/{uuid}"]

SYSINV_PATH_MAP = {
    consts.RESOURCE_TYPE_SYSINV_CERTIFICATE: CERTIFICATE_PATHS,
    consts.RESOURCE_TYPE_SYSINV_USER: USER_PATHS,
    consts.RESOURCE_TYPE_SYSINV_DEVICE_IMAGE: DEVICE_IMAGE_PATHS,
}

USM_PATH_MAP = {
    consts.RESOURCE_TYPE_USM_RELEASE: RELEASE_PATHS,
}

LOAD_FILES_STAGING_DIR = "/scratch/tmp_load"

DEVICE_IMAGE_VAULT_DIR = "/opt/dc-vault/device_images"

# Cinder
CINDER_QUOTA_PATHS = [
    "/{version}/{admin_project_id}/os-quota-sets/{project_id}",
]

CINDER_QUOTA_CLASS_PATHS = [
    "/{version}/{admin_project_id}/os-quota-class-sets/{quota_class_name}",
]

CINDER_PATH_MAP = {
    consts.RESOURCE_TYPE_VOLUME_QUOTA_SET: {
        QUOTA_RESOURCE_TAG: CINDER_QUOTA_PATHS,
    },
    consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET: {
        QUOTA_CLASS_RESOURCE_TAG: CINDER_QUOTA_CLASS_PATHS
    },
}

# Neutron
NEUTRON_SEC_GROUPS_PATHS = [
    "/v2.0/security-groups",
    "/v2.0/security-groups/{security_group_id}",
]

NEUTRON_SEC_GROUP_RULES_PATHS = [
    "/v2.0/security-group-rules",
    "/v2.0/security-group-rules/{security_group_rule_id}",
]

NEUTRON_QOS_PATHS = [
    "/v2.0/qos/policies",
    "/v2.0/wrs-tm/qoses",
    "/v2.0/qos/policies/{policy_id}",
    "/v2.0/wrs-tm/qoses/{policy_id}",
]

NEUTRON_BANDWIDTH_LIMIT_RULES_PATHS = [
    "/v2.0/qos/policies/{policy_id}/bandwidth_limit_rules",
]

NEUTRON_DSCP_MARKING_RULES_PATHS = [
    "/v2.0/qos/policies/{policy_id}/dscp_marking_rules",
]

NEUTRON_MINIMUM_BANDWIDTH_RULES_PATHS = [
    "/v2.0/qos/policies/{policy_id}/minimum_bandwidth_rules",
    "/v2.0/qos/policies/{policy_id}/minimum_bandwidth_rules/{rule_id}",
]

NEUTRON_QUOTA_PATHS = [
    "/v2.0/quotas/{project_id}",
]

NEUTRON_QUOTA_DETAIL_PATHS = [
    "/v2.0/quotas/{project_id}/details.json",
]

NEUTRON_PATH_MAP = {
    consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP: NEUTRON_SEC_GROUPS_PATHS,
    consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE: NEUTRON_SEC_GROUP_RULES_PATHS,
    consts.RESOURCE_TYPE_NETWORK_QUOTA_SET: NEUTRON_QUOTA_PATHS,
    consts.RESOURCE_TYPE_QOS_POLICY: NEUTRON_QOS_PATHS,
}

# Identity
IDENTITY_USERS_PATH = [
    "/v3/users",
    "/v3/users/{user_id}",
]

IDENTITY_USERS_PW_PATH = [
    "/v3/users/{user_id}/password",
]

IDENTITY_USER_GROUPS_PATH = [
    "/v3/groups",
    "/v3/groups/{group_id}",
    "/v3/groups/{group_id}/users/{user_id}",
]

IDENTITY_ROLES_PATH = [
    "/v3/roles",
    "/v3/roles/{role_id}",
]

IDENTITY_PROJECTS_PATH = [
    "/v3/projects",
    "/v3/projects/{project_id}",
]

IDENTITY_PROJECTS_ROLE_PATH = [
    "/v3/projects/{project_id}/users/{user_id}/roles/{role_id}",
    "/v3/projects/{project_id}/groups/{group_id}/roles/{role_id}",
]

IDENTITY_TOKEN_EVENTS_PATH = [
    "/v3/auth/tokens",
]

IDENTITY_PATH_MAP = {
    consts.RESOURCE_TYPE_IDENTITY_USERS: IDENTITY_USERS_PATH,
    consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD: IDENTITY_USERS_PW_PATH,
    consts.RESOURCE_TYPE_IDENTITY_GROUPS: IDENTITY_USER_GROUPS_PATH,
    consts.RESOURCE_TYPE_IDENTITY_ROLES: IDENTITY_ROLES_PATH,
    consts.RESOURCE_TYPE_IDENTITY_PROJECTS: IDENTITY_PROJECTS_PATH,
    consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS: IDENTITY_PROJECTS_ROLE_PATH,
    consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS: IDENTITY_TOKEN_EVENTS_PATH,
}

ROUTE_METHOD_MAP = {
    consts.ENDPOINT_TYPE_COMPUTE: {
        FLAVOR_RESOURCE_TAG: ["POST", "DELETE"],
        FLAVOR_ACCESS_RESOURCE_TAG: ["POST"],
        FLAVOR_EXTRA_SPECS_RESOURCE_TAG: ["POST", "PUT", "DELETE"],
        KEYPAIRS_RESOURCE_TAG: ["POST", "DELETE"],
        QUOTA_RESOURCE_TAG: ["PUT", "DELETE", "GET"],
        QUOTA_CLASS_RESOURCE_TAG: ["PUT"],
    },
    consts.ENDPOINT_TYPE_VOLUME: {
        QUOTA_RESOURCE_TAG: ["PUT", "DELETE", "GET"],
        QUOTA_CLASS_RESOURCE_TAG: ["PUT"],
    },
    dccommon_consts.ENDPOINT_TYPE_PLATFORM: {
        consts.RESOURCE_TYPE_SYSINV_CERTIFICATE: ["POST", "DELETE"],
        consts.RESOURCE_TYPE_SYSINV_USER: ["PATCH", "PUT"],
        consts.RESOURCE_TYPE_SYSINV_DEVICE_IMAGE: ["POST", "PATCH", "DELETE"],
    },
    consts.ENDPOINT_TYPE_NETWORK: {
        consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP: ["POST", "PUT", "DELETE"],
        consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE: ["POST", "DELETE"],
        consts.RESOURCE_TYPE_NETWORK_QUOTA_SET: ["PUT", "DELETE"],
        consts.RESOURCE_TYPE_QOS_POLICY: ["POST", "PUT", "DELETE"],
    },
    dccommon_consts.ENDPOINT_TYPE_IDENTITY: {
        consts.RESOURCE_TYPE_IDENTITY_USERS: ["POST", "PATCH", "DELETE"],
        consts.RESOURCE_TYPE_IDENTITY_GROUPS: ["POST", "PUT", "PATCH", "DELETE"],
        consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD: ["POST"],
        consts.RESOURCE_TYPE_IDENTITY_ROLES: ["POST", "PATCH", "DELETE"],
        consts.RESOURCE_TYPE_IDENTITY_PROJECTS: ["POST", "PATCH", "DELETE"],
        consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS: ["PUT", "DELETE"],
        consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS: ["DELETE"],
    },
    dccommon_consts.ENDPOINT_TYPE_USM: {
        consts.RESOURCE_TYPE_USM_RELEASE: ["PUT", "POST", "DELETE"],
    },
}

ENDPOINT_TYPE_PLATFORM_TMPDIR = "/scratch/platform-api-proxy-tmpdir"
ENDPOINT_TYPE_USM_TMPDIR = "/scratch/software-upload-tmpdir"
