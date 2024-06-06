# Copyright 2017-2024 Wind River
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
VERSION_ROOT = '/{version:[^/]*?(\/$)?}'

# Compute
FLAVOR_RESOURCE_TAG = 'flavors'
FLAVOR_ACCESS_RESOURCE_TAG = 'action'
FLAVOR_EXTRA_SPECS_RESOURCE_TAG = 'os-extra_specs'
KEYPAIRS_RESOURCE_TAG = 'os-keypairs'
QUOTA_RESOURCE_TAG = 'os-quota-sets'
QUOTA_CLASS_RESOURCE_TAG = 'os-quota-class-sets'

FLAVOR_PATHS = [
    '/v2.1/{project_id:.*?}/flavors',
    '/v2.1/{project_id:.*?}/flavors/{flavor_id}'
]

FLAVOR_ACCESS_PATHS = [
    '/v2.1/{project_id:.*?}/flavors/{flavor_id}/action'
]

EXTRA_SPECS_PATHS = [
    '/v2.1/{project_id:.*?}/flavors/{flavor_id}/os-extra_specs',
    '/v2.1/{project_id:.*?}/flavors/{flavor_id}/os-extra_specs/{extra_spec}'
]

KEYPAIRS_PATHS = [
    '/v2.1/{project_id:.*?}/os-keypairs',
    '/v2.1/{project_id:.*?}/os-keypairs/{keypair}'
]

QUOTA_PATHS = [
    '/v2.1/{project_id:.*?}/os-quota-sets/{tenant_id}',
]

QUOTA_DETAIL_PATHS = [
    '/v2.1/{project_id:.*?}/os-quota-sets/{tenant_id}/detail',
]

QUOTA_CLASS_PATHS = [
    '/v2.1/{project_id:.*?}/os-quota-class-sets/{id}',
]

COMPUTE_PATH_MAP = {
    consts.RESOURCE_TYPE_COMPUTE_FLAVOR: {
        FLAVOR_RESOURCE_TAG: FLAVOR_PATHS,
        FLAVOR_ACCESS_RESOURCE_TAG: FLAVOR_ACCESS_PATHS,
        FLAVOR_EXTRA_SPECS_RESOURCE_TAG: EXTRA_SPECS_PATHS
    },
    consts.RESOURCE_TYPE_COMPUTE_KEYPAIR: {
        KEYPAIRS_RESOURCE_TAG: KEYPAIRS_PATHS
    },
    consts.RESOURCE_TYPE_COMPUTE_QUOTA_SET: {
        QUOTA_RESOURCE_TAG: QUOTA_PATHS,
    },
    consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET: {
        QUOTA_CLASS_RESOURCE_TAG: QUOTA_CLASS_PATHS
    },
}

# Sysinv
CERTIFICATE_PATHS = [
    '/v1/certificate/certificate_install',
    '/v1/certificate/{uuid}'
]

USER_PATHS = [
    '/v1/iuser/{uuid}'
]

LOAD_PATHS = [
    '/v1/loads/import_load',
    '/v1/loads/{id}'
]

DEVICE_IMAGE_PATHS = [
    '/v1/device_images',
    '/v1/device_images/{uuid}'
]

SYSINV_PATH_MAP = {
    consts.RESOURCE_TYPE_SYSINV_CERTIFICATE: CERTIFICATE_PATHS,
    consts.RESOURCE_TYPE_SYSINV_USER: USER_PATHS,
    consts.RESOURCE_TYPE_SYSINV_LOAD: LOAD_PATHS,
    consts.RESOURCE_TYPE_SYSINV_DEVICE_IMAGE: DEVICE_IMAGE_PATHS,
}

LOAD_FILES_STAGING_DIR = '/scratch/tmp_load'
IMPORT_LOAD_FILES = ['path_to_iso', 'path_to_sig']
IMPORTED_LOAD_MAX_COUNT = 1

DEVICE_IMAGE_VAULT_DIR = '/opt/dc-vault/device_images'

# Cinder
CINDER_QUOTA_PATHS = [
    '/{version}/{admin_project_id}/os-quota-sets/{project_id}',
]

CINDER_QUOTA_CLASS_PATHS = [
    '/{version}/{admin_project_id}/os-quota-class-sets/{quota_class_name}',
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
NEUTRON_SECURITY_GROUPS_PATHS = [
    '/v2.0/security-groups',
    '/v2.0/security-groups/{security_group_id}',
]

NEUTRON_SECURITY_GROUP_RULES_PATHS = [
    '/v2.0/security-group-rules',
    '/v2.0/security-group-rules/{security_group_rule_id}',
]

NEUTRON_QOS_PATHS = [
    '/v2.0/qos/policies',
    '/v2.0/wrs-tm/qoses',
    '/v2.0/qos/policies/{policy_id}',
    '/v2.0/wrs-tm/qoses/{policy_id}',
]

NEUTRON_BANDWIDTH_LIMIT_RULES_PATHS = [
    '/v2.0/qos/policies/{policy_id}/bandwidth_limit_rules',
]

NEUTRON_DSCP_MARKING_RULES_PATHS = [
    '/v2.0/qos/policies/{policy_id}/dscp_marking_rules',
]

NEUTRON_MINIMUM_BANDWIDTH_RULES_PATHS = [
    '/v2.0/qos/policies/{policy_id}/minimum_bandwidth_rules',
    '/v2.0/qos/policies/{policy_id}/minimum_bandwidth_rules/{rule_id}',
]

NEUTRON_QUOTA_PATHS = [
    '/v2.0/quotas/{project_id}',
]

NEUTRON_QUOTA_DETAIL_PATHS = [
    '/v2.0/quotas/{project_id}/details.json',
]

NEUTRON_PATH_MAP = {
    consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
        NEUTRON_SECURITY_GROUPS_PATHS,
    consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
        NEUTRON_SECURITY_GROUP_RULES_PATHS,
    consts.RESOURCE_TYPE_NETWORK_QUOTA_SET:
        NEUTRON_QUOTA_PATHS,
    consts.RESOURCE_TYPE_QOS_POLICY:
        NEUTRON_QOS_PATHS,
}


# Software
SOFTWARE_ACTION_QUERY = 'query'
SOFTWARE_ACTION_QUERY_DEPENDENCIES = 'query_dependencies'
SOFTWARE_ACTION_COMMIT_PATCH = 'commit-patch'
SOFTWARE_ACTION_SHOW = 'show'


SOFTWARE_QUERY_PATHS = [
    '/v1/query',
    '/v1/software/query',
]

SOFTWARE_SHOW_PATHS = [
    '/v1/show/{release_id}',
    '/v1/software/show/{release_id:.*?}',
]

SOFTWARE_COMMIT_PATCH_PATHS = [
    '/v1/software/commit_dry_run/{release_id:.*?}',
    '/v1/software/commit_patch/{release_id:.*?}',
]

SOFTWARE_QUERY_DEPENDENCIES_PATHS = [
    '/v1/software/query_dependencies/{release_id:.*?}',
]

SOFTWARE_PATH_MAP = {
    SOFTWARE_ACTION_QUERY: SOFTWARE_QUERY_PATHS,
    SOFTWARE_ACTION_SHOW: SOFTWARE_SHOW_PATHS,
    SOFTWARE_ACTION_COMMIT_PATCH: SOFTWARE_COMMIT_PATCH_PATHS,
    SOFTWARE_ACTION_QUERY_DEPENDENCIES: SOFTWARE_QUERY_DEPENDENCIES_PATHS
}

# Patching
# allow version request
PATCH_ACTION_GET_VERSION = 'version'
PATCH_ACTION_UPLOAD = 'upload'
PATCH_ACTION_UPLOAD_DIR = 'upload_dir'
PATCH_ACTION_APPLY = 'apply'
PATCH_ACTION_REMOVE = 'remove'
PATCH_ACTION_DELETE = 'delete'
PATCH_ACTION_QUERY = 'query'
PATCH_ACTION_SHOW = 'show'
PATCH_ACTION_COMMIT = 'commit'
PATCH_ACTION_WHAT_REQS = 'what_requires'
PATCH_ACTION_QUERY_DEPS = 'query_dependencies'

PATCH_API_VERSION = ['/']

PATCH_UPLOAD_PATHS = [
    '/v1/upload',
    '/patch/upload',
]

# upload_dir is not supported for REST API access
PATCH_UPLOAD_DIR_PATHS = [
    '/patch/upload_dir'
]

PATCH_APPLY_PATHS = [
    '/v1/apply/{patch_id}',
    '/patch/apply/{patch_id:.*?}',
]

PATCH_REMOVE_PATHS = [
    '/v1/remove/{patch_id}',
    '/patch/remove/{patch_id:.*?}',
]

PATCH_DELETE_PATHS = [
    '/v1/delete/{patch_id}',
    '/patch/delete/{patch_id:.*?}',
]

PATCH_QUERY_PATHS = [
    '/v1/query',
    '/patch/query',
]

PATCH_SHOW_PATHS = [
    '/v1/show/{patch_id}',
    '/patch/show/{patch_id:.*?}',
]

PATCH_COMMIT_PATHS = [
    '/patch/commit_dry_run/{patch_id:.*?}',
    '/patch/commit/{patch_id:.*?}',
]

PATCH_WHAT_REQS_PATHS = [
    '/patch/what_requires/{patch_id:.*?}'
]

PATCH_QUERY_DEPS_PATHS = [
    '/patch/query_dependencies/{patch_id:.*?}'
]

PATCH_PATH_MAP = {
    PATCH_ACTION_GET_VERSION: PATCH_API_VERSION,
    PATCH_ACTION_UPLOAD: PATCH_UPLOAD_PATHS,
    PATCH_ACTION_UPLOAD_DIR: PATCH_UPLOAD_DIR_PATHS,
    PATCH_ACTION_APPLY: PATCH_APPLY_PATHS,
    PATCH_ACTION_REMOVE: PATCH_REMOVE_PATHS,
    PATCH_ACTION_DELETE: PATCH_DELETE_PATHS,
    PATCH_ACTION_QUERY: PATCH_QUERY_PATHS,
    PATCH_ACTION_SHOW: PATCH_SHOW_PATHS,
    PATCH_ACTION_COMMIT: PATCH_COMMIT_PATHS,
    PATCH_ACTION_WHAT_REQS: PATCH_WHAT_REQS_PATHS,
    PATCH_ACTION_QUERY_DEPS: PATCH_QUERY_DEPS_PATHS,
}

# Identity
IDENTITY_USERS_PATH = [
    '/v3/users',
    '/v3/users/{user_id}',
]

IDENTITY_USERS_PW_PATH = [
    '/v3/users/{user_id}/password',
]

IDENTITY_USER_GROUPS_PATH = [
    '/v3/groups',
    '/v3/groups/{group_id}',
    '/v3/groups/{group_id}/users/{user_id}',
]

IDENTITY_ROLES_PATH = [
    '/v3/roles',
    '/v3/roles/{role_id}',
]

IDENTITY_PROJECTS_PATH = [
    '/v3/projects',
    '/v3/projects/{project_id}',
]

IDENTITY_PROJECTS_ROLE_PATH = [
    '/v3/projects/{project_id}/users/{user_id}/roles/{role_id}',
    '/v3/projects/{project_id}/groups/{group_id}/roles/{role_id}',
]

IDENTITY_TOKEN_REVOKE_EVENTS_PATH = [
    '/v3/auth/tokens',
]

IDENTITY_PATH_MAP = {
    consts.RESOURCE_TYPE_IDENTITY_USERS: IDENTITY_USERS_PATH,
    consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD: IDENTITY_USERS_PW_PATH,
    consts.RESOURCE_TYPE_IDENTITY_GROUPS: IDENTITY_USER_GROUPS_PATH,
    consts.RESOURCE_TYPE_IDENTITY_ROLES: IDENTITY_ROLES_PATH,
    consts.RESOURCE_TYPE_IDENTITY_PROJECTS: IDENTITY_PROJECTS_PATH,
    consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS:
        IDENTITY_PROJECTS_ROLE_PATH,
    consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS:
        IDENTITY_TOKEN_REVOKE_EVENTS_PATH,
}

ROUTE_METHOD_MAP = {
    consts.ENDPOINT_TYPE_COMPUTE: {
        FLAVOR_RESOURCE_TAG: ['POST', 'DELETE'],
        FLAVOR_ACCESS_RESOURCE_TAG: ['POST'],
        FLAVOR_EXTRA_SPECS_RESOURCE_TAG: ['POST', 'PUT', 'DELETE'],
        KEYPAIRS_RESOURCE_TAG: ['POST', 'DELETE'],
        QUOTA_RESOURCE_TAG: ['PUT', 'DELETE', 'GET'],
        QUOTA_CLASS_RESOURCE_TAG: ['PUT'],
    },
    consts.ENDPOINT_TYPE_VOLUME: {
        QUOTA_RESOURCE_TAG: ['PUT', 'DELETE', 'GET'],
        QUOTA_CLASS_RESOURCE_TAG: ['PUT'],
    },
    dccommon_consts.ENDPOINT_TYPE_PLATFORM: {
        consts.RESOURCE_TYPE_SYSINV_CERTIFICATE: ['POST', 'DELETE'],
        consts.RESOURCE_TYPE_SYSINV_USER: ['PATCH', 'PUT'],
        consts.RESOURCE_TYPE_SYSINV_LOAD: ['POST', 'DELETE'],
        consts.RESOURCE_TYPE_SYSINV_DEVICE_IMAGE: ['POST', 'PATCH', 'DELETE'],
    },
    consts.ENDPOINT_TYPE_NETWORK: {
        consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP: ['POST', 'PUT', 'DELETE'],
        consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE: ['POST', 'DELETE'],
        consts.RESOURCE_TYPE_NETWORK_QUOTA_SET: ['PUT', 'DELETE'],
        consts.RESOURCE_TYPE_QOS_POLICY: ['POST', 'PUT', 'DELETE'],
    },
    dccommon_consts.ENDPOINT_TYPE_PATCHING: {
        PATCH_ACTION_GET_VERSION: ['GET'],
        PATCH_ACTION_UPLOAD: ['POST'],
        PATCH_ACTION_UPLOAD_DIR: ['POST'],
        PATCH_ACTION_APPLY: ['POST'],
        PATCH_ACTION_REMOVE: ['POST'],
        PATCH_ACTION_DELETE: ['POST'],
        PATCH_ACTION_QUERY: ['GET'],
        PATCH_ACTION_SHOW: ['POST', 'GET'],
        PATCH_ACTION_COMMIT: ['POST'],
        PATCH_ACTION_WHAT_REQS: ['GET'],
        PATCH_ACTION_QUERY_DEPS: ['GET'],
        SOFTWARE_ACTION_QUERY: ['GET'],
        SOFTWARE_ACTION_SHOW: ['GET'],
        SOFTWARE_ACTION_QUERY_DEPENDENCIES: ['GET'],
        SOFTWARE_ACTION_COMMIT_PATCH: ['POST'],
    },
    dccommon_consts.ENDPOINT_TYPE_IDENTITY: {
        consts.RESOURCE_TYPE_IDENTITY_USERS:
            ['POST', 'PATCH', 'DELETE'],
        consts.RESOURCE_TYPE_IDENTITY_GROUPS:
            ['POST', 'PUT', 'PATCH', 'DELETE'],
        consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD:
            ['POST'],
        consts.RESOURCE_TYPE_IDENTITY_ROLES:
            ['POST', 'PATCH', 'DELETE'],
        consts.RESOURCE_TYPE_IDENTITY_PROJECTS:
            ['POST', 'PATCH', 'DELETE'],
        consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS:
            ['PUT', 'DELETE'],
        consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS:
            ['DELETE']

    }
}

LOAD_VAULT_DIR = '/opt/dc-vault/loads'
LOAD_VAULT_TMP_DIR = '/opt/dc-vault/loads/load_tmpdir'
ENDPOINT_TYPE_PATCHING_TMPDIR = "/scratch/patch-api-proxy-tmpdir"
ENDPOINT_TYPE_PLATFORM_TMPDIR = "/scratch/platform-api-proxy-tmpdir"
