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
VERSION_ROOT = r"/{version:[^/]*?(\/$)?}"

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
    dccommon_consts.ENDPOINT_TYPE_PLATFORM: {
        consts.RESOURCE_TYPE_SYSINV_CERTIFICATE: ["POST", "DELETE"],
        consts.RESOURCE_TYPE_SYSINV_USER: ["PATCH", "PUT"],
        consts.RESOURCE_TYPE_SYSINV_DEVICE_IMAGE: ["POST", "PATCH", "DELETE"],
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
