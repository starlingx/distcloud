# Copyright (c) 2015 Huawei Tech. Co., Ltd.
# Copyright (c) 2017-2022, 2024, 2026 Wind River Systems, Inc.
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

import abc

from oslo_log import log as logging
from pecan import expose
from pecan import request
from platform_util.oidc import oidc_utils

import dcmanager.common.context as k_context
from dcmanager.common.exceptions import NotAuthorized

LOG = logging.getLogger(__name__)

# For OIDC use default project
_ADMIN_PROJECT_NAME = "admin"


def extract_context_from_environ():
    environ = request.environ

    oidc_token = request.headers.get("OIDC-Token")
    keystone_token = environ.get("HTTP_X_AUTH_TOKEN")

    # The default authentication method is always keystone, so, if the user provides
    # both tokens, the authentication should be performed with keystone, ignoring the
    # stx-auth-type parameter provided in the header.
    # Note that the dcmanager-client will not generate a scenario where both are sent
    # simultaneously.
    if keystone_token:
        context_paras = {
            "auth_token": "HTTP_X_AUTH_TOKEN",
            "user": "HTTP_X_USER_ID",
            "project": "HTTP_X_TENANT_ID",
            "user_name": "HTTP_X_USER_NAME",
            "tenant_name": "HTTP_X_PROJECT_NAME",
            "domain": "HTTP_X_DOMAIN_ID",
            "roles": "HTTP_X_ROLE",
            "user_domain": "HTTP_X_USER_DOMAIN_ID",
            "project_domain": "HTTP_X_PROJECT_DOMAIN_ID",
            "request_id": "openstack.request_id",
        }

        for key, val in context_paras.items():
            context_paras[key] = environ.get(val)
        role = environ.get("HTTP_X_ROLE")

        context_paras["is_admin"] = "admin" in role.split(",")
        context_paras["auth_type"] = "keystone"
        return k_context.RequestContext(**context_paras)

    # OIDC RequestContext
    username, roles = parse_oidc_token_claims(oidc_token)

    return k_context.RequestContext(
        auth_type="oidc",
        oidc_token=oidc_token,
        user_name=username,
        project_name=_ADMIN_PROJECT_NAME,
        roles=roles,
        is_admin=any(role in ["admin", "configurator"] for role in roles),
        request_id=environ.get("openstack.request_id"),
    )


def extract_credentials_for_policy():
    environ = request.environ
    oidc_token = request.headers.get("OIDC-Token")
    keystone_token = environ.get("HTTP_X_AUTH_TOKEN")

    if keystone_token:
        context_paras = {"project_name": "HTTP_X_PROJECT_NAME", "roles": "HTTP_X_ROLE"}
        for key, val in context_paras.items():
            context_paras[key] = environ.get(val)
        context_paras["roles"] = context_paras["roles"].split(",")
        return context_paras

    # OIDC Credentials
    _, roles = parse_oidc_token_claims(oidc_token)
    return {"project_name": _ADMIN_PROJECT_NAME, "roles": roles}


def parse_oidc_token_claims(oidc_token):
    """Return (username, roles) using a tiny shared cache."""

    oidc_config = k_context.get_oidc_args_cached(k_context._oidc_cache)
    with k_context._oidc_cache_lock:
        token_bucket = k_context._oidc_cache.setdefault("oidc_tokens", {})

    claims = oidc_utils.validate_oidc_token(
        oidc_token,
        token_bucket,
        oidc_config["oidc-issuer-url"],
        oidc_config["oidc-client-id"],
    )

    if not claims:
        LOG.error("OIDC token validation failed")
        raise NotAuthorized()

    username = oidc_utils.get_username_from_oidc_token(
        claims, oidc_config["oidc-username-claim"]
    )
    roles = oidc_utils.get_keystone_roles_for_oidc_token(
        claims,
        oidc_config["oidc-username-claim"],
        oidc_config["oidc-groups-claim"],
    )
    return username, roles


def _get_pecan_data(obj):
    return getattr(obj, "_pecan", {})


def _is_exposed(obj):
    return getattr(obj, "exposed", False)


def _is_generic(obj):
    data = _get_pecan_data(obj)
    return "generic" in data.keys()


def _is_generic_handler(obj):
    data = _get_pecan_data(obj)
    return "generic_handler" in data.keys()


class GenericPathController(object, metaclass=abc.ABCMeta):
    """A controller that allows path parameters to be equal to handler names.

    The _route method provides a custom route resolution that checks if the
    next object is marked as generic or a generic handler, pointing to the
    generic index method in case it is. Pecan will properly handle the rest
    of the routing process by redirecting it to the proper method function
    handler (GET, POST, PATCH, DELETE, etc.).

    Useful when part of the URL contains path parameters that might have
    the same name as an already defined exposed controller method.

    Requires the definition of an index method with the generator:
    @expose(generic=True, ...)

    Does not support nested subcontrollers.
    """

    RESERVED_NAMES = ("_route", "_default", "_lookup")

    @abc.abstractmethod
    def index(self):
        pass

    @expose()
    def _route(self, remainder, request):
        next_url_part, rest = remainder[0], remainder[1:]
        next_obj = getattr(self, next_url_part, None)

        is_generic = _is_generic(next_obj) or _is_generic_handler(next_obj)
        is_reserved_name = next_url_part in self.__class__.RESERVED_NAMES

        if _is_exposed(next_obj) and not is_generic and not is_reserved_name:
            # A non-generic exposed method with a non-reserved name
            return next_obj, rest
        else:
            return self.index, remainder
