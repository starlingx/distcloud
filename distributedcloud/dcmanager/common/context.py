# Copyright (c) 2017-2022 Wind River Systems, Inc.
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

import pecan
from pecan import hooks
import re
from six.moves.urllib.parse import urlparse
import time

from oslo_context import context as base_context
from oslo_log import log
from oslo_utils import encodeutils
from oslo_utils import uuidutils

from dcmanager.api.policies import base as base_policy
from dcmanager.api import policy
from dcmanager.db import api as db_api

ALLOWED_WITHOUT_AUTH = '/'

audit_log_name = "{}.{}".format(__name__, "auditor")
auditLOG = log.getLogger(audit_log_name)


def generate_request_id():
    return 'req-%s' % uuidutils.generate_uuid()


class RequestContext(base_context.RequestContext):
    """Stores information about the security context.

    The context encapsulates information related to the user accessing the
    the system, as well as additional request information.
    """

    def __init__(self, auth_token=None, user=None, project=None,
                 domain=None, user_domain=None, project_domain=None,
                 is_admin=None, read_only=False, show_deleted=False,
                 request_id=None, auth_url=None, trusts=None,
                 user_name=None, project_name=None, domain_name=None,
                 user_domain_name=None, project_domain_name=None,
                 auth_token_info=None, region_name=None, roles=None,
                 password=None, **kwargs):

        """Initializer of request context."""
        # We still have 'tenant' param because oslo_context still use it.
        # pylint: disable=E1123
        super(RequestContext, self).__init__(
            auth_token=auth_token, user=user, tenant=project,
            domain=domain, user_domain=user_domain,
            project_domain=project_domain, roles=roles,
            read_only=read_only, show_deleted=show_deleted,
            request_id=request_id)

        # request_id might be a byte array
        self.request_id = encodeutils.safe_decode(self.request_id)

        # we save an additional 'project' internally for use
        self.project = project

        # Session for DB access
        self._session = None

        self.auth_url = auth_url
        self.trusts = trusts

        self.user_name = user_name
        self.project_name = project_name
        self.domain_name = domain_name
        self.user_domain_name = user_domain_name
        self.project_domain_name = project_domain_name

        self.auth_token_info = auth_token_info
        self.region_name = region_name
        self.roles = roles or []
        self.password = password

        # Check user is admin or not
        if is_admin is None:
            self.is_admin = policy.authorize(
                base_policy.ADMIN_IN_SYSTEM_PROJECTS, {}, self.to_dict(),
                do_raise=False)
        else:
            self.is_admin = is_admin

    @property
    def session(self):
        if self._session is None:
            self._session = db_api.get_session()
        return self._session

    def to_dict(self):
        return {
            'auth_url': self.auth_url,
            'auth_token': self.auth_token,
            'auth_token_info': self.auth_token_info,
            'user': self.user,
            'user_name': self.user_name,
            'user_domain': self.user_domain,
            'user_domain_name': self.user_domain_name,
            'project': self.project,
            'project_name': self.project_name,
            'project_domain': self.project_domain,
            'project_domain_name': self.project_domain_name,
            'domain': self.domain,
            'domain_name': self.domain_name,
            'trusts': self.trusts,
            'region_name': self.region_name,
            'roles': self.roles,
            'show_deleted': self.show_deleted,
            'is_admin': self.is_admin,
            'request_id': self.request_id,
            'password': self.password,
        }

    @classmethod
    def from_dict(cls, values):
        return cls(**values)


def get_admin_context(show_deleted=False):
    return RequestContext(is_admin=True, show_deleted=show_deleted)


def get_service_context(**args):
    """An abstraction layer for getting service context.

    There could be multiple cloud backends for dcmanager to use. This
    abstraction layer provides an indirection for dcmanager to get the
    credentials of 'dcmanager' user on the specific cloud. By default,
    this credential refers to the credentials built for dcmanager middleware
    in an OpenStack cloud.
    """
    pass


class AuthHook(hooks.PecanHook):
    def before(self, state):
        if state.request.path == ALLOWED_WITHOUT_AUTH:
            return
        req = state.request
        identity_status = req.headers.get('X-Identity-Status')
        service_identity_status = req.headers.get('X-Service-Identity-Status')
        if (identity_status == 'Confirmed' or
                service_identity_status == 'Confirmed'):
            return
        if req.headers.get('X-Auth-Token'):
            msg = 'Auth token is invalid: %s' % req.headers['X-Auth-Token']
        else:
            msg = 'Authentication required'
        msg = "Failed to validate access token: %s" % str(msg)
        pecan.abort(status_code=401, detail=msg)


class AuditLoggingHook(hooks.PecanHook):
    """Request data logging.

    Performs audit logging of all Distributed Cloud Manager
    ["POST", "PUT", "PATCH", "DELETE"] REST requests.
    """

    def __init__(self):
        self.log_methods = ["POST", "PUT", "PATCH", "DELETE"]

    def before(self, state):
        state.request.start_time = time.time()

    def __after(self, state):

        method = state.request.method
        if method not in self.log_methods:
            return

        now = time.time()
        try:
            elapsed = now - state.request.start_time
        except AttributeError:
            auditLOG.info("Start time is not in request, setting it to 0.")
            elapsed = 0

        environ = state.request.environ
        server_protocol = environ["SERVER_PROTOCOL"]

        response_content_length = state.response.content_length

        user_id = state.request.headers.get('X-User-Id')
        user_name = state.request.headers.get('X-User', user_id)
        tenant_id = state.request.headers.get('X-Tenant-Id')
        tenant = state.request.headers.get('X-Tenant', tenant_id)
        domain_name = state.request.headers.get('X-User-Domain-Name')
        try:
            request_id = state.request.context.request_id
        except AttributeError:
            auditLOG.info("Request id is not in request, setting it to an "
                          "auto generated id.")
            request_id = generate_request_id()

        url_path = urlparse(state.request.path_qs).path

        def json_post_data(rest_state):
            if 'form-data' in rest_state.request.headers.get('Content-Type'):
                return " POST: {}".format(rest_state.request.params)
            if not hasattr(rest_state.request, 'json'):
                return ""
            return " POST: {}".format(rest_state.request.json)

        # Filter password from log
        filtered_json = re.sub(r'{[^{}]*(passwd_hash|community|password)[^{}]*},*',
                               '',
                               json_post_data(state))

        log_data = \
            "{} \"{} {} {}\" status: {} len: {} time: {}{} host:{}" \
            " agent:{} user: {} tenant: {} domain: {}".format(
                state.request.remote_addr,
                state.request.method,
                url_path,
                server_protocol,
                state.response.status_int,
                response_content_length,
                elapsed,
                filtered_json,
                state.request.host,
                state.request.user_agent,
                user_name,
                tenant,
                domain_name)

        # The following ctx object will be output in the logger as
        # something like this:
        # [req-088ed3b6-a2c9-483e-b2ad-f1b2d03e06e6
        #  3d76d3c1376744e8ad9916a6c3be3e5f
        #  ca53e70c76d847fd860693f8eb301546]
        # When the ctx is defined, the formatter (defined in common/log.py) requires that keys
        # request_id, user, tenant be defined within the ctx
        ctx = {'request_id': request_id,
               'user': user_id,
               'tenant': tenant_id}

        auditLOG.info("{}".format(log_data), context=ctx)

    def after(self, state):
        try:
            self.__after(state)
        except Exception:
            # Logging and then swallowing exception to ensure
            # rest service does not fail even if audit logging fails
            auditLOG.exception("Exception in AuditLoggingHook on event 'after'")

    def on_error(self, state, e):
        auditLOG.exception("Exception in AuditLoggingHook passed to event 'on_error': " + str(e))
