# Copyright 2017-2019 Wind River
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

import json
import webob.dec
import webob.exc

from dcorch.api.proxy.apps.dispatcher import APIDispatcher
from dcorch.api.proxy.apps.proxy import Proxy
from dcorch.api.proxy.common import constants as proxy_consts
from dcorch.api.proxy.common.service import Middleware
from dcorch.api.proxy.common.service import Request as ProxyRequest
from dcorch.api.proxy.common import utils as proxy_utils
from dcorch.common import consts
import dcorch.common.context as k_context
from dcorch.common import exceptions as exception
from dcorch.common import utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service.wsgi import Request

from dcorch.rpc import client as rpc_client


LOG = logging.getLogger(__name__)

controller_opts = [
    cfg.BoolOpt('show_request',
                default=False,
                help='Print out the request information'),
    cfg.BoolOpt('show_response',
                default=False,
                help='Print out the response information'),
]

CONF = cfg.CONF
CONF.register_opts(controller_opts)


class APIController(Middleware):

    def __init__(self, app, conf):
        super(APIController, self).__init__(app)
        self.ctxt = k_context.get_admin_context()
        self._default_dispatcher = APIDispatcher(app)
        self.rpc_client = rpc_client.EngineClient()
        self.response_hander_map = {}
        self.sync_endpoint = proxy_utils.get_sync_endpoint(CONF)

    @staticmethod
    def get_status_code(response):
        """Returns the integer status code from the response.

        """
        return response.status_int

    @staticmethod
    def _get_resource_type_from_environ(request_environ):
        return proxy_utils.get_routing_match_value(request_environ, 'action')

    @staticmethod
    def get_resource_id_from_link(url):
        return proxy_utils.get_url_path_components(url)[-1]

    @staticmethod
    def get_request_header(environ):
        from paste.request import construct_url
        return construct_url(environ)

    def notify(self, environ, endpoint_type):
        self.rpc_client.sync_request(self.ctxt, endpoint_type)

    def process_request(self, req):
        return self._default_dispatcher

    def process_response(self, environ, request_body, response):
        if CONF.show_response:
            LOG.info("Response: (%s)", str(response))
            LOG.info("Response status: (%d)", self.get_status_code(response))
        handler = self.response_hander_map[CONF.type]
        return handler(environ, request_body, response)

    def _update_response(self, environ, request_body, response):
        # overwrite the usage numbers with the aggregated usage
        # from dcorch
        LOG.info("Query dcorch for usage info")
        desired_fields = {'quota_set': 'in_use',
                          'quota': 'used'}
        project_id = proxy_utils.get_tenant_id(environ)
        user_id = proxy_utils.get_user_id(environ)
        response_data = json.loads(response.body)
        # get the first match since it should only has one match
        resource_type = next((x for x in desired_fields if x in response_data),
                             None)
        if resource_type is None:
            LOG.error("Could not find the quota data to update")
            return response

        resource_info = response_data[resource_type]
        try:
            usage_dict = self.rpc_client.get_usage_for_project_and_user(
                self.ctxt, CONF.type, project_id, user_id)
        except Exception:
            return response

        usage_info = json.dumps(usage_dict)
        LOG.info("Project (%s) User (%s) aggregated usage: (%s)",
                 project_id, user_id, usage_info)

        quota_usage = desired_fields[resource_type]
        to_be_updated = [res for res in usage_dict if res in resource_info]
        for k in to_be_updated:
            resource_info[k][quota_usage] = usage_dict[k]
        response_data[resource_type] = resource_info
        response.body = json.dumps(response_data)
        return response

    @staticmethod
    def print_environ(environ):
        for name, value in sorted(environ.items()):
            if (name not in ['CONTENT_LENGTH', 'CONTENT_TYPE'] and
                    not name.startswith('HTTP_')):
                continue
            LOG.info('  %s: %s\n' % (name, value))

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        if CONF.show_request:
            self.print_request(req)
        environ = req.environ
        # copy the request body
        request_body = req.body
        application = self.process_request(req)
        response = req.get_response(application)
        return self.process_response(environ, request_body, response)

    @staticmethod
    def print_request_body(body):
        if body:
            LOG.info("Request body:")
            for line in body.splitlines():
                LOG.info(line.encode('string_escape') + '\n')

    def print_request(self, req):
        environ = req.environ
        length = int(req.environ.get('CONTENT_LENGTH') or '0')
        LOG.info("Incoming request:(%s), content length: (%d)",
                 environ['REQUEST_METHOD'], length)
        LOG.info("Request URL: (%s)\n", self.get_request_header(environ))
        LOG.info("Request header: \n")
        for k, v in req.headers.items():
            LOG.info("  %s: %s\n", k, v)
        self.print_environ(environ)
        self.print_request_body(req.body)


class ComputeAPIController(APIController):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_COMPUTE
    RESOURCE_TYPE_MAP = {
        consts.RESOURCE_TYPE_COMPUTE_QUOTA_SET: 'quota_set',
    }
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPCreated.code,
        webob.exc.HTTPAccepted.code,
        webob.exc.HTTPNoContent.code
    ]

    def __init__(self, app, conf):
        super(ComputeAPIController, self).__init__(app, conf)
        self.response_hander_map = {
            self.ENDPOINT_TYPE: self._process_response
        }
        self._resource_handler = {
            proxy_consts.FLAVOR_RESOURCE_TAG: self._process_flavor,
            proxy_consts.FLAVOR_ACCESS_RESOURCE_TAG:
                self._process_flavor_action,
            proxy_consts.FLAVOR_EXTRA_SPECS_RESOURCE_TAG:
                self._process_extra_spec,
            proxy_consts.KEYPAIRS_RESOURCE_TAG:
                self._process_keypairs,
            proxy_consts.QUOTA_RESOURCE_TAG:
                self._process_quota,
            proxy_consts.QUOTA_CLASS_RESOURCE_TAG:
                self._process_quota
        }

    @staticmethod
    def _get_resource_tag_from_header(url, operation, resource_type):
        result = proxy_utils.get_url_path_components(url)
        if (operation == consts.OPERATION_TYPE_DELETE or
                resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_SET or
                resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET):
            return result[-2]
        else:
            return result[-1]

    @staticmethod
    def _get_flavor_id_from_environ(environ):
        return proxy_utils.get_routing_match_value(environ, 'flavor_id')

    def _process_response(self, environ, request_body, response):
        operation_type = proxy_utils.get_operation_type(environ)
        if self.get_status_code(response) in self.OK_STATUS_CODE and \
                operation_type != consts.OPERATION_TYPE_GET:
            self._enqueue_work(environ, request_body, response)
            self.notify(environ, self.ENDPOINT_TYPE)
        return response

    def _process_flavor(self, **kwargs):
        resource_id = None
        resource_info = None
        resource_type = kwargs.get('resource_type')
        operation_type = kwargs.get('operation_type')
        if operation_type == consts.OPERATION_TYPE_POST:
            operation_type = consts.OPERATION_TYPE_CREATE
            resp = json.loads(kwargs.get('response_body'))
            resource = json.loads(kwargs.get('request_body'))
            if resource_type in resource:
                resource_info = resource[resource_type]
            else:
                LOG.info("Can't find resource type (%s) in request (%s)",
                         resource_type, resource)

            if resource_type in resp:
                if 'links' in resp[resource_type]:
                    link = resp[resource_type]['links'][0]
                    resource_id = self.get_resource_id_from_link(link['href'])

            # update the resource id if it is available
            if resource_id is not None:
                resource_info['id'] = resource_id
            resource_info = json.dumps(resource_info)
            LOG.info("Resource id: (%s)", resource_id)
            LOG.info("Resource info: (%s)", resource_info)
        elif operation_type == consts.OPERATION_TYPE_DELETE:
            resource_id = self.get_resource_id_from_link(
                kwargs.get('request_header'))
            LOG.info("Resource id: (%s), resource type: (%s)",
                     resource_id, resource_type)
        else:
            # it should never happen
            LOG.info("Ignore request type: (%s)", operation_type)

        return operation_type, resource_id, resource_info

    def _process_flavor_action(self, **kwargs):
        resource_id = self._get_flavor_id_from_environ(kwargs.get('environ'))
        resource_info = kwargs.get('request_body')
        LOG.info("Operation:(%s), resource_id:(%s), resource_info:(%s)",
                 consts.OPERATION_TYPE_ACTION, resource_id, resource_info)
        return consts.OPERATION_TYPE_ACTION, resource_id, resource_info

    def _process_extra_spec(self, **kwargs):
        environ = kwargs.get('environ')
        resource_id = self._get_flavor_id_from_environ(environ)
        operation_type = kwargs.get('operation_type')
        if operation_type == consts.OPERATION_TYPE_DELETE:
            extra_spec = proxy_utils.get_routing_match_value(
                environ, 'extra_spec')
            resource_dict = {consts.ACTION_EXTRASPECS_DELETE: extra_spec}
            resource_info = json.dumps(resource_dict)
        else:
            resource_info = kwargs.get('request_body')
        LOG.info("Operation:(%s), resource_id:(%s), resource_info:(%s)",
                 operation_type, resource_id, resource_info)
        return consts.OPERATION_TYPE_ACTION, resource_id, resource_info

    def _process_keypairs(self, **kwargs):
        resource_info = {}
        user_id = None
        environ = kwargs.get('environ')
        operation_type = kwargs.get('operation_type')
        if operation_type == consts.OPERATION_TYPE_POST:
            operation_type = consts.OPERATION_TYPE_CREATE
            request = json.loads(kwargs.get('request_body'))
            resource_info = request[kwargs.get('resource_type')]

            if 'public_key' not in resource_info:
                # need to get the public_key from response
                resp = json.loads(kwargs.get('response_body'))
                resp_info = resp.get(kwargs.get('resource_type'))
                resource_info['public_key'] = resp_info.get('public_key')

            if 'user_id' in resource_info:
                user_id = resource_info['user_id']
            resource_id = resource_info['name']
        else:
            resource_id = proxy_utils.get_routing_match_value(
                environ, consts.RESOURCE_TYPE_COMPUTE_KEYPAIR)
            user_id = proxy_utils.get_user_id(environ)

        if user_id is None:
            user_id = environ.get('HTTP_X_USER_ID', '')

        # resource_id = "name/user_id"
        resource_id = utils.keypair_construct_id(resource_id, user_id)
        resource_info = json.dumps(resource_info)
        LOG.info("Operation:(%s), resource_id:(%s), resource_info:(%s)",
                 operation_type, resource_id, resource_info)
        return operation_type, resource_id, resource_info

    def _process_quota(self, **kwargs):
        environ = kwargs.get('environ')
        resource_id = self.get_resource_id_from_link(
            kwargs.get('request_header'))
        resource_type = kwargs.get('resource_type')
        operation_type = kwargs.get('operation_type')
        if operation_type == consts.OPERATION_TYPE_DELETE:
            resource_info = {}
        else:
            request = json.loads(kwargs.get('request_body'))
            if resource_type in self.RESOURCE_TYPE_MAP:
                resource_info = request[self.RESOURCE_TYPE_MAP.get(
                    resource_type)]
            else:
                resource_info = request[resource_type]

        # add user_id to resource if it is specified
        user_id = proxy_utils.get_user_id(environ)
        if user_id is not None:
            resource_info['user_id'] = user_id
        resource_info = json.dumps(resource_info)
        LOG.info("Operation:(%s), resource_id:(%s), resource_info:(%s)",
                 operation_type, resource_id, resource_info)
        return operation_type, resource_id, resource_info

    def _enqueue_work(self, environ, request_body, response):
        LOG.info("enqueue_work")
        request_header = self.get_request_header(environ)
        operation_type = proxy_utils.get_operation_type(environ)
        resource_type = self._get_resource_type_from_environ(environ)
        resource_tag = self._get_resource_tag_from_header(request_header,
                                                          operation_type,
                                                          resource_type)

        handler = self._resource_handler[resource_tag]
        operation_type, resource_id, resource_info = handler(
            environ=environ,
            operation_type=operation_type,
            resource_type=resource_type,
            request_header=request_header,
            request_body=request_body,
            response_body=response.body)

        try:
            utils.enqueue_work(self.ctxt,
                               self.ENDPOINT_TYPE,
                               resource_type,
                               resource_id,
                               operation_type,
                               resource_info)
        except exception.ResourceNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.format_message())


class SysinvAPIController(APIController):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_PLATFORM
    RESOURCE_ID_MAP = {
        consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST: 'ip_address',
        consts.RESOURCE_TYPE_SYSINV_SNMP_COMM: 'community'
    }
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPNoContent.code
    ]

    def __init__(self, app, conf):
        super(SysinvAPIController, self).__init__(app, conf)
        self.response_hander_map = {
            self.ENDPOINT_TYPE: self._process_response
        }

    def _process_response(self, environ, request_body, response):
        if self.get_status_code(response) in self.OK_STATUS_CODE:
            self._enqueue_work(environ, request_body, response)
            self.notify(environ, self.ENDPOINT_TYPE)
        return response

    def _enqueue_work(self, environ, request_body, response):
        LOG.info("enqueue_work")
        resource_info = {}
        request_header = self.get_request_header(environ)
        operation_type = proxy_utils.get_operation_type(environ)
        resource_type = self._get_resource_type_from_environ(environ)
        # certificate need special processing
        p_resource_info = 'suppressed'
        if resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            if operation_type == consts.OPERATION_TYPE_DELETE:
                resource_id = json.loads(response.body)['signature']
                resource_ids = [resource_id]
            else:
                resource_info['payload'] = request_body
                resource_info['content_type'] = environ.get('CONTENT_TYPE')
                resource = json.loads(response.body)[resource_type]
                # For ssl_ca cert, the resource in response is a list
                if isinstance(resource, list):
                    resource_ids = [str(res.get('signature'))
                                    for res in resource]
                else:
                    resource_ids = [resource.get('signature')]
        else:
            if (operation_type == consts.OPERATION_TYPE_POST and
                    resource_type in self.RESOURCE_ID_MAP):
                # need to get the id from the request data since it is
                # not available in the header
                rid = self.RESOURCE_ID_MAP.get(resource_type)
                resource_id = json.loads(request_body)[rid]
            else:
                resource_id = self.get_resource_id_from_link(request_header)
            resource_ids = [resource_id]
            if operation_type != consts.OPERATION_TYPE_DELETE:
                resource_info['payload'] = json.loads(request_body)
            p_resource_info = resource_info

        for resource_id in resource_ids:
            LOG.info("Resource id: (%s), type: (%s), info: (%s)",
                     resource_id, resource_type, p_resource_info)
            try:
                utils.enqueue_work(self.ctxt,
                                   self.ENDPOINT_TYPE,
                                   resource_type,
                                   resource_id,
                                   operation_type,
                                   json.dumps(resource_info))
            except exception.ResourceNotFound as e:
                raise webob.exc.HTTPNotFound(explanation=e.format_message())


class IdentityAPIController(APIController):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_IDENTITY
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPCreated.code,
        webob.exc.HTTPAccepted.code,
        webob.exc.HTTPNoContent.code
    ]

    def __init__(self, app, conf):
        super(IdentityAPIController, self).__init__(app, conf)
        self.response_hander_map = {
            self.ENDPOINT_TYPE: self._process_response
        }
        if self.sync_endpoint is None:
            self.sync_endpoint = self.ENDPOINT_TYPE

    def _process_response(self, environ, request_body, response):
        if self.get_status_code(response) in self.OK_STATUS_CODE:
            self._enqueue_work(environ, request_body, response)
            self.notify(environ, self.ENDPOINT_TYPE)
        return response

    def _generate_assignment_rid(self, url, environ):
        resource_id = None
        # for role assignment or revocation, the URL is of format:
        # /v3/projects/{project_id}/users/{user_id}/roles/{role_id}
        # We need to extract all ID parameters from the URL
        role_id = proxy_utils.get_routing_match_value(environ, 'role_id')
        proj_id = proxy_utils.get_routing_match_value(environ, 'project_id')
        user_id = proxy_utils.get_routing_match_value(environ, 'user_id')

        if (not role_id or not proj_id or not user_id):
            LOG.error("Malformed Role Assignment or Revocation URL: %s", url)
        else:
            resource_id = "{}_{}_{}".format(proj_id, user_id, role_id)
        return resource_id

    def _retrieve_token_revoke_event_rid(self, url, environ):
        resource_id = None
        # for token revocation event, we need to retrieve the audit_id
        # from the token being revoked.
        revoked_token = environ.get('HTTP_X_SUBJECT_TOKEN', None)

        if not revoked_token:
            LOG.error("Malformed Token Revocation URL: %s", url)
        else:
            try:
                resource_id = proxy_utils.\
                    retrieve_token_audit_id(revoked_token)
            except Exception as e:
                LOG.error("Failed to retrieve token audit id: %s" % e)

        return resource_id

    def _enqueue_work(self, environ, request_body, response):
        LOG.info("enqueue_work")
        resource_info = {}
        request_header = self.get_request_header(environ)
        operation_type = proxy_utils.get_operation_type(environ)
        resource_type = self._get_resource_type_from_environ(environ)

        # if this is a Role Assignment or Revocation request then
        # we need to extract Project ID, User ID and Role ID from the
        # URL, and not just the Role ID
        if (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS):
            resource_id = self._generate_assignment_rid(request_header,
                                                        environ)
            # grant a role to a user (PUT) creates a project role assignment
            if operation_type == consts.OPERATION_TYPE_PUT:
                operation_type = consts.OPERATION_TYPE_POST
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS):
            resource_id = self._retrieve_token_revoke_event_rid(request_header,
                                                                environ)
            # delete (revoke) a token (DELETE) creates a token revoke event.
            if operation_type == consts.OPERATION_TYPE_DELETE and resource_id:
                operation_type = consts.OPERATION_TYPE_POST
                resource_info = {'token_revoke_event':
                                 {'audit_id': resource_id}}
        elif (resource_type ==
                consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD):
            resource_id = self.get_resource_id_from_link(request_header.
                                                         strip('/password'))
            # user change password (POST) is an update to the user
            if operation_type == consts.OPERATION_TYPE_POST:
                operation_type = consts.OPERATION_TYPE_PATCH
                resource_type = consts.RESOURCE_TYPE_IDENTITY_USERS
        else:
            if operation_type == consts.OPERATION_TYPE_POST:
                # Retrieve the ID from the response
                resource = list(json.loads(response.body).items())[0][1]
                resource_id = resource['id']
            else:
                resource_id = self.get_resource_id_from_link(request_header)

        if (operation_type != consts.OPERATION_TYPE_DELETE and
                request_body and (not resource_info)):
            resource_info = json.loads(request_body)

        LOG.info("%s: Resource id: (%s), type: (%s), info: (%s)",
                 operation_type, resource_id, resource_type, resource_info)

        if resource_id:
            try:
                utils.enqueue_work(self.ctxt,
                                   self.sync_endpoint,
                                   resource_type,
                                   resource_id,
                                   operation_type,
                                   json.dumps(resource_info))
            except exception.ResourceNotFound as e:
                raise webob.exc.HTTPNotFound(explanation=e.format_message())
        else:
            LOG.warning("Empty resource id for resource: %s", operation_type)


class CinderAPIController(APIController):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_VOLUME
    RESOURCE_TYPE_MAP = {
        consts.RESOURCE_TYPE_VOLUME_QUOTA_SET: 'quota_set',
    }
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
    ]

    def __init__(self, app, conf):
        super(CinderAPIController, self).__init__(app, conf)
        self.response_hander_map = {
            self.ENDPOINT_TYPE: self._process_response
        }

    def _process_response(self, environ, request_body, response):
        if self.get_status_code(response) in self.OK_STATUS_CODE:
            operation_type = proxy_utils.get_operation_type(environ)
            if operation_type == consts.OPERATION_TYPE_GET:
                if proxy_utils.show_usage(environ):
                    response = self._update_response(environ, request_body,
                                                     response)
            else:
                self._enqueue_work(environ, request_body, response)
                self.notify(environ, self.ENDPOINT_TYPE)
        return response

    def _enqueue_work(self, environ, request_body, response):
        request_header = self.get_request_header(environ)
        resource_id = self.get_resource_id_from_link(request_header)
        resource_type = self._get_resource_type_from_environ(environ)
        operation_type = proxy_utils.get_operation_type(environ)
        if operation_type == consts.OPERATION_TYPE_DELETE:
            resource_info = {}
        else:
            request = json.loads(request_body)
            if resource_type in self.RESOURCE_TYPE_MAP:
                resource_info = request[self.RESOURCE_TYPE_MAP.get(
                    resource_type)]
            else:
                resource_info = request[resource_type]
        resource_info = json.dumps(resource_info)
        LOG.info("Operation:(%s), resource_id:(%s), resource_info:(%s)",
                 operation_type, resource_id, resource_info)
        try:
            utils.enqueue_work(self.ctxt,
                               self.ENDPOINT_TYPE,
                               resource_type,
                               resource_id,
                               operation_type,
                               resource_info)
        except exception.ResourceNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.format_message())


class NeutronAPIController(APIController):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_NETWORK
    RESOURCE_TYPE_MAP = {
        consts.RESOURCE_TYPE_NETWORK_QUOTA_SET: 'quota',
    }
    # the following fields will be inserted to the resource_info if
    # they are not presented in the request but are provided in the
    # response
    DESIRED_FIELDS = ['tenant_id', 'project_id']
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPCreated.code,
        webob.exc.HTTPNoContent.code
    ]

    def __init__(self, app, conf):
        super(NeutronAPIController, self).__init__(app, conf)
        self.response_hander_map = {
            self.ENDPOINT_TYPE: self._process_response
        }

    def _process_response(self, environ, request_body, response):
        if self.get_status_code(response) in self.OK_STATUS_CODE:
            self._enqueue_work(environ, request_body, response)
            self.notify(environ, self.ENDPOINT_TYPE)
        return response

    def _enqueue_work(self, environ, request_body, response):
        request_header = self.get_request_header(environ)
        resource_type = self._get_resource_type_from_environ(environ)
        operation_type = proxy_utils.get_operation_type(environ)
        if operation_type == consts.OPERATION_TYPE_POST:
            resource = json.loads(response.body)[resource_type]
            resource_id = resource['id']
        else:
            resource_id = self.get_resource_id_from_link(request_header)

        if operation_type == consts.OPERATION_TYPE_DELETE:
            resource_info = {}
        else:
            request = json.loads(request_body)
            if resource_type in self.RESOURCE_TYPE_MAP:
                original_type = self.RESOURCE_TYPE_MAP.get(
                    resource_type)
            else:
                original_type = resource_type
            resource_info = request[original_type]
            if operation_type == consts.OPERATION_TYPE_POST:
                resp_info = json.loads(response.body)[original_type]
                for f in self.DESIRED_FIELDS:
                    if f not in resource_info and f in resp_info:
                        resource_info[f] = resp_info[f]

        resource_info = json.dumps(resource_info)
        LOG.info("Operation:(%s), resource_id:(%s), resource_info:(%s)",
                 operation_type, resource_id, resource_info)
        try:
            utils.enqueue_work(self.ctxt,
                               self.ENDPOINT_TYPE,
                               resource_type,
                               resource_id,
                               operation_type,
                               resource_info)
        except exception.ResourceNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.format_message())


class OrchAPIController(APIController):

    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
    ]

    def __init__(self, app, conf):
        super(OrchAPIController, self).__init__(app, conf)
        self.response_hander_map = {
            consts.ENDPOINT_TYPE_COMPUTE: self._process_response,
            consts.ENDPOINT_TYPE_NETWORK: self._process_response
        }

    def _process_response(self, environ, request_body, response):
        if self.get_status_code(response) in self.OK_STATUS_CODE:
            response = self._update_response(environ, request_body, response)
        return response


class VersionController(Middleware):
    def __init__(self, app, conf):
        self._default_dispatcher = Proxy()
        self._remote_host, self._remote_port = \
            proxy_utils.get_remote_host_port_options(CONF)
        super(VersionController, self).__init__(app)

    @webob.dec.wsgify(RequestClass=ProxyRequest)
    def __call__(self, req):
        LOG.debug("VersionController forward the version request to remote "
                  "host: (%s), port: (%d)" % (self._remote_host,
                                              self._remote_port))
        proxy_utils.set_request_forward_environ(req, self._remote_host,
                                                self._remote_port)
        return self._default_dispatcher
