# Copyright (c) 2017-2024 Wind River Systems, Inc.
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

import grp
import json
import os
import pathlib
import pwd
import shutil
import tempfile
import threading

from eventlet.green import subprocess
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service.wsgi import Request
from oslo_utils._i18n import _
import psutil
import tsconfig.tsconfig as tsc
import webob.dec
import webob.exc
from webob import Response

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.api.proxy.apps.dispatcher import APIDispatcher
from dcorch.api.proxy.apps.proxy import Proxy
from dcorch.api.proxy.common import constants as proxy_consts
from dcorch.api.proxy.common.service import Middleware
from dcorch.api.proxy.common.service import Request as ProxyRequest
from dcorch.api.proxy.common import utils as proxy_utils
from dcorch.common import consts
from dcorch.common import context as k_context
from dcorch.common import exceptions as exception
from dcorch.common import usm_util
from dcorch.common import utils
from dcorch.rpc import client as rpc_client


LOG = logging.getLogger(__name__)

controller_opts = [
    cfg.BoolOpt(
        "show_request", default=False, help="Print out the request information"
    ),
    cfg.BoolOpt(
        "show_response", default=False, help="Print out the response information"
    ),
]

CONF = cfg.CONF
CONF.register_opts(controller_opts)


class APIController(Middleware):

    def __init__(self, app, conf):
        super(APIController, self).__init__(app)
        self.ctxt = k_context.get_admin_context()
        self._default_dispatcher = APIDispatcher(app)
        self.rpc_worker_client = rpc_client.EngineWorkerClient()
        self.rpc_client = rpc_client.EngineClient()
        self.response_hander_map = {}
        self.sync_endpoint = proxy_utils.get_sync_endpoint(CONF)

    @staticmethod
    def get_status_code(response):
        """Returns the integer status code from the response."""
        return response.status_int

    @staticmethod
    def _get_resource_type_from_environ(request_environ):
        return proxy_utils.get_routing_match_value(request_environ, "action")

    @staticmethod
    def get_resource_id_from_link(url):
        return proxy_utils.get_url_path_components(url)[-1]

    @staticmethod
    def get_request_header(environ):
        from paste.request import construct_url

        return construct_url(environ)

    def notify(self, environ, endpoint_type):
        LOG.info(f"{endpoint_type}: Notifying dcorch sync_request.")
        self.rpc_worker_client.sync_request(self.ctxt, endpoint_type)

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
        desired_fields = {"quota_set": "in_use", "quota": "used"}
        project_id = proxy_utils.get_tenant_id(environ)
        user_id = proxy_utils.get_user_id(environ)
        response_data = json.loads(response.body)
        # get the first match since it should only has one match
        resource_type = next((x for x in desired_fields if x in response_data), None)
        if resource_type is None:
            LOG.error("Could not find the quota data to update")
            return response

        resource_info = response_data[resource_type]
        try:
            usage_dict = self.rpc_client.get_usage_for_project_and_user(
                self.ctxt, CONF.type, project_id, user_id
            )
        except Exception:
            return response

        usage_info = json.dumps(usage_dict)
        LOG.info(
            "Project (%s) User (%s) aggregated usage: (%s)",
            project_id,
            user_id,
            usage_info,
        )

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
            if name not in ["CONTENT_LENGTH", "CONTENT_TYPE"] and not name.startswith(
                "HTTP_"
            ):
                continue
            LOG.info("  %s: %s\n" % (name, value))

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
                LOG.info(line.encode("string_escape") + "\n")

    def print_request(self, req):
        environ = req.environ
        length = int(req.environ.get("CONTENT_LENGTH") or "0")
        LOG.info(
            "Incoming request:(%s), content length: (%d)",
            environ["REQUEST_METHOD"],
            length,
        )
        LOG.info("Request URL: (%s)\n", self.get_request_header(environ))
        LOG.info("Request header: \n")
        for k, v in req.headers.items():
            LOG.info("  %s: %s\n", k, v)
        self.print_environ(environ)
        self.print_request_body(req.body)


class ComputeAPIController(APIController):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_COMPUTE
    RESOURCE_TYPE_MAP = {
        consts.RESOURCE_TYPE_COMPUTE_QUOTA_SET: "quota_set",
    }
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPCreated.code,
        webob.exc.HTTPAccepted.code,
        webob.exc.HTTPNoContent.code,
    ]

    def __init__(self, app, conf):
        super(ComputeAPIController, self).__init__(app, conf)
        self.response_hander_map = {self.ENDPOINT_TYPE: self._process_response}
        self._resource_handler = {
            proxy_consts.FLAVOR_RESOURCE_TAG: self._process_flavor,
            proxy_consts.FLAVOR_ACCESS_RESOURCE_TAG: self._process_flavor_action,
            proxy_consts.FLAVOR_EXTRA_SPECS_RESOURCE_TAG: self._process_extra_spec,
            proxy_consts.KEYPAIRS_RESOURCE_TAG: self._process_keypairs,
            proxy_consts.QUOTA_RESOURCE_TAG: self._process_quota,
            proxy_consts.QUOTA_CLASS_RESOURCE_TAG: self._process_quota,
        }

    @staticmethod
    def _get_resource_tag_from_header(url, operation, resource_type):
        result = proxy_utils.get_url_path_components(url)
        if (
            operation == consts.OPERATION_TYPE_DELETE
            or resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_SET
            or resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET
        ):
            return result[-2]
        else:
            return result[-1]

    @staticmethod
    def _get_flavor_id_from_environ(environ):
        return proxy_utils.get_routing_match_value(environ, "flavor_id")

    def _process_response(self, environ, request_body, response):
        operation_type = proxy_utils.get_operation_type(environ)
        if (
            self.get_status_code(response) in self.OK_STATUS_CODE
            and operation_type != consts.OPERATION_TYPE_GET
        ):
            self._enqueue_work(environ, request_body, response)
            self.notify(environ, self.ENDPOINT_TYPE)
        return response

    def _process_flavor(self, **kwargs):
        resource_id = None
        resource_info = None
        resource_type = kwargs.get("resource_type")
        operation_type = kwargs.get("operation_type")
        if operation_type == consts.OPERATION_TYPE_POST:
            operation_type = consts.OPERATION_TYPE_CREATE
            resp = json.loads(kwargs.get("response_body"))
            resource = json.loads(kwargs.get("request_body"))
            if resource_type in resource:
                resource_info = resource[resource_type]
            else:
                LOG.info(
                    "Can't find resource type (%s) in request (%s)",
                    resource_type,
                    resource,
                )

            if resource_type in resp:
                if "links" in resp[resource_type]:
                    link = resp[resource_type]["links"][0]
                    resource_id = self.get_resource_id_from_link(link["href"])

            # update the resource id if it is available
            if resource_id is not None:
                resource_info["id"] = resource_id
            resource_info = json.dumps(resource_info)
            LOG.info("Resource id: (%s)", resource_id)
            LOG.info("Resource info: (%s)", resource_info)
        elif operation_type == consts.OPERATION_TYPE_DELETE:
            resource_id = self.get_resource_id_from_link(kwargs.get("request_header"))
            LOG.info(
                "Resource id: (%s), resource type: (%s)", resource_id, resource_type
            )
        else:
            # it should never happen
            LOG.info("Ignore request type: (%s)", operation_type)

        return operation_type, resource_id, resource_info

    def _process_flavor_action(self, **kwargs):
        resource_id = self._get_flavor_id_from_environ(kwargs.get("environ"))
        resource_info = kwargs.get("request_body")
        LOG.info(
            "Operation:(%s), resource_id:(%s), resource_info:(%s)",
            consts.OPERATION_TYPE_ACTION,
            resource_id,
            resource_info,
        )
        return consts.OPERATION_TYPE_ACTION, resource_id, resource_info

    def _process_extra_spec(self, **kwargs):
        environ = kwargs.get("environ")
        resource_id = self._get_flavor_id_from_environ(environ)
        operation_type = kwargs.get("operation_type")
        if operation_type == consts.OPERATION_TYPE_DELETE:
            extra_spec = proxy_utils.get_routing_match_value(environ, "extra_spec")
            resource_dict = {consts.ACTION_EXTRASPECS_DELETE: extra_spec}
            resource_info = json.dumps(resource_dict)
        else:
            resource_info = kwargs.get("request_body")
        LOG.info(
            "Operation:(%s), resource_id:(%s), resource_info:(%s)",
            operation_type,
            resource_id,
            resource_info,
        )
        return consts.OPERATION_TYPE_ACTION, resource_id, resource_info

    def _process_keypairs(self, **kwargs):
        resource_info = {}
        user_id = None
        environ = kwargs.get("environ")
        operation_type = kwargs.get("operation_type")
        if operation_type == consts.OPERATION_TYPE_POST:
            operation_type = consts.OPERATION_TYPE_CREATE
            request = json.loads(kwargs.get("request_body"))
            resource_info = request[kwargs.get("resource_type")]

            if "public_key" not in resource_info:
                # need to get the public_key from response
                resp = json.loads(kwargs.get("response_body"))
                resp_info = resp.get(kwargs.get("resource_type"))
                resource_info["public_key"] = resp_info.get("public_key")

            if "user_id" in resource_info:
                user_id = resource_info["user_id"]
            resource_id = resource_info["name"]
        else:
            resource_id = proxy_utils.get_routing_match_value(
                environ, consts.RESOURCE_TYPE_COMPUTE_KEYPAIR
            )
            user_id = proxy_utils.get_user_id(environ)

        if user_id is None:
            user_id = environ.get("HTTP_X_USER_ID", "")

        # resource_id = "name/user_id"
        resource_id = utils.keypair_construct_id(resource_id, user_id)
        resource_info = json.dumps(resource_info)
        LOG.info(
            "Operation:(%s), resource_id:(%s), resource_info:(%s)",
            operation_type,
            resource_id,
            resource_info,
        )
        return operation_type, resource_id, resource_info

    def _process_quota(self, **kwargs):
        environ = kwargs.get("environ")
        resource_id = self.get_resource_id_from_link(kwargs.get("request_header"))
        resource_type = kwargs.get("resource_type")
        operation_type = kwargs.get("operation_type")
        if operation_type == consts.OPERATION_TYPE_DELETE:
            resource_info = {}
        else:
            request = json.loads(kwargs.get("request_body"))
            if resource_type in self.RESOURCE_TYPE_MAP:
                resource_info = request[self.RESOURCE_TYPE_MAP.get(resource_type)]
            else:
                resource_info = request[resource_type]

        # add user_id to resource if it is specified
        user_id = proxy_utils.get_user_id(environ)
        if user_id is not None:
            resource_info["user_id"] = user_id
        resource_info = json.dumps(resource_info)
        LOG.info(
            "Operation:(%s), resource_id:(%s), resource_info:(%s)",
            operation_type,
            resource_id,
            resource_info,
        )
        return operation_type, resource_id, resource_info

    def _enqueue_work(self, environ, request_body, response):
        LOG.info("enqueue_work")
        request_header = self.get_request_header(environ)
        operation_type = proxy_utils.get_operation_type(environ)
        resource_type = self._get_resource_type_from_environ(environ)
        resource_tag = self._get_resource_tag_from_header(
            request_header, operation_type, resource_type
        )

        handler = self._resource_handler[resource_tag]
        operation_type, resource_id, resource_info = handler(
            environ=environ,
            operation_type=operation_type,
            resource_type=resource_type,
            request_header=request_header,
            request_body=request_body,
            response_body=response.body,
        )

        try:
            utils.enqueue_work(
                self.ctxt,
                self.ENDPOINT_TYPE,
                resource_type,
                resource_id,
                operation_type,
                resource_info,
            )
        except exception.ResourceNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=str(e))


class SysinvAPIController(APIController):

    ENDPOINT_TYPE = dccommon_consts.ENDPOINT_TYPE_PLATFORM
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPAccepted.code,
        webob.exc.HTTPNoContent.code,
    ]

    def __init__(self, app, conf):
        super(SysinvAPIController, self).__init__(app, conf)
        self.dcmanager_state_rpc_client = dcmanager_rpc_client.SubcloudStateClient()
        self.response_hander_map = {self.ENDPOINT_TYPE: self._process_response}

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        if CONF.show_request:
            self.print_request(req)
        environ = req.environ
        # copy the request and the request body
        request = req
        request.body = req.body

        # load-import is stored in dc-vault and on /scratch temporary
        # folder to be processed by sysinv
        if self._is_load_import(request.path):
            req_body = self._store_load_to_vault(req)
            params_dict = request.POST
            try:
                # If load import is done with --local, the params active
                # and inactive comes from the request body.
                # If not done with --local, the params comes from request.POST
                # in this case, the decode below will raise an exception
                # and params_dict will continue point to request.POST
                params_dict = json.loads(request.body.decode("utf-8"))
            except UnicodeDecodeError:
                pass

            if "active" in params_dict:
                req_body["active"] = params_dict["active"]

            if "inactive" in params_dict:
                req_body["inactive"] = params_dict["inactive"]

            # sysinv will handle a simple application/json request
            # with the file location
            req.content_type = "application/json"
            req.body = json.dumps(req_body).encode("utf8")

        application = self.process_request(req)
        response = req.get_response(application)
        return self.process_response(environ, request, response)

    def _notify_dcmanager(self, request, response, endpoint_type, sync_status):
        # Send a RPC to dcmanager
        LOG.info(
            "Send RPC to dcmanager to set: %s sync status to: %s"
            % (endpoint_type, sync_status)
        )
        self.dcmanager_state_rpc_client.update_subcloud_endpoint_status(
            self.ctxt, endpoint_type=endpoint_type, sync_status=sync_status
        )
        return response

    def _notify_dcmanager_firmware(self, request, response):
        return self._notify_dcmanager(
            request,
            response,
            dccommon_consts.ENDPOINT_TYPE_FIRMWARE,
            dccommon_consts.SYNC_STATUS_UNKNOWN,
        )

    def _process_response(self, environ, request, response):
        try:
            resource_type = self._get_resource_type_from_environ(environ)
            operation_type = proxy_utils.get_operation_type(environ)
            if self.get_status_code(response) in self.OK_STATUS_CODE:
                if resource_type == consts.RESOURCE_TYPE_SYSINV_LOAD:
                    if operation_type == consts.OPERATION_TYPE_POST:
                        new_load = json.loads(response.body)
                        self._save_load_to_vault(new_load["software_version"])
                    else:
                        sw_version = json.loads(response.body)["software_version"]
                        self._remove_load_from_vault(sw_version)
                elif resource_type == consts.RESOURCE_TYPE_SYSINV_DEVICE_IMAGE:
                    notify = True
                    if operation_type == consts.OPERATION_TYPE_POST:
                        resp = json.loads(response.body)
                        if not resp.get("error"):
                            self._device_image_upload_req(request, response)
                        else:
                            notify = False
                    elif operation_type == consts.OPERATION_TYPE_DELETE:
                        filename = self._get_device_image_filename(
                            json.loads(response.body)
                        )
                        self._delete_device_image_from_vault(filename)
                    # PATCH operation for apply/remove commands fall through
                    # as they only require to notify dcmanager
                    if notify:
                        self._notify_dcmanager_firmware(request, response)
                else:
                    self._enqueue_work(environ, request, response)
                    self.notify(environ, self.ENDPOINT_TYPE)
            else:
                if (
                    resource_type == consts.RESOURCE_TYPE_SYSINV_LOAD
                    and operation_type == consts.OPERATION_TYPE_POST
                ):
                    self._check_load_in_vault()

            return response
        finally:
            proxy_utils.cleanup(environ)

    def _is_load_import(self, path):
        return path in proxy_consts.LOAD_PATHS

    def _is_active_load(self, sw_version):
        if sw_version == tsc.SW_VERSION:
            return True
        return False

    def _save_load_to_vault(self, sw_version):
        versioned_vault = os.path.join(proxy_consts.LOAD_VAULT_DIR, sw_version)

        try:
            # Remove any existing loads in the vault. At this point sysinv has
            # validated/added the load so we must match the DC vault to that.
            LOG.info("_save_load_to_vault remove prior %s" % sw_version)
            self._remove_load_from_vault(sw_version)

            if not os.path.isdir(versioned_vault):
                # Check if the temporary folder exists
                if not os.path.isdir(proxy_consts.LOAD_VAULT_TMP_DIR):
                    msg = _(
                        "Failed to store load in vault. Please check "
                        "dcorch log for details."
                    )
                    LOG.error(
                        "_save_load_to_vault failed: %s does not exist."
                        % proxy_consts.LOAD_VAULT_TMP_DIR
                    )
                    raise webob.exc.HTTPInternalServerError(explanation=msg)

                # Check the number of files in the temp folder
                load_path = proxy_consts.LOAD_VAULT_TMP_DIR
                load_files = [
                    f
                    for f in os.listdir(load_path)
                    if os.path.isfile(os.path.join(load_path, f))
                ]
                if len(load_files) != len(proxy_consts.IMPORT_LOAD_FILES):
                    msg = _(
                        "Failed to store load in vault. Please check "
                        "dcorch log for details."
                    )
                    LOG.error("_save_load_to_vault failed to store load in vault")
                    raise webob.exc.HTTPInsufficientStorage(explanation=msg)

                # Move the folder to the final location
                shutil.move(proxy_consts.LOAD_VAULT_TMP_DIR, versioned_vault)

            LOG.info("Load (%s) saved to vault." % sw_version)
        except Exception:
            msg = _(
                "Failed to store load in vault. Please check dcorch log for details."
            )
            raise webob.exc.HTTPInsufficientStorage(explanation=msg)

    def _remove_load_from_vault(self, sw_version):
        versioned_vault = os.path.join(proxy_consts.LOAD_VAULT_DIR, sw_version)

        if os.path.isdir(versioned_vault):
            shutil.rmtree(versioned_vault)
            LOG.info("Load (%s) removed from vault." % sw_version)

    def _check_load_in_vault(self):
        if not os.path.exists(proxy_consts.LOAD_VAULT_DIR):
            # The vault directory has not even been created. This must
            # be the very first load-import request which failed.
            return
        elif len(os.listdir(proxy_consts.LOAD_VAULT_DIR)) == 0:
            try:
                ks_client = OpenStackDriver(
                    region_name=dccommon_consts.DEFAULT_REGION_NAME, region_clients=None
                ).keystone_client
                sysinv_client = SysinvClient(
                    dccommon_consts.DEFAULT_REGION_NAME,
                    ks_client.session,
                    endpoint=ks_client.endpoint_cache.get_endpoint("sysinv"),
                )
                loads = sysinv_client.get_loads()
            except Exception:
                # Shouldn't be here
                LOG.exception("Failed to get list of loads.")
                return
            else:
                if len(loads) > proxy_consts.IMPORTED_LOAD_MAX_COUNT:
                    # The previous load regardless of its current state
                    # was mistakenly imported without the proxy.
                    msg = _(
                        "Previous load was not imported in the right "
                        "region. Please remove the previous load and "
                        "re-import it using 'SystemController' region."
                    )
                    raise webob.exc.HTTPUnprocessableEntity(explanation=msg)
        else:
            # Remove temp load dir
            if os.path.exists(proxy_consts.LOAD_VAULT_TMP_DIR):
                shutil.rmtree(proxy_consts.LOAD_VAULT_TMP_DIR)

    def _copy_device_image_to_vault(self, src_filepath, dst_filename):
        try:
            if not os.path.isdir(proxy_consts.DEVICE_IMAGE_VAULT_DIR):
                os.makedirs(proxy_consts.DEVICE_IMAGE_VAULT_DIR)
            image_file_path = os.path.join(
                proxy_consts.DEVICE_IMAGE_VAULT_DIR, dst_filename
            )
            shutil.copyfile(src_filepath, image_file_path)
            LOG.info("copied %s to %s" % (src_filepath, image_file_path))
        except Exception:
            msg = _(
                "Failed to store device image in vault. Please check "
                "dcorch log for details."
            )
            raise webob.exc.HTTPInsufficientStorage(explanation=msg)

    def _copy_load_to_vault_for_validation(self, src_filepath):
        try:
            validation_vault_dir = proxy_consts.LOAD_VAULT_TMP_DIR
            if not os.path.isdir(validation_vault_dir):
                os.makedirs(validation_vault_dir)
            load_file_path = os.path.join(
                validation_vault_dir, os.path.basename(src_filepath)
            )
            shutil.copyfile(src_filepath, load_file_path)
            LOG.info("copied %s to %s" % (src_filepath, load_file_path))
        except Exception as e:
            msg = _(
                "Failed to store load in vault. Please check "
                "dcorch log for more details: %s" % e
            )
            raise webob.exc.HTTPInsufficientStorage(explanation=msg)
        return load_file_path

    def _upload_file(self, file_item):
        try:
            staging_dir = proxy_consts.LOAD_FILES_STAGING_DIR
            # Need to change the permission on temporary folder to sysinv,
            # sysinv might need to remove the temporary folder
            sysinv_user_id = pwd.getpwnam("sysinv").pw_uid
            sysinv_group_id = grp.getgrnam("sysinv").gr_gid
            if not os.path.isdir(staging_dir):
                os.makedirs(staging_dir)
                os.chown(staging_dir, sysinv_user_id, sysinv_group_id)

            source_file = file_item.file
            staging_file = os.path.join(
                staging_dir, os.path.basename(file_item.filename)
            )

            if source_file is None:
                LOG.error(
                    "Failed to upload load file %s, invalid file object" % staging_file
                )
                return None

            # This try block is to get only the iso file size as the signature
            # file object type is different in Debian than CentOS and and
            # has fileno() attribute but is not a supported operation on Debian
            #
            # The check for st_size is required to determine the file size of *.iso
            # It is not applicable to its signature file
            try:
                file_size = os.fstat(source_file.fileno()).st_size
            except Exception:
                file_size = -1

            if file_size >= 0:
                # Only proceed if there is space available for copying
                avail_space = psutil.disk_usage("/scratch").free
                if avail_space < file_size:
                    LOG.error(
                        "Failed to upload load file %s, not enough space on /scratch"
                        " partition: %d bytes available " % (staging_file, avail_space)
                    )
                    return None

                # Large iso file, allocate the required space
                # pylint: disable-next=not-callable
                subprocess.check_call(
                    ["/usr/bin/fallocate", "-l " + str(file_size), staging_file]
                )

            with open(staging_file, "wb") as destination_file:
                shutil.copyfileobj(source_file, destination_file)
                os.chown(staging_file, sysinv_user_id, sysinv_group_id)

        except subprocess.CalledProcessError as e:
            LOG.error(
                "Failed to upload load file %s, /usr/bin/fallocate error: %s"
                % (staging_file, e.output)
            )
            if os.path.isfile(staging_file):
                os.remove(staging_file)
            return None
        except Exception:
            if os.path.isfile(staging_file):
                os.remove(staging_file)
            LOG.exception("Failed to upload load file %s" % file_item.filename)
            return None

        return staging_file

    def _store_load_to_vault(self, request):
        class LocalLoadFile(object):
            def __init__(self, filename):
                self._filename = filename
                self._file = open(filename, "rb")

            def __del__(self):
                self._file.close()

            @property
            def filename(self):
                return self._filename

            @property
            def file(self):
                return self._file

        load_files = dict()

        # Flag to cleanup staging files in case of errors
        error = True
        try:
            for file in proxy_consts.IMPORT_LOAD_FILES:
                if request.content_type == "application/json":
                    request_body = dict(json.loads(request.body))

                    if file not in request_body:
                        msg = _("Missing required file for %s" % file)
                        raise webob.exc.HTTPInternalServerError(explanation=msg)

                    if not os.path.exists(request_body[file]):
                        msg = _(
                            "File %s does not exist on the active controller"
                            % request_body[file]
                        )
                        raise webob.exc.HTTPInternalServerError(explanation=msg)

                    file_item = LocalLoadFile(request_body[file])
                else:
                    if file not in request.POST:
                        msg = _("Missing required file for %s" % file)
                        raise webob.exc.HTTPInternalServerError(explanation=msg)

                    file_item = request.POST[file]
                    if not file_item.filename:
                        msg = _("No %s file uploaded" % file)
                        raise webob.exc.HTTPInternalServerError(explanation=msg)

                staging_file = self._upload_file(file_item)
                if file in request.POST:
                    request.POST[file] = staging_file
                if staging_file:
                    self._copy_load_to_vault_for_validation(staging_file)
                    load_files.update({file: staging_file})
                else:
                    msg = _(
                        "Failed to save file %s to disk. Please check dcorch "
                        "logs for details." % file_item.filename
                    )
                    raise webob.exc.HTTPInternalServerError(explanation=msg)

            LOG.info("Load files: %s saved to disk." % load_files)
            error = False
        except webob.exc.HTTPInternalServerError:
            raise
        except Exception as e:
            msg = _("Unexpected error copying load to vault: %s" % e)
            raise webob.exc.HTTPInternalServerError(explanation=msg)
        finally:
            if error and os.path.exists(proxy_consts.LOAD_FILES_STAGING_DIR):
                shutil.rmtree(proxy_consts.LOAD_FILES_STAGING_DIR)
        return load_files

    def _store_image_file(self, file_item, dst_filename):
        # First, upload file to a temporary location
        fn = self._upload_file(file_item)

        # copy the device image to the vault
        try:
            if fn:
                self._copy_device_image_to_vault(fn, dst_filename)
            else:
                msg = _(
                    "Failed to save file %s to disk. Please check dcorch "
                    "logs for details." % file_item.filename
                )
                raise webob.exc.HTTPInternalServerError(explanation=msg)
        finally:
            shutil.rmtree(proxy_consts.LOAD_FILES_STAGING_DIR)

    def _device_image_upload_req(self, request, response):
        # stores device image in the vault storage
        file_item = request.POST["file"]
        try:
            resource = json.loads(response.body)[
                consts.RESOURCE_TYPE_SYSINV_DEVICE_IMAGE
            ]
            dst_filename = self._get_device_image_filename(resource)
            self._store_image_file(file_item, dst_filename)
        except Exception:
            LOG.exception("Failed to store the device image to vault")
        proxy_utils.cleanup(request.environ)
        return response

    def _get_device_image_filename(self, resource):
        filename = "{}-{}-{}-{}.bit".format(
            resource.get("bitstream_type"),
            resource.get("pci_vendor"),
            resource.get("pci_device"),
            resource.get("uuid"),
        )
        return filename

    def _delete_device_image_from_vault(self, filename):
        image_file_path = os.path.join(proxy_consts.DEVICE_IMAGE_VAULT_DIR, filename)

        if os.path.isfile(image_file_path):
            os.remove(image_file_path)
            LOG.info("Device image (%s) removed from vault." % filename)

    def _enqueue_work(self, environ, request, response):
        LOG.info("enqueue_work")
        request_body = request.body
        resource_info = {}
        request_header = self.get_request_header(environ)
        operation_type = proxy_utils.get_operation_type(environ)
        resource_type = self._get_resource_type_from_environ(environ)
        # certificate need special processing
        p_resource_info = "suppressed"
        if resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            if operation_type == consts.OPERATION_TYPE_DELETE:
                resource_id = json.loads(response.body)["signature"]
                resource_ids = [resource_id]
            else:
                resource_info["payload"] = request_body
                resource_info["content_type"] = environ.get("CONTENT_TYPE")
                resource = json.loads(response.body)[resource_type]
                # For ssl_ca cert, the resource in response is a list
                if isinstance(resource, list):
                    resource_ids = [str(res.get("signature")) for res in resource]
                else:
                    resource_ids = [resource.get("signature")]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_LOAD:
            if operation_type == consts.OPERATION_TYPE_DELETE:
                resource_id = json.loads(response.body)["software_version"]
                resource_ids = [resource_id]
        else:
            resource_id = self.get_resource_id_from_link(request_header)
            resource_ids = [resource_id]
            if operation_type != consts.OPERATION_TYPE_DELETE:
                resource_info["payload"] = json.loads(request_body)
            p_resource_info = resource_info

        for resource_id in resource_ids:
            LOG.info(
                "Resource id: (%s), type: (%s), info: (%s)",
                resource_id,
                resource_type,
                p_resource_info,
            )
            try:
                utils.enqueue_work(
                    self.ctxt,
                    self.ENDPOINT_TYPE,
                    resource_type,
                    resource_id,
                    operation_type,
                    json.dumps(resource_info),
                )
            except exception.ResourceNotFound as e:
                raise webob.exc.HTTPNotFound(explanation=str(e))


class InsufficientDiskspace(Exception):
    pass


class LocalStorage(object):
    def __init__(self):
        self._storage = threading.local()

    def get_value(self, key):
        if hasattr(self._storage, key):
            return getattr(self._storage, key)
        else:
            return None

    def set_value(self, key, value):
        setattr(self._storage, key, value)

    def void_value(self, key):
        if hasattr(self._storage, key):
            delattr(self._storage, key)


class USMAPIController(APIController):
    ENDPOINT_TYPE = dccommon_consts.ENDPOINT_TYPE_SOFTWARE
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPAccepted.code,
        webob.exc.HTTPNoContent.code,
    ]

    @property
    def tmp_dir(self):
        return self._local_storage.get_value("tmp_dir")

    @tmp_dir.setter
    def tmp_dir(self, value):
        self._local_storage.set_value("tmp_dir", value)

    @property
    def my_copy(self):
        return self._local_storage.get_value("my_copy")

    @my_copy.setter
    def my_copy(self, value):
        self._local_storage.set_value("my_copy", value)

    @property
    def upload_files(self):
        return self._local_storage.get_value("upload_files")

    @upload_files.setter
    def upload_files(self, value):
        self._local_storage.set_value("upload_files", value)

    def __init__(self, app, conf):
        super(USMAPIController, self).__init__(app, conf)
        self.response_hander_map = {self.ENDPOINT_TYPE: self._process_response}
        self._local_storage = LocalStorage()
        self.upload_files = []
        self.my_copy = False
        self.tmp_dir = None
        self.software_vault = dccommon_consts.SOFTWARE_VAULT_DIR

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        if CONF.show_request:
            self.print_request(req)
        environ = req.environ

        self.upload_files = []
        content_type = req.content_type
        new_request = req
        new_request.body = req.body

        if content_type == "text/plain":
            # --local
            self.upload_files = list(json.loads(req.body))
            self.my_copy = False
        else:
            LOG.info("save uploaded files to local storage")
            # upload. save files to scratch then perform a --local
            request_data = list(req.POST.items())
            uploaded_files = sorted(set(request_data))
            self._create_temp_storage()

            # Save all uploaded files to tmp_dir
            for file_item in uploaded_files:
                try:
                    filename = self._save_upload_file(file_item[1])
                except InsufficientDiskspace as e:
                    self._cleanup_temp_storage()
                    ret = {"info": "", "warning": "", "error": str(e)}
                    response = Response(body=json.dumps(ret), status=500)
                    return response

                self.upload_files.append(filename)

            new_request.content_type = "text/plain"
            new_request.body = json.dumps(self.upload_files).encode(new_request.charset)
            self.my_copy = True

        application = self.process_request(new_request)
        response = req.get_response(application)
        resp = self.process_response(environ, new_request, response)
        self._cleanup_temp_storage()
        return resp

    def _cleanup_temp_storage(self):
        if self.tmp_dir:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
            self.tmp_dir = None

    def _save_upload_file(self, file_item):
        file_name = file_item.filename

        target_dir = self.tmp_dir
        file_item.file.seek(0, os.SEEK_END)
        file_size = file_item.file.tell()
        avail_space = shutil.disk_usage(target_dir).free
        if file_size > avail_space:
            LOG.error(
                "Not enough space to save file %s in %s \n "
                + "Available %s bytes. File size %s",
                file_name,
                target_dir,
                avail_space,
                file_size,
            )

            raise InsufficientDiskspace(f"Insufficient disk space in {self.tmp_dir}")

        target_file = os.path.join(target_dir, os.path.basename(file_name))
        with open(target_file, "wb") as destination_file:
            destination_file.write(file_item.value)
        return target_file

    def _process_response(self, environ, request, response):
        def is_usm_software(fn):
            return os.path.splitext(fn)[-1] in [".iso", ".patch"]

        try:
            resource_type = self._get_resource_type_from_environ(environ)
            operation_type = proxy_utils.get_operation_type(environ)
            if self.get_status_code(response) in self.OK_STATUS_CODE:
                LOG.info("resource type %s" % resource_type)
                if resource_type == consts.RESOURCE_TYPE_USM_RELEASE:
                    if operation_type == consts.OPERATION_TYPE_POST:
                        body = response.body
                        if isinstance(body, bytes):
                            body = body.decode()

                        files = usm_util.parse_upload(body)
                        releases = [f for f in files if is_usm_software(f["filename"])]
                        for release in releases:
                            sw_version = usm_util.get_major_release_version(
                                release["sw_release"]
                            )
                            self._save_load_to_vault(sw_version)

            sw_versions = self._get_major_releases(environ, request)
            LOG.info("current available software versions %s" % sw_versions)
            if sw_versions:
                dcvault_versions = self._get_version_from_dcvault()
                LOG.info("software in dcvault %s" % dcvault_versions)
                self._audit_dcvault(sw_versions, dcvault_versions)
            return response
        finally:
            proxy_utils.cleanup(environ)

    def _get_major_releases(self, environ, request):
        new_request = request
        new_request.body = None
        new_environ = environ
        new_environ["REQUEST_METHOD"] = "GET"
        new_environ["PATH_INFO"] = "/v1/release/"

        new_request = Request(new_environ)
        application = self.process_request(new_request)
        resp = new_request.get_response(application)
        if self.get_status_code(resp) not in self.OK_STATUS_CODE:
            # can't retrieve software list at the moment
            return None

        data = json.loads(resp.body)
        sw_versions = []
        for d in data:
            sw_version = usm_util.get_component_and_versions(d["release_id"])[2]
            if sw_version and sw_version not in sw_versions:
                sw_versions.append(sw_version)
        return sw_versions

    def _get_version_from_dcvault(self):
        if os.path.exists(self.software_vault):
            dirs = os.listdir(self.software_vault)
            return dirs
        return []

    def _audit_dcvault(self, sw_versions, dcvalut_versions):
        for dcvault_ver in dcvalut_versions:
            if dcvault_ver not in sw_versions:
                self._remove_load_from_vault(dcvault_ver)

    def _create_temp_storage(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="upload", dir="/scratch")
        LOG.info("created %s" % self.tmp_dir)
        return self.tmp_dir

    def _save_load_to_vault(self, sw_version):
        versioned_vault = os.path.join(self.software_vault, sw_version)
        pathlib.Path(versioned_vault).mkdir(parents=True, exist_ok=True)
        if not self.my_copy:
            self._create_temp_storage()
            for upload_file in self.upload_files:
                base_name = os.path.basename(upload_file)
                target_file = os.path.join(self.tmp_dir, base_name)
                shutil.copy(upload_file, target_file)

        # Move the files to the final location
        for upload_file in self.upload_files:
            base_name = os.path.basename(upload_file)
            target_file = os.path.join(versioned_vault, base_name)
            src_file = os.path.join(self.tmp_dir, base_name)
            shutil.move(src_file, target_file)

        LOG.info("Release %s (%s) saved to vault." % (self.upload_files, sw_version))

    def _remove_load_from_vault(self, sw_version):
        versioned_vault = os.path.join(self.software_vault, sw_version)

        if os.path.isdir(versioned_vault):
            shutil.rmtree(versioned_vault)
            LOG.info("Load (%s) removed from vault." % sw_version)


class IdentityAPIController(APIController):

    ENDPOINT_TYPE = dccommon_consts.ENDPOINT_TYPE_IDENTITY
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPCreated.code,
        webob.exc.HTTPAccepted.code,
        webob.exc.HTTPNoContent.code,
    ]

    def __init__(self, app, conf):
        super(IdentityAPIController, self).__init__(app, conf)
        self.response_hander_map = {self.ENDPOINT_TYPE: self._process_response}
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
        # /v3/projects/{project_id}/users/{user_id}/roles/{role_id} or
        # /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}
        # We need to extract all ID parameters from the URL
        role_id = proxy_utils.get_routing_match_value(environ, "role_id")
        proj_id = proxy_utils.get_routing_match_value(environ, "project_id")
        if "user_id" in proxy_utils.get_routing_match_arguments(environ):
            actor_id = proxy_utils.get_routing_match_value(environ, "user_id")
        else:
            actor_id = proxy_utils.get_routing_match_value(environ, "group_id")

        if not role_id or not proj_id or not actor_id:
            LOG.error("Malformed Role Assignment or Revocation URL: %s", url)
        else:
            resource_id = "{}_{}_{}".format(proj_id, actor_id, role_id)
        return resource_id

    def _retrieve_token_revoke_event_rid(self, url, environ):
        resource_id = None
        # for token revocation event, we need to retrieve the audit_id
        # from the token being revoked.
        revoked_token = environ.get("HTTP_X_SUBJECT_TOKEN", None)

        if not revoked_token:
            LOG.error("Malformed Token Revocation URL: %s", url)
        else:
            try:
                resource_id = proxy_utils.retrieve_token_audit_id(revoked_token)
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
        # we need to extract Project ID, User ID/Group ID and Role ID from the
        # URL, and not just the Role ID
        if resource_type == consts.RESOURCE_TYPE_IDENTITY_PROJECT_ROLE_ASSIGNMENTS:
            resource_id = self._generate_assignment_rid(request_header, environ)
            # grant a role to a user (PUT) creates a project role assignment
            if operation_type == consts.OPERATION_TYPE_PUT:
                operation_type = consts.OPERATION_TYPE_POST
        elif resource_type == consts.RESOURCE_TYPE_IDENTITY_TOKEN_REVOKE_EVENTS:
            resource_id = self._retrieve_token_revoke_event_rid(request_header, environ)
            # delete (revoke) a token (DELETE) creates a token revoke event.
            if operation_type == consts.OPERATION_TYPE_DELETE and resource_id:
                operation_type = consts.OPERATION_TYPE_POST
                resource_info = {"token_revoke_event": {"audit_id": resource_id}}
        elif resource_type == consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD:
            resource_id = self.get_resource_id_from_link(
                request_header.strip("/password")
            )
            # user change password (POST) is an update to the user
            if operation_type == consts.OPERATION_TYPE_POST:
                operation_type = consts.OPERATION_TYPE_PATCH
                resource_type = consts.RESOURCE_TYPE_IDENTITY_USERS
        elif (
            resource_type == consts.RESOURCE_TYPE_IDENTITY_GROUPS
            and operation_type != consts.OPERATION_TYPE_POST
        ):
            if "users" in request_header:
                # Requests for adding a user (PUT) and removing a user (DELETE)
                # should be converted to a PUT request
                # The url in this case looks like /groups/{group_id}/users/{user_id}
                # We need to extract the group_id and assign that to resource_id
                index = request_header.find("/users")
                resource_id = self.get_resource_id_from_link(request_header[0:index])
                resource_info = {"group": {"id": resource_id}}
                operation_type = consts.OPERATION_TYPE_PUT
            else:
                resource_id = self.get_resource_id_from_link(request_header)
        else:
            if operation_type == consts.OPERATION_TYPE_POST:
                # Retrieve the ID from the response
                resource = list(json.loads(response.body).items())[0][1]
                resource_id = resource["id"]
            else:
                resource_id = self.get_resource_id_from_link(request_header)

        if (
            operation_type != consts.OPERATION_TYPE_DELETE
            and request_body
            and (not resource_info)
        ):
            resource_info = json.loads(request_body)

        LOG.info(
            "%s: Resource id: (%s), type: (%s), info: (%s)",
            operation_type,
            resource_id,
            resource_type,
            resource_info,
        )

        if resource_id:
            try:
                utils.enqueue_work(
                    self.ctxt,
                    self.sync_endpoint,
                    resource_type,
                    resource_id,
                    operation_type,
                    json.dumps(resource_info),
                )
            except exception.ResourceNotFound as e:
                raise webob.exc.HTTPNotFound(explanation=str(e))
        else:
            LOG.warning("Empty resource id for resource: %s", operation_type)


class CinderAPIController(APIController):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_VOLUME
    RESOURCE_TYPE_MAP = {
        consts.RESOURCE_TYPE_VOLUME_QUOTA_SET: "quota_set",
    }
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
    ]

    def __init__(self, app, conf):
        super(CinderAPIController, self).__init__(app, conf)
        self.response_hander_map = {self.ENDPOINT_TYPE: self._process_response}

    def _process_response(self, environ, request_body, response):
        if self.get_status_code(response) in self.OK_STATUS_CODE:
            operation_type = proxy_utils.get_operation_type(environ)
            if operation_type == consts.OPERATION_TYPE_GET:
                if proxy_utils.show_usage(environ):
                    response = self._update_response(environ, request_body, response)
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
                resource_info = request[self.RESOURCE_TYPE_MAP.get(resource_type)]
            else:
                resource_info = request[resource_type]
        resource_info = json.dumps(resource_info)
        LOG.info(
            "Operation:(%s), resource_id:(%s), resource_info:(%s)",
            operation_type,
            resource_id,
            resource_info,
        )
        try:
            utils.enqueue_work(
                self.ctxt,
                self.ENDPOINT_TYPE,
                resource_type,
                resource_id,
                operation_type,
                resource_info,
            )
        except exception.ResourceNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=str(e))


class NeutronAPIController(APIController):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_NETWORK
    RESOURCE_TYPE_MAP = {
        consts.RESOURCE_TYPE_NETWORK_QUOTA_SET: "quota",
    }
    # the following fields will be inserted to the resource_info if
    # they are not presented in the request but are provided in the
    # response
    DESIRED_FIELDS = ["tenant_id", "project_id"]
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
        webob.exc.HTTPCreated.code,
        webob.exc.HTTPNoContent.code,
    ]

    def __init__(self, app, conf):
        super(NeutronAPIController, self).__init__(app, conf)
        self.response_hander_map = {self.ENDPOINT_TYPE: self._process_response}

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
            resource_id = resource["id"]
        else:
            resource_id = self.get_resource_id_from_link(request_header)

        if operation_type == consts.OPERATION_TYPE_DELETE:
            resource_info = {}
        else:
            request = json.loads(request_body)
            if resource_type in self.RESOURCE_TYPE_MAP:
                original_type = self.RESOURCE_TYPE_MAP.get(resource_type)
            else:
                original_type = resource_type
            resource_info = request[original_type]
            if operation_type == consts.OPERATION_TYPE_POST:
                resp_info = json.loads(response.body)[original_type]
                for f in self.DESIRED_FIELDS:
                    if f not in resource_info and f in resp_info:
                        resource_info[f] = resp_info[f]

        resource_info = json.dumps(resource_info)
        LOG.info(
            "Operation:(%s), resource_id:(%s), resource_info:(%s)",
            operation_type,
            resource_id,
            resource_info,
        )
        try:
            utils.enqueue_work(
                self.ctxt,
                self.ENDPOINT_TYPE,
                resource_type,
                resource_id,
                operation_type,
                resource_info,
            )
        except exception.ResourceNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=str(e))


class OrchAPIController(APIController):

    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
    ]

    def __init__(self, app, conf):
        super(OrchAPIController, self).__init__(app, conf)
        self.response_hander_map = {
            consts.ENDPOINT_TYPE_COMPUTE: self._process_response,
            consts.ENDPOINT_TYPE_NETWORK: self._process_response,
        }

    def _process_response(self, environ, request_body, response):
        if self.get_status_code(response) in self.OK_STATUS_CODE:
            response = self._update_response(environ, request_body, response)
        return response


class VersionController(Middleware):
    def __init__(self, app, conf):
        self._default_dispatcher = Proxy()
        self._remote_host, self._remote_port = proxy_utils.get_remote_host_port_options(
            CONF
        )
        super(VersionController, self).__init__(app)

    @webob.dec.wsgify(RequestClass=ProxyRequest)
    def __call__(self, req):
        LOG.debug(
            "VersionController forward the version request to remote "
            "host: (%s), port: (%d)" % (self._remote_host, self._remote_port)
        )
        proxy_utils.set_request_forward_environ(
            req, self._remote_host, self._remote_port
        )
        return self._default_dispatcher
