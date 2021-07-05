# Copyright 2018-2020 Wind River
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


import glob
import json
import os
import shutil
import tempfile
import webob.dec
import webob.exc

from cgcs_patch.patch_functions import get_release_from_patch
from dcmanager.common import consts as dcmanager_consts
from dcorch.api.proxy.apps.dispatcher import APIDispatcher
from dcorch.api.proxy.common import constants as proxy_consts
from dcorch.api.proxy.common.service import Middleware
from dcorch.api.proxy.common import utils as proxy_utils
from dcorch.common import consts
from dcorch.common import context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service.wsgi import Request
from oslo_utils._i18n import _

from dcmanager.rpc import client as dcmanager_rpc_client

LOG = logging.getLogger(__name__)

patch_opts = [
    cfg.StrOpt('patch_vault',
               default='/opt/dc-vault/patches/',
               help='file system for patch storage on SystemController'),
]


CONF = cfg.CONF
CONF.register_opts(patch_opts, CONF.type)


class PatchAPIController(Middleware):

    ENDPOINT_TYPE = consts.ENDPOINT_TYPE_PATCHING
    OK_STATUS_CODE = [
        webob.exc.HTTPOk.code,
    ]

    PATCH_META_DATA = 'metadata.xml'
    SOFTWARE_VERSION = 'sw_version'

    def __init__(self, app, conf):
        super(PatchAPIController, self).__init__(app)
        self.ctxt = context.get_admin_context()
        self._default_dispatcher = APIDispatcher(app)
        self.rpc_client = dcmanager_rpc_client.ManagerClient()
        self.response_hander_map = {
            proxy_consts.PATCH_ACTION_UPLOAD: self.patch_upload_req,
            proxy_consts.PATCH_ACTION_UPLOAD_DIR: self.patch_upload_dir_req,
            proxy_consts.PATCH_ACTION_DELETE: self.patch_delete_req,
            proxy_consts.PATCH_ACTION_APPLY: self.notify,
            proxy_consts.PATCH_ACTION_COMMIT: self.notify,
            proxy_consts.PATCH_ACTION_REMOVE: self.notify,
        }

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        # copy the request
        request = req
        application = self.process_request(req)
        response = req.get_response(application)
        return self.process_response(request, response)

    def ok_response(self, response):
        rc = True
        # check if the request was successful
        if response.status_int in self.OK_STATUS_CODE:
            data = json.loads(response.text)
            if 'error' in data and data["error"] != "":
                rc = False
        else:
            rc = False

        return rc

    def copy_patch_to_version_vault(self, patch):
        try:
            sw_version = get_release_from_patch(patch)
        except Exception:
            msg = "Unable to fetch release version from patch"
            LOG.error(msg)
            raise webob.exc.HTTPUnprocessableEntity(explanation=msg)
        versioned_vault = CONF.patching.patch_vault + \
            sw_version
        if not os.path.isdir(versioned_vault):
            os.makedirs(versioned_vault)
        try:
            shutil.copy(patch, versioned_vault)
        except shutil.Error:
            msg = _("Unable to store patch file (%s)") % patch
            LOG.error(msg)
            raise webob.exc.HTTPUnprocessableEntity(explanation=msg)

    @staticmethod
    def delete_patch_from_version_vault(patch):
        vault = CONF.patching.patch_vault
        for name in os.listdir(vault):
            fn = os.path.join(vault, name, patch)
            if os.path.isfile(fn):
                LOG.debug("Deleting (%s)", fn)
                try:
                    os.remove(fn)
                    return
                except OSError:
                    msg = ("Unable to remove patch file (%s) from the central"
                           "storage." % fn)
                    raise webob.exc.HTTPUnprocessableEntity(explanation=msg)
        LOG.info("Patch (%s) was not found in (%s)", patch, vault)

    def store_patch_file(self, filename, fileno):
        # the following copy method is taken from from api/controllers/root.py
        # it is used for writing files from the http request stream chunk by
        # chunk, rather than reading the file into memory as a whole

        # write the patch to a temporary directory first
        tempdir = tempfile.mkdtemp(prefix="patch_proxy_", dir='/scratch')
        fn = tempdir + '/' + os.path.basename(filename)
        dst = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        size = 64 * 1024
        n = size
        while n >= size:
            s = os.read(fileno, size)
            n = os.write(dst, s)
        os.close(dst)

        # copy the patch to the versioned vault
        try:
            self.copy_patch_to_version_vault(fn)
        finally:
            shutil.rmtree(tempdir)

    def patch_upload_req(self, request, response):
        # stores patch in the patch storage
        file_item = request.POST['file']
        try:
            self.store_patch_file(file_item.filename, file_item.file.fileno())
        except Exception:
            LOG.exception("Failed to store the patch to vault")
            # return a warning and prompt the user to try again
            if hasattr(response, 'text'):
                from builtins import str as text
                data = json.loads(response.text)
                if 'warning' in data:
                    msg = _('The patch file could not be stored in the vault, '
                            'please upload the patch again!')
                    data['warning'] += msg
                    response.text = text(json.dumps(data))
        proxy_utils.cleanup(request.environ)
        return response

    def patch_upload_dir_req(self, request, response):
        files = []
        for key, path in request.GET.items():
            LOG.info("upload-dir: Retrieving patches from %s" % path)
            for f in glob.glob(path + '/*.patch'):
                if os.path.isfile(f):
                    files.append(f)

        for f in files:
            self.copy_patch_to_version_vault(f)

        return response

    def notify(self, request, response):
        # Send a RPC to dcmanager
        LOG.info("Send RPC to dcmanager to set patching sync status to "
                 "unknown")
        self.rpc_client.update_subcloud_endpoint_status(
            self.ctxt,
            endpoint_type=self.ENDPOINT_TYPE,
            sync_status=dcmanager_consts.SYNC_STATUS_UNKNOWN)
        return response

    def patch_delete_req(self, request, response):
        patch_ids = proxy_utils.get_routing_match_value(request.environ,
                                                        'patch_id')
        LOG.info("Deleting patches: %s", patch_ids)
        patch_list = os.path.normpath(patch_ids).split(os.path.sep)
        for patch_file in patch_list:
            LOG.debug("Patch file:(%s)", patch_file)
            self.delete_patch_from_version_vault(os.path.basename(patch_file)
                                                 + '.patch')
        return response

    def process_request(self, req):
        if CONF.show_request:
            LOG.info("Request URL: (%s)", req.url)
        return self._default_dispatcher

    def process_response(self, request, response):
        if CONF.show_response:
            LOG.info("Response: (%s)", str(response))
            LOG.info("Response status: (%s)", response.status)
        action = proxy_utils.get_routing_match_value(request.environ, 'action')
        if self.ok_response(response) and action in self.response_hander_map:
            handler = self.response_hander_map[action]
            return handler(request, response)
        else:
            proxy_utils.cleanup(request.environ)
            return response
