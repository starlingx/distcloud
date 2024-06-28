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
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os

import http.client as httpclient
from oslo_config import cfg
from oslo_log import log as logging
import pecan
from pecan import expose
from pecan import request

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import subcloud_deploy as subcloud_deploy_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common.i18n import _
from dcmanager.common import utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

LOCK_NAME = "SubcloudDeployController"


class SubcloudDeployController(object):

    def __init__(self):
        super(SubcloudDeployController, self).__init__()

    @staticmethod
    def _upload_files(dir_path, file_option, file_item, binary):

        prefix = file_option + "_"
        # create the version directory if it does not exist
        if not os.path.isdir(dir_path):
            os.mkdir(dir_path, 0o755)
        else:
            # check if the file exists, if so remove it
            filename = utils.get_filename_by_prefix(dir_path, prefix)
            if filename is not None:
                os.remove(dir_path + "/" + filename)

        # upload the new file
        file_item.file.seek(0, os.SEEK_SET)
        contents = file_item.file.read()
        fn = os.path.join(dir_path, prefix + os.path.basename(file_item.filename))
        if binary:
            dst = open(fn, "wb")
            dst.write(contents)
        else:
            dst = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
            os.write(dst, contents)

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @utils.synchronized(LOCK_NAME)
    @index.when(method="POST", template="json")
    def post(self):
        policy.authorize(
            subcloud_deploy_policy.POLICY_ROOT % "upload",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        deploy_dicts = dict()
        missing_options = set()
        for f in consts.DEPLOY_COMMON_FILE_OPTIONS:
            if f not in request.POST:
                missing_options.add(f)

        # The API will only accept three types of input scenarios:
        # 1. DEPLOY_PLAYBOOK, DEPLOY_OVERRIDES, and DEPLOY_CHART
        # 2. DEPLOY_PLAYBOOK, DEPLOY_OVERRIDES, DEPLOY_CHART, and DEPLOY_PRESTAGE
        # 3. DEPLOY_PRESTAGE
        size = len(missing_options)
        if len(missing_options) > 0:
            if (consts.DEPLOY_PRESTAGE in missing_options and size != 1) or (
                consts.DEPLOY_PRESTAGE not in missing_options and size != 3
            ):
                missing_str = str()
                for missing in missing_options:
                    if missing is not consts.DEPLOY_PRESTAGE:
                        missing_str += "--%s " % missing
                error_msg = "error: argument %s is required" % missing_str.rstrip()
                pecan.abort(httpclient.BAD_REQUEST, error_msg)

        deploy_dicts["software_version"] = utils.get_sw_version(
            request.POST.get("release")
        )

        dir_path = os.path.join(
            dccommon_consts.DEPLOY_DIR, deploy_dicts["software_version"]
        )
        for f in consts.DEPLOY_COMMON_FILE_OPTIONS:
            if f not in request.POST:
                continue

            file_item = request.POST[f]
            filename = getattr(file_item, "filename", "")
            if not filename:
                pecan.abort(httpclient.BAD_REQUEST, _("No %s file uploaded" % f))

            binary = False
            if f == consts.DEPLOY_CHART:
                binary = True
            try:
                self._upload_files(dir_path, f, file_item, binary)
            except Exception as e:
                pecan.abort(
                    httpclient.INTERNAL_SERVER_ERROR,
                    _("Failed to upload %s file: %s" % (f, e)),
                )
            deploy_dicts.update({f: filename})

        return deploy_dicts

    @index.when(method="GET", template="json")
    def get(self, release=None):
        """Get the subcloud deploy files that has been uploaded and stored.

        :param release: release version
        """

        policy.authorize(
            subcloud_deploy_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        deploy_dicts = dict()
        deploy_dicts["software_version"] = utils.get_sw_version(release)
        dir_path = os.path.join(
            dccommon_consts.DEPLOY_DIR, deploy_dicts["software_version"]
        )
        for f in consts.DEPLOY_COMMON_FILE_OPTIONS:
            filename = None
            if os.path.isdir(dir_path):
                prefix = f + "_"
                filename = utils.get_filename_by_prefix(dir_path, prefix)
                if filename is not None:
                    filename = filename.replace(prefix, "", 1)
            deploy_dicts.update({f: filename})
        return dict(subcloud_deploy=deploy_dicts)

    @index.when(method="DELETE", template="json")
    def delete(self, release=None):
        """Delete the subcloud deploy files.

        :param release: release version
        """
        policy.authorize(
            subcloud_deploy_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        is_prestage_images = request.params.get("prestage_images", "").lower() == "true"
        is_deployment_files = (
            request.params.get("deployment_files", "").lower() == "true"
        )

        dir_path = os.path.join(
            dccommon_consts.DEPLOY_DIR, utils.get_sw_version(release)
        )
        if not os.path.isdir(dir_path):
            pecan.abort(httpclient.NOT_FOUND, _("Directory not found: %s" % dir_path))
        try:
            file_options = []
            if is_prestage_images:
                file_options.append(consts.DEPLOY_PRESTAGE)

            if is_deployment_files:
                file_options.extend(
                    [
                        consts.DEPLOY_OVERRIDES,
                        consts.DEPLOY_CHART,
                        consts.DEPLOY_PLAYBOOK,
                    ]
                )

            if not (is_deployment_files or is_prestage_images):
                file_options.extend(consts.DEPLOY_COMMON_FILE_OPTIONS)

            for file_option in file_options:
                prefix = file_option + "_"
                file_name = utils.get_filename_by_prefix(dir_path, prefix)
                if file_name:
                    os.remove(os.path.join(dir_path, file_name))
                else:
                    LOG.warning("%s file not present" % file_option)

        except Exception as e:
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Failed to delete file: %s" % e)
            )
        return None
