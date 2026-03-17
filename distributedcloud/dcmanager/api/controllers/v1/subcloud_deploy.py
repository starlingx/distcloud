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
# Copyright (c) 2020-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import shutil
import zipfile

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
APPLICATION_ZIP_FILETYPE = "application/zip"


class SubcloudDeployController(object):

    def __init__(self):
        super(SubcloudDeployController, self).__init__()

    @staticmethod
    def _upload_files(dir_path, file_option, file_item):

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
        fn = os.path.join(dir_path, prefix + os.path.basename(file_item.filename))
        if file_item.type == APPLICATION_ZIP_FILETYPE:
            with zipfile.ZipFile(file_item.file, "r") as zf:
                zf.extractall(dir_path)
            # add the prefix to the original file
            shutil.move(
                os.path.join(dir_path, os.path.basename(file_item.filename)), fn
            )
        else:
            with open(fn, "wb") as dst:
                shutil.copyfileobj(file_item.file, dst)

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @utils.synchronized(LOCK_NAME)
    @index.when(method="POST", template="json")
    def post(self):
        """Upload subcloud deploy files

        ---
        post:
          summary: Upload subcloud deploy files
          description: |
            Upload deployment files including playbook, chart,
            overrides, and prestage images for a specific
            software release.

            Required Properties:
            - For deployment files: deploy_playbook AND deploy_chart are both required
            - For prestage-only uploads: only prestage_images is required

            Optional Properties:
            - release: Software release version (defaults to
              the system controller version if not provided)
            - deploy_overrides: Deployment manager overrides file
          operationId: uploadSubcloudDeployFiles
          tags:
          - subcloud-deploy
          requestBody:
            required: true
            content:
              multipart/form-data:
                schema:
                  type: object
                  properties:
                    release:
                      $ref: '#/components/schemas/release'
                    deploy_playbook:
                      $ref: '#/components/schemas/subcloud_deploy_playbook'
                    deploy_overrides:
                      $ref: '#/components/schemas/subcloud_deploy_overrides'
                    deploy_chart:
                      $ref: '#/components/schemas/subcloud_deploy_chart'
                    prestage_images:
                      $ref: '#/components/schemas/subcloud_deploy_prestage_images'
                examples:
                  deployment_files:
                    summary: Upload deployment files
                    value:
                      release: "26.03"
                      deploy_playbook: "deploy-playbook.yaml"
                      deploy_chart: "deploy-chart.tgz"
                  prestage_only:
                    summary: Upload prestage images only
                    value:
                      release: "25.09"
                      prestage_images: "images.lst"
          responses:
            200:
              description: Files uploaded successfully
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      software_version:
                        $ref: '#/components/schemas/software_version'
                  examples:
                    deployment_files:
                      summary: Deployment files uploaded
                      value:
                        software_version: "26.03"
                        deploy_playbook: "deploy-playbook.yaml"
                        deploy_chart: "deploy-chart.tgz"
                    prestage_only:
                      summary: Prestage images uploaded
                      value:
                        software_version: "25.09"
                        prestage_images: "images.lst"
            400:
              description: Bad request - missing required files
            500:
              description: Internal server error
        """
        policy.authorize(
            subcloud_deploy_policy.POLICY_ROOT % "upload",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        user_options = set(consts.DEPLOY_COMMON_FILE_OPTIONS).intersection(request.POST)
        missing_options = set(consts.REQUIRED_DEPLOY_FILE_OPTIONS).difference(
            user_options
        )

        if consts.DEPLOY_PRESTAGE in user_options and len(user_options) == 1:
            pass
        elif not missing_options:
            pass
        else:
            missing_str = "".join([f"--{m}" for m in missing_options])
            error_msg = f"error: argument {missing_str.rstrip()} is required"
            pecan.abort(httpclient.BAD_REQUEST, error_msg)

        deploy_dicts = dict()
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

            try:
                self._upload_files(dir_path, f, file_item)
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
        ---
        get:
          summary: Get subcloud deploy files
          description: >-
            Retrieve information about uploaded deployment
            files for a specific release
          operationId: getSubcloudDeployFiles
          tags:
          - subcloud-deploy
          parameters:
          - name: release
            in: query
            description: Software release version
            required: false
            schema:
              type: string
            example: "26.03"
          responses:
            200:
              description: Deploy files retrieved successfully
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      subcloud_deploy:
                        $ref: '#/components/schemas/subcloud_deploy'
                  example:
                    subcloud_deploy:
                      software_version: "26.03"
                      deploy_playbook: "deploy-playbook.yaml"
                      deploy_overrides: null
                      deploy_chart: "deploy-chart.tgz"
                      prestage_images: null
            500:
              description: Internal server error
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
        ---
        delete:
          summary: Delete subcloud deploy files
          description: Delete deployment files for a specific release
          operationId: deleteSubcloudDeployFiles
          tags:
          - subcloud-deploy
          parameters:
          - name: release
            in: query
            description: Software release version
            required: false
            schema:
              type: string
            example: "26.03"
          - name: prestage_images
            in: query
            description: Delete prestage images
            required: false
            schema:
              type: boolean
            example: true
          - name: deployment_files
            in: query
            description: Delete deployment files
            required: false
            schema:
              type: boolean
            example: true
          responses:
            200:
              description: Files deleted successfully
              content:
                application/json:
                  schema:
                    type: object
                  example: null
            404:
              description: Directory not found
            500:
              description: Internal server error
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
