# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2022, 2024-2026 Wind River Systems, Inc.
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

from oslo_config import cfg
from oslo_log import log as logging

import pecan
from pecan import expose
from pecan import request

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import sw_update_options as sw_update_options_policy
from dcmanager.api import policy
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# TODO(gherzmann): remove the "RegionOne", it's being kept for
# now to maintain backwards compatibility with older clients
REGION_ONE = "RegionOne"


class SwUpdateOptionsController(object):

    def __init__(self):
        super(SwUpdateOptionsController, self).__init__()
        self.rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method="GET", template="json")
    def get(self, subcloud_ref=None):
        """Get details about software update options.

        :param subcloud: name or id of subcloud (optional)
        ---
        get:
          summary: Get software update options
          description: >-
            Retrieve software update options for
            all subclouds or a specific subcloud
          operationId: getSwUpdateOptions
          tags:
          - sw-update-options
          parameters:
          - name: subcloud_ref
            in: query
            description: ID or name of subcloud
            required: false
            schema:
              type: string
          responses:
            200:
              description: Options retrieved successfully
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    id: 1
                    name: subcloud1-stx-latest
                    subcloud-id: 9
                    storage-apply-type: parallel
                    worker-apply-type: parallel
                    max-parallel-workers: 10
                    alarm-restriction-type: relaxed
                    default-instance-action: migrate
                    created-at: '2026-03-04 00:50:07.041135'
                    updated-at: null
            404:
              description: Subcloud not found
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    code: 404
                    title: Not Found
                    description: >-
                      No options found for Subcloud
                      with id 9, defaults will be used.
            500:
              description: Internal server error
        """
        policy.authorize(
            sw_update_options_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        if subcloud_ref is None:
            # List of all subcloud options requested.
            # Prepend the all clouds default options to the result.

            result = dict()
            result["sw-update-options"] = list()

            default_sw_update_opts_dict = utils.get_sw_update_opts(context)

            result["sw-update-options"].append(default_sw_update_opts_dict)

            subclouds = db_api.sw_update_opts_get_all_plus_subcloud_info(context)

            for subcloud, sw_update_opts in subclouds:
                if sw_update_opts:
                    result["sw-update-options"].append(
                        db_api.sw_update_opts_w_name_db_model_to_dict(
                            sw_update_opts, subcloud.name
                        )
                    )

            return result

        elif subcloud_ref in (dccommon_consts.SYSTEM_CONTROLLER_NAME, REGION_ONE):
            # Default options requested, guaranteed to succeed

            return utils.get_sw_update_opts(context)

        else:
            # Specific subcloud options requested

            if subcloud_ref.isdigit():
                # Look up subcloud as an ID
                try:
                    subcloud = db_api.subcloud_get(context, subcloud_ref)
                except exceptions.SubcloudNotFound:
                    pecan.abort(404, _("Subcloud not found"))
            else:
                # Look up subcloud by name
                try:
                    subcloud = db_api.subcloud_get_by_name(context, subcloud_ref)
                except exceptions.SubcloudNameNotFound:
                    pecan.abort(404, _("Subcloud not found"))

            try:
                return utils.get_sw_update_opts(context, subcloud_id=subcloud.id)
            except Exception as e:
                pecan.abort(404, _("%s") % e)

    @index.when(method="POST", template="json")
    def post(self, subcloud_ref=None):
        """Update or create sw update options.

        :param subcloud: name or id of subcloud (optional)
        ---
        post:
          summary: Create or update software update options
          description: >-
            Create or update software update options for a
            subcloud or default options
          operationId: updateSwUpdateOptions
          tags:
          - sw-update-options
          parameters:
          - name: subcloud_ref
            in: query
            description: ID or name of subcloud
            required: false
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required:
                  - storage-apply-type
                  - worker-apply-type
                  - max-parallel-workers
                  - alarm-restriction-type
                  - default-instance-action
                  properties:
                    storage-apply-type:
                      $ref: '#/components/schemas/storage_apply_type'
                    worker-apply-type:
                      $ref: '#/components/schemas/worker_apply_type'
                    max-parallel-workers:
                      $ref: '#/components/schemas/max_parallel_workers'
                    alarm-restriction-type:
                      $ref: '#/components/schemas/alarm_restriction_type'
                    default-instance-action:
                      $ref: '#/components/schemas/default_instance_action'
          responses:
            200:
              description: Options updated successfully
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    id: 1
                    name: subcloud1-stx-latest
                    subcloud-id: 9
                    storage-apply-type: parallel
                    worker-apply-type: parallel
                    max-parallel-workers: 10
                    alarm-restriction-type: relaxed
                    default-instance-action: migrate
                    created-at: '2026-03-04 00:50:07.041135'
                    updated-at: null
            400:
              description: Bad request - invalid parameters
            404:
              description: Subcloud not found
            500:
              description: Internal server error
        """

        # Note creating or updating subcloud specific options require
        # setting all options.

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            sw_update_options_policy.POLICY_ROOT % "update",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        payload = eval(request.body)
        if not payload:
            pecan.abort(400, _("Body required"))

        if subcloud_ref in (dccommon_consts.SYSTEM_CONTROLLER_NAME, REGION_ONE):

            # update default options
            subcloud_name = dccommon_consts.SW_UPDATE_DEFAULT_TITLE

            if db_api.sw_update_opts_default_get(context):
                # entry already in db, update it.
                try:
                    sw_update_opts_ref = db_api.sw_update_opts_default_update(
                        context,
                        payload["storage-apply-type"],
                        payload["worker-apply-type"],
                        payload["max-parallel-workers"],
                        payload["alarm-restriction-type"],
                        payload["default-instance-action"],
                    )
                except Exception as e:
                    LOG.exception(e)
                    raise e
            else:
                # no entry in db, create one.
                try:
                    sw_update_opts_ref = db_api.sw_update_opts_default_create(
                        context,
                        payload["storage-apply-type"],
                        payload["worker-apply-type"],
                        payload["max-parallel-workers"],
                        payload["alarm-restriction-type"],
                        payload["default-instance-action"],
                    )
                except Exception as e:
                    LOG.exception(e)
                    raise e
        else:
            # update subcloud options

            if subcloud_ref.isdigit():
                # Look up subcloud as an ID
                try:
                    subcloud = db_api.subcloud_get(context, subcloud_ref)
                except exceptions.SubcloudNotFound:
                    pecan.abort(404, _("Subcloud not found"))

                subcloud_name = subcloud.name

            else:
                # Look up subcloud by name
                try:
                    subcloud = db_api.subcloud_get_by_name(context, subcloud_ref)
                except exceptions.SubcloudNameNotFound:
                    pecan.abort(404, _("Subcloud not found"))

                subcloud_name = subcloud_ref

            sw_update_opts = db_api.sw_update_opts_get(context, subcloud.id)

            if sw_update_opts is None:
                sw_update_opts_ref = db_api.sw_update_opts_create(
                    context,
                    subcloud.id,
                    payload["storage-apply-type"],
                    payload["worker-apply-type"],
                    payload["max-parallel-workers"],
                    payload["alarm-restriction-type"],
                    payload["default-instance-action"],
                )

            else:
                # a row is present in table, update
                sw_update_opts_ref = db_api.sw_update_opts_update(
                    context,
                    subcloud.id,
                    payload["storage-apply-type"],
                    payload["worker-apply-type"],
                    payload["max-parallel-workers"],
                    payload["alarm-restriction-type"],
                    payload["default-instance-action"],
                )

        return db_api.sw_update_opts_w_name_db_model_to_dict(
            sw_update_opts_ref, subcloud_name
        )

    @index.when(method="delete", template="json")
    def delete(self, subcloud_ref):
        """Delete the software update options.

        ---
        delete:
          summary: Delete software update options
          description: Delete software update options for a subcloud
          operationId: deleteSwUpdateOptions
          tags:
          - sw-update-options
          parameters:
          - name: subcloud_ref
            in: query
            description: ID or name of subcloud
            required: true
            schema:
              type: string
          responses:
            200:
              description: Options deleted successfully
              content:
                application/json:
                  schema:
                    type: object
            404:
              description: Subcloud not found
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            sw_update_options_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        if subcloud_ref in (dccommon_consts.SYSTEM_CONTROLLER_NAME, REGION_ONE):
            # Delete defaults.
            # Note by deleting these, the next get will repopulate with
            # the global constants.

            try:
                db_api.sw_update_opts_default_destroy(context)
            except Exception:
                return
        else:

            if subcloud_ref.isdigit():
                # Look up subcloud as an ID
                try:
                    subcloud = db_api.subcloud_get(context, subcloud_ref)
                except exceptions.SubcloudNotFound:
                    pecan.abort(404, _("Subcloud not found"))

            else:
                # Look up subcloud by name
                try:
                    subcloud = db_api.subcloud_get_by_name(context, subcloud_ref)
                except exceptions.SubcloudNameNotFound:
                    pecan.abort(404, _("Subcloud not found"))

            # Delete the subcloud specific options
            if db_api.sw_update_opts_get(context, subcloud.id):
                db_api.sw_update_opts_destroy(context, subcloud.id)
            else:
                pecan.abort(404, _("Subcloud patch options not found"))
