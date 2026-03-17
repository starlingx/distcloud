# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2020-2022,2024-2026 Wind River Systems, Inc.
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

import http.client as httpclient
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_messaging import RemoteError
import pecan
from pecan import expose
from pecan import request

from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import subcloud_group as subcloud_group_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

SUPPORTED_GROUP_APPLY_TYPES = [
    consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
    consts.SUBCLOUD_APPLY_TYPE_SERIAL,
]

# validation constants for Subcloud Group
MAX_SUBCLOUD_GROUP_NAME_LEN = 255
MAX_SUBCLOUD_GROUP_DESCRIPTION_LEN = 255
MIN_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS = 1
MAX_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS = 5000


class SubcloudGroupsController(restcomm.GenericPathController):

    def __init__(self):
        super(SubcloudGroupsController, self).__init__()
        self.rpc_client = rpc_client.ManagerClient()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    def _get_subcloud_list_for_group(self, context, group_id):
        subclouds = db_api.subcloud_get_for_group(context, group_id)
        return utils.subcloud_db_list_to_dict(subclouds)

    def _get_subcloud_group_list(self, context):
        groups = db_api.subcloud_group_get_all(context)
        subcloud_group_list = []

        for group in groups:
            group_dict = db_api.subcloud_group_db_model_to_dict(group)
            subcloud_group_list.append(group_dict)

        result = dict()
        result["subcloud_groups"] = subcloud_group_list
        return result

    @index.when(method="GET", template="json")
    def get(self, group_ref=None, subclouds=False):
        """Get details about subcloud group.

        :param group_ref: ID or name of subcloud group
        ---
        get:
          summary: Get subcloud groups
          description: >-
            Retrieve list of all subcloud groups
            or details of a specific group
          operationId: getSubcloudGroups
          tags:
          - subcloud-groups
          parameters:
          - name: group_ref
            in: query
            description: ID or name of subcloud group
            required: false
            schema:
              type: string
          - name: subclouds
            in: query
            description: Return only subclouds for this group
            required: false
            schema:
              type: boolean
          responses:
            200:
              description: Groups retrieved successfully
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      subcloud_groups:
                        $ref: '#/components/schemas/subcloud_groups'
            404:
              description: Subcloud group not found
            500:
              description: Internal server error
        """
        policy.authorize(
            subcloud_group_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        if group_ref is None:
            # List of subcloud groups requested
            return self._get_subcloud_group_list(context)

        group = utils.subcloud_group_get_by_ref(context, group_ref)
        if group is None:
            pecan.abort(httpclient.NOT_FOUND, _("Subcloud Group not found"))
        if subclouds:
            # Return only the subclouds for this subcloud group
            return self._get_subcloud_list_for_group(context, group.id)
        subcloud_group_dict = db_api.subcloud_group_db_model_to_dict(group)
        return subcloud_group_dict

    def _validate_description(self, description):
        if not description:
            return False
        if len(description) >= MAX_SUBCLOUD_GROUP_DESCRIPTION_LEN:
            return False
        return True

    def _validate_update_apply_type(self, update_apply_type):
        if not update_apply_type:
            return False
        if update_apply_type not in SUPPORTED_GROUP_APPLY_TYPES:
            return False
        return True

    def _validate_max_parallel_subclouds(self, max_parallel_str):
        if not max_parallel_str:
            return False
        try:
            # Check the value is an integer
            val = int(max_parallel_str)
        except ValueError:
            return False

        # We do not support less than min or greater than max
        if val < MIN_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS:
            return False
        if val > MAX_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS:
            return False
        return True

    @index.when(method="POST", template="json")
    def post(self):
        """Create a new subcloud group.

        ---
        post:
          summary: Create a new subcloud group
          description: Create a new subcloud group with specified configuration
          operationId: createSubcloudGroup
          tags:
          - subcloud-groups
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    name:
                      $ref: '#/components/schemas/subcloud_group_name'
                    description:
                      $ref: '#/components/schemas/subcloud_group_description'
                    update_apply_type:
                      $ref: '#/components/schemas/subcloud_group_update_apply_type'
                    max_parallel_subclouds:
                      $ref: '#/components/schemas/group_max_parallel_subclouds'
                example:
                  name: mygroup
                  description: My subcloud group
                  update_apply_type: parallel
                  max_parallel_subclouds: 3
          responses:
            200:
              description: Group created successfully
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    id: 2
                    name: New Group
                    description: bla
                    update_apply_type: parallel
                    max_parallel_subclouds: 2
                    created-at: '2026-03-04 00:57:16.732189'
                    updated-at: null
            400:
              description: Bad request - invalid parameters
            422:
              description: Unprocessable entity - validation failed
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            subcloud_group_policy.POLICY_ROOT % "create",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        payload = eval(request.body)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _("Body required"))

        name = payload.get("name")
        description = payload.get("description")
        update_apply_type = payload.get("update_apply_type")
        max_parallel_subclouds = payload.get("max_parallel_subclouds")

        # Validate payload
        if not utils.validate_name(
            name, prohibited_name_list=[consts.DEFAULT_SUBCLOUD_GROUP_NAME]
        ):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid group name"))
        if not self._validate_description(description):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid group description"))
        if not self._validate_update_apply_type(update_apply_type):
            pecan.abort(httpclient.BAD_REQUEST, _("Invalid group update_apply_type"))
        if not self._validate_max_parallel_subclouds(max_parallel_subclouds):
            pecan.abort(
                httpclient.BAD_REQUEST, _("Invalid group max_parallel_subclouds")
            )
        try:
            group_ref = db_api.subcloud_group_create(
                context, name, description, update_apply_type, max_parallel_subclouds
            )
            return db_api.subcloud_group_db_model_to_dict(group_ref)
        except db_exc.DBDuplicateEntry:
            LOG.info("Group create failed. Group %s already exists" % name)
            pecan.abort(
                httpclient.BAD_REQUEST,
                _("A subcloud group with this name already exists"),
            )
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to create subcloud group")
            )

    @index.when(method="PATCH", template="json")
    def patch(self, group_ref):
        """Update a subcloud group.

        :param group_ref: ID or name of subcloud group to update
        ---
        patch:
          summary: Update a subcloud group
          description: Update subcloud group configuration
          operationId: updateSubcloudGroup
          tags:
          - subcloud-groups
          parameters:
          - name: group_ref
            in: query
            description: ID or name of subcloud group
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    name:
                      $ref: '#/components/schemas/subcloud_group_name'
                    description:
                      $ref: '#/components/schemas/subcloud_group_description'
                    update_apply_type:
                      $ref: '#/components/schemas/subcloud_group_update_apply_type'
                    max_parallel_subclouds:
                      $ref: '#/components/schemas/group_max_parallel_subclouds'
          responses:
            200:
              description: Group updated successfully
              content:
                application/json:
                  schema:
                    type: object
                  example:
                    id: 2
                    name: RENAME
                    description: bla
                    update_apply_type: parallel
                    max_parallel_subclouds: 3
                    created-at: '2026-03-04 00:57:16.732189'
                    updated-at: '2026-03-04 00:58:36.034341'
            400:
              description: Bad request - invalid parameters
            404:
              description: Subcloud group not found
            422:
              description: Unprocessable entity - validation failed
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            subcloud_group_policy.POLICY_ROOT % "modify",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        if group_ref is None:
            pecan.abort(httpclient.BAD_REQUEST, _("Subcloud Group Name or ID required"))

        payload = eval(request.body)
        if not payload:
            pecan.abort(httpclient.BAD_REQUEST, _("Body required"))

        group = utils.subcloud_group_get_by_ref(context, group_ref)
        if group is None:
            pecan.abort(httpclient.NOT_FOUND, _("Subcloud Group not found"))

        name = payload.get("name")
        description = payload.get("description")
        update_apply_type = payload.get("update_apply_type")
        max_parallel_str = payload.get("max_parallel_subclouds")

        if not (name or description or update_apply_type or max_parallel_str):
            pecan.abort(httpclient.BAD_REQUEST, _("nothing to update"))

        # Check value is not None or empty before calling validate
        if name:
            if not utils.validate_name(
                name, prohibited_name_list=[consts.DEFAULT_SUBCLOUD_GROUP_NAME]
            ):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid group name"))
            # Special case. Default group name cannot be changed
            if group.id == consts.DEFAULT_SUBCLOUD_GROUP_ID:
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Default group name cannot be changed")
                )

        if description:
            if not self._validate_description(description):
                pecan.abort(httpclient.BAD_REQUEST, _("Invalid group description"))
        if update_apply_type:
            if not self._validate_update_apply_type(update_apply_type):
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Invalid group update_apply_type")
                )
        if max_parallel_str:
            if not self._validate_max_parallel_subclouds(max_parallel_str):
                pecan.abort(
                    httpclient.BAD_REQUEST, _("Invalid group max_parallel_subclouds")
                )

        try:
            updated_group = db_api.subcloud_group_update(
                context,
                group.id,
                name=name,
                description=description,
                update_apply_type=update_apply_type,
                max_parallel_subclouds=max_parallel_str,
            )
            return db_api.subcloud_group_db_model_to_dict(updated_group)
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            # additional exceptions.
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to update subcloud group")
            )

    @index.when(method="delete", template="json")
    def delete(self, group_ref):
        """Delete the subcloud group.

        ---
        delete:
          summary: Delete a subcloud group
          description: Delete a subcloud group if it is empty
          operationId: deleteSubcloudGroup
          tags:
          - subcloud-groups
          parameters:
          - name: group_ref
            in: query
            description: ID or name of subcloud group
            required: true
            schema:
              type: string
          responses:
            200:
              description: Group deleted successfully
              content:
                application/json:
                  schema:
                    type: object
            400:
              description: Bad request - group not empty or default group
            404:
              description: Subcloud group not found
            422:
              description: Unprocessable entity - validation failed
            500:
              description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            subcloud_group_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )

        if group_ref is None:
            pecan.abort(httpclient.BAD_REQUEST, _("Subcloud Group Name or ID required"))
        group = utils.subcloud_group_get_by_ref(context, group_ref)
        if group is None:
            pecan.abort(httpclient.NOT_FOUND, _("Subcloud Group not found"))
        if group.name == consts.DEFAULT_SUBCLOUD_GROUP_NAME:
            pecan.abort(
                httpclient.BAD_REQUEST, _("Default Subcloud Group may not be deleted")
            )
        try:
            # a subcloud group may not be deleted if it is use by any subclouds
            subclouds = db_api.subcloud_get_for_group(context, group.id)
            if len(subclouds) > 0:
                pecan.abort(httpclient.BAD_REQUEST, _("Subcloud Group not empty"))
            db_api.subcloud_group_destroy(context, group.id)
        except RemoteError as e:
            pecan.abort(httpclient.UNPROCESSABLE_ENTITY, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(
                httpclient.INTERNAL_SERVER_ERROR, _("Unable to delete subcloud group")
            )
        # This should return nothing
        return None
