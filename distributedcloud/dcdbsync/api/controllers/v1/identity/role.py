# Copyright (c) 2017 Ericsson AB.
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
# Copyright (c) 2019, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json

from oslo_config import cfg
from oslo_log import log as logging
import pecan
from pecan import expose
from pecan import request
from pecan import response

from dcdbsync.api.controllers import restcomm
from dcdbsync.common import exceptions
from dcdbsync.common.i18n import _
from dcdbsync.db.identity import api as db_api

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class RolesController(object):
    VERSION_ALIASES = {
        "Stein": "1.0",
    }

    def __init__(self):
        super(RolesController, self).__init__()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method="GET", template="json")
    def get(self, role_ref=None):
        """Get a list of roles."""
        context = restcomm.extract_context_from_environ()

        try:
            if role_ref is None:
                return db_api.role_get_all(context)

            else:
                role = db_api.role_get(context, role_ref)
                return role

        except exceptions.RoleNotFound as e:
            pecan.abort(404, _("Role not found: %s") % e)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to get role"))

    @index.when(method="POST", template="json")
    def post(self):
        """Create a new role."""

        context = restcomm.extract_context_from_environ()

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _("Request body decoding error"))

        if not payload:
            pecan.abort(400, _("Body required"))
        role_name = payload.get("role").get("name")

        if not role_name:
            pecan.abort(400, _("role name required"))

        try:
            # Insert the role into DB tables
            role_ref = db_api.role_create(context, payload)
            response.status = 201
            return role_ref

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to create role"))

    @index.when(method="PUT", template="json")
    def put(self, role_ref=None):
        """Update a existing role."""

        context = restcomm.extract_context_from_environ()

        if role_ref is None:
            pecan.abort(400, _("Role ID required"))

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _("Request body decoding error"))

        if not payload:
            pecan.abort(400, _("Body required"))

        try:
            # Update the role in DB tables
            role_ref = db_api.role_update(context, role_ref, payload)
            return role_ref

        except exceptions.RoleNotFound as e:
            pecan.abort(404, _("Role not found: %s") % e)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to update role"))
