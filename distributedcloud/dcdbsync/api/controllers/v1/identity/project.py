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


class ProjectsController(object):
    VERSION_ALIASES = {
        "Stein": "1.0",
    }

    def __init__(self):
        super(ProjectsController, self).__init__()

    # to do the version compatibility for future purpose
    def _determine_version_cap(self, target):
        version_cap = 1.0
        return version_cap

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method="GET", template="json")
    def get(self, project_ref=None):

        context = restcomm.extract_context_from_environ()

        try:
            if project_ref is None:
                return db_api.project_get_all(context)

            else:
                project = db_api.project_get(context, project_ref)
                return project

        except exceptions.ProjectNotFound as e:
            pecan.abort(404, _("Project not found: %s") % e)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to get project"))

    @index.when(method="POST", template="json")
    def post(self):
        """Create a new project."""

        context = restcomm.extract_context_from_environ()

        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _("Request body decoding error"))

        if not payload:
            pecan.abort(400, _("Body required"))
        project_name = payload.get("project").get("name")

        if not project_name:
            pecan.abort(400, _("project name required"))

        try:
            # Insert the project into DB tables
            project_ref = db_api.project_create(context, payload)
            response.status = 201
            return project_ref

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to create project"))

    @index.when(method="PUT", template="json")
    def put(self, project_ref=None):
        """Update a existing project."""

        context = restcomm.extract_context_from_environ()

        if project_ref is None:
            pecan.abort(400, _("Project ID required"))

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _("Request body decoding error"))

        if not payload:
            pecan.abort(400, _("Body required"))

        try:
            # Update the project in DB tables
            project_ref = db_api.project_update(context, project_ref, payload)
            return project_ref

        except exceptions.ProjectNotFound as e:
            pecan.abort(404, _("Project not found: %s") % e)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to update project"))
