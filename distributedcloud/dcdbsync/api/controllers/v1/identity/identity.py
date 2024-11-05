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
# Copyright (c) 2019-2021, 2024 Wind River Systems, Inc.
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


class UsersController(object):
    VERSION_ALIASES = {
        "Stein": "1.0",
    }

    def __init__(self):
        super(UsersController, self).__init__()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method="GET", template="json")
    def get(self, user_ref=None):
        """Get a list of users."""
        context = restcomm.extract_context_from_environ()
        try:
            if user_ref is None:
                return db_api.user_get_all(context)

            else:
                user = db_api.user_get(context, user_ref)
                return user

        except exceptions.UserNotFound as e:
            pecan.abort(404, _("User not found: %s") % e)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to get user"))

    @index.when(method="POST", template="json")
    def post(self):
        """Create a new user."""

        context = restcomm.extract_context_from_environ()

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _("Request body decoding error"))

        if not payload:
            pecan.abort(400, _("Body required"))
        user_name = payload.get("local_user").get("name")

        if not user_name:
            pecan.abort(400, _("User name required"))

        try:
            # Insert the user into DB tables
            user_ref = db_api.user_create(context, payload)
            response.status = 201
            return user_ref

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to create user"))

    @index.when(method="PUT", template="json")
    def put(self, user_ref=None):
        """Update a existing user."""

        context = restcomm.extract_context_from_environ()

        if user_ref is None:
            pecan.abort(400, _("User ID required"))

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _("Request body decoding error"))

        if not payload:
            pecan.abort(400, _("Body required"))

        try:
            # Update the user in DB tables
            return db_api.user_update(context, user_ref, payload)

        except exceptions.UserNotFound as e:
            pecan.abort(404, _("User not found: %s") % e)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to update user"))


class GroupsController(object):
    VERSION_ALIASES = {
        "Stein": "1.0",
    }

    def __init__(self):
        super(GroupsController, self).__init__()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method="GET", template="json")
    def get(self, group_ref=None):
        """Get a list of groups."""
        context = restcomm.extract_context_from_environ()
        try:
            if group_ref is None:
                return db_api.group_get_all(context)

            else:
                group = db_api.group_get(context, group_ref)
                return group

        except exceptions.GroupNotFound as e:
            pecan.abort(404, _("Group not found: %s") % e)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to get group"))

    @index.when(method="POST", template="json")
    def post(self):
        """Create a new group."""

        context = restcomm.extract_context_from_environ()

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _("Request body decoding error"))

        if not payload:
            pecan.abort(400, _("Body required"))
        group_name = payload.get("group").get("name")

        if not group_name:
            pecan.abort(400, _("Group name required"))

        try:
            # Insert the group into DB tables
            group_ref = db_api.group_create(context, payload)
            response.status = 201
            return group_ref

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to create group"))

    @index.when(method="PUT", template="json")
    def put(self, group_ref=None):
        """Update a existing group."""

        context = restcomm.extract_context_from_environ()

        if group_ref is None:
            pecan.abort(400, _("Group ID required"))

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _("Request body decoding error"))

        if not payload:
            pecan.abort(400, _("Body required"))

        try:
            # Update the group in DB tables
            return db_api.group_update(context, group_ref, payload)

        except exceptions.GroupNotFound as e:
            pecan.abort(404, _("Group not found: %s") % e)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to update group"))
