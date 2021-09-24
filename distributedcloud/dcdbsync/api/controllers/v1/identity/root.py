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
# Copyright (c) 2019-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_config import cfg
from oslo_log import log as logging

import pecan

from dcdbsync.api.controllers.v1.identity import identity
from dcdbsync.api.controllers.v1.identity import project
from dcdbsync.api.controllers.v1.identity import role
from dcdbsync.api.controllers.v1.identity import token_revoke_event

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class IdentityController(object):

    def _get_resource_controller(self, remainder):

        if not remainder:
            pecan.abort(404)
            return

        res_controllers = dict()
        res_controllers["users"] = identity.UsersController
        res_controllers["groups"] = identity.GroupsController
        res_controllers["projects"] = project.ProjectsController
        res_controllers["roles"] = role.RolesController
        res_controllers["token-revocation-events"] = \
            token_revoke_event.RevokeEventsController

        for name, ctrl in res_controllers.items():
            setattr(self, name, ctrl)

        resource = remainder[0]
        if resource not in res_controllers:
            pecan.abort(404)
            return

        remainder = remainder[1:]
        return res_controllers[resource](), remainder

    @pecan.expose()
    def _lookup(self, *remainder):
        return self._get_resource_controller(remainder)
