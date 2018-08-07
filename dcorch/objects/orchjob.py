# Copyright (c) 2015 Ericsson AB.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""OrchJob object."""

from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.objects import base
from oslo_versionedobjects import fields


@base.OrchestratorObjectRegistry.register
class OrchJob(base.OrchestratorObject, base.VersionedObjectDictCompat):
    """DC Orchestrator orchestration job object."""

    fields = {
        'id': fields.IntegerField(),
        'uuid': fields.UUIDField(),
        'user_id': fields.StringField(),
        'project_id': fields.StringField(),
        'endpoint_type': fields.StringField(),
        'source_resource_id': fields.StringField(),  # resource master_id
        'operation_type': fields.StringField(),
        'resource_id': fields.IntegerField(),
        'resource_info': fields.StringField(nullable=True),
    }

    def create(self):
        if self.obj_attr_is_set('id'):
            raise exceptions.ObjectActionError(action='create',
                                               reason='already created')
        updates = self.obj_get_changes()
        try:
            resource_id = updates.pop('resource_id')
        except KeyError:
            raise exceptions.ObjectActionError(
                action="create",
                reason="cannot create a Subcloud object without a "
                       "resource_id set")

        updates = self.obj_get_changes()
        try:
            endpoint_type = updates.pop('endpoint_type')
        except KeyError:
            raise exceptions.ObjectActionError(
                action="create",
                reason="cannot create a Subcloud object without a "
                       "endpoint_type set")

        updates = self.obj_get_changes()
        try:
            operation_type = updates.pop('operation_type')
        except KeyError:
            raise exceptions.ObjectActionError(
                action="create",
                reason="cannot create a Subcloud object without a "
                       "operation_type set")

        db_orch_job = db_api.orch_job_create(
            self._context, resource_id, endpoint_type,
            operation_type, updates)
        return self._from_db_object(self._context, self, db_orch_job)

    @classmethod
    def get_by_id(cls, context, id):
        db_orch_job = db_api.orch_job_get(context, id)
        return cls._from_db_object(context, cls(), db_orch_job)

    def save(self):
        updates = self.obj_get_changes()
        updates.pop('id', None)
        updates.pop('uuid', None)
        db_orch_job = db_api.orch_job_update(self._context, self.id, updates)
        self._from_db_object(self._context, self, db_orch_job)
        self.obj_reset_changes()

    def delete(self):
        db_api.orch_job_delete(self._context, self.id)
