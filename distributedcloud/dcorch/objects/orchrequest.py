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

"""OrchRequest object."""

from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.objects import base
from dcorch.objects import orchjob
from oslo_versionedobjects import base as ovo_base
from oslo_versionedobjects import fields


@base.OrchestratorObjectRegistry.register
class OrchRequest(base.OrchestratorObject, base.VersionedObjectDictCompat):
    """DC Orchestrator orchestration request object."""

    fields = {
        'id': fields.IntegerField(),
        'uuid': fields.UUIDField(),
        'state': fields.StringField(),
        'try_count': fields.IntegerField(),
        'api_version': fields.StringField(nullable=True),
        'target_region_name': fields.StringField(),
        'orch_job_id': fields.IntegerField(),
        'orch_job': fields.ObjectField('OrchJob')
    }

    def create(self):
        if self.obj_attr_is_set('id'):
            raise exceptions.ObjectActionError(action='create',
                                               reason='already created')
        updates = self.obj_get_changes()
        try:
            orch_job_id = updates.pop('orch_job_id')
        except KeyError:
            raise exceptions.ObjectActionError(
                action="create",
                reason="cannot create a Subcloud object without a "
                       "orch_job_id set")

        updates = self.obj_get_changes()
        try:
            target_region_name = updates.pop('target_region_name')
        except KeyError:
            raise exceptions.ObjectActionError(
                action="create",
                reason="cannot create a Subcloud object without a "
                       "target_region_name set")

        db_orch_request = db_api.orch_request_create(
            self._context, orch_job_id, target_region_name, updates)
        return self._from_db_object(self._context, self, db_orch_request)

    @staticmethod
    def _from_db_object(context, obj, db_obj):
        # This call to _as_dict() can't be the proper way to do it,
        # but I couldn't figure out the "correct" method.
        db_orch_request = db_obj._as_dict()
        # When first creating the request, the db_obj won't have
        # orch_job set.
        if 'orch_job' in db_orch_request:
            orch_job = orchjob.OrchJob._from_db_object(
                context, orchjob.OrchJob(), db_orch_request['orch_job'])
        else:
            orch_job = orchjob.OrchJob.get_by_id(
                context, db_orch_request['orch_job_id'])
        db_orch_request['orch_job'] = orch_job
        return super(obj.__class__, obj)._from_db_object(context, obj,
                                                         db_orch_request)

    @classmethod
    def get_by_id(cls, context, id):
        db_orch_request = db_api.orch_request_get(context, id)
        return cls._from_db_object(context, cls(), db_orch_request)

    def save(self):
        updates = self.obj_get_changes()
        updates.pop('id', None)
        updates.pop('uuid', None)
        db_orch_request = db_api.orch_request_update(
            self._context, self.id, updates)
        self._from_db_object(self._context, self, db_orch_request)
        self.obj_reset_changes()

    def delete(self):
        db_api.orch_request_destroy(self._context, self.id)


@base.OrchestratorObjectRegistry.register
class OrchRequestList(ovo_base.ObjectListBase, base.OrchestratorObject):
    """DC Orchestrator orchestration request list object."""
    VERSION = '1.1'

    fields = {
        'objects': fields.ListOfObjectsField('OrchRequest'),
    }

    @classmethod
    def get_by_attrs(cls, context, endpoint_type, resource_type=None,
                     target_region_name=None, states=None):
        orch_reqs = db_api.orch_request_get_by_attrs(
            context, endpoint_type, resource_type=resource_type,
            target_region_name=target_region_name, states=states)
        return ovo_base.obj_make_list(
            context, cls(context), OrchRequest, orch_reqs)
