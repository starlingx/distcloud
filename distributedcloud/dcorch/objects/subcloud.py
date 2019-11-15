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

"""Subcloud object."""

from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.objects import base
from oslo_versionedobjects import base as ovo_base
from oslo_versionedobjects import fields


@base.OrchestratorObjectRegistry.register
class Subcloud(base.OrchestratorObject, base.VersionedObjectDictCompat):
    """DC Orchestrator subcloud object."""

    fields = {
        'id': fields.IntegerField(),
        'uuid': fields.UUIDField(),
        'region_name': fields.StringField(),
        'software_version': fields.StringField(),
        'management_state': fields.StringField(nullable=True),
        'availability_status': fields.StringField(),
        'capabilities': fields.DictOfListOfStringsField(),
    }

    def create(self):
        if self.obj_attr_is_set('id'):
            raise exceptions.ObjectActionError(action='create',
                                               reason='already created')
        updates = self.obj_get_changes()
        try:
            region_name = updates.pop('region_name')
        except KeyError:
            raise exceptions.ObjectActionError(
                action="create",
                reason="cannot create a Subcloud object without a "
                       "region_name set")
        # create entry into alarm summary table, we will get real values later
        alarm_updates = {'critical_alarms': -1,
                         'major_alarms': -1,
                         'minor_alarms': -1,
                         'warnings': -1,
                         'cloud_status': consts.ALARMS_DISABLED}
        db_api.subcloud_alarms_create(self._context, region_name,
                                      alarm_updates)
        db_subcloud = db_api.subcloud_create(
            self._context, region_name, updates)
        return self._from_db_object(self._context, self, db_subcloud)

    @classmethod
    def get_by_name(cls, context, subcloud_name):
        db_subcloud = db_api.subcloud_get(context, subcloud_name)
        return cls._from_db_object(context, cls(), db_subcloud)

    def save(self):
        updates = self.obj_get_changes()
        updates.pop('id', None)
        updates.pop('uuid', None)
        db_subcloud = db_api.subcloud_update(self._context, self.region_name,
                                             updates)
        self._from_db_object(self._context, self, db_subcloud)
        self.obj_reset_changes()

    def delete(self):
        # TODO(cfriesen): fix up to use delete cascade
        # delete the associated sync requests
        db_api.orch_request_delete_by_subcloud(self._context, self.region_name)
        # delete the associated alarm entry
        db_api.subcloud_alarms_delete(self._context, self.region_name)
        db_api.subcloud_delete(self._context, self.region_name)


@base.OrchestratorObjectRegistry.register
class SubcloudList(ovo_base.ObjectListBase, base.OrchestratorObject):
    """DC Orchestrator subcloud list object."""
    VERSION = '1.1'

    fields = {
        'objects': fields.ListOfObjectsField('Subcloud'),
    }

    @classmethod
    def get_all(cls, context):
        subclouds = db_api.subcloud_get_all(context)
        return ovo_base.obj_make_list(
            context, cls(context), Subcloud, subclouds)
