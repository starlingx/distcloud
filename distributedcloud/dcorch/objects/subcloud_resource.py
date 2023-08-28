# Copyright (c) 2015 Ericsson AB.
# Copyright (c) 2024 Wind River Systems, Inc.
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

"""SubcloudResource object."""

from oslo_versionedobjects import base as ovo_base
from oslo_versionedobjects import fields as ovo_fields

from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.objects import base


# pylint: disable=no-member
@base.OrchestratorObjectRegistry.register
class SubcloudResource(base.OrchestratorObject,
                       base.VersionedObjectDictCompat):
    """DC Orchestrator subcloud object."""

    fields = {
        'id': ovo_fields.IntegerField(),
        'uuid': ovo_fields.UUIDField(),
        'shared_config_state': ovo_fields.StringField(),
        'subcloud_resource_id': ovo_fields.StringField(),
        'resource_id': ovo_fields.IntegerField(),
        'subcloud_id': ovo_fields.IntegerField(),
    }

    def create(self):
        if self.obj_attr_is_set('id'):
            raise exceptions.ObjectActionError(action='create',
                                               reason='already created')
        updates = self.obj_get_changes()
        if 'subcloud_resource_id' not in updates:
            raise exceptions.ObjectActionError(
                action="create",
                reason="cannot create a SubcloudResource object without a "
                       "subcloud_resource_id")

        resource_id = updates.pop('resource_id')
        subcloud_id = updates.pop('subcloud_id')

        db_subcloud_resource = db_api.subcloud_resource_create(
            self._context, subcloud_id, resource_id, updates)
        return self._from_db_object(self._context, self, db_subcloud_resource)

    def is_managed(self):
        return self.shared_config_state == consts.SHARED_CONFIG_STATE_MANAGED

    @classmethod
    def get_by_id(cls, context, id):
        db_subcloud_resource = db_api.subcloud_resource_get(context, id)
        return cls._from_db_object(context, cls(), db_subcloud_resource)

    @classmethod
    def get_by_resource_and_subcloud(cls, context, res_id, subcloud_id):
        db_subcloud_resource = \
            db_api.subcloud_resource_get_by_resource_and_subcloud(
                context, res_id, subcloud_id)
        return cls._from_db_object(context, cls(), db_subcloud_resource)

    def save(self):
        updates = self.obj_get_changes()
        updates.pop('id', None)
        updates.pop('uuid', None)
        updates.pop('resource', None)
        updates.pop('subcloud', None)
        db_subcloud = db_api.subcloud_resource_update(
            self._context,
            self.id,  # pylint: disable=E1101
            updates)
        self._from_db_object(self._context, self, db_subcloud)
        self.obj_reset_changes()

    def delete(self):
        db_api.subcloud_resource_delete(self._context,
                                        self.id)  # pylint: disable=E1101


@base.OrchestratorObjectRegistry.register
class SubcloudResourceList(ovo_base.ObjectListBase, base.OrchestratorObject):
    """DC Orchestrator subcloud list object."""
    VERSION = '1.1'

    fields = {
        'objects': ovo_fields.ListOfObjectsField('SubcloudResource'),
    }

    @classmethod
    def get_by_resource_id(cls, context, resource_id):
        subcloud_resources = db_api.subcloud_resources_get_by_resource(
            context, resource_id)
        return ovo_base.obj_make_list(
            context, cls(context), SubcloudResource, subcloud_resources)
