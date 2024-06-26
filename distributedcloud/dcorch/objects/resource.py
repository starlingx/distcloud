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

"""Resource object."""

from oslo_versionedobjects import base as ovo_base
from oslo_versionedobjects import fields as ovo_fields

from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.objects import base


@base.OrchestratorObjectRegistry.register
class Resource(base.OrchestratorObject, base.VersionedObjectDictCompat):
    """DC Orchestrator subcloud object."""

    fields = {
        "id": ovo_fields.IntegerField(),
        "uuid": ovo_fields.UUIDField(),
        "resource_type": ovo_fields.StringField(),
        "master_id": ovo_fields.StringField(),
    }

    def create(self):
        if self.obj_attr_is_set("id"):
            raise exceptions.ObjectActionError(
                action="create", reason="already created"
            )
        updates = self.obj_get_changes()
        try:
            resource_type = updates.pop("resource_type")
        except KeyError:
            raise exceptions.ObjectActionError(
                action="create",
                reason="cannot create a Resource object without a " "resource_type set",
            )

        db_resource = db_api.resource_create(self._context, resource_type, updates)
        return self._from_db_object(self._context, self, db_resource)

    @classmethod
    def get_by_type_and_master_id(cls, context, resource_type, master_id):
        db_resource = db_api.resource_get_by_type_and_master_id(
            context, resource_type, master_id
        )
        return cls._from_db_object(context, cls(), db_resource)

    @classmethod
    def get_by_id(cls, context, id):
        db_resource = db_api.resource_get_by_id(context, id)
        return cls._from_db_object(context, cls(), db_resource)

    def delete(self):
        db_api.resource_delete(
            self._context, self.resource_type, self.master_id  # pylint: disable=E1101
        )  # pylint: disable=E1101

    def save(self):
        updates = self.obj_get_changes()
        updates.pop("id", None)
        updates.pop("uuid", None)
        db_resource = db_api.resource_update(
            self._context, self.id, updates  # pylint: disable=E1101
        )
        self._from_db_object(self._context, self, db_resource)
        self.obj_reset_changes()


@base.OrchestratorObjectRegistry.register
class ResourceList(ovo_base.ObjectListBase, base.OrchestratorObject):
    """DC Orchestrator resource list object."""

    VERSION = "1.1"

    fields = {
        "objects": ovo_fields.ListOfObjectsField("Resource"),
    }

    @classmethod
    def get_all(cls, context, resource_type=None):
        resources = db_api.resource_get_all(context, resource_type)
        return ovo_base.obj_make_list(context, cls(context), Resource, resources)
