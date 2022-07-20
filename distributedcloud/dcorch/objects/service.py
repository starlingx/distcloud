# Copyright (c) 2015 Ericsson AB.
# Copyright (c) 2020-2022 Wind River Systems, Inc.
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

"""Service object."""

from dcorch.db import api as db_api
from dcorch.objects import base
from oslo_versionedobjects import fields as ovo_fields


@base.OrchestratorObjectRegistry.register
class Service(base.OrchestratorObject, base.VersionedObjectDictCompat):
    """DC Orchestrator service object."""

    fields = {
        'id': ovo_fields.UUIDField(),
        'host': ovo_fields.StringField(),
        'binary': ovo_fields.StringField(),
        'topic': ovo_fields.StringField(),
        'disabled': ovo_fields.BooleanField(),
        'disabled_reason': ovo_fields.StringField(nullable=True),
        'created_at': ovo_fields.DateTimeField(),
        'updated_at': ovo_fields.DateTimeField(),
        'deleted_at': ovo_fields.DateTimeField(nullable=True),
        'deleted': ovo_fields.IntegerField(nullable=True),
    }

    @classmethod
    def create(cls, context, service_id, host=None, binary=None, topic=None):
        obj = db_api.service_create(context, service_id=service_id, host=host,
                                    binary=binary, topic=topic)
        return cls._from_db_object(context, cls(context), obj)

    @classmethod
    def get(cls, context, service_id):
        obj = db_api.service_get(context, service_id)
        return cls._from_db_object(context, cls(), obj)

    @classmethod
    def get_all(cls, context):
        objs = db_api.service_get_all(context)
        return [cls._from_db_object(context, cls(), obj) for obj in objs]

    # A function named update has been defined inside the base class (oslo_versionedobjects)
    # which was defined with different parameters and served a different purpose
    # Pylint was not able to distinguish the two thus raised an warning (W0237) suggesting
    # undesired parameter name change. Added suppress to ignore this check
    # Since alarm W0237 was not introduced until pylint 2.1x, the CentOS pylint (running 2.3) will
    # raise an alarm (E0012) on W0237 suggesting it is invalid, Another suppress is added for E0012
    @classmethod
    def update(cls, context, obj_id, values=None):  # pylint: disable=E0012,W0237
        obj = db_api.service_update(context, obj_id, values=values)
        return cls._from_db_object(context, cls(), obj)

    @classmethod
    def delete(cls, context, obj_id):
        db_api.service_delete(context, obj_id)
