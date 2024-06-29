# Copyright (c) 2015 Ericsson AB.
# Copyright (c) 2017, 2019, 2021, 2024 Wind River Systems, Inc.
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
#

import mock
from oslo_versionedobjects import fields as obj_fields

from dcmanager.objects import base as obj_base
from dcmanager.tests import base


class TestBaseObject(base.DCManagerTestCase):
    def test_base_class(self):
        obj = obj_base.DCManagerObject()
        self.assertEqual(
            obj_base.DCManagerObject.OBJ_PROJECT_NAMESPACE, obj.OBJ_PROJECT_NAMESPACE
        )
        self.assertEqual(obj_base.DCManagerObject.VERSION, obj.VERSION)

    @mock.patch.object(obj_base.DCManagerObject, "obj_reset_changes")
    def test_from_db_object(self, mock_obj_reset_ch):
        class TestDCManagerObject(
            obj_base.DCManagerObject, obj_base.VersionedObjectDictCompat
        ):
            fields = {
                "key1": obj_fields.StringField(),
                "key2": obj_fields.StringField(),
            }

        obj = TestDCManagerObject()
        context = mock.Mock()
        db_obj = {
            "key1": "value1",
            "key2": "value2",
        }
        res = obj_base.DCManagerObject._from_db_object(context, obj, db_obj)
        self.assertIsNotNone(res)
        self.assertEqual("value1", obj["key1"])
        self.assertEqual("value2", obj["key2"])
        self.assertEqual(obj._context, context)
        mock_obj_reset_ch.assert_called_once_with()

    def test_from_db_object_none(self):
        obj = obj_base.DCManagerObject()
        db_obj = None
        context = mock.Mock()

        res = obj_base.DCManagerObject._from_db_object(context, obj, db_obj)
        self.assertIsNone(res)
