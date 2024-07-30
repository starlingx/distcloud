# Copyright (c) 2020-2021, 2024 Wind River Systems, Inc.
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

from oslo_db import exception as db_exception

from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.db import api
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests import base

get_engine = api.get_engine


class DBAPISubcloudAlarm(base.DCManagerTestCase):

    @staticmethod
    def create_subcloud_alarms(ctxt, name):
        values = {
            "critical_alarms": -1,
            "major_alarms": -1,
            "minor_alarms": -1,
            "warnings": -1,
            "cloud_status": consts.ALARMS_DISABLED,
        }
        return db_api.subcloud_alarms_create(ctxt, name, values)

    def setUp(self):
        super(DBAPISubcloudAlarm, self).setUp()
        # calling setUp for the superclass sets up the DB and context

    def test_subcloud_alarms_create(self):
        result = self.create_subcloud_alarms(self.ctx, "subcloud1")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "subcloud1")
        self.assertEqual(result["cloud_status"], "disabled")

    def test_subcloud_alarms_create_duplicate(self):
        result = self.create_subcloud_alarms(self.ctx, "subcloud1")
        self.assertIsNotNone(result)
        self.assertRaises(
            db_exception.DBDuplicateEntry,
            self.create_subcloud_alarms,
            self.ctx,
            "subcloud1",
        )

    def test_subcloud_alarms_get(self):
        result = self.create_subcloud_alarms(self.ctx, "subcloud1")
        self.assertIsNotNone(result)
        subcloud = db_api.subcloud_alarms_get(self.ctx, "subcloud1")
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud["name"], "subcloud1")

    def test_subcloud_alarms_get_not_found(self):
        result = self.create_subcloud_alarms(self.ctx, "subcloud1")
        self.assertIsNotNone(result)
        self.assertRaises(
            exception.SubcloudNameNotFound,
            db_api.subcloud_alarms_get,
            self.ctx,
            "subcloud2",
        )

    def test_subcloud_alarms_get_all(self):
        result = self.create_subcloud_alarms(self.ctx, "subcloud1")
        self.assertIsNotNone(result)
        result = self.create_subcloud_alarms(self.ctx, "subcloud2")
        self.assertIsNotNone(result)
        subclouds = db_api.subcloud_alarms_get_all(self.ctx)
        self.assertEqual(len(subclouds), 2)
        self.assertEqual(subclouds[0]["name"], "subcloud2")
        self.assertEqual(subclouds[1]["name"], "subcloud1")

    def test_subcloud_alarms_get_one(self):
        result = self.create_subcloud_alarms(self.ctx, "subcloud1")
        self.assertIsNotNone(result)
        result = self.create_subcloud_alarms(self.ctx, "subcloud2")
        self.assertIsNotNone(result)
        subclouds = db_api.subcloud_alarms_get_all(self.ctx, "subcloud1")
        self.assertEqual(subclouds[0]["name"], "subcloud1")

    def test_subcloud_alarms_update(self):
        result = self.create_subcloud_alarms(self.ctx, "subcloud1")
        self.assertIsNotNone(result)
        values = {
            "critical_alarms": 0,
            "major_alarms": 1,
            "minor_alarms": 2,
            "warnings": 3,
            "cloud_status": consts.ALARM_DEGRADED_STATUS,
        }
        result = db_api.subcloud_alarms_update(self.ctx, "subcloud1", values)
        self.assertIsNotNone(result)
        self.assertEqual(result["major_alarms"], 1)
        subcloud = db_api.subcloud_alarms_get(self.ctx, "subcloud1")
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud["major_alarms"], 1)

    def test_subcloud_alarms_delete(self):
        result = self.create_subcloud_alarms(self.ctx, "subcloud1")
        self.assertIsNotNone(result)
        db_api.subcloud_alarms_delete(self.ctx, "subcloud1")
        subclouds = db_api.subcloud_alarms_get_all(self.ctx)
        self.assertEqual(len(subclouds), 0)
