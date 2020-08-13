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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import sqlalchemy

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_db import options

from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.db import api as api
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests import base
from dcmanager.tests import utils

get_engine = api.get_engine


class DBAPISubcloudAlarm(base.DCManagerTestCase):
    def setup_dummy_db(self):
        options.cfg.set_defaults(options.database_opts,
                                 sqlite_synchronous=False)
        options.set_defaults(cfg.CONF, connection="sqlite://")
        engine = get_engine()
        db_api.db_sync(engine)
        engine.connect()

    @staticmethod
    def reset_dummy_db():
        engine = get_engine()
        meta = sqlalchemy.MetaData()
        meta.reflect(bind=engine)

        for table in reversed(meta.sorted_tables):
            if table.name == 'migrate_version':
                continue
            engine.execute(table.delete())

    @staticmethod
    def create_subcloud_alarms(ctxt, name):
        values = {'critical_alarms': -1,
                  'major_alarms': -1,
                  'minor_alarms': -1,
                  'warnings': -1,
                  'cloud_status': consts.ALARMS_DISABLED}
        return db_api.subcloud_alarms_create(ctxt, name, values)

    def setUp(self):
        super(DBAPISubcloudAlarm, self).setUp()

        self.setup_dummy_db()
        self.addCleanup(self.reset_dummy_db)
        self.ctxt = utils.dummy_context()

    def test_subcloud_alarms_create(self):
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud1')
        self.assertIsNotNone(result)
        self.assertEqual(result['name'], 'subcloud1')
        self.assertEqual(result['cloud_status'], 'disabled')

    def test_subcloud_alarms_create_duplicate(self):
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud1')
        self.assertIsNotNone(result)
        self.assertRaises(db_exception.DBDuplicateEntry,
                          self.create_subcloud_alarms,
                          self.ctx, 'subcloud1')

    def test_subcloud_alarms_get(self):
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud1')
        self.assertIsNotNone(result)
        subcloud = db_api.subcloud_alarms_get(self.ctxt, 'subcloud1')
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud['name'], 'subcloud1')

    def test_subcloud_alarms_get_not_found(self):
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud1')
        self.assertIsNotNone(result)
        self.assertRaises(exception.SubcloudNameNotFound,
                          db_api.subcloud_alarms_get,
                          self.ctx, 'subcloud2')

    def test_subcloud_alarms_get_all(self):
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud1')
        self.assertIsNotNone(result)
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud2')
        self.assertIsNotNone(result)
        subclouds = db_api.subcloud_alarms_get_all(self.ctxt)
        self.assertEqual(len(subclouds), 2)
        self.assertEqual(subclouds[0]['name'], 'subcloud2')
        self.assertEqual(subclouds[1]['name'], 'subcloud1')

    def test_subcloud_alarms_get_one(self):
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud1')
        self.assertIsNotNone(result)
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud2')
        self.assertIsNotNone(result)
        subclouds = db_api.subcloud_alarms_get_all(self.ctxt, 'subcloud1')
        self.assertEqual(subclouds[0]['name'], 'subcloud1')

    def test_subcloud_alarms_update(self):
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud1')
        self.assertIsNotNone(result)
        values = {'critical_alarms': 0,
                  'major_alarms': 1,
                  'minor_alarms': 2,
                  'warnings': 3,
                  'cloud_status': consts.ALARM_DEGRADED_STATUS}
        result = db_api.subcloud_alarms_update(self.ctxt, 'subcloud1', values)
        self.assertIsNotNone(result)
        self.assertEqual(result['major_alarms'], 1)
        subcloud = db_api.subcloud_alarms_get(self.ctxt, 'subcloud1')
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud['major_alarms'], 1)

    def test_subcloud_alarms_delete(self):
        result = self.create_subcloud_alarms(self.ctxt, 'subcloud1')
        self.assertIsNotNone(result)
        db_api.subcloud_alarms_delete(self.ctxt, 'subcloud1')
        subclouds = db_api.subcloud_alarms_get_all(self.ctxt)
        self.assertEqual(len(subclouds), 0)
