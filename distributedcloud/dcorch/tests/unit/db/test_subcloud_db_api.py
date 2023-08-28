# Copyright (c) 2015 Ericsson AB
# Copyright (c) 2017-2022, 2024 Wind River Systems, Inc.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
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

import sqlalchemy

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_db import options

from dccommon import consts as dccommon_consts
from dcorch.common import config
from dcorch.common import exceptions
from dcorch.db import api
from dcorch.db.sqlalchemy import api as db_api
from dcorch.tests import base
from dcorch.tests import utils

config.register_options()
get_engine = api.get_engine


class DBAPISubcloudTest(base.OrchestratorTestCase):
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
    def create_subcloud(ctxt, region_name, **kwargs):
        values = {}
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, region_name, values)

    def create_default_subcloud(self, ctxt):
        region_name = 'RegionOne'
        software_version = '17.07'
        availability_status = dccommon_consts.AVAILABILITY_ONLINE
        subcloud = self.create_subcloud(
            ctxt, region_name,
            software_version=software_version,
            availability_status=availability_status)
        self.assertIsNotNone(subcloud)
        return subcloud

    def setUp(self):
        super(DBAPISubcloudTest, self).setUp()

        self.setup_dummy_db()
        self.addCleanup(self.reset_dummy_db)
        self.ctx = utils.dummy_context()

    def test_create_subcloud(self):
        subcloud = self.create_default_subcloud(self.ctx)

        asubcloud = db_api.subcloud_get(self.ctx, subcloud.region_name)
        self.assertIsNotNone(asubcloud)
        self.assertEqual(subcloud.software_version, asubcloud.software_version)

    def test_update_subcloud(self):
        subcloud = self.create_default_subcloud(self.ctx)

        availability_status_update = dccommon_consts.AVAILABILITY_OFFLINE
        software_version_update = subcloud.software_version + '1'
        values = {'availability_status': availability_status_update,
                  'software_version': software_version_update}
        updated = db_api.subcloud_update(self.ctx, subcloud.region_name,
                                         values)
        self.assertIsNotNone(updated)

        updated_subcloud = db_api.subcloud_get(self.ctx, subcloud.region_name)
        self.assertEqual(availability_status_update,
                         updated_subcloud.availability_status)
        self.assertEqual(software_version_update,
                         updated_subcloud.software_version)

    def test_delete_subcloud(self):
        subcloud = self.create_default_subcloud(self.ctx)

        db_api.subcloud_delete(self.ctx, subcloud.region_name)

        self.assertRaises(exceptions.SubcloudNotFound,
                          db_api.subcloud_get,
                          self.ctx, subcloud.region_name)

    def test_delete_all_subcloud(self):
        region_names = ['RegionOne', 'RegionTwo']
        software_version = '17.07'
        availability_status = dccommon_consts.AVAILABILITY_ONLINE

        for region_name in region_names:
            subcloud = self.create_subcloud(
                self.ctx, region_name,
                software_version=software_version,
                availability_status=availability_status)
            self.assertIsNotNone(subcloud)

            db_api.subcloud_delete(self.ctx, region_name)

        for region_name in region_names:
            self.assertRaises(exceptions.SubcloudNotFound,
                              db_api.subcloud_get,
                              self.ctx, region_name)

    def test_subcloud_get_by_region_name(self):
        subcloud = self.create_default_subcloud(self.ctx)

        by_region_names = db_api.subcloud_get_all(
            self.ctx,
            region_name=subcloud.region_name)
        self.assertIsNotNone(by_region_names)
        for by_region_name in by_region_names:
            self.assertEqual(subcloud.region_name, by_region_name.region_name)

    def test_subcloud_get_by_administrative_and_availability_status(self):
        subcloud = self.create_default_subcloud(self.ctx)

        by_statuses = db_api.subcloud_get_all(
            self.ctx,
            management_state=subcloud.management_state,
            availability_status=subcloud.availability_status)
        self.assertIsNotNone(by_statuses)

        for by_status in by_statuses:
            self.assertEqual(subcloud.management_state,
                             by_status.management_state)
            self.assertEqual(subcloud.availability_status,
                             by_status.availability_status)

    def test_subcloud_get_by_availability_status(self):
        region_names = ['RegionOne', 'RegionTwo']
        software_version = '17.07'
        availability_status = dccommon_consts.AVAILABILITY_ONLINE
        for region_name in region_names:
            subcloud = self.create_subcloud(
                self.ctx, region_name,
                software_version=software_version,
                availability_status=availability_status)
            self.assertIsNotNone(subcloud)

        region_names = ['RegionThree', 'RegionFour']
        software_version = '17.07'
        availability_status = dccommon_consts.AVAILABILITY_OFFLINE
        for region_name in region_names:
            subcloud = self.create_subcloud(
                self.ctx, region_name,
                software_version=software_version,
                availability_status=availability_status)
            self.assertIsNotNone(subcloud)

        by_statuses = db_api.subcloud_get_all(
            self.ctx,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)
        self.assertIsNotNone(by_statuses)

        for by_status in by_statuses:
            self.assertEqual(dccommon_consts.AVAILABILITY_ONLINE,
                             by_status.availability_status)

        by_statuses = db_api.subcloud_get_all(
            self.ctx,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE)
        self.assertIsNotNone(by_statuses)

        for by_status in by_statuses:
            self.assertEqual(dccommon_consts.AVAILABILITY_OFFLINE,
                             by_status.availability_status)

    def test_subcloud_duplicate_region_names(self):
        region_name = 'RegionOne'
        subcloud = self.create_subcloud(self.ctx, region_name)
        self.assertRaises(db_exc.DBDuplicateEntry,
                          self.create_subcloud,
                          self.ctx, subcloud.region_name)
