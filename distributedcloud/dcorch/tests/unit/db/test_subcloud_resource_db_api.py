# Copyright (c) 2017 Ericsson AB
# Copyright (c) 2017-2021, 2024 Wind River Systems, Inc.
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

from oslo_config import cfg
import oslo_db
from oslo_db import options
from oslo_utils import uuidutils
import sqlalchemy

from dcorch.common import config
from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.db import api
from dcorch.db.sqlalchemy import api as db_api
from dcorch.tests import base
from dcorch.tests import utils

config.register_options()
get_engine = api.get_engine
UUID1 = utils.UUID1
UUID2 = utils.UUID2
SUBCLOUD_NAME_REGION_ONE = "RegionOne"


class DBAPISubcloudResourceTest(base.OrchestratorTestCase):
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
        values = {
            'management_state': None,
            'management_ip': '192.168.0.1'
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, region_name, values)

    def create_default_subcloud(self, ctxt):
        region_name = 'RegionOne'
        software_version = '17.07'
        availability_status = 'online'
        subcloud = self.create_subcloud(
            ctxt, region_name,
            software_version=software_version,
            availability_status=availability_status)
        self.assertIsNotNone(subcloud)
        return subcloud

    @staticmethod
    def create_resource(ctxt, resource_type, **kwargs):
        values = {}
        values.update(kwargs)
        return db_api.resource_create(ctxt, resource_type, values)

    @staticmethod
    def create_subcloud_resource(ctxt, subcloud_id, resource_id, **kwargs):
        values = {}
        values.update(kwargs)
        return db_api.subcloud_resource_create(ctxt,
                                               subcloud_id,
                                               resource_id,
                                               values)

    def setUp(self):
        super(DBAPISubcloudResourceTest, self).setUp()

        self.setup_dummy_db()
        self.addCleanup(self.reset_dummy_db)
        self.ctx = utils.dummy_context()

    def test_create_resource(self):
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_USER)
        self.assertIsNotNone(resource)
        self.assertEqual(consts.RESOURCE_TYPE_SYSINV_USER,
                         resource.resource_type)
        created_resource = db_api.resource_get_all(
            self.ctx,
            consts.RESOURCE_TYPE_SYSINV_USER)
        self.assertEqual(consts.RESOURCE_TYPE_SYSINV_USER,
                         created_resource[0].get('resource_type'))

    def test_primary_key_subcloud(self):
        self.create_subcloud(self.ctx, SUBCLOUD_NAME_REGION_ONE)
        self.assertRaises(oslo_db.exception.DBDuplicateEntry,
                          self.create_subcloud, self.ctx,
                          SUBCLOUD_NAME_REGION_ONE)

    def test_unique_key_resource_uuid(self):
        created_resource = self.create_resource(
            self.ctx,
            consts.RESOURCE_TYPE_SYSINV_USER)
        self.assertRaises(oslo_db.exception.DBDuplicateEntry,
                          self.create_resource, self.ctx,
                          consts.RESOURCE_TYPE_SYSINV_USER,
                          uuid=created_resource.uuid)

    def skip_test_resource_update(self):
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_USER)
        self.assertIsNotNone(resource)
        master_id = resource.master_id
        values = {'master_id': master_id}
        db_api.resource_update(self.ctx,
                               consts.RESOURCE_TYPE_SYSINV_USER,
                               values)
        gresource = db_api.resource_get_by_id(self.ctx, resource.id)
        self.assertEqual(master_id,
                         gresource.get('master_id'))

    def test_resource_get_all(self):
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_USER)
        self.assertIsNotNone(resource)
        query = db_api.resource_get_all(self.ctx)
        self.assertEqual(query[0].get('resource_type'), resource.resource_type)

    def skip_test_update_invalid_resource(self):
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_USER)
        self.assertIsNotNone(resource)
        # master_uuid = uuidutils.generate_uuid()
        master_id = resource.master_id
        values = {'master_id': master_id}
        self.assertRaises(exceptions.ResourceNotFound,
                          db_api.resource_update,
                          self.ctx,
                          'fake_resource_type',
                          master_id,
                          values)

    def test_subcloud_resource_create(self):
        subcloud = self.create_subcloud(self.ctx, SUBCLOUD_NAME_REGION_ONE)
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_USER)
        subcloud_resource_uuid = uuidutils.generate_uuid()
        shared_config_state = consts.SHARED_CONFIG_STATE_UNMANAGED
        subcloud_resource_create = self.create_subcloud_resource(
            self.ctx, subcloud.id, resource.id,
            shared_config_state=shared_config_state,
            subcloud_resource_uuid=subcloud_resource_uuid)
        self.assertIsNotNone(subcloud_resource_create)
        self.assertEqual(consts.SHARED_CONFIG_STATE_UNMANAGED,
                         subcloud_resource_create.shared_config_state)

    def test_subcloud_resource_update(self):
        subcloud = self.create_subcloud(self.ctx, SUBCLOUD_NAME_REGION_ONE)
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_USER)
        subcloud_resource_uuid = uuidutils.generate_uuid()
        shared_config_state = consts.SHARED_CONFIG_STATE_UNMANAGED
        subcloud_resource_create = self.create_subcloud_resource(
            self.ctx, subcloud.id, resource.id,
            shared_config_state=shared_config_state,
            subcloud_resource_uuid=subcloud_resource_uuid)
        self.assertIsNotNone(subcloud_resource_create)

        values = {'shared_config_state': consts.SHARED_CONFIG_STATE_MANAGED}
        db_api.subcloud_resource_update(
            self.ctx, subcloud_resource_create.id,
            values)

        subcloud_resources = db_api.subcloud_resources_get_by_resource(
            self.ctx,
            resource.uuid)
        self.assertEqual(consts.SHARED_CONFIG_STATE_MANAGED,
                         subcloud_resources[0].get('shared_config_state'))

    def test_foreign_keys(self):
        subcloud = self.create_subcloud(self.ctx, SUBCLOUD_NAME_REGION_ONE)
        self.assertIsNotNone(subcloud)
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_USER)
        self.assertIsNotNone(resource)

        subcloud_resource_uuid = uuidutils.generate_uuid()
        shared_config_state = consts.SHARED_CONFIG_STATE_UNMANAGED
        subcloud_resource_create = self.create_subcloud_resource(
            self.ctx, subcloud.id, resource.id,
            shared_config_state=shared_config_state,
            subcloud_resource_uuid=subcloud_resource_uuid)

        self.assertIsNotNone(subcloud_resource_create)
        self.assertEqual(subcloud.id, subcloud_resource_create.subcloud_id)
        self.assertEqual(resource.id, subcloud_resource_create.resource_id)

    def test_delete_subcloud_resource(self):
        subcloud = self.create_subcloud(self.ctx, SUBCLOUD_NAME_REGION_ONE)
        self.assertIsNotNone(subcloud)
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_USER)
        self.assertIsNotNone(resource)

        subcloud_resource_uuid = uuidutils.generate_uuid()
        shared_config_state = consts.SHARED_CONFIG_STATE_UNMANAGED
        subcloud_resource = self.create_subcloud_resource(
            self.ctx, subcloud.id, resource.id,
            shared_config_state=shared_config_state,
            subcloud_resource_uuid=subcloud_resource_uuid)

        db_api.subcloud_resource_delete(self.ctx, subcloud_resource.uuid)
        subcloud_resources = db_api.subcloud_resources_get_all(self.ctx)
        self.assertEqual(0, len(subcloud_resources))

    # def test_composite_primary_key(self):
    #     job = self.create_subcloud(self.ctx, SUBCLOUD_NAME_REGION_ONE)
    #     self.create_subcloud_resource(
    #         self.ctx, job=job, region='Fake_region',
    #         source_region='Fake_region2', resource='fake_key',
    #         resource_type='keypair')
    #     self.assertRaises(oslo_db.exception.DBDuplicateEntry,
    #                       self.create_subcloud_resource, self.ctx, job=job,
    #                       region='Fake_region', source_region='Fake_region2',
    #                       resource='fake_key', resource_type='keypair')
