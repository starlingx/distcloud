# Copyright (c) 2017 Ericsson AB
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

import datetime
import oslo_db
import sqlalchemy

from oslo_config import cfg
from oslo_db import options
from oslo_utils import timeutils
from oslo_utils import uuidutils

from dcorch.common import config
from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.db import api as api
from dcorch.db.sqlalchemy import api as db_api
from dcorch.tests import base
from dcorch.tests import utils

config.register_options()
get_engine = api.get_engine
SUBCLOUD_NAME_REGION_ONE = "RegionOne"


class DBAPIOrchRequestTest(base.OrchestratorTestCase):
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
    def create_orch_job(ctxt, resource_id, endpoint_type,
                        operation_type, values=None):
        if values is None:
            values = {}
        endpoint_type = endpoint_type
        operation_type = operation_type
        values = values
        orch_job = db_api.orch_job_create(ctxt,
                                          resource_id,
                                          endpoint_type,
                                          operation_type,
                                          values)
        return orch_job

    @staticmethod
    def create_subcloud_resource(ctxt, subcloud_id, resource_id, **kwargs):
        values = {}
        values.update(kwargs)
        return db_api.subcloud_resource_create(ctxt,
                                               subcloud_id,
                                               resource_id,
                                               values)

    def setUp(self):
        super(DBAPIOrchRequestTest, self).setUp()

        self.setup_dummy_db()
        self.addCleanup(self.reset_dummy_db)
        self.ctx = utils.dummy_context()

    def test_create_orch_job(self):
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_DNS)
        endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        operation_type = consts.OPERATION_TYPE_PATCH
        orch_job = self.create_orch_job(self.ctx,
                                        resource.id,
                                        endpoint_type,
                                        operation_type)
        self.assertIsNotNone(orch_job)
        self.assertEqual(consts.ENDPOINT_TYPE_PLATFORM,
                         orch_job.endpoint_type)

        created_orch_jobs = db_api.orch_job_get_all(
            self.ctx,
            resource_id=resource.id)
        self.assertEqual(resource.id,
                         created_orch_jobs[0].get('resource_id'))

    def test_primary_key_subcloud(self):
        self.create_subcloud(self.ctx, SUBCLOUD_NAME_REGION_ONE)
        self.assertRaises(oslo_db.exception.DBDuplicateEntry,
                          self.create_subcloud, self.ctx,
                          SUBCLOUD_NAME_REGION_ONE)

    def no_test_unique_key_orch_job_uuid(self):
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_DNS)
        endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        operation_type = consts.OPERATION_TYPE_PATCH
        orch_job = self.create_orch_job(self.ctx,
                                        resource.id,
                                        endpoint_type,
                                        operation_type)
        self.assertIsNotNone(orch_job)

        self.assertRaises(oslo_db.exception.DBDuplicateEntry,
                          self.create_orch_job, self.ctx,
                          resource.id,
                          endpoint_type,
                          operation_type)

    def create_default_resource(self, resource_type):
        resource = self.create_resource(self.ctx,
                                        resource_type)
        return resource

    def create_default_orch_request(self, orch_job_id, target_region_name):
        api_version = 1.0
        values = {'api_version': api_version,
                  'target_region_name': target_region_name}
        orch_request = db_api.orch_request_create(self.ctx,
                                                  orch_job_id,
                                                  target_region_name,
                                                  values)
        return orch_request

    def test_orch_request_update(self):
        resource = self.create_default_resource(
            consts.RESOURCE_TYPE_SYSINV_DNS)
        target_region_name = "RegionOne"

        endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        operation_type = consts.OPERATION_TYPE_PATCH
        values = {}
        orch_job = self.create_orch_job(self.ctx,
                                        resource.id,
                                        endpoint_type,
                                        operation_type,
                                        values)
        orch_request = self.create_default_orch_request(orch_job.id,
                                                        target_region_name)
        self.assertIsNotNone(orch_request)

        orch_job_state = consts.ORCH_REQUEST_STATE_COMPLETED
        try_count = 6
        api_version = "1.0"

        values = {'state': orch_job_state,
                  'try_count': try_count,
                  'api_version': api_version}

        db_api.orch_request_update(self.ctx,
                                   orch_request.uuid,
                                   values)
        gorch_request = db_api.orch_request_get(self.ctx,
                                                orch_request.uuid)
        self.assertEqual(orch_job_state,
                         gorch_request.state)
        self.assertEqual(try_count,
                         gorch_request.try_count)
        self.assertEqual(api_version,
                         gorch_request.api_version)
        self.assertEqual(target_region_name,
                         gorch_request.target_region_name)

    def test_orch_request_get_all(self):
        resource = self.create_default_resource(
            consts.RESOURCE_TYPE_SYSINV_DNS)

        endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        operation_type = consts.OPERATION_TYPE_PATCH
        values = {}
        orch_job = self.create_orch_job(self.ctx,
                                        resource.id,
                                        endpoint_type,
                                        operation_type,
                                        values)

        target_region_name = "RegionOne"
        self.create_default_orch_request(orch_job.id,
                                         target_region_name)
        target_region_name = "RegionTwo"
        self.create_default_orch_request(orch_job.id,
                                         target_region_name)

        orch_requests = db_api.orch_request_get_all(self.ctx)
        self.assertEqual(2, len(orch_requests))

    def test_orch_request_get_by_orch_job(self):
        resource_sysinv = self.create_default_resource(
            consts.RESOURCE_TYPE_SYSINV_DNS)

        endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        operation_type = consts.OPERATION_TYPE_PATCH
        values = {}
        orch_job_sysinv = self.create_orch_job(self.ctx,
                                               resource_sysinv.id,
                                               endpoint_type,
                                               operation_type,
                                               values)
        target_region_name = "RegionOne"
        self.create_default_orch_request(orch_job_sysinv.id,
                                         target_region_name)

        resource_flavor = self.create_default_resource(
            consts.RESOURCE_TYPE_COMPUTE_FLAVOR)

        endpoint_type = consts.ENDPOINT_TYPE_COMPUTE
        operation_type = consts.OPERATION_TYPE_POST
        values = {}
        orch_job_flavor = self.create_orch_job(self.ctx,
                                               resource_flavor.id,
                                               endpoint_type,
                                               operation_type,
                                               values)
        self.create_default_orch_request(orch_job_flavor.id,
                                         target_region_name)

        orch_requests_sysinv = db_api.orch_request_get_all(
            self.ctx,
            orch_job_id=orch_job_sysinv.id)
        orch_requests_flavor = db_api.orch_request_get_all(
            self.ctx,
            orch_job_id=orch_job_flavor.id)

        self.assertEqual(1, len(orch_requests_sysinv))
        self.assertEqual(1, len(orch_requests_flavor))

    def test_orch_request_get_most_recent_failed_request(self):
        orch_requests = self.create_some_failed_orch_requests()
        orts = orch_requests[0].updated_at
        orid = orch_requests[0].id
        for request in orch_requests:
            if request.updated_at > orts:
                orid = request.id

        most_recent = \
            db_api.orch_request_get_most_recent_failed_request(self.ctx)
        self.assertIsNotNone(most_recent)
        self.assertEqual(orid,
                         most_recent.id)

    def test_orch_request_delete_previous_failed_requests(self):
        orch_requests = self.create_some_orch_requests()
        total_count = len(orch_requests)
        failed_count = 0
        for request in orch_requests:
            if request.state == consts.ORCH_REQUEST_STATE_FAILED:
                failed_count += 1

        expected_count = total_count - failed_count
        db_api.orch_request_delete_previous_failed_requests(
            self.ctx, timeutils.utcnow())
        orch_requests = db_api.orch_request_get_all(self.ctx)
        self.assertEqual(expected_count, len(orch_requests))

    def create_some_failed_orch_requests(self):
        # All db apis used in this method have already been verified
        orch_requests = []
        orch_request1 = self.create_default_sysinv_orch_job()
        orch_request2 = self.create_default_sysinv_orch_job()

        values = {'state': consts.ORCH_REQUEST_STATE_FAILED,
                  'try_count': 2}

        db_api.orch_request_update(self.ctx,
                                   orch_request1.uuid,
                                   values)

        db_api.orch_request_update(self.ctx,
                                   orch_request2.uuid,
                                   values)

        orch_requests = db_api.orch_request_get_all(self.ctx)
        return orch_requests

    def create_some_orch_requests(self):
        orch_requests = self.create_some_failed_orch_requests()
        orch_requests.append(self.create_default_sysinv_orch_job())
        return orch_requests

    def create_default_sysinv_orch_job(self):
        resource_sysinv = self.create_default_resource(
            consts.RESOURCE_TYPE_SYSINV_DNS)

        endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        operation_type = consts.OPERATION_TYPE_PATCH
        values = {}
        orch_job_sysinv = self.create_orch_job(self.ctx,
                                               resource_sysinv.id,
                                               endpoint_type,
                                               operation_type,
                                               values)
        target_region_name = "RegionOne"
        orch_request = self.create_default_orch_request(
            orch_job_sysinv.id,
            target_region_name)
        return orch_request

    def test_orch_request_update_invalid(self):
        orch_request = self.create_default_sysinv_orch_job()
        self.assertIsNotNone(orch_request)

        values = {}
        test_uuid = uuidutils.generate_uuid()
        if orch_request.uuid != test_uuid:
            self.assertRaises(exceptions.OrchRequestNotFound,
                              db_api.orch_request_update,
                              self.ctx,
                              test_uuid,
                              values)

    def test_foreign_keys(self):
        subcloud = self.create_subcloud(self.ctx, SUBCLOUD_NAME_REGION_ONE)
        self.assertIsNotNone(subcloud)
        resource = self.create_resource(self.ctx,
                                        consts.RESOURCE_TYPE_SYSINV_DNS)
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

    def test_delete_orch_request(self):
        orch_request = self.create_default_sysinv_orch_job()
        self.assertIsNotNone(orch_request)

        db_api.orch_request_destroy(self.ctx, orch_request.uuid)
        self.assertRaises(exceptions.OrchRequestNotFound,
                          db_api.orch_request_get,
                          self.ctx,
                          orch_request.uuid)

    def skip_test_orch_request_get_by_attrs(self):
        resource_sysinv = self.create_default_resource(
            consts.RESOURCE_TYPE_SYSINV_DNS)

        endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        operation_type = consts.OPERATION_TYPE_PATCH
        values = {}
        orch_job_sysinv = self.create_orch_job(self.ctx,
                                               resource_sysinv.id,
                                               endpoint_type,
                                               operation_type,
                                               values)
        target_region_name = "RegionOne"
        orch_request_sysinv_1 = self.create_default_orch_request(
            orch_job_sysinv.id,
            target_region_name)

        db_api.orch_request_update(self.ctx,
                                   orch_request_sysinv_1.uuid,
                                   {'state':
                                    consts.ORCH_REQUEST_STATE_COMPLETED})

        orch_request_sysinv_2 = self.create_default_orch_request(
            orch_job_sysinv.id,
            target_region_name)

        db_api.orch_request_update(self.ctx,
                                   orch_request_sysinv_2.uuid,
                                   {'state':
                                    consts.ORCH_REQUEST_STATE_IN_PROGRESS})

        resource_flavor = self.create_default_resource(
            consts.RESOURCE_TYPE_COMPUTE_FLAVOR)

        endpoint_type = consts.ENDPOINT_TYPE_COMPUTE
        operation_type = consts.OPERATION_TYPE_POST
        values = {}
        orch_job_flavor = self.create_orch_job(self.ctx,
                                               resource_flavor.id,
                                               endpoint_type,
                                               operation_type,
                                               values)

        orch_request_compute = self.create_default_orch_request(
            orch_job_flavor.id,
            target_region_name)

        attrs_endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        attrs_resource_type = consts.RESOURCE_TYPE_SYSINV_DNS
        orch_requests_attrs_1 = db_api.orch_request_get_by_attrs(
            self.ctx,
            attrs_endpoint_type,
            attrs_resource_type,
            target_region_name=target_region_name,
            states=[consts.ORCH_REQUEST_STATE_IN_PROGRESS])

        self.assertEqual(1, len(orch_requests_attrs_1))

        orch_requests_attrs_2 = db_api.orch_request_get_by_attrs(
            self.ctx,
            attrs_endpoint_type,
            attrs_resource_type,
            target_region_name=target_region_name,
            states=[consts.ORCH_REQUEST_STATE_IN_PROGRESS,
                    consts.ORCH_REQUEST_STATE_COMPLETED])

        self.assertEqual(2, len(orch_requests_attrs_2))

        orch_requests_attrs = db_api.orch_request_get_by_attrs(
            self.ctx,
            consts.ENDPOINT_TYPE_COMPUTE,
            consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
            target_region_name=target_region_name,
            states=consts.ORCH_REQUEST_STATE_NONE)

        self.assertEqual(1, len(orch_requests_attrs))
        self.assertEqual(orch_request_compute.id, orch_requests_attrs[0].id)

    def test_purge_deleted_records(self):
        orch_requests = self.create_some_orch_requests()
        total_count = len(orch_requests)
        soft_deleted_count = 0

        delete_time = timeutils.utcnow() - datetime.timedelta(days=2)
        values = {'deleted': 1,
                  'deleted_at': delete_time}
        for request in orch_requests:
            if request == consts.ORCH_REQUEST_STATE_FAILED:
                db_api.orch_request_update(self.ctx, request.uuid, values)
                soft_deleted_count += 1

        expected_count = total_count - soft_deleted_count
        db_api.purge_deleted_records(self.ctx, 1)
        # As each resource in this unit test has a single orch job which
        # has a single orch request, the number of resources, orch jobs
        # and orch requests after purge must be the same.
        orch_requests = db_api.orch_request_get_all(self.ctx)
        self.assertEqual(expected_count, len(orch_requests))
        orch_jobs = db_api.orch_job_get_all(self.ctx)
        self.assertEqual(expected_count, len(orch_jobs))
        resources = db_api.resource_get_all(self.ctx)
        self.assertEqual(expected_count, len(resources))
