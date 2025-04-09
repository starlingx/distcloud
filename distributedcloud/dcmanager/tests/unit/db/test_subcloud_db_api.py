# Copyright (c) 2015 Ericsson AB
# Copyright (c) 2017-2025 Wind River Systems, Inc.
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

from oslo_db import exception as db_exception
from sqlalchemy.engine import Engine
from sqlalchemy import event

from dccommon import consts as dccommon_consts
from dcmanager.common import config
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.db import api as db_api
from dcmanager.tests import base
from dcmanager.tests import utils

config.register_options()
get_engine = db_api.get_engine


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class DBAPISubcloudTest(base.DCManagerTestCase):
    @staticmethod
    def create_subcloud_static(ctxt, **kwargs):
        values = {
            "name": "subcloud1",
            "description": "This is a subcloud",
            "location": "This is the location of the subcloud",
            "software_version": "10.04",
            "management_subnet": "192.168.101.0/24",
            "management_gateway_ip": "192.168.101.1",
            "management_start_ip": "192.168.101.2",
            "management_end_ip": "192.168.101.50",
            "systemcontroller_gateway_ip": "192.168.204.101",
            "external_oam_subnet_ip_family": "4",
            "deploy_status": "not-deployed",
            "error_description": "No errors present",
            "region_name": base.SUBCLOUD_1["region_name"],
            "openstack_installed": False,
            "group_id": 1,
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, **values)

    @staticmethod
    def create_subcloud(ctxt, data):
        values = {
            "name": data["name"],
            "description": data["description"],
            "location": data["location"],
            "software_version": data["software-version"],
            "management_subnet": data["management_subnet"],
            "management_gateway_ip": data["management_gateway_address"],
            "management_start_ip": data["management_start_address"],
            "management_end_ip": data["management_end_address"],
            "systemcontroller_gateway_ip": data["systemcontroller_gateway_address"],
            "external_oam_subnet_ip_family": "4",
            "deploy_status": "not-deployed",
            "error_description": "No errors present",
            "region_name": data["region_name"],
            "openstack_installed": False,
            "group_id": 1,
        }
        return db_api.subcloud_create(ctxt, **values)

    @staticmethod
    def create_subcloud_status(ctxt, **kwargs):
        values = {
            "subcloud_id": 1,
            "endpoint_type": "sysinv",
        }
        values.update(kwargs)
        return db_api.subcloud_status_create(ctxt, **values)

    @staticmethod
    def create_sw_update_strategy(ctxt, **kwargs):
        values = {
            "type": consts.SW_UPDATE_TYPE_PATCH,
            "state": consts.SW_UPDATE_STATE_INITIAL,
            "subcloud_apply_type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
            "max_parallel_subclouds": 10,
            "stop_on_failure": True,
        }
        values.update(kwargs)
        return db_api.sw_update_strategy_create(ctxt, **values)

    @staticmethod
    def create_strategy_step(ctxt, **kwargs):
        values = {
            "subcloud_id": 1,
            "stage": 1,
            "state": consts.STRATEGY_STATE_INITIAL,
            "details": "The details",
        }
        values.update(kwargs)
        return db_api.strategy_step_create(ctxt, **values)

    def setUp(self):
        super(DBAPISubcloudTest, self).setUp()
        # calling setUp for the superclass sets up the DB and context

    def test_create_subcloud(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        name = fake_subcloud["name"]
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        new_subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertIsNotNone(new_subcloud)
        self.assertEqual(name, new_subcloud.name)

    def test_create_subcloud_duplicate_name(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)
        fake_subcloud2 = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        fake_subcloud2["management-start-ip"] = "2.3.4.6"
        fake_subcloud2["management-end-ip"] = "2.3.4.7"
        self.assertRaises(
            db_exception.DBDuplicateEntry,
            self.create_subcloud,
            self.ctx,
            fake_subcloud2,
        )

    def test_create_multiple_subclouds(self):
        name1 = "testname1"
        region1 = base.SUBCLOUD_1["region_name"]
        name2 = "testname2"
        region2 = base.SUBCLOUD_2["region_name"]
        name3 = "testname3"
        region3 = base.SUBCLOUD_3["region_name"]
        subcloud = self.create_subcloud_static(
            self.ctx, name=name1, region_name=region1
        )
        self.assertIsNotNone(subcloud)

        subcloud2 = self.create_subcloud_static(
            self.ctx,
            name=name2,
            region_name=region2,
            management_start_ip="2.3.4.6",
            management_end_ip="2.3.4.7",
        )
        self.assertIsNotNone(subcloud2)

        subcloud3 = self.create_subcloud_static(
            self.ctx,
            name=name3,
            region_name=region3,
            management_start_ip="3.3.4.6",
            management_end_ip="3.3.4.7",
        )
        self.assertIsNotNone(subcloud3)

        new_subclouds = db_api.subcloud_get_all(self.ctx)
        self.assertIsNotNone(new_subclouds)
        self.assertEqual(3, len(new_subclouds))
        self.assertEqual(name1, new_subclouds[0].name)
        self.assertEqual(1, new_subclouds[0].id)
        self.assertEqual(name2, new_subclouds[1].name)
        self.assertEqual(2, new_subclouds[1].id)
        self.assertEqual(name3, new_subclouds[2].name)
        self.assertEqual(3, new_subclouds[2].id)

    def test_update_subcloud(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        management_state = "testmanagementstate"
        availability_status = "testavailabilitystatus"
        software_version = "testversion"
        admin_subnet = "192.168.102.0/24"
        admin_start_ip = "192.168.102.5"
        admin_end_ip = "192.168.102.49"
        admin_gateway_ip = "192.168.102.1"
        rehomed = True
        updated = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            management_state=management_state,
            availability_status=availability_status,
            software_version=software_version,
            management_subnet=admin_subnet,
            management_start_ip=admin_start_ip,
            management_end_ip=admin_end_ip,
            management_gateway_ip=admin_gateway_ip,
            rehomed=rehomed,
        )
        self.assertIsNotNone(updated)
        self.assertEqual(management_state, updated.management_state)
        self.assertEqual(availability_status, updated.availability_status)
        self.assertEqual(software_version, updated.software_version)
        self.assertEqual(admin_subnet, updated.management_subnet)
        self.assertEqual(admin_start_ip, updated.management_start_ip)
        self.assertEqual(admin_end_ip, updated.management_end_ip)
        self.assertEqual(admin_gateway_ip, updated.management_gateway_ip)
        self.assertEqual(rehomed, updated.rehomed)

        updated_subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertEqual(management_state, updated_subcloud.management_state)
        self.assertEqual(availability_status, updated_subcloud.availability_status)
        self.assertEqual(software_version, updated_subcloud.software_version)
        self.assertEqual(admin_subnet, updated_subcloud.management_subnet)
        self.assertEqual(admin_start_ip, updated_subcloud.management_start_ip)
        self.assertEqual(admin_end_ip, updated_subcloud.management_end_ip)
        self.assertEqual(admin_gateway_ip, updated_subcloud.management_gateway_ip)
        self.assertEqual(rehomed, updated_subcloud.rehomed)

    def test_delete_subcloud(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        db_api.subcloud_destroy(self.ctx, subcloud.id)

        self.assertRaises(
            exceptions.SubcloudNotFound, db_api.subcloud_get, self.ctx, subcloud.id
        )

    def test_subcloud_get_by_name(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        name = fake_subcloud["name"]
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        by_name = db_api.subcloud_get_by_name(self.ctx, name)
        self.assertIsNotNone(by_name)
        self.assertEqual(name, by_name.name)

    def test_subcloud_get_by_non_existing_name(self):
        name = "testname"
        self.assertRaises(
            exceptions.SubcloudNameNotFound,
            db_api.subcloud_get_by_name,
            self.ctx,
            name,
        )

    def test_create_subcloud_status(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        endpoint_type = "testendpoint"
        subcloud_status = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type
        )
        self.assertIsNotNone(subcloud_status)

        new_subcloud_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint_type
        )
        self.assertIsNotNone(new_subcloud_status)
        self.assertEqual(endpoint_type, new_subcloud_status.endpoint_type)
        self.assertEqual(
            dccommon_consts.SYNC_STATUS_UNKNOWN, new_subcloud_status.sync_status
        )

    def test_create_multiple_subcloud_statuses(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        default_subcloud_statuses = db_api.subcloud_status_get_all(
            self.ctx, subcloud.id
        )
        num_default_subcloud_statuses = len(default_subcloud_statuses)
        self.assertEqual(
            num_default_subcloud_statuses, len(dccommon_consts.AUDIT_TYPES_LIST)
        )

        endpoint_type1 = "testendpoint1"
        subcloud_status1 = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type1
        )
        self.assertIsNotNone(subcloud_status1)

        endpoint_type2 = "testendpoint2"
        subcloud_status2 = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type2
        )
        self.assertIsNotNone(subcloud_status2)

        endpoint_type3 = "testendpoint3"
        subcloud_status3 = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type3
        )
        self.assertIsNotNone(subcloud_status3)

        new_subcloud_statuses = db_api.subcloud_status_get_all(self.ctx, subcloud.id)
        self.assertIsNotNone(new_subcloud_statuses)
        self.assertEqual(num_default_subcloud_statuses + 3, len(new_subcloud_statuses))
        self.assertEqual(
            endpoint_type1,
            new_subcloud_statuses[num_default_subcloud_statuses].endpoint_type,
        )
        self.assertEqual(
            num_default_subcloud_statuses + 1,
            new_subcloud_statuses[num_default_subcloud_statuses].id,
        )
        self.assertEqual(
            endpoint_type2,
            new_subcloud_statuses[num_default_subcloud_statuses + 1].endpoint_type,
        )
        self.assertEqual(
            num_default_subcloud_statuses + 2,
            new_subcloud_statuses[num_default_subcloud_statuses + 1].id,
        )
        self.assertEqual(
            endpoint_type3,
            new_subcloud_statuses[num_default_subcloud_statuses + 2].endpoint_type,
        )
        self.assertEqual(
            num_default_subcloud_statuses + 3,
            new_subcloud_statuses[num_default_subcloud_statuses + 2].id,
        )

    def test_update_subcloud_status(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        endpoint_type = "testendpoint"
        subcloud_status = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type
        )
        self.assertIsNotNone(subcloud_status)

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC
        updated = db_api.subcloud_status_update(
            self.ctx,
            subcloud.id,
            endpoint_type=endpoint_type,
            sync_status=sync_status,
        )
        self.assertIsNotNone(updated)
        self.assertEqual(sync_status, updated.sync_status)

        updated_subcloud_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint_type
        )
        self.assertIsNotNone(updated_subcloud_status)
        self.assertEqual(endpoint_type, updated_subcloud_status.endpoint_type)
        self.assertEqual(sync_status, updated_subcloud_status.sync_status)

    def test_update_subcloud_status_endpoints(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        endpoint_type1 = "testendpoint1"
        subcloud_status = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type1
        )
        self.assertIsNotNone(subcloud_status)

        endpoint_type2 = "testendpoint2"
        subcloud_status = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type2
        )
        self.assertIsNotNone(subcloud_status)

        endpoint_type3 = "testendpoint3"
        subcloud_status = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type3
        )
        self.assertIsNotNone(subcloud_status)

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC
        endpoint_type_list = [endpoint_type1, endpoint_type2]
        db_api.subcloud_status_update_endpoints(
            self.ctx,
            subcloud.id,
            endpoint_type_list=endpoint_type_list,
            sync_status=sync_status,
        )

        updated_endpoint1_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint_type1
        )
        self.assertIsNotNone(updated_endpoint1_status)
        self.assertEqual(endpoint_type1, updated_endpoint1_status.endpoint_type)
        self.assertEqual(sync_status, updated_endpoint1_status.sync_status)

        updated_endpoint2_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint_type2
        )
        self.assertIsNotNone(updated_endpoint2_status)
        self.assertEqual(endpoint_type2, updated_endpoint2_status.endpoint_type)
        self.assertEqual(sync_status, updated_endpoint2_status.sync_status)

        updated_endpoint3_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint_type3
        )
        self.assertIsNotNone(updated_endpoint3_status)
        self.assertEqual(endpoint_type3, updated_endpoint3_status.endpoint_type)
        self.assertNotEqual(sync_status, updated_endpoint3_status.sync_status)

    def test_update_subcloud_status_endpints_not_exists(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        endpoint_type1 = "testendpoint1"
        subcloud_status = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type1
        )
        self.assertIsNotNone(subcloud_status)

        endpoint_type2 = "testendpoint2"

        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC
        endpoint_type_list = [endpoint_type2]
        self.assertRaises(
            exceptions.SubcloudStatusNotFound,
            db_api.subcloud_status_update_endpoints,
            self.ctx,
            subcloud.id,
            endpoint_type_list,
            sync_status,
        )

    def test_delete_subcloud_status(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        endpoint_type = "testendpoint"
        subcloud_status = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type
        )
        self.assertIsNotNone(subcloud_status)

        db_api.subcloud_status_destroy_all(self.ctx, subcloud.id)
        self.assertRaises(
            exceptions.SubcloudStatusNotFound,
            db_api.subcloud_status_get,
            self.ctx,
            subcloud.id,
            endpoint_type,
        )

    def test_cascade_delete_subcloud_status(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        endpoint_type = "testendpoint"
        subcloud_status = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type
        )
        self.assertIsNotNone(subcloud_status)

        db_api.subcloud_destroy(self.ctx, subcloud.id)
        self.assertRaises(
            exceptions.SubcloudNotFound, db_api.subcloud_get, self.ctx, subcloud.id
        )
        self.assertRaises(
            exceptions.SubcloudStatusNotFound,
            db_api.subcloud_status_get,
            self.ctx,
            subcloud.id,
            endpoint_type,
        )

    def test_subcloud_status_get_all_by_name(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        name = fake_subcloud["name"]
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        default_subcloud_statuses = db_api.subcloud_status_get_all(
            self.ctx, subcloud.id
        )
        num_default_subcloud_statuses = len(default_subcloud_statuses)
        self.assertEqual(
            num_default_subcloud_statuses, len(dccommon_consts.AUDIT_TYPES_LIST)
        )

        endpoint_type1 = "testendpoint1"
        subcloud_status1 = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type1
        )
        self.assertIsNotNone(subcloud_status1)

        endpoint_type2 = "testendpoint2"
        subcloud_status2 = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type2
        )
        self.assertIsNotNone(subcloud_status2)

        endpoint_type3 = "testendpoint3"
        subcloud_status3 = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type3
        )
        self.assertIsNotNone(subcloud_status3)

        new_subcloud_statuses = db_api.subcloud_status_get_all_by_name(self.ctx, name)
        self.assertIsNotNone(new_subcloud_statuses)
        self.assertEqual(num_default_subcloud_statuses + 3, len(new_subcloud_statuses))
        self.assertEqual(
            endpoint_type1,
            new_subcloud_statuses[num_default_subcloud_statuses].endpoint_type,
        )
        self.assertEqual(
            num_default_subcloud_statuses + 1,
            new_subcloud_statuses[num_default_subcloud_statuses + 0].id,
        )
        self.assertEqual(
            endpoint_type2,
            new_subcloud_statuses[num_default_subcloud_statuses + 1].endpoint_type,
        )
        self.assertEqual(
            num_default_subcloud_statuses + 2,
            new_subcloud_statuses[num_default_subcloud_statuses + 1].id,
        )
        self.assertEqual(
            endpoint_type3,
            new_subcloud_statuses[num_default_subcloud_statuses + 2].endpoint_type,
        )
        self.assertEqual(
            num_default_subcloud_statuses + 3,
            new_subcloud_statuses[num_default_subcloud_statuses + 2].id,
        )

    def test_subcloud_status_get_all_by_non_existing_name(self):
        fake_subcloud = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud = self.create_subcloud(self.ctx, fake_subcloud)
        self.assertIsNotNone(subcloud)

        endpoint_type1 = "testendpoint1"
        subcloud_status1 = self.create_subcloud_status(
            self.ctx, endpoint_type=endpoint_type1
        )
        self.assertIsNotNone(subcloud_status1)

        new_subcloud_statuses = db_api.subcloud_status_get_all_by_name(
            self.ctx, "thisnameisnotknown"
        )
        self.assertEqual([], new_subcloud_statuses)

    def test_create_sw_update_strategy(self):
        sw_update_strategy = self.create_sw_update_strategy(
            self.ctx,
            type=consts.SW_UPDATE_TYPE_SOFTWARE,
            subcloud_apply_type=consts.SUBCLOUD_APPLY_TYPE_SERIAL,
            max_parallel_subclouds=42,
            stop_on_failure=False,
            state=consts.SW_UPDATE_STATE_APPLYING,
        )
        self.assertIsNotNone(sw_update_strategy)

        new_sw_update_strategy = db_api.sw_update_strategy_get(self.ctx)
        self.assertIsNotNone(new_sw_update_strategy)
        self.assertEqual(consts.SW_UPDATE_TYPE_SOFTWARE, new_sw_update_strategy.type)
        self.assertEqual(
            consts.SUBCLOUD_APPLY_TYPE_SERIAL,
            new_sw_update_strategy.subcloud_apply_type,
        )
        self.assertEqual(42, new_sw_update_strategy.max_parallel_subclouds)
        self.assertEqual(False, new_sw_update_strategy.stop_on_failure)
        self.assertEqual(consts.SW_UPDATE_STATE_APPLYING, new_sw_update_strategy.state)

    def test_create_sw_update_strategy_duplicate(self):
        sw_update_strategy = self.create_sw_update_strategy(self.ctx)
        self.assertIsNotNone(sw_update_strategy)

        self.assertRaises(
            db_exception.DBDuplicateEntry, self.create_sw_update_strategy, self.ctx
        )

    def test_update_sw_update_strategy(self):
        sw_update_strategy = self.create_sw_update_strategy(self.ctx)
        self.assertIsNotNone(sw_update_strategy)

        state = consts.SW_UPDATE_STATE_APPLYING
        updated = db_api.sw_update_strategy_update(self.ctx, state=state)
        self.assertIsNotNone(updated)
        self.assertEqual(state, updated.state)

        updated_sw_update_strategy = db_api.sw_update_strategy_get(self.ctx)
        self.assertEqual(state, updated_sw_update_strategy.state)

    def test_delete_sw_update_strategy(self):
        sw_update_strategy = self.create_sw_update_strategy(self.ctx)
        self.assertIsNotNone(sw_update_strategy)

        db_api.sw_update_strategy_destroy(self.ctx)

        self.assertRaises(exceptions.NotFound, db_api.sw_update_strategy_get, self.ctx)

    def test_create_strategy_step(self):
        name = "testname"
        subcloud = self.create_subcloud_static(self.ctx, name=name)
        self.assertIsNotNone(subcloud)

        strategy_step = self.create_strategy_step(
            self.ctx, stage=1, details="Bart was here"
        )
        self.assertIsNotNone(strategy_step)

        new_strategy_step = db_api.strategy_step_get(self.ctx, subcloud.id)
        self.assertIsNotNone(new_strategy_step)
        self.assertEqual(1, new_strategy_step.stage)
        self.assertEqual(consts.STRATEGY_STATE_INITIAL, new_strategy_step.state)
        self.assertEqual("Bart was here", new_strategy_step.details)

        new_strategy_step = db_api.strategy_step_get_by_name(self.ctx, subcloud.name)
        self.assertIsNotNone(new_strategy_step)
        self.assertEqual(1, new_strategy_step.stage)
        self.assertEqual(consts.STRATEGY_STATE_INITIAL, new_strategy_step.state)
        self.assertEqual("Bart was here", new_strategy_step.details)

    def test_strategy_step_get_all(self):
        subcloud1 = self.create_subcloud_static(self.ctx, name="subcloud one")
        self.assertIsNotNone(subcloud1)
        subcloud2 = self.create_subcloud_static(self.ctx, name="subcloud two")
        self.assertIsNotNone(subcloud2)
        subcloud3 = self.create_subcloud_static(self.ctx, name="subcloud three")
        self.assertIsNotNone(subcloud3)

        strategy_step_stage1 = self.create_strategy_step(
            self.ctx, subcloud_id=1, stage=1
        )
        self.assertIsNotNone(strategy_step_stage1)

        strategy_step_stage2 = self.create_strategy_step(
            self.ctx, subcloud_id=2, stage=2
        )
        self.assertIsNotNone(strategy_step_stage2)

        strategy_step_stage3 = self.create_strategy_step(
            self.ctx, subcloud_id=3, stage=2
        )
        self.assertIsNotNone(strategy_step_stage3)

        new_strategy = db_api.strategy_step_get_all(self.ctx)

        self.assertIsNotNone(new_strategy)
        self.assertEqual(3, len(new_strategy))

        self.assertEqual(1, new_strategy[0].id)
        self.assertEqual(1, new_strategy[0].stage)
        self.assertEqual("subcloud one", new_strategy[0].subcloud.name)
        self.assertEqual(2, new_strategy[1].id)
        self.assertEqual(2, new_strategy[1].stage)
        self.assertEqual("subcloud two", new_strategy[1].subcloud.name)
        self.assertEqual(3, new_strategy[2].id)
        self.assertEqual(2, new_strategy[2].stage)
        self.assertEqual("subcloud three", new_strategy[2].subcloud.name)

    def test_update_strategy_step(self):
        name = "testname"
        subcloud = self.create_subcloud_static(self.ctx, name=name)
        self.assertIsNotNone(subcloud)

        strategy_step = self.create_strategy_step(
            self.ctx, stage=1, details="Bart was here"
        )
        self.assertIsNotNone(strategy_step)

        updated = db_api.strategy_step_update(
            self.ctx,
            subcloud.id,
            stage=2,
            state=consts.STRATEGY_STATE_COMPLETE,
            details="New details",
        )
        self.assertIsNotNone(updated)
        self.assertEqual(2, updated.stage)
        self.assertEqual(consts.STRATEGY_STATE_COMPLETE, updated.state)
        self.assertEqual("New details", updated.details)

        updated_strategy_step = db_api.strategy_step_get(self.ctx, subcloud.id)
        self.assertIsNotNone(updated_strategy_step)
        self.assertEqual(2, updated_strategy_step.stage)
        self.assertEqual(consts.STRATEGY_STATE_COMPLETE, updated_strategy_step.state)
        self.assertEqual("New details", updated_strategy_step.details)

    def test_delete_strategy_step(self):
        name = "testname"
        subcloud = self.create_subcloud_static(self.ctx, name=name)
        self.assertIsNotNone(subcloud)

        strategy_step = self.create_strategy_step(
            self.ctx, stage=1, details="Bart was here"
        )
        self.assertIsNotNone(strategy_step)

        db_api.strategy_step_destroy_all(self.ctx)
        new_strategy = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual([], new_strategy)

    def test_cascade_delete_strategy_step(self):
        name = "testname"
        subcloud = self.create_subcloud_static(self.ctx, name=name)
        self.assertIsNotNone(subcloud)

        strategy_step = self.create_strategy_step(
            self.ctx, stage=1, details="Bart was here"
        )
        self.assertIsNotNone(strategy_step)

        db_api.subcloud_destroy(self.ctx, subcloud.id)
        self.assertRaises(
            exceptions.SubcloudNotFound, db_api.subcloud_get, self.ctx, subcloud.id
        )

        self.assertRaises(
            exceptions.StrategyStepNotFound,
            db_api.strategy_step_get,
            self.ctx,
            subcloud.id,
        )
