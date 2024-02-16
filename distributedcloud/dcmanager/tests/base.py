# Copyright (c) 2015 Ericsson AB
# Copyright (c) 2017-2024 Wind River Systems, Inc.
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

import base64
import builtins
import json
import mock
import pecan

from oslo_config import cfg
from oslo_db import options
from oslotest import base
import sqlalchemy
from sqlalchemy.engine import Engine
from sqlalchemy import event

from dcmanager.audit import rpcapi as audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import utils as dutils
from dcmanager.db import api
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.rpc import client as rpc_client

from dcmanager.tests import utils

get_engine = api.get_engine

# Enable foreign key support in sqlite - see:
# http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html

SUBCLOUD_1 = {'name': 'subcloud1',
              'region_name': '2ec93dfb654846909efe61d1b39dd2ce',
              'rehomed': True,
              'software_version': "22.12"}
SUBCLOUD_2 = {'name': 'subcloud2',
              'region_name': 'ca2761ee7aa34cbe8415ec9a3c86854f',
              'rehomed': True,
              'software_version': "22.12"}
SUBCLOUD_3 = {'name': 'subcloud3',
              'region_name': '659e12e5f7ad411abfcd83f5cedca0bf',
              'rehomed': True,
              'software_version': "21.12"}
SUBCLOUD_4 = {'name': 'subcloud4',
              'region_name': 'c25f3b0553384104b664789bd93a2ba8',
              'rehomed': False,
              'software_version': "21.12"}
SUBCLOUD_5 = {'name': 'subcloud5',
              'region_name': '809581dc2d154e008480bac1f43b7aff',
              'rehomed': False,
              'software_version': "21.12"}
SUBCLOUD_6 = {'name': 'subcloud6',
              'region_name': '8c60b99f3e1245b7bc5a049802ade8d2',
              'rehomed': False,
              'software_version': "22.12"}
SUBCLOUD_7 = {'name': 'subcloud7',
              'region_name': '9fde6dca22fa422bb1e8cf03bedc18e4'}
SUBCLOUD_8 = {'name': 'subcloud8',
              'region_name': 'f3cb0b109c4543fda3ed50ed5783279d'}
SUBCLOUD_9 = {'name': 'subcloud9',
              'region_name': '1cfab1df7b444bb3bd562894d684f352'}
SUBCLOUD_10 = {'name': 'subcloud10',
               'region_name': '6d0040199b4f4a9fb4a1f2ed4d498159'}
SUBCLOUD_11 = {'name': 'subcloud11',
               'region_name': '169e6fc231e94959ad6ff0a66fbcb753'}

SUBCLOUD_SAMPLE_DATA_0 = [
    6,  # id
    "subcloud-4",  # name
    "demo subcloud",   # description
    "Ottawa-Lab-Aisle_3-Rack_C",  # location
    "12.34",  # software-version
    "managed",   # management-state
    "online",  # availability-status
    "fd01:3::0/64",  # management_subnet
    "fd01:3::1",  # management_gateway_address
    "fd01:3::2",  # management_start_address
    "fd01:3::f",  # management_end_address
    "fd01:1::1",  # systemcontroller_gateway_address
    0,  # audit-fail-count
    "NULL",  # reserved-1
    "NULL",  # reserved-2
    "2018-05-15 14:45:12.508708",  # created-at
    "2018-05-24 10:48:18.090931",  # updated-at
    "NULL",   # deleted-at
    0,  # deleted
    "10.10.10.0/24",  # external_oam_subnet
    "10.10.10.1",  # external_oam_gateway_address
    "10.10.10.12",  # external_oam_floating_address
    "testpass",  # sysadmin_password
    1,  # group_id
    consts.DEPLOY_STATE_DONE,  # deploy_status
    consts.ERROR_DESC_EMPTY,  # error_description
    SUBCLOUD_4['region_name'],  # region_name
    json.dumps({'data_install': 'test data install values'}),  # data_install
]


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


class FakeException(Exception):
    """Exception used to throw a generic exception in the application

    Using the Exception class might lead to linter errors for being too broad. In
    these cases, the FakeException is used
    """


class DCManagerTestCase(base.BaseTestCase):
    """Test case base class for all unit tests."""

    def setup_dummy_db(self):
        options.cfg.set_defaults(options.database_opts,
                                 sqlite_synchronous=False)
        options.set_defaults(cfg.CONF, connection="sqlite://")
        engine = get_engine()
        db_api.db_sync(engine)

    @staticmethod
    def reset_dummy_db():
        engine = get_engine()
        meta = sqlalchemy.MetaData()
        meta.reflect(bind=engine)

        for table in reversed(meta.sorted_tables):
            if table.name == 'migrate_version':
                continue
            engine.execute(table.delete())

    def setUp(self):
        super(DCManagerTestCase, self).setUp()

        # register cleanup of DB before setup, in case setup fails
        self.addCleanup(self.reset_dummy_db)
        self.setup_dummy_db()
        self.ctx = utils.dummy_context()
        self._mock_pecan()

    def _mock_pecan(self):
        """Mock pecan's abort"""

        mock_patch = mock.patch.object(pecan, 'abort', wraps=pecan.abort)
        self.mock_pecan_abort = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_audit_rpc_client(self):
        """Mock rpc's manager audit client"""

        mock_patch = mock.patch.object(audit_rpc_client, 'ManagerAuditClient')
        self.mock_audit_rpc_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_rpc_client(self):
        """Mock rpc's manager client"""

        mock_patch = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_rpc_subcloud_state_client(self):
        """Mock rpc's subcloud state client"""

        mock_patch = mock.patch.object(rpc_client, 'SubcloudStateClient')
        self.mock_rpc_subcloud_state_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_openstack_driver(self, target):
        """Mock the target's OpenStackDriver"""

        mock_patch = mock.patch.object(target, 'OpenStackDriver')
        self.mock_openstack_driver = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_sysinv_client(self, target):
        """Mock the target's SysinvClient"""

        mock_patch = mock.patch.object(target, 'SysinvClient')
        self.mock_sysinv_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_get_network_address_pool(self):
        """Mock phased subcloud deploy's get_network_address_pool"""

        mock_patch_object = mock.patch.object(psd_common, 'get_network_address_pool')
        self.mock_get_network_address_pool = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_get_ks_client(self):
        """Mock phased subcloud deploy's get_ks_client"""

        mock_patch_object = mock.patch.object(psd_common, 'get_ks_client')
        self.mock_get_ks_client = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_query(self):
        """Mock phased subcloud deploy's query"""

        mock_patch_object = mock.patch.object(psd_common.PatchingClient, 'query')
        self.mock_query = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_get_subcloud_db_install_values(self):
        """Mock phased subcloud deploy's get_subcloud_db_install_values"""

        mock_patch_object = mock.patch.object(
            psd_common, 'get_subcloud_db_install_values'
        )
        self.mock_get_subcloud_db_install_values = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_validate_k8s_version(self):
        """Mock phased subcloud deploy's validate_k8s_version"""

        mock_patch_object = mock.patch.object(psd_common, 'validate_k8s_version')
        self.mock_validate_k8s_version = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_get_vault_load_files(self):
        """Mock dcmanager util's get_vault_load_files"""

        mock_patch_object = mock.patch.object(dutils, 'get_vault_load_files')
        self.mock_get_vault_load_files = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_builtins_open(self):
        """Mock builtins' open"""

        mock_patch = mock.patch.object(builtins, 'open')
        self.mock_builtins_open = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _assert_pecan(self, http_status, content=None, call_count=1):
        """Assert pecan was called with the correct arguments"""

        self.assertEqual(self.mock_pecan_abort.call_count, call_count)

        if content:
            self.mock_pecan_abort.assert_called_with(http_status, content)
        else:
            self.mock_pecan_abort.assert_called_with(http_status)

    def _create_password(self, keyword='default'):
        """Create a password with based on the specified keyword"""

        return base64.b64encode(keyword.encode("utf-8")).decode("utf-8")

    def _mock_SubcloudManager(self, target):
        """Mock the target's SubcloudManager"""

        mock_patch = mock.patch.object(target, 'SubcloudManager')
        self.mock_subcloud_manager = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_PeerMonitorManager(self, target):
        """Mock the target's PeerMonitorManager"""

        mock_patch = mock.patch.object(target, 'PeerMonitorManager')
        self.mock_PeerMonitor_Manager = mock_patch.start()
        self.addCleanup(mock_patch.stop)
