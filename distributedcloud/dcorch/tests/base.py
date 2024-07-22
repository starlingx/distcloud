# Copyright (c) 2015 Ericsson AB
# Copyright (c) 2020-2024 Wind River Systems, Inc.
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

import builtins
import mock
import pecan

from oslo_config import cfg
from oslo_db import options
from oslotest import base
import sqlalchemy

from dccommon import consts as dccommon_consts
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.db import api
from dcorch.db.sqlalchemy import api as db_api
from dcorch.rpc import client as rpc_client
from dcorch.tests import utils


get_engine = api.get_engine


CAPABILITES = {
    "endpoint_types": [
        dccommon_consts.ENDPOINT_TYPE_PLATFORM,
        dccommon_consts.ENDPOINT_TYPE_IDENTITY,
    ]
}


class FakeException(Exception):
    """Exception used to throw a generic exception in the application

    Using the Exception class might lead to linter errors for being too broad. In
    these cases, the FakeException is used
    """


class OrchestratorTestCase(base.BaseTestCase):
    """Test case base class for all unit tests."""

    def setup_dummy_db(self):
        options.cfg.set_defaults(options.database_opts, sqlite_synchronous=False)
        options.set_defaults(cfg.CONF, connection="sqlite://")
        engine = get_engine()
        db_api.db_sync(engine)

    @staticmethod
    def reset_dummy_db():
        engine = get_engine()
        meta = sqlalchemy.MetaData()
        meta.reflect(bind=engine)

        for table in reversed(meta.sorted_tables):
            if table.name == "migrate_version":
                continue
            engine.execute(table.delete())

    def setUp(self):
        super(OrchestratorTestCase, self).setUp()

        self.setup_dummy_db()
        self.addCleanup(self.reset_dummy_db)
        self.ctx = utils.dummy_context()
        self._mock_pecan()

    def _mock_pecan(self):
        """Mock pecan's abort"""

        mock_patch = mock.patch.object(pecan, "abort", wraps=pecan.abort)
        self.mock_pecan_abort = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_rpc_client(self):
        """Mock rpc's manager client"""

        mock_patch = mock.patch.object(rpc_client, "EngineWorkerClient")
        self.mock_rpc_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_rpc_client_subcloud_state_client(self):
        mock_patch = mock.patch.object(dcmanager_rpc_client, "SubcloudStateClient")
        self.rpc_client_subcloud_state_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_rpc_client_manager(self):
        mock_patch = mock.patch.object(dcmanager_rpc_client, "ManagerClient")
        self.rpc_client_manager = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_log(self, target):
        mock_patch = mock.patch.object(target, "LOG")
        self.log = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_openstack_driver(self):
        mock_patch = mock.patch(
            "dccommon.drivers.openstack.sdk_platform.OpenStackDriver"
        )
        self.mock_openstack_driver = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_keystone_client(self):
        mock_patch = mock.patch("keystoneclient.client.Client")
        self.mock_keystone_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_keystone_endpoint_cache_get_admin_session(self):
        mock_patch = mock.patch(
            "dccommon.drivers.openstack.keystone_v3.EndpointCache.get_admin_session"
        )
        self.mock_endpoint_cache_from_keystone = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_endpoint_cache_get_admin_session(self):
        mock_patch = mock.patch(
            "dccommon.endpoint_cache.EndpointCache.get_admin_session"
        )
        self.mock_endpoint_cache = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_m_dbs_client(self):
        mock_patch = mock.patch("dcorch.engine.sync_thread.dbsyncclient.Client")
        self.mock_m_dbs_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_sc_dbs_client(self):
        mock_patch = mock.patch("dcorch.engine.sync_services.identity.Client")
        self.mock_sc_dbs_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_sysinv_client(self, target):
        mock_patch = mock.patch.object(target, "SysinvClient")
        self.mock_sysinv_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_builtins_open(self):
        """Mock builtins' open"""

        mock_patch = mock.patch.object(builtins, "open")
        self.mock_builtins_open = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _assert_pecan(self, http_status, content=None, call_count=1):
        """Assert pecan was called with the correct arguments"""

        self.assertEqual(self.mock_pecan_abort.call_count, call_count)

        if content:
            self.mock_pecan_abort.assert_called_with(http_status, content)
        else:
            self.mock_pecan_abort.assert_called_with(http_status)
