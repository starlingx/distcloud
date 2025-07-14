# Copyright (c) 2015 Ericsson AB
# Copyright (c) 2020-2025 Wind River Systems, Inc.
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
import pecan

from oslo_config import cfg
from oslo_db import options
from oslotest import base
import sqlalchemy

from dccommon import consts as dccommon_consts
from dcorch.db import api as db_api
from dcorch.tests import utils


get_engine = db_api.get_engine


CAPABILITIES = {
    "endpoint_types": [
        dccommon_consts.ENDPOINT_TYPE_PLATFORM,
        dccommon_consts.ENDPOINT_TYPE_IDENTITY,
    ]
}


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
        self.mock_pecan_abort = self._mock_object(pecan, "abort", wraps=pecan.abort)

    def _mock_object(self, target, attribute, wraps=None):
        """Mock a specified target's attribute and return the mock object"""

        mock_patch_object = mock.patch.object(target, attribute, wraps=wraps)
        self.addCleanup(mock_patch_object.stop)

        return mock_patch_object.start()

    def _assert_pecan(self, http_status, content=None, call_count=1):
        """Assert pecan was called with the correct arguments"""

        self.assertEqual(self.mock_pecan_abort.call_count, call_count)

        if content:
            self.mock_pecan_abort.assert_called_with(http_status, content)
        else:
            self.mock_pecan_abort.assert_called_with(http_status)
