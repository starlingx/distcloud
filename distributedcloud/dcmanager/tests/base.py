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
import json

import mock
from oslo_config import cfg
from oslo_db import options
from oslotest import base
import pecan
import sqlalchemy
from sqlalchemy.engine import Engine
from sqlalchemy import event

from dcmanager.audit import subcloud_audit_worker_manager
from dcmanager.common import consts
from dcmanager.db import api
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests import utils

get_engine = api.get_engine

# Enable foreign key support in sqlite - see:
# http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html

SUBCLOUD_1 = {
    "name": "subcloud1",
    "region_name": "2ec93dfb654846909efe61d1b39dd2ce",
    "rehomed": True,
    "software_version": "22.12",
}
SUBCLOUD_2 = {
    "name": "subcloud2",
    "region_name": "ca2761ee7aa34cbe8415ec9a3c86854f",
    "rehomed": True,
    "software_version": "22.12",
}
SUBCLOUD_3 = {
    "name": "subcloud3",
    "region_name": "659e12e5f7ad411abfcd83f5cedca0bf",
    "rehomed": True,
    "software_version": "21.12",
}
SUBCLOUD_4 = {
    "name": "subcloud4",
    "region_name": "c25f3b0553384104b664789bd93a2ba8",
    "rehomed": False,
    "software_version": "21.12",
}
SUBCLOUD_5 = {
    "name": "subcloud5",
    "region_name": "809581dc2d154e008480bac1f43b7aff",
    "rehomed": False,
    "software_version": "21.12",
}
SUBCLOUD_6 = {
    "name": "subcloud6",
    "region_name": "8c60b99f3e1245b7bc5a049802ade8d2",
    "rehomed": False,
    "software_version": "22.12",
}
SUBCLOUD_7 = {"name": "subcloud7", "region_name": "9fde6dca22fa422bb1e8cf03bedc18e4"}
SUBCLOUD_8 = {"name": "subcloud8", "region_name": "f3cb0b109c4543fda3ed50ed5783279d"}
SUBCLOUD_9 = {"name": "subcloud9", "region_name": "1cfab1df7b444bb3bd562894d684f352"}
SUBCLOUD_10 = {"name": "subcloud10", "region_name": "6d0040199b4f4a9fb4a1f2ed4d498159"}
SUBCLOUD_11 = {"name": "subcloud11", "region_name": "169e6fc231e94959ad6ff0a66fbcb753"}

SUBCLOUD_SAMPLE_DATA_0 = [
    6,  # id
    "subcloud-4",  # name
    "demo subcloud",  # description
    "Ottawa-Lab-Aisle_3-Rack_C",  # location
    "12.34",  # software-version
    "managed",  # management-state
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
    "NULL",  # deleted-at
    0,  # deleted
    "10.10.10.0/24",  # external_oam_subnet
    "10.10.10.1",  # external_oam_gateway_address
    "10.10.10.12",  # external_oam_floating_address
    "testpass",  # sysadmin_password
    1,  # group_id
    consts.DEPLOY_STATE_DONE,  # deploy_status
    consts.ERROR_DESC_EMPTY,  # error_description
    SUBCLOUD_4["region_name"],  # region_name
    json.dumps({"data_install": "test data install values"}),  # data_install
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
        super(DCManagerTestCase, self).setUp()

        # register cleanup of DB before setup, in case setup fails
        self.addCleanup(self.reset_dummy_db)
        self.setup_dummy_db()
        self.ctx = utils.dummy_context()
        self.mock_pecan_abort = self._mock_object(pecan, "abort", wraps=pecan.abort)

        # This is required to avoid tests timing out because of the infinite thread
        # that runs in the worker process
        self.mock_audit_worker_time = self._mock_object(
            subcloud_audit_worker_manager, "time"
        )
        self.mock_audit_worker_time.sleep.side_effect = Exception()

    def _mock_object(self, target, attribute, name=None, wraps=None):
        """Mock a specified target's attribute and save it in a variable"""

        mock_patch_object = mock.patch.object(target, attribute, wraps=wraps)
        created_mock = mock_patch_object.start()
        # TODO(rlima): update the mock usage not to use the name parameter
        self.__dict__[name] = created_mock
        self.addCleanup(mock_patch_object.stop)

        return created_mock

    def _assert_pecan(self, http_status, content=None, call_count=1):
        """Assert pecan was called with the correct arguments"""

        self.assertEqual(self.mock_pecan_abort.call_count, call_count)

        if content:
            self.mock_pecan_abort.assert_called_with(http_status, content)
        else:
            self.mock_pecan_abort.assert_called_with(http_status)

    def _create_password(self, keyword="default"):
        """Create a password with based on the specified keyword"""

        return base64.b64encode(keyword.encode("utf-8")).decode("utf-8")
