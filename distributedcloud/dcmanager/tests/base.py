# Copyright (c) 2015 Ericsson AB
# Copyright (c) 2017-2022 Wind River Systems, Inc.
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

import json
import sqlalchemy

from oslo_config import cfg
from oslo_db import options

from dcmanager.common import consts
from dcmanager.db import api as api
from dcmanager.db.sqlalchemy import api as db_api

from dcmanager.tests import utils
from oslotest import base


get_engine = api.get_engine

# Enable foreign key support in sqlite - see:
# http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
from sqlalchemy.engine import Engine
from sqlalchemy import event

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
    json.dumps({'data_install': 'test data install values'}),  # data_install
]


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()


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
