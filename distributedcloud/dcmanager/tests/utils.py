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

import eventlet
import random
import string
import uuid

from dcmanager.common import context
from dcmanager.db import api as db_api


get_engine = db_api.get_engine


class UUIDStub(object):
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self.uuid4 = uuid.uuid4
        uuid_stub = lambda: self.value
        uuid.uuid4 = uuid_stub

    def __exit__(self, *exc_info):
        uuid.uuid4 = self.uuid4


UUIDs = (UUID1, UUID2, UUID3, UUID4, UUID5) = sorted([str(uuid.uuid4())
                                                     for x in range(5)])


def random_name():
    return ''.join(random.choice(string.ascii_uppercase)
                   for x in range(10))


def dummy_context(user='test_username', tenant='test_project_id',
                  region_name=None):
    return context.RequestContext.from_dict({
        'auth_token': 'abcd1234',
        'user': user,
        'project': tenant,
        'is_admin': True,
        'region_name': region_name
    })


def wait_until_true(predicate, timeout=60, sleep=1, exception=None):
    with eventlet.timeout.Timeout(timeout, exception):
        while not predicate():
            eventlet.sleep(sleep)


def create_subcloud_dict(data_list):
    return {'id': data_list[0],
            'name': data_list[1],
            'description': data_list[2],
            'location': data_list[3],
            'software-version': data_list[4],
            'management-state': data_list[5],
            'availability-status': data_list[6],
            'management_subnet': data_list[7],
            'management_gateway_address': data_list[8],
            'management_start_address': data_list[9],
            'management_end_address': data_list[10],
            'systemcontroller_gateway_address': data_list[11],
            'audit-fail-count': data_list[12],
            'reserved-1': data_list[13],
            'reserved-2': data_list[14],
            'created-at': data_list[15],
            'updated-at': data_list[16],
            'deleted-at': data_list[17],
            'deleted': data_list[18],
            'external_oam_subnet': data_list[19],
            'external_oam_gateway_address': data_list[20],
            'external_oam_floating_address': data_list[21],
            'sysadmin_password': data_list[22],
            'group_id': data_list[23],
            'deploy_status': data_list[24],
            'error_description': data_list[25],
            'region_name': data_list[26],
            'data_install': data_list[27]}
