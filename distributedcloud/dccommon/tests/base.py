# Copyright (c) 2015 Ericsson AB
# Copyright (c) 2020-2023 Wind River Systems, Inc.
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

from dccommon.tests import utils
from oslotest import base

KEYSTONE_ENDPOINT_0 = [
    "9785cc7f99b6469ba6fe89bd8d5b9072", "NULL", "admin",
    "7d48ddb964034eb588e557b976d11cdf", "http://[fd01:1::2]:9292", "{}", True,
    "SystemController"
]

ROUTE_0 = [
    "2018-04-11 17:01:49.654734", "NULL", "NULL", 1,
    "3a07ca95-d6fe-48cb-9393-b949f800b552", 6,
    "fd01:2::", 64, "fd01:1::1", 1, 9
]

ROUTE_1 = [
    "2018-04-11 17:01:49.654734", "NULL", "NULL", 1,
    "3a07ca95-d6fe-48cb-9393-b949f800b552", 6,
    "fd01:3::", 64, "fd01:1::1", 1, 9
]


class DCCommonTestCase(base.BaseTestCase):
    """Test case base class for all unit tests."""

    def setUp(self):
        super(DCCommonTestCase, self).setUp()
        self.ctx = utils.dummy_context()
