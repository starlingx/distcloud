# -*- coding: utf-8 -*-
# Copyright (c) 2017, 2019, 2021 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#


import mock

from dcmanager.common import config
from dcmanager.common import messaging
from dcmanager.rpc import client as rpc_client
from dcmanager.tests import base
from dcmanager.tests import utils

config.register_options()


class ManagerRpcAPITestCase(base.DCManagerTestCase):

    def setUp(self):
        messaging.setup("fake://", optional=True)
        self.addCleanup(messaging.cleanup)
        self.context = utils.dummy_context()
        # self.stubs = stubout.StubOutForTesting()
        self.rpcapi = rpc_client.ManagerClient()
        super(ManagerRpcAPITestCase, self).setUp()

    @mock.patch.object(messaging, 'get_rpc_client')
    def test_call(self, mock_client):
        client = mock.Mock()
        mock_client.return_value = client

        method = 'fake_method'
        kwargs = {'key': 'value'}
        rpcapi = rpc_client.ManagerClient()
        msg = rpcapi.make_msg(method, **kwargs)

        # with no version
        res = rpcapi.call(self.context, msg)

        self.assertEqual(client, rpcapi._client)
        client.call.assert_called_once_with(self.context, 'fake_method',
                                            key='value')
        self.assertEqual(res, client.call.return_value)

        # with version
        res = rpcapi.call(self.context, msg, version='123')
        client.prepare.assert_called_once_with(version='123')
        new_client = client.prepare.return_value
        new_client.call.assert_called_once_with(self.context, 'fake_method',
                                                key='value')
        self.assertEqual(res, new_client.call.return_value)

    @mock.patch.object(messaging, 'get_rpc_client')
    def test_cast(self, mock_client):
        client = mock.Mock()
        mock_client.return_value = client

        method = 'fake_method'
        kwargs = {'key': 'value'}
        rpcapi = rpc_client.ManagerClient()
        msg = rpcapi.make_msg(method, **kwargs)

        # with no version
        res = rpcapi.cast(self.context, msg)

        self.assertEqual(client, rpcapi._client)
        client.cast.assert_called_once_with(self.context, 'fake_method',
                                            key='value')
        self.assertEqual(res, client.cast.return_value)

        # with version
        res = rpcapi.cast(self.context, msg, version='123')
        client.prepare.assert_called_once_with(version='123')
        new_client = client.prepare.return_value
        new_client.cast.assert_called_once_with(self.context, 'fake_method',
                                                key='value')
        self.assertEqual(res, new_client.cast.return_value)
