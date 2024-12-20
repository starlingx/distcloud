# Copyright (c) 2017, 2019, 2021, 2024 Wind River Systems, Inc.
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


from dcmanager.common import config
from dcmanager.common import messaging
from dcmanager.rpc import client as rpc_client
from dcmanager.tests import base

config.register_options()


class ManagerRpcAPITestCase(base.DCManagerTestCase):

    def setUp(self):
        messaging.setup("fake://", optional=True)
        self.addCleanup(messaging.cleanup)

        super().setUp()

        self.mock_get_rpc_client = self._mock_object(messaging, "get_rpc_client")

        self.method = "fake_method"
        self.kwargs = {"key": "value"}
        self.rpcapi = rpc_client.ManagerClient()
        self.msg = self.rpcapi.make_msg(self.method, **self.kwargs)

    def test_call(self):
        # with no version
        res = self.rpcapi.call(self.ctx, self.msg)

        self.assertEqual(self.mock_get_rpc_client(), self.rpcapi._client)
        self.mock_get_rpc_client().call.assert_called_once_with(
            self.ctx, self.method, key="value"
        )
        self.assertEqual(res, self.mock_get_rpc_client().call.return_value)

        # with version
        res = self.rpcapi.call(self.ctx, self.msg, version="123")
        self.mock_get_rpc_client().prepare.assert_called_once_with(version="123")
        new_client = self.mock_get_rpc_client().prepare.return_value
        new_client.call.assert_called_once_with(self.ctx, "fake_method", key="value")
        self.assertEqual(res, new_client.call.return_value)

    def test_cast(self):
        # with no version
        res = self.rpcapi.cast(self.ctx, self.msg)

        self.assertEqual(self.mock_get_rpc_client(), self.rpcapi._client)
        self.mock_get_rpc_client().cast.assert_called_once_with(
            self.ctx, "fake_method", key="value"
        )
        self.assertEqual(res, self.mock_get_rpc_client().cast.return_value)

        # with version
        res = self.rpcapi.cast(self.ctx, self.msg, version="123")
        self.mock_get_rpc_client().prepare.assert_called_once_with(
            fanout=None, version="123"
        )
        new_client = self.mock_get_rpc_client().prepare.return_value
        new_client.cast.assert_called_once_with(self.ctx, "fake_method", key="value")
        self.assertEqual(res, new_client.cast.return_value)
