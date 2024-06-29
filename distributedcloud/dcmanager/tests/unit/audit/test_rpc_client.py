# Copyright (c) 2023-2024 Wind River Systems, Inc.
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

import oslo_messaging

from dcmanager.audit import rpcapi as rpc_client
from dcmanager.common import config
from dcmanager.common import consts
from dcmanager.common import messaging
from dcmanager.tests import base
from dcmanager.tests import utils

config.register_options()


class ManagerRpcAuditAPITestCase(base.DCManagerTestCase):

    def setUp(self):
        messaging.setup("fake://", optional=True)
        self.addCleanup(messaging.cleanup)
        self.context = utils.dummy_context()
        super(ManagerRpcAuditAPITestCase, self).setUp()

    def test_cast(self):
        rpcapi = rpc_client.ManagerAuditWorkerClient()
        transport = messaging.get_transport()
        transport._send = mock.Mock()

        fake_endpoints = {"service": "fake_ip", "service2": "other_fake_ip"}

        rpcapi.update_subcloud_endpoints(self.context, "subcloud", fake_endpoints)

        exp_msg = {
            "method": "update_subcloud_endpoints",
            "args": {"subcloud_name": "subcloud", "endpoints": fake_endpoints},
            "version": "1.0",
        }

        # With fanout a new target is created
        new_target = oslo_messaging.Target(
            fanout=True,
            version=rpcapi.BASE_RPC_API_VERSION,
            topic=consts.TOPIC_DC_MANAGER_AUDIT_WORKER,
        )
        transport._send.assert_called_with(
            new_target, mock.ANY, exp_msg, retry=None, transport_options=None
        )

        # Without fanout the target is the same
        rpcapi.audit_subclouds(
            self.context,
            ["subcloud1", "subcloud2"],
            True,
            False,
            True,
            True,
            False,
            False,
        )

        exp_msg2 = {
            "method": "audit_subclouds",
            "args": {
                "subcloud_ids": ["subcloud1", "subcloud2"],
                "patch_audit_data": True,
                "firmware_audit_data": False,
                "kubernetes_audit_data": True,
                "do_openstack_audit": True,
                "kube_rootca_update_audit_data": False,
                "software_audit_data": False,
            },
            "version": "1.0",
        }

        transport._send.assert_called_with(
            rpcapi._client.target,
            mock.ANY,
            exp_msg2,
            retry=None,
            transport_options=None,
        )
