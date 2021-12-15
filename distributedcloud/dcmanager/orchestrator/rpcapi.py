# Copyright (c) 2020-2021 Wind River Systems, Inc.
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

"""
Client side of the DC Manager Orchestrator RPC API.
"""

from dcmanager.common import consts
from dcmanager.common import messaging


class ManagerOrchestratorClient(object):
    """Client side of the DC Manager Orchestrator RPC API.

    Version History:
     1.0 - Initial version
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        self._client = messaging.get_rpc_client(
            topic=consts.TOPIC_DC_MANAGER_ORCHESTRATOR,
            version=self.BASE_RPC_API_VERSION)

    @staticmethod
    def make_msg(method, **kwargs):
        return method, kwargs

    def call(self, ctxt, msg, version=None):
        method, kwargs = msg
        if version is not None:
            client = self._client.prepare(version=version)
        else:
            client = self._client
        return client.call(ctxt, method, **kwargs)

    def cast(self, ctxt, msg, version=None):
        method, kwargs = msg
        if version is not None:
            client = self._client.prepare(version=version)
        else:
            client = self._client
        return client.cast(ctxt, method, **kwargs)

    def create_sw_update_strategy(self, ctxt, payload):
        return self.call(ctxt, self.make_msg('create_sw_update_strategy',
                                             payload=payload))

    def delete_sw_update_strategy(self, ctxt, update_type=None):
        return self.call(ctxt, self.make_msg('delete_sw_update_strategy',
                                             update_type=update_type))

    def apply_sw_update_strategy(self, ctxt, update_type=None):
        return self.call(ctxt, self.make_msg('apply_sw_update_strategy',
                                             update_type=update_type))

    def abort_sw_update_strategy(self, ctxt, update_type=None):
        return self.call(ctxt, self.make_msg('abort_sw_update_strategy',
                                             update_type=update_type))
