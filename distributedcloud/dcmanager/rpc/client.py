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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

"""
Client side of the DC Manager RPC API.
"""

from oslo_log import log as logging

from dcmanager.common import consts
from dcmanager.common import messaging

LOG = logging.getLogger(__name__)


class ManagerClient(object):
    """Client side of the DC Manager rpc API.

    Version History:
     1.0 - Initial version (Mitaka 1.0 release)
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        self._client = messaging.get_rpc_client(
            topic=consts.TOPIC_DC_MANAGER,
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

    def add_subcloud(self, ctxt, payload):
        return self.cast(ctxt, self.make_msg('add_subcloud',
                                             payload=payload))

    def delete_subcloud(self, ctxt, subcloud_id):
        return self.call(ctxt, self.make_msg('delete_subcloud',
                                             subcloud_id=subcloud_id))

    def update_subcloud(self, ctxt, subcloud_id, management_state=None,
                        description=None, location=None, group_id=None):
        return self.call(ctxt, self.make_msg('update_subcloud',
                                             subcloud_id=subcloud_id,
                                             management_state=management_state,
                                             description=description,
                                             location=location,
                                             group_id=group_id))

    def update_subcloud_endpoint_status(self, ctxt, subcloud_name=None,
                                        endpoint_type=None,
                                        sync_status=consts.
                                        SYNC_STATUS_OUT_OF_SYNC):
        return self.cast(ctxt, self.make_msg('update_subcloud_endpoint_status',
                                             subcloud_name=subcloud_name,
                                             endpoint_type=endpoint_type,
                                             sync_status=sync_status))

    def create_sw_update_strategy(self, ctxt, payload):
        return self.call(ctxt, self.make_msg('create_sw_update_strategy',
                                             payload=payload))

    def delete_sw_update_strategy(self, ctxt):
        return self.call(ctxt, self.make_msg('delete_sw_update_strategy'))

    def apply_sw_update_strategy(self, ctxt):
        return self.call(ctxt, self.make_msg('apply_sw_update_strategy'))

    def abort_sw_update_strategy(self, ctxt):
        return self.call(ctxt, self.make_msg('abort_sw_update_strategy'))
