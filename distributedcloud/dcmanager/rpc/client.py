# Copyright (c) 2017-2022 Wind River Systems, Inc.
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
Client side of the DC Manager RPC API.
"""

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import messaging

LOG = logging.getLogger(__name__)


class RPCClient(object):
    """RPC client

    Basic RPC client implementation to deliver RPC 'call' and 'cast'
    """

    def __init__(self, topic, version):
        self._client = messaging.get_rpc_client(
            topic=topic,
            version=version)

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


class SubcloudStateClient(RPCClient):
    """Client to update subcloud availability."""

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        super(SubcloudStateClient, self).__init__(
            consts.TOPIC_DC_MANAGER_STATE,
            self.BASE_RPC_API_VERSION)

    def update_subcloud_availability(self, ctxt,
                                     subcloud_name,
                                     availability_status,
                                     update_state_only=False,
                                     audit_fail_count=None):
        # Note: synchronous
        return self.call(
            ctxt,
            self.make_msg('update_subcloud_availability',
                          subcloud_name=subcloud_name,
                          availability_status=availability_status,
                          update_state_only=update_state_only,
                          audit_fail_count=audit_fail_count))

    def update_subcloud_endpoint_status(self, ctxt, subcloud_name=None,
                                        endpoint_type=None,
                                        sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                                        ignore_endpoints=None):
        # Note: This is an asynchronous operation.
        # See below for synchronous method call
        return self.cast(ctxt, self.make_msg('update_subcloud_endpoint_status',
                                             subcloud_name=subcloud_name,
                                             endpoint_type=endpoint_type,
                                             sync_status=sync_status,
                                             ignore_endpoints=ignore_endpoints))

    def update_subcloud_endpoint_status_sync(self, ctxt, subcloud_name=None,
                                             endpoint_type=None,
                                             sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                                             ignore_endpoints=None):
        # Note: synchronous
        return self.call(ctxt, self.make_msg('update_subcloud_endpoint_status',
                                             subcloud_name=subcloud_name,
                                             endpoint_type=endpoint_type,
                                             sync_status=sync_status,
                                             ignore_endpoints=ignore_endpoints))


class ManagerClient(RPCClient):
    """Client side of the DC Manager rpc API.

    Version History:
     1.0 - Initial version (Mitaka 1.0 release)
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        super(ManagerClient, self).__init__(
            consts.TOPIC_DC_MANAGER,
            self.BASE_RPC_API_VERSION)

    def add_subcloud(self, ctxt, payload):
        return self.cast(ctxt, self.make_msg('add_subcloud',
                                             payload=payload))

    def delete_subcloud(self, ctxt, subcloud_id):
        return self.call(ctxt, self.make_msg('delete_subcloud',
                                             subcloud_id=subcloud_id))

    def update_subcloud(self, ctxt, subcloud_id, management_state=None,
                        description=None, location=None, group_id=None,
                        data_install=None, force=None):
        return self.call(ctxt, self.make_msg('update_subcloud',
                                             subcloud_id=subcloud_id,
                                             management_state=management_state,
                                             description=description,
                                             location=location,
                                             group_id=group_id,
                                             data_install=data_install,
                                             force=force))

    def reconfigure_subcloud(self, ctxt, subcloud_id, payload):
        return self.call(ctxt, self.make_msg('reconfigure_subcloud',
                                             subcloud_id=subcloud_id,
                                             payload=payload))

    def reinstall_subcloud(self, ctxt, subcloud_id, payload):
        return self.cast(ctxt, self.make_msg('reinstall_subcloud',
                                             subcloud_id=subcloud_id,
                                             payload=payload))

    def backup_subclouds(self, ctxt, payload):
        return self.cast(ctxt, self.make_msg('backup_subclouds',
                                             payload=payload))

    def delete_subcloud_backups(self, ctxt, release_version, payload):
        return self.call(ctxt, self.make_msg('delete_subcloud_backups',
                                             release_version=release_version,
                                             payload=payload))

    def restore_subcloud_backups(self, ctxt, payload):
        return self.cast(ctxt, self.make_msg('restore_subcloud_backups',
                                             payload=payload))

    def update_subcloud_sync_endpoint_type(self, ctxt,
                                           subcloud_name,
                                           endpoint_type_list,
                                           openstack_installed):
        return self.cast(
            ctxt,
            self.make_msg('update_subcloud_sync_endpoint_type',
                          subcloud_name=subcloud_name,
                          endpoint_type_list=endpoint_type_list,
                          openstack_installed=openstack_installed))

    def prestage_subcloud(self, ctxt, payload):
        return self.call(ctxt, self.make_msg('prestage_subcloud',
                                             payload=payload))


class DCManagerNotifications(RPCClient):
    """DC Manager Notification interface to broadcast subcloud state changed

    Version History:
       1.0 - Initial version
    """

    def __init__(self):
        DCMANAGER_RPC_API_VERSION = '1.0'
        TOPIC_DC_NOTIFICIATION = 'DCMANAGER-NOTIFICATION'

        super(DCManagerNotifications, self).__init__(
            TOPIC_DC_NOTIFICIATION, DCMANAGER_RPC_API_VERSION)

    def subcloud_online(self, ctxt, subcloud_name):
        return self.cast(ctxt, self.make_msg('subcloud_online',
                                             subcloud_name=subcloud_name))

    def subcloud_managed(self, ctxt, subcloud_name):
        return self.cast(ctxt, self.make_msg('subcloud_managed',
                                             subcloud_name=subcloud_name))
