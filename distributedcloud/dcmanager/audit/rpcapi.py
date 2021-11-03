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
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

"""
Client side of the DC Manager Audit RPC API.
"""

from dcmanager.common import consts
from dcmanager.common import messaging


class ManagerAuditClient(object):
    """Client side of the DC Manager Audit rpc API.

    Version History:
     1.0 - Initial version
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        self._client = messaging.get_rpc_client(
            topic=consts.TOPIC_DC_MANAGER_AUDIT,
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

    def trigger_firmware_audit(self, ctxt):
        return self.cast(ctxt, self.make_msg('trigger_firmware_audit'))

    def trigger_kube_rootca_update_audit(self, ctxt):
        return self.cast(ctxt,
                         self.make_msg('trigger_kube_rootca_update_audit'))

    def trigger_kubernetes_audit(self, ctxt):
        return self.cast(ctxt, self.make_msg('trigger_kubernetes_audit'))

    def trigger_patch_audit(self, ctxt):
        return self.cast(ctxt, self.make_msg('trigger_patch_audit'))

    def trigger_load_audit(self, ctxt):
        return self.cast(ctxt, self.make_msg('trigger_load_audit'))

    def trigger_subcloud_audits(self, ctxt, subcloud_id, exclude_endpoints=None):
        return self.cast(ctxt, self.make_msg('trigger_subcloud_audits',
                                             subcloud_id=subcloud_id,
                                             exclude_endpoints=exclude_endpoints))

    def trigger_subcloud_patch_load_audits(self, ctxt, subcloud_id):
        return self.cast(ctxt, self.make_msg('trigger_subcloud_patch_load_audits',
                                             subcloud_id=subcloud_id))


class ManagerAuditWorkerClient(object):
    """Client side of the DC Manager Audit Worker rpc API.

    Version History:
     1.0 - Initial version
    """

    # todo(abailey): Does the RPC version need to increment
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        self._client = messaging.get_rpc_client(
            topic=consts.TOPIC_DC_MANAGER_AUDIT_WORKER,
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

    def audit_subclouds(self,
                        ctxt,
                        subcloud_ids,
                        patch_audit_data=None,
                        firmware_audit_data=None,
                        kubernetes_audit_data=None,
                        do_openstack_audit=False,
                        kube_rootca_update_data=None):
        """Tell audit-worker to perform audit on the subclouds with these

           subcloud IDs.
        """
        return self.cast(ctxt, self.make_msg(
            'audit_subclouds',
            subcloud_ids=subcloud_ids,
            patch_audit_data=patch_audit_data,
            firmware_audit_data=firmware_audit_data,
            kubernetes_audit_data=kubernetes_audit_data,
            do_openstack_audit=do_openstack_audit,
            kube_rootca_update_audit_data=kube_rootca_update_data))
