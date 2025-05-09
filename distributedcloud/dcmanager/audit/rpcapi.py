# Copyright (c) 2020-2025 Wind River Systems, Inc.
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
Client side of the DC Manager Audit RPC API.
"""

from dcmanager.common import consts
from dcmanager.common import messaging


class ManagerAuditClient(object):
    """Client side of the DC Manager Audit rpc API.

    Version History:
     1.0 - Initial version
    """

    BASE_RPC_API_VERSION = "1.0"

    def __init__(self, timeout=None):
        self._client = messaging.get_rpc_client(
            timeout=timeout,
            topic=consts.TOPIC_DC_MANAGER_AUDIT,
            version=self.BASE_RPC_API_VERSION,
        )

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
        return self.cast(ctxt, self.make_msg("trigger_firmware_audit"))

    def trigger_kube_rootca_update_audit(self, ctxt):
        return self.cast(ctxt, self.make_msg("trigger_kube_rootca_update_audit"))

    def trigger_kubernetes_audit(self, ctxt):
        return self.cast(ctxt, self.make_msg("trigger_kubernetes_audit"))

    def trigger_software_audit(self, ctxt):
        return self.cast(ctxt, self.make_msg("trigger_software_audit"))

    def trigger_subcloud_audits(self, ctxt, subcloud_id, exclude_endpoints=None):
        return self.cast(
            ctxt,
            self.make_msg(
                "trigger_subcloud_audits",
                subcloud_id=subcloud_id,
                exclude_endpoints=exclude_endpoints,
            ),
        )

    def trigger_subcloud_endpoints_update(self, ctxt, subcloud_name, endpoints):
        return self.cast(
            ctxt,
            self.make_msg(
                "trigger_subcloud_endpoints_update",
                subcloud_name=subcloud_name,
                endpoints=endpoints,
            ),
        )


class ManagerAuditWorkerClient(object):
    """Client side of the DC Manager Audit Worker rpc API.

    Version History:
     1.0 - Initial version
    """

    # todo(abailey): Does the RPC version need to increment
    BASE_RPC_API_VERSION = "1.0"

    def __init__(self, timeout=None):
        self._client = messaging.get_rpc_client(
            timeout=timeout,
            topic=consts.TOPIC_DC_MANAGER_AUDIT_WORKER,
            version=self.BASE_RPC_API_VERSION,
        )

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

    def cast(self, ctxt, msg, fanout=None, version=None):
        method, kwargs = msg
        if version or fanout:
            client = self._client.prepare(fanout=fanout, version=version)
        else:
            client = self._client
        return client.cast(ctxt, method, **kwargs)

    def audit_subclouds(
        self,
        ctxt,
        subcloud_ids,
        firmware_audit_data=None,
        kubernetes_audit_data=None,
        kube_rootca_update_data=None,
        software_audit_data=None,
        use_cache=True,
    ):
        """Tell audit-worker to perform audit on the subclouds with these

        subcloud IDs.
        """
        return self.cast(
            ctxt,
            self.make_msg(
                "audit_subclouds",
                subcloud_ids=subcloud_ids,
                firmware_audit_data=firmware_audit_data,
                kubernetes_audit_data=kubernetes_audit_data,
                kube_rootca_update_audit_data=kube_rootca_update_data,
                software_audit_data=software_audit_data,
                use_cache=use_cache,
            ),
        )

    def update_subcloud_endpoints(self, ctxt, subcloud_name, endpoints):
        """Update endpoints of services for a subcloud region"""
        return self.cast(
            ctxt,
            self.make_msg(
                "update_subcloud_endpoints",
                subcloud_name=subcloud_name,
                endpoints=endpoints,
            ),
            fanout=True,
            version=self.BASE_RPC_API_VERSION,
        )
