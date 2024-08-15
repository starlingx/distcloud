# Copyright (c) 2017-2024 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
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

    def __init__(self, timeout, topic, version):
        self._client = messaging.get_rpc_client(
            timeout=timeout, topic=topic, version=version
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
        if fanout or version:
            client = self._client.prepare(fanout=fanout, version=version)
        else:
            client = self._client
        return client.cast(ctxt, method, **kwargs)


class SubcloudStateClient(RPCClient):
    """Client to update subcloud availability."""

    BASE_RPC_API_VERSION = "1.0"

    def __init__(self, timeout=None):
        super(SubcloudStateClient, self).__init__(
            timeout, consts.TOPIC_DC_MANAGER_STATE, self.BASE_RPC_API_VERSION
        )

    def bulk_update_subcloud_availability_and_endpoint_status(
        self, ctxt, subcloud_name, subcloud_region, availability_data, endpoint_data
    ):
        # Note: This is an asynchronous operation.
        return self.cast(
            ctxt,
            self.make_msg(
                "bulk_update_subcloud_availability_and_endpoint_status",
                subcloud_name=subcloud_name,
                subcloud_region=subcloud_region,
                availability_data=availability_data,
                endpoint_data=endpoint_data,
            ),
        )

    def update_subcloud_availability(
        self,
        ctxt,
        subcloud_name,
        subcloud_region,
        availability_status,
        update_state_only=False,
        audit_fail_count=None,
    ):
        # Note: synchronous
        return self.call(
            ctxt,
            self.make_msg(
                "update_subcloud_availability",
                subcloud_name=subcloud_name,
                subcloud_region=subcloud_region,
                availability_status=availability_status,
                update_state_only=update_state_only,
                audit_fail_count=audit_fail_count,
            ),
        )

    def update_subcloud_endpoint_status(
        self,
        ctxt,
        subcloud_name=None,
        subcloud_region=None,
        endpoint_type=None,
        sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        ignore_endpoints=None,
        alarmable=True,
    ):
        # Note: This is an asynchronous operation.
        # See below for synchronous method call
        return self.cast(
            ctxt,
            self.make_msg(
                "update_subcloud_endpoint_status",
                subcloud_name=subcloud_name,
                subcloud_region=subcloud_region,
                endpoint_type=endpoint_type,
                sync_status=sync_status,
                ignore_endpoints=ignore_endpoints,
                alarmable=alarmable,
            ),
        )

    def update_subcloud_endpoint_status_sync(
        self,
        ctxt,
        subcloud_name=None,
        subcloud_region=None,
        endpoint_type=None,
        sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        ignore_endpoints=None,
        alarmable=True,
    ):
        # Note: synchronous
        return self.call(
            ctxt,
            self.make_msg(
                "update_subcloud_endpoint_status",
                subcloud_name=subcloud_name,
                subcloud_region=subcloud_region,
                endpoint_type=endpoint_type,
                sync_status=sync_status,
                ignore_endpoints=ignore_endpoints,
                alarmable=alarmable,
            ),
        )


class ManagerClient(RPCClient):
    """Client side of the DC Manager rpc API.

    Version History:
     1.0 - Initial version (Mitaka 1.0 release)
    """

    BASE_RPC_API_VERSION = "1.0"

    def __init__(self, timeout=None):
        super(ManagerClient, self).__init__(
            timeout, consts.TOPIC_DC_MANAGER, self.BASE_RPC_API_VERSION
        )

    def add_subcloud(self, ctxt, subcloud_id, payload):
        return self.cast(
            ctxt,
            self.make_msg("add_subcloud", subcloud_id=subcloud_id, payload=payload),
        )

    def add_secondary_subcloud(self, ctxt, subcloud_id, payload):
        return self.call(
            ctxt,
            self.make_msg(
                "add_secondary_subcloud", subcloud_id=subcloud_id, payload=payload
            ),
        )

    def delete_subcloud(self, ctxt, subcloud_id):
        return self.call(
            ctxt, self.make_msg("delete_subcloud", subcloud_id=subcloud_id)
        )

    def rename_subcloud(
        self, ctxt, subcloud_id, curr_subcloud_name, new_subcloud_name=None
    ):
        return self.call(
            ctxt,
            self.make_msg(
                "rename_subcloud",
                subcloud_id=subcloud_id,
                curr_subcloud_name=curr_subcloud_name,
                new_subcloud_name=new_subcloud_name,
            ),
        )

    def update_subcloud(
        self,
        ctxt,
        subcloud_id,
        management_state=None,
        description=None,
        location=None,
        group_id=None,
        data_install=None,
        force=None,
        deploy_status=None,
        peer_group_id=None,
        bootstrap_values=None,
        bootstrap_address=None,
    ):
        return self.call(
            ctxt,
            self.make_msg(
                "update_subcloud",
                subcloud_id=subcloud_id,
                management_state=management_state,
                description=description,
                location=location,
                group_id=group_id,
                data_install=data_install,
                force=force,
                deploy_status=deploy_status,
                peer_group_id=peer_group_id,
                bootstrap_values=bootstrap_values,
                bootstrap_address=bootstrap_address,
            ),
        )

    def update_subcloud_with_network_reconfig(self, ctxt, subcloud_id, payload):
        return self.cast(
            ctxt,
            self.make_msg(
                "update_subcloud_with_network_reconfig",
                subcloud_id=subcloud_id,
                payload=payload,
            ),
        )

    def redeploy_subcloud(self, ctxt, subcloud_id, payload, previous_version):
        return self.cast(
            ctxt,
            self.make_msg(
                "redeploy_subcloud",
                subcloud_id=subcloud_id,
                payload=payload,
                previous_version=previous_version,
            ),
        )

    def backup_subclouds(self, ctxt, payload):
        return self.cast(ctxt, self.make_msg("backup_subclouds", payload=payload))

    def delete_subcloud_backups(self, ctxt, release_version, payload):
        return self.call(
            ctxt,
            self.make_msg(
                "delete_subcloud_backups",
                release_version=release_version,
                payload=payload,
            ),
        )

    def restore_subcloud_backups(self, ctxt, payload):
        return self.cast(
            ctxt, self.make_msg("restore_subcloud_backups", payload=payload)
        )

    def update_subcloud_sync_endpoint_type(
        self, ctxt, subcloud_region, endpoint_type_list, openstack_installed
    ):
        return self.cast(
            ctxt,
            self.make_msg(
                "update_subcloud_sync_endpoint_type",
                subcloud_region=subcloud_region,
                endpoint_type_list=endpoint_type_list,
                openstack_installed=openstack_installed,
            ),
        )

    def prestage_subcloud(self, ctxt, payload):
        return self.call(ctxt, self.make_msg("prestage_subcloud", payload=payload))

    def subcloud_deploy_create(self, ctxt, subcloud_id, payload):
        return self.call(
            ctxt,
            self.make_msg(
                "subcloud_deploy_create", subcloud_id=subcloud_id, payload=payload
            ),
        )

    def subcloud_deploy_install(
        self, ctxt, subcloud_id, payload, initial_deployment, previous_version
    ):
        return self.cast(
            ctxt,
            self.make_msg(
                "subcloud_deploy_install",
                subcloud_id=subcloud_id,
                payload=payload,
                initial_deployment=initial_deployment,
                previous_version=previous_version,
            ),
        )

    def subcloud_deploy_enroll(self, ctxt, subcloud_id, payload):
        return self.cast(
            ctxt,
            self.make_msg(
                "subcloud_deploy_enroll", subcloud_id=subcloud_id, payload=payload
            ),
        )

    def subcloud_deploy_bootstrap(self, ctxt, subcloud_id, payload, initial_deployment):
        return self.cast(
            ctxt,
            self.make_msg(
                "subcloud_deploy_bootstrap",
                subcloud_id=subcloud_id,
                payload=payload,
                initial_deployment=initial_deployment,
            ),
        )

    def subcloud_deploy_config(self, ctxt, subcloud_id, payload, initial_deployment):
        return self.cast(
            ctxt,
            self.make_msg(
                "subcloud_deploy_config",
                subcloud_id=subcloud_id,
                payload=payload,
                initial_deployment=initial_deployment,
            ),
        )

    def subcloud_deploy_complete(self, ctxt, subcloud_id):
        return self.call(
            ctxt, self.make_msg("subcloud_deploy_complete", subcloud_id=subcloud_id)
        )

    def subcloud_deploy_abort(self, ctxt, subcloud_id, deploy_status):
        return self.cast(
            ctxt,
            self.make_msg(
                "subcloud_deploy_abort",
                subcloud_id=subcloud_id,
                deploy_status=deploy_status,
            ),
        )

    def subcloud_deploy_resume(
        self,
        ctxt,
        subcloud_id,
        subcloud_name,
        payload,
        deploy_states_to_run,
        previous_version,
    ):
        return self.cast(
            ctxt,
            self.make_msg(
                "subcloud_deploy_resume",
                subcloud_id=subcloud_id,
                subcloud_name=subcloud_name,
                payload=payload,
                deploy_states_to_run=deploy_states_to_run,
                previous_version=previous_version,
            ),
        )

    def get_subcloud_name_by_region_name(self, ctxt, subcloud_region):
        return self.call(
            ctxt,
            self.make_msg(
                "get_subcloud_name_by_region_name", subcloud_region=subcloud_region
            ),
        )

    def batch_migrate_subcloud(self, ctxt, payload):
        return self.cast(ctxt, self.make_msg("batch_migrate_subcloud", payload=payload))

    def sync_subcloud_peer_group(self, ctxt, association_id):
        return self.cast(
            ctxt,
            self.make_msg("sync_subcloud_peer_group", association_id=association_id),
        )

    def sync_subcloud_peer_group_only(self, ctxt, association_id):
        # Without synchronizing subclouds
        return self.call(
            ctxt,
            self.make_msg(
                "sync_subcloud_peer_group",
                association_id=association_id,
                sync_subclouds=False,
            ),
        )

    def update_subcloud_peer_group(
        self,
        ctxt,
        peer_group_id,
        group_state,
        max_subcloud_rehoming,
        group_name,
        new_group_name=None,
    ):
        return self.call(
            ctxt,
            self.make_msg(
                "update_subcloud_peer_group",
                peer_group_id=peer_group_id,
                group_state=group_state,
                max_subcloud_rehoming=max_subcloud_rehoming,
                group_name=group_name,
                new_group_name=new_group_name,
            ),
        )

    def delete_peer_group_association(self, ctxt, association_id):
        return self.call(
            ctxt,
            self.make_msg(
                "delete_peer_group_association", association_id=association_id
            ),
        )

    def update_association_sync_status(
        self, ctxt, peer_group_id, sync_status, sync_message=None
    ):
        return self.call(
            ctxt,
            self.make_msg(
                "update_association_sync_status",
                peer_group_id=peer_group_id,
                sync_status=sync_status,
                sync_message=sync_message,
            ),
        )

    def peer_monitor_notify(self, ctxt):
        return self.call(ctxt, self.make_msg("peer_monitor_notify"))

    def peer_group_audit_notify(self, ctxt, peer_group_name, payload):
        return self.call(
            ctxt,
            self.make_msg(
                "peer_group_audit_notify",
                peer_group_name=peer_group_name,
                payload=payload,
            ),
        )


class DCManagerNotifications(RPCClient):
    """DC Manager Notification interface to broadcast subcloud state changed

    Version History:
       1.0 - Initial version
    """

    DCMANAGER_RPC_API_VERSION = "1.0"
    TOPIC_DC_NOTIFICIATION = "DCMANAGER-NOTIFICATION"

    def __init__(self, timeout=None):
        super(DCManagerNotifications, self).__init__(
            timeout, self.TOPIC_DC_NOTIFICIATION, self.DCMANAGER_RPC_API_VERSION
        )

    def subcloud_online(self, ctxt, subcloud_name):
        return self.cast(
            ctxt, self.make_msg("subcloud_online", subcloud_name=subcloud_name)
        )

    def subcloud_managed(self, ctxt, subcloud_name):
        return self.cast(
            ctxt, self.make_msg("subcloud_managed", subcloud_name=subcloud_name)
        )

    def subcloud_sysinv_endpoint_update(self, ctxt, subcloud_name, endpoint):
        return self.cast(
            ctxt,
            self.make_msg(
                "subcloud_sysinv_endpoint_update",
                subcloud_name=subcloud_name,
                endpoint=endpoint,
            ),
            fanout=True,
            version=self.DCMANAGER_RPC_API_VERSION,
        )
