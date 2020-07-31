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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import six

import functools
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service
from oslo_utils import uuidutils

from dcorch.common import consts as dcorch_consts

from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import messaging as rpc_messaging
from dcmanager.common import scheduler
from dcmanager.manager.subcloud_manager import SubcloudManager
from dcmanager.manager.sw_update_manager import SwUpdateManager

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def request_context(func):
    @functools.wraps(func)
    def wrapped(self, ctx, *args, **kwargs):
        if ctx is not None and not isinstance(ctx, context.RequestContext):
            ctx = context.RequestContext.from_dict(ctx.to_dict())
        try:
            return func(self, ctx, *args, **kwargs)
        except exceptions.DCManagerException:
            raise oslo_messaging.rpc.dispatcher.ExpectedException()

    return wrapped


class DCManagerService(service.Service):
    """Lifecycle manager for a running service.

    - All the methods in here are called from the RPC client.
    - If a RPC call does not have a corresponding method here, an exception
      will be thrown.
    - Arguments to these calls are added dynamically and will be treated as
      keyword arguments by the RPC client.
    """

    def __init__(self, host, topic, manager=None):

        super(DCManagerService, self).__init__()
        self.host = cfg.CONF.host
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_DC_MANAGER
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.engine_id = None
        self.TG = None
        self.target = None
        self._rpc_server = None
        self.subcloud_manager = None
        self.sw_update_manager = None
        self.audit_rpc_client = None

    def init_tgm(self):
        self.TG = scheduler.ThreadGroupManager()

    def init_managers(self):
        self.subcloud_manager = SubcloudManager()
        self.sw_update_manager = SwUpdateManager()

    def stop_managers(self):
        self.sw_update_manager.stop()

    def start(self):
        self.dcmanager_id = uuidutils.generate_uuid()
        self.init_tgm()
        self.init_managers()
        target = oslo_messaging.Target(version=self.rpc_api_version,
                                       server=self.host,
                                       topic=self.topic)
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()
        # Used to notify dcmanager-audit
        self.audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()

        super(DCManagerService, self).start()

    @request_context
    def add_subcloud(self, context, payload):
        # Adds a subcloud
        LOG.info("Handling add_subcloud request for: %s" % payload.get('name'))
        return self.subcloud_manager.add_subcloud(context, payload)

    @request_context
    def delete_subcloud(self, context, subcloud_id):
        # Deletes a subcloud
        LOG.info("Handling delete_subcloud request for: %s" % subcloud_id)
        return self.subcloud_manager.delete_subcloud(context, subcloud_id)

    @request_context
    def update_subcloud(self, context, subcloud_id, management_state=None,
                        description=None, location=None, group_id=None,
                        data_install=None, force=None):
        # Updates a subcloud
        LOG.info("Handling update_subcloud request for: %s" % subcloud_id)
        subcloud = self.subcloud_manager.update_subcloud(context, subcloud_id,
                                                         management_state,
                                                         description,
                                                         location,
                                                         group_id,
                                                         data_install,
                                                         force)
        # If a subcloud has been set to the managed state, trigger the
        # patching audit and firmware audit so it can update the
        # sync status ASAP.
        if management_state == consts.MANAGEMENT_MANAGED:
            self.audit_rpc_client.trigger_patch_audit(context)
            self.audit_rpc_client.trigger_firmware_audit(context)

        return subcloud

    @request_context
    def reconfigure_subcloud(self, context, subcloud_id, payload):
        # Reconfigures a subcloud
        LOG.info("Handling reconfigure_subcloud request for: %s" % subcloud_id)
        return self.subcloud_manager.reconfigure_subcloud(context,
                                                          subcloud_id,
                                                          payload)

    @request_context
    def update_subcloud_endpoint_status(self, context, subcloud_name=None,
                                        endpoint_type=None,
                                        sync_status=consts.
                                        SYNC_STATUS_OUT_OF_SYNC,
                                        alarmable=True):
        # Updates subcloud endpoint sync status
        LOG.info("Handling update_subcloud_endpoint_status request for: %s" %
                 subcloud_name)

        self.subcloud_manager. \
            update_subcloud_endpoint_status(context,
                                            subcloud_name,
                                            endpoint_type,
                                            sync_status,
                                            alarmable)

        # If the patching sync status is being set to unknown, trigger the
        # patching audit so it can update the sync status ASAP.
        if endpoint_type == dcorch_consts.ENDPOINT_TYPE_PATCHING and \
                sync_status == consts.SYNC_STATUS_UNKNOWN:
            self.audit_rpc_client.trigger_patch_audit(context)

        # If the firmware sync status is being set to unknown, trigger the
        # firmware audit so it can update the sync status ASAP.
        if endpoint_type == dcorch_consts.ENDPOINT_TYPE_FIRMWARE and \
                sync_status == consts.SYNC_STATUS_UNKNOWN:
            self.audit_rpc_client.trigger_firmware_audit(context)

        return

    @request_context
    def update_subcloud_availability(self, context,
                                     subcloud_name,
                                     availability_status,
                                     update_state_only=False,
                                     audit_fail_count=None):
        # Updates subcloud availability
        LOG.info("Handling update_subcloud_availability request for: %s" %
                 subcloud_name)
        self.subcloud_manager.update_subcloud_availability(
            context,
            subcloud_name,
            availability_status,
            update_state_only,
            audit_fail_count)

    @request_context
    def update_subcloud_sync_endpoint_type(self, context, subcloud_name,
                                           endpoint_type_list,
                                           openstack_installed):
        # Updates subcloud sync endpoint type
        LOG.info("Handling update_subcloud_sync_endpoint_type request for: %s"
                 % subcloud_name)
        self.subcloud_manager.update_subcloud_sync_endpoint_type(
            context, subcloud_name, endpoint_type_list, openstack_installed)

    @request_context
    def create_sw_update_strategy(self, context, payload):
        # Creates a software update strategy
        LOG.info("Handling create_sw_update_strategy request of type %s" %
                 payload.get('type'))
        return self.sw_update_manager.create_sw_update_strategy(
            context, payload)

    @request_context
    def delete_sw_update_strategy(self, context, update_type=None):
        # Deletes the software update strategy
        LOG.info("Handling delete_sw_update_strategy request")
        return self.sw_update_manager.delete_sw_update_strategy(
            context,
            update_type=update_type)

    @request_context
    def apply_sw_update_strategy(self, context, update_type=None):
        # Applies the software update strategy
        LOG.info("Handling apply_sw_update_strategy request")
        return self.sw_update_manager.apply_sw_update_strategy(
            context,
            update_type=update_type)

    @request_context
    def abort_sw_update_strategy(self, context, update_type=None):
        # Aborts the software update strategy
        LOG.info("Handling abort_sw_update_strategy request")
        return self.sw_update_manager.abort_sw_update_strategy(
            context,
            update_type=update_type)

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug(_("Attempting to stop engine service..."))
        try:
            self._rpc_server.stop()
            self._rpc_server.wait()
            LOG.info('Engine service stopped successfully')
        except Exception as ex:
            LOG.error('Failed to stop engine service: %s',
                      six.text_type(ex))

    def stop(self):
        self._stop_rpc_server()

        self.TG.stop()
        self.stop_managers()

        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super(DCManagerService, self).stop()
