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
# Copyright (c) 2017-2022 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import functools
import six

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service

from dcorch.common import consts as dcorch_consts

from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import messaging as rpc_messaging
from dcmanager.state.subcloud_state_manager import SubcloudStateManager

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


class DCManagerStateService(service.Service):
    """Lifecycle manager for a running service.

    - All the methods in here are called from the RPC client.
    - If a RPC call does not have a corresponding method here, an exception
      will be thrown.
    - Arguments to these calls are added dynamically and will be treated as
      keyword arguments by the RPC client.
    """

    def __init__(self, host):
        super(DCManagerStateService, self).__init__()
        self.host = cfg.CONF.host
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_DC_MANAGER_STATE
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.engine_id = None
        self.target = None
        self._rpc_server = None
        self.subcloud_state_manager = None
        self.audit_rpc_client = None

    def _init_managers(self):
        self.subcloud_state_manager = SubcloudStateManager()

    def start(self):
        LOG.info("Starting %s", self.__class__.__name__)
        self._init_managers()
        target = oslo_messaging.Target(version=self.rpc_api_version,
                                       server=self.host,
                                       topic=self.topic)
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()
        # Used to notify dcmanager-audit
        self.audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()

        super(DCManagerStateService, self).start()

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
        LOG.info("Stopping %s", self.__class__.__name__)
        self._stop_rpc_server()
        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super(DCManagerStateService, self).stop()

    @request_context
    def update_subcloud_endpoint_status(self, context, subcloud_name=None,
                                        endpoint_type=None,
                                        sync_status=consts.
                                        SYNC_STATUS_OUT_OF_SYNC,
                                        alarmable=True,
                                        ignore_endpoints=None):
        # Updates subcloud endpoint sync status
        LOG.info("Handling update_subcloud_endpoint_status request for "
                 "subcloud: (%s) endpoint: (%s) status:(%s) "
                 % (subcloud_name, endpoint_type, sync_status))

        self.subcloud_state_manager. \
            update_subcloud_endpoint_status(context,
                                            subcloud_name,
                                            endpoint_type,
                                            sync_status,
                                            alarmable,
                                            ignore_endpoints)

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

        # If the kubernetes sync status is being set to unknown, trigger the
        # kubernetes audit so it can update the sync status ASAP.
        if endpoint_type == dcorch_consts.ENDPOINT_TYPE_KUBERNETES and \
                sync_status == consts.SYNC_STATUS_UNKNOWN:
            self.audit_rpc_client.trigger_kubernetes_audit(context)

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
        self.subcloud_state_manager.update_subcloud_availability(
            context,
            subcloud_name,
            availability_status,
            update_state_only,
            audit_fail_count)
