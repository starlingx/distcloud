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

import os
import six

import functools
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service
from oslo_utils import uuidutils

from dccommon.subprocess_cleanup import SubprocessCleanup
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import messaging as rpc_messaging
from dcmanager.manager.subcloud_manager import SubcloudManager

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
        self.target = None
        self._rpc_server = None
        self.subcloud_manager = None
        self.audit_rpc_client = None

    def init_managers(self):
        self.subcloud_manager = SubcloudManager()

    def start(self):
        self.dcmanager_id = uuidutils.generate_uuid()
        self.init_managers()
        target = oslo_messaging.Target(version=self.rpc_api_version,
                                       server=self.host,
                                       topic=self.topic)
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()
        # Used to notify dcmanager-audit
        self.audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()

        if not os.path.isdir(consts.DC_ANSIBLE_LOG_DIR):
            os.mkdir(consts.DC_ANSIBLE_LOG_DIR, 0o755)

        self.subcloud_manager.handle_subcloud_operations_in_progress()
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
        return subcloud

    @request_context
    def reconfigure_subcloud(self, context, subcloud_id, payload):
        # Reconfigures a subcloud
        LOG.info("Handling reconfigure_subcloud request for: %s" % subcloud_id)
        return self.subcloud_manager.reconfigure_subcloud(context,
                                                          subcloud_id,
                                                          payload)

    @request_context
    def reinstall_subcloud(self, context, subcloud_id, payload):
        # Reinstall a subcloud
        LOG.info("Handling reinstall_subcloud request for: %s" % subcloud_id)
        return self.subcloud_manager.reinstall_subcloud(context,
                                                        subcloud_id,
                                                        payload)

    @request_context
    def restore_subcloud(self, context, subcloud_id, payload):
        # Restore a subcloud
        LOG.info("Handling restore_subcloud request for: %s" % subcloud_id)
        return self.subcloud_manager.restore_subcloud(context,
                                                      subcloud_id,
                                                      payload)

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
    def prestage_subcloud(self, context, payload):
        LOG.info("Handling prestage_subcloud request for: %s",
                 payload['subcloud_name'])
        return self.subcloud_manager.prestage_subcloud(context, payload)

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug(_("Attempting to stop RPC service..."))
        try:
            self._rpc_server.stop()
            self._rpc_server.wait()
            LOG.info('RPC service stopped successfully')
        except Exception as ex:
            LOG.error('Failed to stop RPC service: %s',
                      six.text_type(ex))

    def stop(self):
        SubprocessCleanup.shutdown_cleanup(origin="service")
        self._stop_rpc_server()
        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super(DCManagerService, self).stop()
