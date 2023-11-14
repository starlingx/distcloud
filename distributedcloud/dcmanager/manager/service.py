# Copyright (c) 2017-2023 Wind River Systems, Inc.
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
import threading

import functools
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service
from oslo_utils import uuidutils

from dccommon import consts as dccommon_consts
from dccommon.subprocess_cleanup import SubprocessCleanup
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import messaging as rpc_messaging
from dcmanager.common import utils
from dcmanager.manager.peer_monitor_manager import PeerMonitorManager
from dcmanager.manager.subcloud_manager import SubcloudManager
from dcmanager.manager.system_peer_manager import SystemPeerManager

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


# The RPC server has a thread limit (defaults to 64), by manually
# threading the functions the RPC cast returns earlier, allowing to
# run multiple operations in parallel past the RPC limit.
def run_in_thread(fn):
    """Decorator to run a function in a separate thread."""
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
    return wrapper


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
        self.peer_monitor_manager = None
        self.system_peer_manager = None
        self.audit_rpc_client = None
        self.context = context.get_admin_context()

    def init_managers(self):
        self.subcloud_manager = SubcloudManager()
        self.peer_monitor_manager = PeerMonitorManager(self.subcloud_manager)
        self.system_peer_manager = SystemPeerManager(self.peer_monitor_manager)

    def start(self):
        utils.set_open_file_limit(cfg.CONF.worker_rlimit_nofile)
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

        os.makedirs(dccommon_consts.ANSIBLE_OVERRIDES_PATH, 0o600, exist_ok=True)

        self.subcloud_manager.handle_subcloud_operations_in_progress()

        # Send notify to peer monitor.
        self.peer_monitor_manager.peer_monitor_notify(self.context)

        super(DCManagerService, self).start()

    @run_in_thread
    @request_context
    def add_subcloud(self, context, subcloud_id, payload):
        # Adds a subcloud
        LOG.info("Handling add_subcloud request for: %s" % payload.get('name'))
        return self.subcloud_manager.add_subcloud(context, subcloud_id, payload)

    @request_context
    def add_secondary_subcloud(self, context, subcloud_id, payload):
        # Adds a secondary subcloud
        LOG.info("Handling add_secondary_subcloud request for: %s" %
                 payload.get('name'))
        return self.subcloud_manager.add_subcloud(context, subcloud_id, payload)

    @request_context
    def delete_subcloud(self, context, subcloud_id):
        # Deletes a subcloud
        LOG.info("Handling delete_subcloud request for: %s" % subcloud_id)
        return self.subcloud_manager.delete_subcloud(context, subcloud_id)

    @request_context
    def rename_subcloud(self, context, subcloud_id, curr_subcloud_name,
                        new_subcloud_name=None):
        # Rename a subcloud
        LOG.info("Handling rename_subcloud request for: %s" %
                 curr_subcloud_name)
        subcloud = self.subcloud_manager.rename_subcloud(context,
                                                         subcloud_id,
                                                         curr_subcloud_name,
                                                         new_subcloud_name)
        return subcloud

    @request_context
    def get_subcloud_name_by_region_name(self, context, subcloud_region):
        # get subcloud by region name
        LOG.debug("Handling get_subcloud_name_by_region_name request for "
                  "region: %s" % subcloud_region)
        subcloud = self.subcloud_manager.get_subcloud_name_by_region_name(context,
                                                                          subcloud_region)
        return subcloud

    @request_context
    def update_subcloud(self, context, subcloud_id, management_state=None,
                        description=None, location=None,
                        group_id=None, data_install=None, force=None,
                        deploy_status=None,
                        peer_group_id=None, bootstrap_values=None, bootstrap_address=None):
        # Updates a subcloud
        LOG.info("Handling update_subcloud request for: %s" % subcloud_id)
        subcloud = self.subcloud_manager.update_subcloud(context, subcloud_id,
                                                         management_state,
                                                         description,
                                                         location,
                                                         group_id,
                                                         data_install,
                                                         force,
                                                         deploy_status,
                                                         peer_group_id,
                                                         bootstrap_values,
                                                         bootstrap_address)
        return subcloud

    @request_context
    def update_subcloud_with_network_reconfig(self, context, subcloud_id, payload):
        LOG.info("Handling update_subcloud_with_network_reconfig request for: %s",
                 subcloud_id)
        return self.subcloud_manager.update_subcloud_with_network_reconfig(context,
                                                                           subcloud_id,
                                                                           payload)

    @run_in_thread
    @request_context
    def redeploy_subcloud(self, context, subcloud_id, payload):
        # Redeploy a subcloud
        LOG.info("Handling redeploy_subcloud request for: %s" % subcloud_id)
        return self.subcloud_manager.redeploy_subcloud(context,
                                                       subcloud_id,
                                                       payload)

    @request_context
    def backup_subclouds(self, context, payload):
        # Backup a subcloud or group of subclouds
        entity = 'subcloud' if payload.get('subcloud') else 'group'
        LOG.info("Handling backup_subclouds request for %s ID: %s" %
                 (entity, (payload.get('subcloud') or payload.get('group'))))
        return self.subcloud_manager.create_subcloud_backups(context, payload)

    @request_context
    def delete_subcloud_backups(self, context, release_version, payload):
        # Delete backup on subcloud or group of subclouds
        entity = 'subcloud' if payload.get('subcloud') else 'group'
        LOG.info("Handling delete_subcloud_backups request for %s ID: %s" %
                 (entity, (payload.get('subcloud') or payload.get('group'))))
        return self.subcloud_manager.delete_subcloud_backups(context,
                                                             release_version,
                                                             payload)

    @request_context
    def restore_subcloud_backups(self, context, payload):
        # Restore a subcloud backup or a group of subclouds backups
        entity = 'subcloud' if payload.get('subcloud') else 'group'
        LOG.info("Handling restore_subcloud_backups request for %s ID: %s" %
                 (entity, (payload.get('subcloud') or payload.get('group'))))
        return self.subcloud_manager.restore_subcloud_backups(context, payload)

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

    @request_context
    def subcloud_deploy_create(self, context, subcloud_id, payload):
        # Adds a subcloud
        LOG.info("Handling subcloud_deploy_create request for: %s" %
                 payload.get('name'))
        return self.subcloud_manager.subcloud_deploy_create(context,
                                                            subcloud_id,
                                                            payload)

    @run_in_thread
    @request_context
    def subcloud_deploy_bootstrap(self, context, subcloud_id, payload,
                                  initial_deployment):
        # Bootstraps a subcloud
        LOG.info("Handling subcloud_deploy_bootstrap request for: %s" %
                 payload.get('name'))
        return self.subcloud_manager.subcloud_deploy_bootstrap(
            context, subcloud_id, payload, initial_deployment)

    @run_in_thread
    @request_context
    def subcloud_deploy_config(self, context, subcloud_id, payload,
                               initial_deployment):
        # Configures a subcloud
        LOG.info("Handling subcloud_deploy_config request for: %s" % subcloud_id)
        return self.subcloud_manager.subcloud_deploy_config(
            context, subcloud_id, payload, initial_deployment)

    @run_in_thread
    @request_context
    def subcloud_deploy_install(self, context, subcloud_id, payload,
                                initial_deployment):
        # Install a subcloud
        LOG.info("Handling subcloud_deploy_install request for: %s" % subcloud_id)
        return self.subcloud_manager.subcloud_deploy_install(
            context, subcloud_id, payload, initial_deployment)

    @request_context
    def subcloud_deploy_complete(self, context, subcloud_id):
        # Complete the subcloud deployment
        LOG.info("Handling subcloud_deploy_complete request for: %s" % subcloud_id)
        return self.subcloud_manager.subcloud_deploy_complete(context, subcloud_id)

    @run_in_thread
    @request_context
    def subcloud_deploy_abort(self, context, subcloud_id, deploy_status):
        # Abort the subcloud deployment
        LOG.info("Handling subcloud_deploy_abort request for: %s" % subcloud_id)
        return self.subcloud_manager.subcloud_deploy_abort(context,
                                                           subcloud_id,
                                                           deploy_status)

    @request_context
    def migrate_subcloud(self, context, subcloud_ref, payload):
        LOG.info("Handling migrate_subcloud request for: %s",
                 subcloud_ref)
        return self.subcloud_manager.migrate_subcloud(context, subcloud_ref, payload)

    @run_in_thread
    @request_context
    def subcloud_deploy_resume(self, context, subcloud_id, subcloud_name,
                               payload, deploy_states_to_run):
        # Adds a subcloud
        LOG.info("Handling subcloud_deploy_resume request for: %s" % subcloud_name)
        return self.subcloud_manager.subcloud_deploy_resume(context,
                                                            subcloud_id,
                                                            subcloud_name,
                                                            payload,
                                                            deploy_states_to_run)

    @request_context
    def batch_migrate_subcloud(self, context, payload):
        LOG.info("Handling batch_migrate_subcloud request for peer_group: %s",
                 payload['peer_group'])
        return self.subcloud_manager.batch_migrate_subcloud(context, payload)

    @request_context
    def peer_monitor_notify(self, context):
        LOG.info("Handling peer monitor notify")
        return self.peer_monitor_manager.peer_monitor_notify(context)

    @request_context
    def peer_group_audit_notify(self, context, peer_group_name, payload):
        LOG.info("Handling peer group audit notify of peer group "
                 f"{peer_group_name}")
        return self.peer_monitor_manager.peer_group_audit_notify(
            context, peer_group_name, payload)

    @request_context
    def sync_subcloud_peer_group(self, context, association_id,
                                 sync_subclouds=True, priority=None):
        LOG.info("Handling sync_subcloud_peer_group request for: %s",
                 association_id)
        return self.system_peer_manager.sync_subcloud_peer_group(
            context, association_id, sync_subclouds, priority)

    @request_context
    def delete_peer_group_association(self, context, association_id):
        LOG.info("Handling delete_peer_group_association request for: %s",
                 association_id)
        return self.system_peer_manager.delete_peer_group_association(
            context, association_id)

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
