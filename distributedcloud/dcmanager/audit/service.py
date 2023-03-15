# Copyright (c) 2020-2023 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import functools
import resource
import six

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service

from dcmanager.audit.subcloud_audit_manager import SubcloudAuditManager
from dcmanager.audit.subcloud_audit_worker_manager import SubcloudAuditWorkerManager
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import messaging as rpc_messaging
from dcmanager.common import scheduler

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


class DCManagerAuditService(service.Service):
    """Lifecycle manager for a running audit service."""

    def __init__(self):

        super(DCManagerAuditService, self).__init__()
        self.host = cfg.CONF.host
        # To be used by the sw update manager to trigger the patch audit
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_DC_MANAGER_AUDIT
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.TG = None
        self.target = None
        self._rpc_server = None
        self.subcloud_audit_manager = None

    def start(self):
        target = oslo_messaging.Target(version=self.rpc_api_version,
                                       server=self.host,
                                       topic=self.topic)
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()

        self.init_tgm()
        self.init_audit_managers()
        super(DCManagerAuditService, self).start()

    def init_tgm(self):
        self.TG = scheduler.ThreadGroupManager()

    def init_audit_managers(self):
        self.subcloud_audit_manager = SubcloudAuditManager()
        # Audit availability of all subclouds.
        # Note this will run in a separate green thread
        self.TG.start(self.subcloud_audit_manager.periodic_subcloud_audit)

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

        if self.TG:
            self.TG.stop()

        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super(DCManagerAuditService, self).stop()

    @request_context
    def trigger_firmware_audit(self, context):
        """Used to force a firmware audit on the next interval"""

        LOG.info("Trigger firmware audit.")
        return self.subcloud_audit_manager.trigger_firmware_audit(context)

    @request_context
    def trigger_kube_rootca_update_audit(self, context):
        """Used to force a kube rootca update audit on the next interval"""

        LOG.info("Trigger kube rootca update audit.")
        return self.subcloud_audit_manager.trigger_kube_rootca_update_audit(
            context)

    @request_context
    def trigger_kubernetes_audit(self, context):
        """Used to force a kubernetes audit on the next interval"""

        LOG.info("Trigger kubernetes audit.")
        return self.subcloud_audit_manager.trigger_kubernetes_audit(context)

    @request_context
    def trigger_patch_audit(self, context):
        """Used to force a patch audit on the next interval"""

        LOG.info("Trigger patch audit.")
        return self.subcloud_audit_manager.trigger_patch_audit(context)

    @request_context
    def trigger_load_audit(self, context):
        """Used to force a load audit on the next interval"""

        LOG.info("Trigger load audit.")
        return self.subcloud_audit_manager.trigger_load_audit(context)

    @request_context
    def trigger_subcloud_audits(self, context, subcloud_id, exclude_endpoints):
        """Trigger all subcloud audits for one subcloud."""
        LOG.info("Trigger all audits for subcloud %s except endpoints %s" %
                 (subcloud_id, exclude_endpoints))
        return self.subcloud_audit_manager.trigger_subcloud_audits(
            context, subcloud_id, exclude_endpoints)

    @request_context
    def trigger_subcloud_patch_load_audits(self, context, subcloud_id):
        """Trigger patch and load audits for one subcloud."""
        LOG.info("Trigger patch and load audits for subcloud %s", subcloud_id)
        return self.subcloud_audit_manager.trigger_subcloud_patch_load_audits(
            context, subcloud_id)

    @request_context
    def trigger_subcloud_endpoints_update(self, context, subcloud_name, endpoints):
        """Trigger update endpoints of services for a subcloud region."""
        LOG.info("Trigger update endpoints for subcloud %s", subcloud_name)
        return self.subcloud_audit_manager.trigger_subcloud_endpoints_update(
            context, subcloud_name, endpoints)


class DCManagerAuditWorkerService(service.Service):
    """Lifecycle manager for a running audit service."""

    def __init__(self):

        super(DCManagerAuditWorkerService, self).__init__()
        self.host = cfg.CONF.host
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_DC_MANAGER_AUDIT_WORKER
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.TG = None
        self.target = None
        self._rpc_server = None
        self.subcloud_audit_worker_manager = None

    def start(self):
        self.init_tgm()
        self.set_resource_limit()
        self.init_audit_managers()
        target = oslo_messaging.Target(version=self.rpc_api_version,
                                       server=self.host,
                                       topic=self.topic)
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()
        super(DCManagerAuditWorkerService, self).start()

    def init_tgm(self):
        self.TG = scheduler.ThreadGroupManager()

    def init_audit_managers(self):
        self.subcloud_audit_worker_manager = SubcloudAuditWorkerManager()

    @staticmethod
    def set_resource_limit():
        """Adjust the maximum number open files for this process (soft limit)"""
        try:
            (current_soft,
             current_hard) = resource.getrlimit(resource.RLIMIT_NOFILE)
            new_soft = cfg.CONF.worker_rlimit_nofile
            if new_soft > current_hard:
                LOG.error('New process open file soft limit [%s] '
                          'exceeds the hard limit [%s]. '
                          'Setting to hard limit instead.' % (new_soft,
                                                              current_hard))
                new_soft = current_hard
            if new_soft != current_soft:
                LOG.info('Setting process open file limit to %s (from %s)',
                         new_soft, current_soft)
                resource.setrlimit(resource.RLIMIT_NOFILE,
                                   (new_soft, current_hard))
        except Exception as ex:
            LOG.exception(
                'Failed to set the audit worker NOFILE resource limit: %s' %
                ex)

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug(_("Attempting to stop audit-worker RPC service..."))
        try:
            self._rpc_server.stop()
            self._rpc_server.wait()
            LOG.info('Audit-worker RPC service stopped successfully')
        except Exception as ex:
            LOG.error('Failed to stop audit-worker RPC service: %s',
                      six.text_type(ex))

    def stop(self):
        self._stop_rpc_server()

        if self.TG:
            self.TG.stop()

        # Terminate the engine process
        LOG.info("All threads were gone, terminating audit-worker engine")
        super(DCManagerAuditWorkerService, self).stop()

    @request_context
    def audit_subclouds(self,
                        context,
                        subcloud_ids,
                        patch_audit_data,
                        firmware_audit_data,
                        kubernetes_audit_data,
                        do_openstack_audit,
                        kube_rootca_update_audit_data):
        """Used to trigger audits of the specified subcloud(s)"""
        self.subcloud_audit_worker_manager.audit_subclouds(
            context,
            subcloud_ids,
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            do_openstack_audit,
            kube_rootca_update_audit_data)

    @request_context
    def update_subcloud_endpoints(self, context, subcloud_name, endpoints):
        """Update endpoints of services for a subcloud region"""
        self.subcloud_audit_worker_manager.update_subcloud_endpoints(
            context,
            subcloud_name,
            endpoints
        )
