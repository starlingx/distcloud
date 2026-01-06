#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service

from dccertmon.common.certificate_monitor_manager import CertificateMonitorManager
from dcmanager.common import consts as dcmanager_consts
from dcmanager.common import messaging as rpc_messaging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CertificateMonitorService(service.Service):
    """Lifecycle manager for a running DC cert monitor service."""

    def __init__(self):
        super(CertificateMonitorService, self).__init__()
        self.rpc_api_version = dcmanager_consts.RPC_API_VERSION
        self.topic = dcmanager_consts.TOPIC_DC_NOTIFICATION
        self.manager = CertificateMonitorManager()
        self._rpc_server = None
        self.target = None

    def start(self):
        LOG.info(f"Starting {self.__class__.__name__}")
        super(CertificateMonitorService, self).start()

        self.manager.start_cert_watcher()
        self.manager.start_task_executor()

        self.target = oslo_messaging.Target(
            version=self.rpc_api_version, server=CONF.host, topic=self.topic
        )
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()

    def stop(self):
        LOG.info(f"Stopping {self.__class__.__name__}")

        self._stop_rpc_server()

        self.manager.stop_cert_watcher()
        self.manager.stop_task_executor()
        super(CertificateMonitorService, self).stop()

    def _stop_rpc_server(self):
        if self._rpc_server:
            try:
                self._rpc_server.stop()
                self._rpc_server.wait()
                LOG.info("Engine service stopped successfully")
            except Exception as ex:
                LOG.error(f"Failed to stop engine service: {ex}")
                LOG.exception(ex)

    # TODO(gherzman): verify if it's possible to add the subcloud management IP
    # as a parameter as a way to further optimize the audit request during
    # subcloud deployment. Might require passing the parameter to the audit
    # enqueue method as well.
    def subcloud_online(self, context, subcloud_name=None):
        """Trigger a subcloud online audit."""
        LOG.info(f"{subcloud_name} is online. An online audit is queued")
        # Enqueue the subcloud into the dedicated notification queue
        # to trigger an immediate certificate audit, independent from
        # the periodic audit queue.
        self.manager.audit_subcloud(subcloud_name, self.manager.sc_notify_audit_queue)

    def subcloud_managed(self, context, subcloud_name=None):
        """Trigger a subcloud audit."""
        LOG.info(f"{subcloud_name} is managed. An audit is queued")
        self.manager.audit_subcloud(subcloud_name, self.manager.sc_audit_queue)

    def subcloud_sysinv_endpoint_update(self, ctxt, subcloud_name, endpoint):
        """Update sysinv endpoint of dc token cache."""
        LOG.info(f"Update subcloud: {subcloud_name} sysinv endpoint")
        self.manager.subcloud_sysinv_endpoint_update(subcloud_name, endpoint)
