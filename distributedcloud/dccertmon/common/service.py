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
from dccertmon.common import utils
from dcmanager.common import consts
from dcmanager.common import messaging as rpc_messaging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CertificateMonitorService(service.Service):
    """Lifecycle manager for a running DC cert monitor service."""

    def __init__(self):
        super(CertificateMonitorService, self).__init__()
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_DC_NOTIFICATION
        # TODO(srana): Refactor DC role usage due to deprecation.
        self.dc_role = utils.DC_ROLE_UNDETECTED
        self.manager = CertificateMonitorManager()
        self._rpc_server = None
        self.target = None

    def start(self):
        LOG.info("Starting %s", self.__class__.__name__)
        super(CertificateMonitorService, self).start()
        self._get_dc_role()

        self.manager.start_cert_watcher()
        self.manager.start_task_executor()

        if self.dc_role == utils.DC_ROLE_SYSTEMCONTROLLER:
            self.target = oslo_messaging.Target(
                version=self.rpc_api_version, server=CONF.host, topic=self.topic
            )
            self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
            self._rpc_server.start()

    def stop(self):
        LOG.info("Stopping %s", self.__class__.__name__)

        if self.dc_role == utils.DC_ROLE_SYSTEMCONTROLLER:
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
                LOG.error("Failed to stop engine service: %s" % ex)
                LOG.exception(ex)

    def _get_dc_role(self):
        # TODO(srana): Update after migrating from certmon
        return utils.DC_ROLE_SYSTEMCONTROLLER

    def subcloud_online(self, context, subcloud_name=None):
        """TODO(srana): Trigger a subcloud online audit"""
        LOG.info("%s is online." % subcloud_name)

    def subcloud_managed(self, context, subcloud_name=None):
        """TODO(srana): Trigger a subcloud audit"""
        LOG.info("%s is managed." % subcloud_name)

    def subcloud_sysinv_endpoint_update(self, ctxt, subcloud_name, endpoint):
        """TODO(srana): Update sysinv endpoint of dc token cache"""
        LOG.info("Update subcloud: %s sysinv endpoint" % subcloud_name)
