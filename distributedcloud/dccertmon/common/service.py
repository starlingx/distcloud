#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service

from dccertmon.common.certificate_monitor_manager import CertificateMonitorManager
from dccertmon.common import constants
from dccertmon.common import utils
from dcmanager.common import consts as dcmanager_consts
from dcmanager.common import messaging as rpc_messaging

DC_ROLE_TIMEOUT_SECONDS = 180
DC_ROLE_DELAY_SECONDS = 5

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CertificateMonitorService(service.Service):
    """Lifecycle manager for a running DC cert monitor service."""

    def __init__(self):
        super(CertificateMonitorService, self).__init__()
        self.rpc_api_version = dcmanager_consts.RPC_API_VERSION
        self.topic = dcmanager_consts.TOPIC_DC_NOTIFICATION
        # TODO(srana): Refactor DC role usage due to deprecation.
        self.dc_role = constants.DC_ROLE_UNDETECTED
        self.manager = CertificateMonitorManager()
        self._rpc_server = None
        self.target = None

    def start(self):
        LOG.info("Starting %s", self.__class__.__name__)
        super(CertificateMonitorService, self).start()
        self._get_dc_role()

        self.manager.start_cert_watcher()
        self.manager.start_task_executor()

        if self.dc_role == constants.DC_ROLE_SYSTEMCONTROLLER:
            self.target = oslo_messaging.Target(
                version=self.rpc_api_version, server=CONF.host, topic=self.topic
            )
            self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
            self._rpc_server.start()

    def stop(self):
        LOG.info("Stopping %s", self.__class__.__name__)

        if self.dc_role == constants.DC_ROLE_SYSTEMCONTROLLER:
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
        if self.dc_role != constants.DC_ROLE_UNDETECTED:
            return self.dc_role

        delay = DC_ROLE_DELAY_SECONDS
        max_dc_role_attempts = DC_ROLE_TIMEOUT_SECONDS // delay
        dc_role_attempts = 1
        while dc_role_attempts < max_dc_role_attempts:
            try:
                self.dc_role = utils.get_dc_role()
                return self.dc_role
            except Exception as e:
                LOG.info(
                    "Unable to get DC role: %s [attempt: %s]", str(e), dc_role_attempts
                )
            time.sleep(delay)
            dc_role_attempts += 1
        raise Exception("Failed to obtain DC role from keystone")

    # TODO(gherzman): verify if it's possible to add the subcloud management IP
    # as a parameter as a way to further optimize the audit request during
    # subcloud deployment. Might require passing the parameter to the audit
    # enqueue method as well.
    def subcloud_online(self, context, subcloud_name=None):
        """Trigger a subcloud online audit."""
        LOG.info("%s is online. An online audit is queued" % subcloud_name)
        # Enqueue the subcloud into the dedicated notification queue
        # to trigger an immediate certificate audit, independent from
        # the periodic audit queue.
        self.manager.audit_subcloud(subcloud_name, self.manager.sc_notify_audit_queue)

    def subcloud_managed(self, context, subcloud_name=None):
        """Trigger a subcloud audit."""
        LOG.info("%s is managed. An audit is queued" % subcloud_name)
        self.manager.audit_subcloud(subcloud_name, self.manager.sc_audit_queue)

    def subcloud_sysinv_endpoint_update(self, ctxt, subcloud_name, endpoint):
        """Update sysinv endpoint of dc token cache."""
        LOG.info("Update subcloud: %s sysinv endpoint" % subcloud_name)
        self.manager.subcloud_sysinv_endpoint_update(subcloud_name, endpoint)
