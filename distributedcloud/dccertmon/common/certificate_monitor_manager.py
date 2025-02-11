#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

import eventlet
import greenlet
from oslo_config import cfg
from oslo_log import log
from oslo_service import periodic_task

from dccertmon.common import watcher


LOG = log.getLogger(__name__)
CONF = cfg.CONF


class CertificateMonitorManager(periodic_task.PeriodicTasks):
    def __init__(self):
        super(CertificateMonitorManager, self).__init__(CONF)
        self.mon_thread = None
        self.worker_thread = None

    def on_start(self):
        LOG.info("Service Start - prepare for initial audit")

    def start_task_executor(self):
        self.worker_thread = eventlet.greenthread.spawn(self.worker_task_loop)
        self.on_start()

    def start_cert_watcher(self):
        dc_monitor = None
        while True:
            try:
                dc_monitor = watcher.DC_CertWatcher()
                dc_monitor.initialize()
            except Exception as e:
                LOG.exception(e)
                time.sleep(5)
            else:
                break

        # spawn monitor thread
        self.mon_thread = eventlet.greenthread.spawn(self.monitor_cert_loop, dc_monitor)

    def stop_cert_watcher(self):
        if self.mon_thread:
            self.mon_thread.kill()
            self.mon_thread.wait()
            self.mon_thread = None

    def stop_task_executor(self):
        if self.worker_thread:
            self.worker_thread.kill()
            self.worker_thread.wait()
            self.worker_thread = None

    def worker_task_loop(self):
        while True:
            try:
                self.run_periodic_tasks(context=None)
                # TODO(srana): Reset sleep after proper implementation
                time.sleep(60)
            except greenlet.GreenletExit:
                break
            except Exception as e:
                LOG.exception(e)

    def monitor_cert_loop(self, monitor):
        while True:
            # never exit until exit signal received
            try:
                monitor.start_watch(on_success=None, on_error=None)
            except greenlet.GreenletExit:
                break
            except Exception:
                # It shouldn't fall to here, but log and restart if it did
                LOG.exception("Unexpected exception from start_watch")
                time.sleep(1)

    @periodic_task.periodic_task(spacing=CONF.dccertmon.audit_interval)
    def audit_sc_cert_start(self, context):
        LOG.info("periodic_task: audit_sc_cert_start")

    @periodic_task.periodic_task(spacing=5)
    def audit_sc_cert_task(self, context):
        LOG.info("periodic_task: audit_sc_cert_task")

    @periodic_task.periodic_task(spacing=CONF.dccertmon.retry_interval)
    def retry_monitor_task(self, context):
        LOG.info("periodic_task: retry_monitor_task")
