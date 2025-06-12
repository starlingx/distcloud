#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

import eventlet
import greenlet

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import base64
from oslo_service import periodic_task

from dccertmon.common import subcloud_audit_queue
from dccertmon.common import utils
from dccertmon.common import watcher
from dccommon import consts as constants

LOG = log.getLogger(__name__)
CONF = cfg.CONF


class CertificateMonitorManager(periodic_task.PeriodicTasks):
    def __init__(self):
        super(CertificateMonitorManager, self).__init__(CONF)
        self.mon_thread = None
        self.worker_thread = None
        self.reattempt_monitor_tasks = []
        self.sc_audit_queue = subcloud_audit_queue.SubcloudAuditPriorityQueue()
        self.sc_notify_audit_queue = subcloud_audit_queue.NotificationAuditQueue()

        self.sc_audit_pool = None
        if CONF.dccertmon.audit_greenpool_size > 0:
            self.sc_audit_pool = eventlet.greenpool.GreenPool(
                size=CONF.dccertmon.audit_greenpool_size
            )

    def start_task_executor(self):
        LOG.info(f"Auditing interval {CONF.dccertmon.audit_interval}")
        self.worker_thread = eventlet.greenthread.spawn(self.worker_task_loop)
        self.on_start()

    def start_cert_watcher(self):
        dc_monitor = None
        while True:
            try:
                dc_monitor = watcher.DC_CertWatcher()
                dc_monitor.initialize(
                    audit_subcloud=lambda subcloud_name: self.audit_subcloud(
                        subcloud_name, self.sc_audit_queue, allow_requeue=True
                    ),
                    invalid_deploy_states=(
                        constants.INVALID_SUBCLOUD_AUDIT_DEPLOY_STATES
                    ),
                )

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
                time.sleep(1)
                self.run_periodic_tasks(context=None)
            except greenlet.GreenletExit:
                break
            except Exception as e:
                LOG.exception(e)

    def monitor_cert_loop(self, monitor):
        while True:
            # never exit until exit signal received
            try:
                monitor.start_watch(
                    on_success=lambda task_id: self._purge_reattempt_monitor_task(
                        task_id, "on success"
                    ),
                    on_error=self._add_reattempt_monitor_task,
                )
            except greenlet.GreenletExit:
                break
            except Exception:
                # It shouldn't fall to here, but log and restart if it did
                LOG.exception("Unexpected exception from start_watch")
                time.sleep(1)

    def _add_reattempt_monitor_task(self, task):
        id = task.get_id()
        self._purge_reattempt_monitor_task(id, "for new reattempt")
        self.reattempt_monitor_tasks.append(task)

    def _purge_reattempt_monitor_task(self, id, reason_msg):
        for t in self.reattempt_monitor_tasks:
            if t.get_id() == id:
                self.reattempt_monitor_tasks.remove(t)
                LOG.info(f"Purging reattempt monitor task {reason_msg}: {id}")
                break

    def subcloud_sysinv_endpoint_update(self, subcloud_name, sysinv_url):
        utils.SubcloudSysinvEndpointCache.update_endpoints({subcloud_name: sysinv_url})

    def on_start(self):
        """On service start audit Audit all subclouds that are out-of-sync."""
        LOG.info("Service Start - prepare for initial audit")

        if CONF.dccertmon.startup_audit_all:
            LOG.info("Service start startup_audit_all: audit all subclouds")
            self.audit_sc_cert_start(None)
            return

        all_subclouds = utils.get_subclouds_from_dcmanager(
            constants.INVALID_SUBCLOUD_AUDIT_DEPLOY_STATES
        )

        # Update sysinv endpoint cache
        management_ips = {sc["name"]: sc["management_ip"] for sc in all_subclouds}
        utils.SubcloudSysinvEndpointCache.cache_endpoints_by_ip(management_ips)

        LOG.info(
            "Service start: begin subcloud certificate audit [#sc: "
            f"{len(all_subclouds)}, batch: {CONF.dccertmon.audit_batch_size}]"
        )

        for subcloud in all_subclouds:
            if (
                subcloud[constants.ENDPOINT_TYPE_DC_CERT]
                != constants.SYNC_STATUS_IN_SYNC
            ):
                subcloud_name = subcloud["name"]
                if self.sc_audit_queue.contains(subcloud_name):
                    LOG.info(f"{subcloud_name} is not in-sync but already under audit")
                else:
                    LOG.info(f"{subcloud_name} is not in-sync, adding it to audit")
                    self.sc_audit_queue.enqueue(
                        subcloud_audit_queue.SubcloudAuditData(subcloud_name)
                    )

        if self.sc_audit_queue.qsize() > 0:
            LOG.info(
                "Startup audit: "
                f"{self.sc_audit_queue.qsize()} subcloud(s) to be audited"
            )
        else:
            LOG.info("Startup audit: all subclouds are in-sync")

    def do_subcloud_audit(self, queue, sc_audit_item):
        """Ensure the subcloud audit task is marked done within the given queue."""
        try:
            self._subcloud_audit(queue, sc_audit_item, subcloud_name=sc_audit_item.name)
        except Exception:
            LOG.exception("An error occurred during the subcloud audit task")
        finally:
            queue.task_done()

    def _subcloud_audit(self, queue, sc_audit_item, subcloud_name=None):
        """Invoke a subcloud audit."""

        lock_name = f"audit-subcloud-{subcloud_name}"
        with lockutils.lock(name=lock_name, external=False):
            LOG.info(
                f"Auditing subcloud {subcloud_name}, "
                f"attempt #{sc_audit_item.audit_count} [qsize: {queue.qsize()}]"
            )

            # Abort audit if subcloud is not in a valid deploy status
            subcloud = utils.get_subcloud(subcloud_name)
            if (
                subcloud["deploy-status"]
                in constants.INVALID_SUBCLOUD_AUDIT_DEPLOY_STATES
            ):
                LOG.info(
                    f"Subcloud {subcloud_name} is in an invalid deploy status:"
                    f" {subcloud['deploy-status']}, aborting audit"
                )
                return

            subcloud_sysinv_url = None
            try:
                subcloud_sysinv_url = utils.SubcloudSysinvEndpointCache.build_endpoint(
                    subcloud["management-start-ip"]
                )
                utils.SubcloudSysinvEndpointCache.update_endpoints(
                    {subcloud_name: subcloud_sysinv_url}
                )

                sc_ssl_cert = utils.get_endpoint_certificate(
                    subcloud_sysinv_url,
                    timeout_secs=CONF.dccertmon.certificate_timeout_secs,
                )

            except Exception:
                if not utils.is_subcloud_online(subcloud_name):
                    LOG.warning(
                        f"Subcloud is not online, aborting audit: {subcloud_name}"
                    )
                    return
                # Handle network-level issues
                # Re-enqueue the subcloud for reauditing
                max_attempts = CONF.dccertmon.network_max_retry
                if sc_audit_item.audit_count < max_attempts:
                    LOG.exception(
                        f"Cannot retrieve ssl certificate for {subcloud_name} via:"
                        f" {subcloud_sysinv_url} (requeuing audit)"
                    )
                    self.requeue_audit_subcloud(
                        queue, sc_audit_item, CONF.dccertmon.network_retry_interval
                    )
                else:
                    LOG.exception(
                        f"Cannot retrieve ssl certificate for {subcloud_name} via: "
                        f"{subcloud_sysinv_url}; maximum retry limit exceeded "
                        f"[{max_attempts}], giving up"
                    )
                    utils.update_subcloud_status(
                        subcloud_name, constants.SYNC_STATUS_OUT_OF_SYNC
                    )
                return
            try:
                secret = utils.get_sc_intermediate_ca_secret(subcloud_name)
                check_list = ["ca.crt", "tls.crt", "tls.key"]
                for item in check_list:
                    if item not in secret.data:
                        raise Exception(
                            f"{subcloud_name} certificate data missing: {item}"
                        )

                txt_ssl_cert = base64.decode_as_text(secret.data["tls.crt"])
                txt_ssl_key = base64.decode_as_text(secret.data["tls.key"])
                txt_ca_cert = base64.decode_as_text(secret.data["ca.crt"])
            except Exception:
                # Handle certificate-level issues
                if not utils.is_subcloud_online(subcloud_name):
                    LOG.exception(
                        "Error getting subcloud intermediate cert. "
                        f"Subcloud is not online, aborting audit: {subcloud_name}"
                    )
                    return
                LOG.exception(
                    f"Cannot audit ssl certificate on {subcloud_name}. "
                    "Certificate is not ready."
                )
                # certificate is not ready, no reaudit. Will be picked up
                # by certificate MODIFIED event if it comes back
                return

            cert_chain = txt_ssl_cert + txt_ca_cert
            if not utils.verify_intermediate_ca_cert(cert_chain, sc_ssl_cert):
                # The subcloud needs renewal.
                LOG.info(
                    f"Updating {subcloud_name} intermediate CA as it is out-of-sync"
                )
                # reaudit this subcloud after delay
                self.requeue_audit_subcloud(queue, sc_audit_item)
                try:
                    utils.update_subcloud_ca_cert(
                        subcloud_name,
                        subcloud_sysinv_url,
                        txt_ca_cert,
                        txt_ssl_cert,
                        txt_ssl_key,
                    )
                except Exception:
                    LOG.exception(
                        f"Failed to update intermediate CA on {subcloud_name}"
                    )
                    utils.update_subcloud_status(
                        subcloud_name, constants.SYNC_STATUS_OUT_OF_SYNC
                    )
            else:
                LOG.info(f"{subcloud_name} intermediate CA cert is in-sync")
                utils.update_subcloud_status(
                    subcloud_name, constants.SYNC_STATUS_IN_SYNC
                )

    def requeue_audit_subcloud(self, queue, sc_audit_item, delay_secs=60):
        if not queue.contains(sc_audit_item.name):
            queue.enqueue(sc_audit_item, delay_secs)

    def audit_subcloud(self, subcloud_name, queue, allow_requeue=False):
        """Enqueue a subcloud audit in the specified queue.

        queue: The audit queue to use (either sc_audit_queue or
               sc_notify_audit_queue).
        allow_requeue: This can come from a watch after a DC certificate renew.
                       i.e., outside of the periodic subcloud audit tasks.
                       We allow a re-enqueue here with a new delay.
        """
        if queue.contains(subcloud_name):
            if allow_requeue and queue.enqueued_subcloud_names.count(subcloud_name) < 2:
                LOG.info(f"audit_subcloud: requeing {subcloud_name}")
            else:
                LOG.debug(f"audit_subcloud: ignoring {subcloud_name}, already in queue")
                return
        queue.enqueue(
            subcloud_audit_queue.SubcloudAuditData(subcloud_name),
            allow_requeue=allow_requeue,
        )

    @periodic_task.periodic_task(spacing=CONF.dccertmon.audit_interval)
    def audit_sc_cert_start(self, context):
        """Kicks an audit of all subclouds.

        By default this task runs once every 24 hours.
        """
        # auditing subcloud certificate
        all_subclouds = utils.get_subclouds_from_dcmanager(
            constants.INVALID_SUBCLOUD_AUDIT_DEPLOY_STATES
        )

        # Update sysinv endpoint cache
        management_ips = {sc["name"]: sc["management_ip"] for sc in all_subclouds}
        utils.SubcloudSysinvEndpointCache.cache_endpoints_by_ip(management_ips)

        LOG.info(
            f"Periodic: begin subcloud certificate audit: {len(all_subclouds)} "
            "subclouds"
        )
        for sc in all_subclouds:
            try:
                self.sc_audit_queue.enqueue(
                    subcloud_audit_queue.SubcloudAuditData(sc["name"])
                )
            except subcloud_audit_queue.SubcloudAuditException as exc:
                # Log as warn because we can see this if the watch has fired
                # near the same time as we are auditing the subcloud
                LOG.warning(f"Failed to enqueue subcloud audit: {str(exc)}")

    def _process_audit_queue(self, queue, queue_name):
        for batch_count in range(CONF.dccertmon.audit_batch_size):
            if queue.qsize() < 1:
                # Nothing to do
                return

            # Only continue if the next in queue is ready to be audited
            # Peek into the timestamp of the next item in our priority queue
            next_audit_timestamp = queue.queue[0][0]
            if next_audit_timestamp > int(time.time()):
                LOG.debug(
                    f"{queue_name}: no audits ready for processing, "
                    f"qsize={queue.qsize()}"
                )
                return

            _, sc_audit_item = queue.get()
            LOG.debug(
                f"{queue_name}: processing audit {sc_audit_item} "
                f"(qsize={queue.qsize()}, batch={batch_count})"
            )

            # This item is ready for audit
            if self.sc_audit_pool is not None:
                self.sc_audit_pool.spawn_n(self.do_subcloud_audit, queue, sc_audit_item)
            else:
                self.do_subcloud_audit(queue, sc_audit_item)

            eventlet.sleep()

    @periodic_task.periodic_task(spacing=constants.PERIODIC_AUDIT_INTERVAL_SECS)
    def audit_sc_cert_task(self, context):
        """This task runs every N seconds and processes a single subcloud.

        It moves the subcloud through its next step in the subcloud audit process.
        The task pulls up to <batch_count> ready-to-audit subcloud audit data items
        from the `sc_audit_queue` and spawns each item to be executed via the
        GreenPool. If the GreenPool is disabled, the audit is invoked directly.
        """
        self._process_audit_queue(self.sc_audit_queue, "audit_sc_cert_task")

    @periodic_task.periodic_task(
        spacing=constants.NOTIFICATION_QUEUE_AUDIT_INTERVAL_SECS
    )
    def audit_notification_queue_task(self, context):
        """Processes audits from the notification audit queue."""
        self._process_audit_queue(
            self.sc_notify_audit_queue, "audit_notification_queue_task"
        )

    @periodic_task.periodic_task(spacing=CONF.dccertmon.retry_interval)
    def retry_monitor_task(self, context):
        # Failed tasks that need to be reattempted will be taken care here
        max_attempts = CONF.dccertmon.max_retry
        tasks = self.reattempt_monitor_tasks[:]

        num_tasks = len(tasks)
        if num_tasks > 0:
            LOG.info(f"Start retry_monitor_task: #tasks in queue: {num_tasks}")

        # NOTE: this loop can potentially retry ALL subclouds, which
        # may be a resource concern.
        for task in tasks:
            task_id = task.get_id()
            LOG.info(
                f"retry_monitor_task: {task_id}, attempt: {task.number_of_reattempt}"
            )
            if task.run():
                self.reattempt_monitor_tasks.remove(task)
                LOG.info(f"retry_monitor_task: {task_id}, reattempt has succeeded")
            elif task.number_of_reattempt >= max_attempts:
                LOG.error(
                    (
                        f"retry_monitor_task: {task_id}, maximum attempts "
                        f"({max_attempts}) has been reached. Give up"
                    )
                )
                if task in self.reattempt_monitor_tasks:
                    self.reattempt_monitor_tasks.remove(task)

                # task has failed
                task.failed()

            # Pause and allow other eventlets to run
            eventlet.sleep(0.1)
        LOG.debug("End retry_monitor_task")
