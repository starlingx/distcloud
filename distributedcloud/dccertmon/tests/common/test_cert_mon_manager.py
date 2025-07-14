# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os.path
import time

import base64 as pybase64
import eventlet
import greenlet
from keystoneauth1 import session
import mock
from oslo_config import cfg
from oslo_config import fixture as config_fixture


from dccertmon.common import certificate_monitor_manager as cert_mon_manager
from dccertmon.common import subcloud_audit_queue
import dccertmon.common.watcher
from dccertmon.tests.base import DCCertMonTestCase
from dccommon.endpoint_cache import EndpointCache

OPT_GROUP_NAME = "dccertmon"
if not cfg.CONF._get_group(OPT_GROUP_NAME)._opts:
    cfg.CONF.import_group(OPT_GROUP_NAME, "keystonemiddleware.auth_token")


class CertMonManagerBase(DCCertMonTestCase):

    def setUp(self):
        super(CertMonManagerBase, self).setUp()
        self.manager = cert_mon_manager.CertificateMonitorManager()
        self.manager.sc_audit_pool = None  # Force serial audit for testing
        self.config_fixture = self.useFixture(config_fixture.Config(cfg.CONF))
        self.mock_get_subcloud = self._mock_object(
            cert_mon_manager.utils, "get_subcloud"
        )
        self.mock_update_subcloud_status = self._mock_object(
            cert_mon_manager.utils, "update_subcloud_status"
        )
        self.mock_is_subcloud_online = self._mock_object(
            cert_mon_manager.utils, "is_subcloud_online"
        )
        self.mock_build_endpoint = self._mock_object(
            cert_mon_manager.utils.SubcloudSysinvEndpointCache, "build_endpoint"
        )
        self.mock_get_endpoint_certificate = self._mock_object(
            cert_mon_manager.utils, "get_endpoint_certificate"
        )
        self.mock_get_intermediate_ca = self._mock_object(
            cert_mon_manager.utils, "get_sc_intermediate_ca_secret"
        )
        self.mock_verify_ca = self._mock_object(
            cert_mon_manager.utils, "verify_intermediate_ca_cert"
        )
        self.mock_update_ca_cert = self._mock_object(
            cert_mon_manager.utils, "update_subcloud_ca_cert"
        )
        self._mock_object(EndpointCache, "get_admin_session")
        self.mock_get_token = self._mock_object(session.Session, "get_token")

        # Default return values
        self.mock_get_token.return_value = "fake-token"
        self.mock_get_subcloud.return_value = self._mock_subcloud()
        self.mock_build_endpoint.return_value = "http://fake"
        self.mock_get_endpoint_certificate.return_value = (
            self._get_valid_certificate_pem()
        )
        self.mock_get_intermediate_ca.return_value = (
            self._get_sc_intermediate_ca_secret()
        )
        self.mock_is_subcloud_online.return_value = True

    def _mock_token_cache(self):
        mock_token_cache = mock.Mock()
        mock_token_cache.get_token.return_value = "fake-token"
        return mock_token_cache

    def _mock_subcloud(self, status="completed", ip="1.1.1.1"):
        return {"deploy-status": status, "management-start-ip": ip}

    def _mock_dcmanager_subcloud(self, name, ip, status):
        return {"name": name, "management_ip": ip, "dc-cert": status}

    def _get_data_file_path(self, file_name):
        return os.path.join(os.path.dirname(__file__), "data", file_name)

    def _get_valid_certificate_pem(self):
        cert_filename = self._get_data_file_path("audit/cacert.pem")
        with open(cert_filename, "r") as cfile:
            cert_file = cfile.read()
        return cert_file

    def _get_sc_intermediate_ca_secret(self):
        cert_filename = self._get_data_file_path("audit/ca-chain-bundle.cert.pem")
        key_filename = self._get_data_file_path("audit/cakey.pem")
        cacert_filename = self._get_data_file_path("audit/cacert.pem")

        with open(cert_filename, "rb") as cfile:
            tls_cert = pybase64.b64encode(cfile.read()).decode("utf-8")
        with open(key_filename, "rb") as kfile:
            tls_key = pybase64.b64encode(kfile.read()).decode("utf-8")
        with open(cacert_filename, "rb") as cafile:
            ca_cert = pybase64.b64encode(cafile.read()).decode("utf-8")

        secret = mock.Mock()
        secret.data = {
            "tls.crt": tls_cert,
            "tls.key": tls_key,
            "ca.crt": ca_cert,
        }
        return secret


class TestAuditQueueBehavior(CertMonManagerBase):

    def test_audit_notification_queue_task_delegates_to_process_audit_queue(self):
        """Test that audit_notification_queue_task delegates to _process_audit_queue."""

        mock_process = self._mock_object(self.manager, "_process_audit_queue")
        self.manager.audit_notification_queue_task(None)
        mock_process.assert_called_once_with(
            self.manager.sc_notify_audit_queue, "audit_notification_queue_task"
        )

    def test_do_subcloud_audit_logs_exception(self):
        """Ensure that exceptions during subcloud audit are logged."""

        item = subcloud_audit_queue.SubcloudAuditData("fail-subcloud")
        mock_queue = mock.Mock()
        mock_queue.task_done = mock.Mock()

        mock_sc_audit = self._mock_object(self.manager, "_subcloud_audit")
        mock_sc_audit.side_effect = Exception("exc")
        mock_log = self._mock_object(cert_mon_manager.LOG, "exception")

        self.manager.do_subcloud_audit(mock_queue, item)

        mock_log.assert_called_once_with(
            "An error occurred during the subcloud audit task"
        )
        mock_queue.task_done.assert_called_once()

    def test_process_audit_queue_uses_greenpool(self):
        """Test that _process_audit_queue uses GreenPool to spawn audit workers."""

        queue = subcloud_audit_queue.SubcloudAuditPriorityQueue()
        item = subcloud_audit_queue.SubcloudAuditData("test-subcloud")
        queue.enqueue(item, delay_secs=0)

        self.manager.sc_audit_pool = mock.Mock()
        self.manager._process_audit_queue(queue, "test-queue")
        self.manager.sc_audit_pool.spawn_n.assert_called_once()

    def test_audit_sc_cert_task_shallow(self):
        """Test the audit_sc_cert_task basic queuing functionality.

        Mocks beginning at do_subcloud_audit.
        """
        mock_do_audit = self._mock_object(self.manager, "do_subcloud_audit")
        mock_do_audit.return_value = None
        # Add two items with future timestamps
        self.manager.sc_audit_queue.enqueue(
            subcloud_audit_queue.SubcloudAuditData("test1"), delay_secs=1
        )
        self.manager.sc_audit_queue.enqueue(
            subcloud_audit_queue.SubcloudAuditData("test2"), delay_secs=2
        )
        self.assertEqual(self.manager.sc_audit_queue.qsize(), 2)
        # Run audit immediately, it should not have picked up anything
        self.manager.audit_sc_cert_task(None)
        mock_do_audit.assert_not_called()
        self.assertEqual(self.manager.sc_audit_queue.qsize(), 2)

        time.sleep(3)
        self.manager.audit_sc_cert_task(None)
        # It should now be drained:
        mock_do_audit.assert_called()
        self.assertEqual(self.manager.sc_audit_queue.qsize(), 0)

        mock_do_audit.reset_mock()
        self.manager.audit_sc_cert_task(None)
        mock_do_audit.assert_not_called()

    def test_audit_sc_cert_task_deep(self):
        """Validate a complete subcloud audit flow with all utils mocked"""

        self.manager.sc_audit_queue.enqueue(
            subcloud_audit_queue.SubcloudAuditData("test1"), delay_secs=1
        )
        self.manager.sc_audit_queue.enqueue(
            subcloud_audit_queue.SubcloudAuditData("test2"), delay_secs=2
        )
        self.assertEqual(self.manager.sc_audit_queue.qsize(), 2)

        # Run audit immediately, it should not have picked up anything
        self.manager.audit_sc_cert_task(None)
        self.assertEqual(self.manager.sc_audit_queue.qsize(), 2)

        time.sleep(3)
        self.manager.audit_sc_cert_task(None)
        # It should now be drained:
        self.assertEqual(self.manager.sc_audit_queue.qsize(), 0)

    def test_requeue_audit_subcloud_enqueues_if_not_present(self):
        """Test that requeue_audit_subcloud adds the subcloud if not present."""

        item = subcloud_audit_queue.SubcloudAuditData("subcloud1")

        self.manager.sc_audit_queue = mock.Mock()
        self.manager.sc_audit_queue.contains.return_value = False

        self.manager.requeue_audit_subcloud(
            self.manager.sc_audit_queue, item, delay_secs=42
        )

        self.manager.sc_audit_queue.enqueue.assert_called_once_with(item, 42)

    def test_requeue_audit_subcloud_skips_if_already_queued(self):
        """Test that requeue_audit_subcloud does not enqueue duplicates."""

        queue = mock.Mock()
        queue.contains.return_value = True
        item = subcloud_audit_queue.SubcloudAuditData("subcloud1")
        self.manager.requeue_audit_subcloud(queue, item, delay_secs=42)
        queue.enqueue.assert_not_called()

    def test_audit_subcloud_allow_requeue(self):
        """Test that audit_subcloud requeues if allow_requeue is True and count < 2."""

        queue = subcloud_audit_queue.SubcloudAuditPriorityQueue()
        subcloud_name = "subcloud1"

        queue.enqueue(subcloud_audit_queue.SubcloudAuditData(subcloud_name))

        mock_enqueue = self._mock_object(queue, "enqueue")
        self.manager.audit_subcloud(subcloud_name, queue, allow_requeue=True)
        mock_enqueue.assert_called_once()

    def test_audit_subcloud_ignored_if_already_in_queue(self):
        """Test that audit_subcloud does not requeue if allow_requeue is False."""

        queue = subcloud_audit_queue.SubcloudAuditPriorityQueue()
        subcloud_name = "subcloud2"
        # Enqueue once so it's already present
        queue.enqueue(subcloud_audit_queue.SubcloudAuditData(subcloud_name))

        mock_enqueue = self._mock_object(queue, "enqueue")

        self.manager.audit_subcloud(subcloud_name, queue, allow_requeue=False)
        mock_enqueue.assert_not_called()


class TestSubcloudAuditFlow(CertMonManagerBase):
    def setUp(self):
        super().setUp()
        self.mock_requeue = self._mock_object(self.manager, "requeue_audit_subcloud")

    def test_subcloud_sysinv_endpoint_update(self):
        """Test that subcloud_sysinv_endpoint_update calls update_endpoints."""

        self.mock_update_endpoints = self._mock_object(
            cert_mon_manager.utils.SubcloudSysinvEndpointCache, "update_endpoints"
        )
        self.manager.subcloud_sysinv_endpoint_update("sc1", "http://sysinv.sc1")
        self.mock_update_endpoints.assert_called_once_with({"sc1": "http://sysinv.sc1"})

    def test_subcloud_audit_invalid_deploy_status(self):
        """Test that subcloud audit exits early for invalid deploy status."""

        item = subcloud_audit_queue.SubcloudAuditData("subcloud1")
        self.mock_get_subcloud.return_value = self._mock_subcloud(
            status="create-failed"
        )

        self.manager._subcloud_audit(
            self.manager.sc_audit_queue, item, subcloud_name="subcloud1"
        )
        self.mock_update_subcloud_status.assert_not_called()

    def test_subcloud_audit_endpoint_failure_then_retry(self):
        """Test that audit retries on endpoint failure when subcloud is online."""

        item = subcloud_audit_queue.SubcloudAuditData("subcloud1")
        item.audit_count = 0
        self.mock_build_endpoint.side_effect = Exception("network error")

        self.manager._subcloud_audit(
            self.manager.sc_audit_queue, item, subcloud_name="subcloud1"
        )
        self.mock_requeue.assert_called_once_with(
            self.manager.sc_audit_queue, item, mock.ANY
        )
        self.mock_update_subcloud_status.assert_not_called()

    def test_subcloud_audit_subcloud_offline(self):
        """Test that no retry happens when the subcloud is offline."""

        item = subcloud_audit_queue.SubcloudAuditData("subcloud1")
        item.audit_count = 0
        self.mock_build_endpoint.side_effect = Exception("network error")
        self.mock_is_subcloud_online.return_value = False

        self.manager._subcloud_audit(
            self.manager.sc_audit_queue, item, subcloud_name="subcloud1"
        )
        self.mock_requeue.assert_not_called()
        self.mock_update_subcloud_status.assert_not_called()

    def test_subcloud_audit_missing_cert_data(self):
        """Test that audit exits when intermediate cert data is incomplete."""

        item = subcloud_audit_queue.SubcloudAuditData("subcloud1")
        self.mock_get_endpoint_certificate.return_value = "cert"
        self.mock_get_intermediate_ca.return_value = {"data": {"ca.crt": "ca"}}
        self.manager._subcloud_audit(
            self.manager.sc_audit_queue, item, subcloud_name="subcloud1"
        )
        self.mock_requeue.assert_not_called()
        self.mock_update_subcloud_status.assert_not_called()

    def test_subcloud_audit_cert_chain_out_of_sync(self):
        """Test audit flow when intermediate CA is out-of-sync and needs update."""

        item = subcloud_audit_queue.SubcloudAuditData("subcloud1")
        self.mock_verify_ca.return_value = False
        mock_log = self._mock_object(cert_mon_manager.LOG, "exception")
        self.manager._subcloud_audit(
            self.manager.sc_audit_queue, item, subcloud_name="subcloud1"
        )
        mock_log.assert_not_called()
        self.mock_verify_ca.assert_called_once()
        self.mock_update_ca_cert.assert_called_once()
        self.mock_update_subcloud_status.assert_not_called()

    def test_subcloud_audit_cert_already_in_sync(self):
        """Test audit flow when the intermediate CA cert is already in sync."""

        item = subcloud_audit_queue.SubcloudAuditData("subcloud1")
        self.mock_verify_ca.return_value = True

        self.manager._subcloud_audit(
            self.manager.sc_audit_queue,
            item,
            subcloud_name="subcloud1",
        )
        self.mock_verify_ca.assert_called_once()
        self.mock_update_subcloud_status.assert_called_once_with(
            "subcloud1",
            mock.ANY,
        )


class TestStartupAuditBehavior(CertMonManagerBase):
    """Tests related to subcloud auditing triggered during service startup."""

    def setUp(self):
        super().setUp()
        # Patch functions and methods commonly used across tests
        self.mock_get_subclouds = self._mock_object(
            cert_mon_manager.utils, "get_subclouds_from_dcmanager"
        )
        self.mock_cache_endpoints = self._mock_object(
            cert_mon_manager.utils.SubcloudSysinvEndpointCache,
            "cache_endpoints_by_ip",
        )

    def test_on_start_audits_out_of_sync_subclouds(self):
        """Test that on_start enqueues only out-of-sync subclouds."""

        self.mock_get_subclouds.return_value = [
            self._mock_dcmanager_subcloud("subcloud1", "192.168.101.2", "out-of-sync"),
            self._mock_dcmanager_subcloud("subcloud2", "192.168.101.3", "in-sync"),
        ]
        self.manager.token_cache = self._mock_token_cache()
        mock_enqueue = self._mock_object(self.manager.sc_audit_queue, "enqueue")

        self.manager.on_start()
        mock_enqueue.assert_called_once()
        audit_data = mock_enqueue.call_args[0][0]
        self.assertEqual(audit_data.name, "subcloud1")

    def test_on_start_with_startup_audit_all(self):
        """Test that on_start triggers full audit when startup_audit_all is set."""

        self.config_fixture.config(startup_audit_all=True, group=OPT_GROUP_NAME)
        mock_audit = self._mock_object(self.manager, "audit_sc_cert_start")
        self.manager.on_start()
        mock_audit.assert_called_once()

    def test_on_start_skips_subcloud_already_under_audit(self):
        """Test that subcloud already under audit is not re-enqueued."""

        self.config_fixture.config(startup_audit_all=False, group=OPT_GROUP_NAME)
        self.mock_get_subclouds.return_value = [
            self._mock_dcmanager_subcloud("subcloud1", "192.168.101.2", "out-of-sync")
        ]
        self.manager.token_cache = self._mock_token_cache()
        # Manually enqueue before running on_start
        self.manager.sc_audit_queue.enqueue(
            subcloud_audit_queue.SubcloudAuditData("subcloud1")
        )
        mock_enqueue = self._mock_object(self.manager.sc_audit_queue, "enqueue")
        self.manager.on_start()
        mock_enqueue.assert_not_called()

    def test_audit_sc_cert_start_enqueues_all_subclouds(self):
        """Test that audit_sc_cert_start enqueues all subclouds for auditing."""

        self.mock_get_subclouds.return_value = [
            {"name": "sc1", "management_ip": "1.2.3.4"},
            {"name": "sc2", "management_ip": "1.2.3.5"},
        ]
        self.manager.token_cache = self._mock_token_cache()
        mock_enqueue = self._mock_object(self.manager.sc_audit_queue, "enqueue")
        self.manager.audit_sc_cert_start(None)
        self.assertEqual(mock_enqueue.call_count, 2)


class TestRetryMechanism(CertMonManagerBase):
    def setUp(self):
        super().setUp()
        # Create a reusable mock task
        self.fake_task = mock.Mock()
        self.fake_task.get_id.return_value = "task1"
        self.fake_task.run.return_value = True
        self.fake_task.number_of_reattempt = 1
        self.fake_task.failed = mock.Mock()

    def test_retry_monitor_task(self):
        """Test that retry_monitor_task removes successful tasks from the queue."""
        self.manager.reattempt_monitor_tasks = [self.fake_task]

        self._mock_object(time, "sleep")
        self.manager.retry_monitor_task(None)

        self.assertNotIn(self.fake_task, self.manager.reattempt_monitor_tasks)

    def test_retry_monitor_task_failed_permanently(self):
        """Test retry_monitor_task removes and fails task after max attempts."""
        self.fake_task.run.return_value = False
        self.fake_task.number_of_reattempt = cfg.CONF.dccertmon.max_retry

        self.manager.reattempt_monitor_tasks = [self.fake_task]

        self._mock_object(eventlet, "sleep")
        self.manager.retry_monitor_task(None)

        self.assertNotIn(self.fake_task, self.manager.reattempt_monitor_tasks)
        self.fake_task.failed.assert_called_once()

    def test_add_reattempt_monitor_task(self):
        """Test that a new reattempt task is added to the retry list."""

        self.fake_task.get_id.return_value = "task-123"
        self.manager.reattempt_monitor_tasks = [self.fake_task]
        mock_purge = self._mock_object(self.manager, "_purge_reattempt_monitor_task")

        self.manager._add_reattempt_monitor_task(self.fake_task)
        mock_purge.assert_called_once_with("task-123", "for new reattempt")
        self.assertIn(self.fake_task, self.manager.reattempt_monitor_tasks)

    def test_purge_reattempt_monitor_task_removes_task(self):
        """Test that purge does nothing if the task is not found."""

        self.fake_task.get_id.return_value = "task-abc"
        self.manager.reattempt_monitor_tasks = [self.fake_task]

        self.manager._purge_reattempt_monitor_task("task-abc", "reason")
        self.assertNotIn(self.fake_task, self.manager.reattempt_monitor_tasks)

    def test_purge_reattempt_monitor_task_not_found(self):
        """Test that purge does nothing if the task is not found."""

        self.fake_task.get_id.return_value = "other-task"
        self.manager.reattempt_monitor_tasks = [self.fake_task]

        # Should not raise
        self.manager._purge_reattempt_monitor_task("non-existent", "reason")
        self.assertIn(self.fake_task, self.manager.reattempt_monitor_tasks)


class TestTaskExecutorLifecycle(CertMonManagerBase):
    def test_start_and_stop_task_executor(self):
        """Test that the task executor thread starts and stops correctly."""

        mock_on_start = self._mock_object(self.manager, "on_start")
        mock_spawn = self._mock_object(eventlet.greenthread, "spawn")
        thread_mock = mock.Mock()
        thread_mock.kill = mock.Mock()
        thread_mock.wait = mock.Mock()
        mock_spawn.return_value = thread_mock

        self.manager.start_task_executor()
        mock_on_start.assert_called_once()
        mock_spawn.assert_called_once()
        self.assertIsNotNone(self.manager.worker_thread)

        self.manager.stop_task_executor()
        thread_mock.kill.assert_called_once()
        thread_mock.wait.assert_called_once()
        self.assertIsNone(self.manager.worker_thread)

    def test_worker_task_loop_exits_on_greenlet_exit(self):
        """Test that worker_task_loop exits gracefully on GreenletExit."""
        mock_sleep = self._mock_object(time, "sleep")
        mock_sleep.side_effect = greenlet.GreenletExit
        self.manager.worker_task_loop()  # Should exit cleanly without error

    def test_worker_task_loop_handles_generic_exception(self):
        """Test worker_task_loop logs exceptions and continues."""

        self.manager.run_periodic_tasks = mock.Mock(
            side_effect=[Exception("exc"), greenlet.GreenletExit]
        )
        self._mock_object(time, "sleep")
        mock_log = self._mock_object(cert_mon_manager.LOG, "exception")
        self.manager.worker_task_loop()
        mock_log.assert_called_once()


class TestCertWatcherBehavior(CertMonManagerBase):
    def test_stop_cert_watcher(self):
        """Test that stop_cert_watcher kills and clears mon_thread."""

        thread = mock.Mock()
        self.manager.mon_thread = thread

        self.manager.stop_cert_watcher()
        thread.kill.assert_called_once()
        thread.wait.assert_called_once()
        self.assertIsNone(self.manager.mon_thread)

    def test_start_cert_watcher_retry_on_exception(self):
        """Test that start_cert_watcher retries once on failure."""

        mock_class = self._mock_object(dccertmon.common.watcher, "DC_CertWatcher")
        mock_class.side_effect = Exception("fail"), mock.Mock()
        mock_sleep = self._mock_object(time, "sleep")
        mock_spawn = self._mock_object(eventlet.greenthread, "spawn")
        self.manager.start_cert_watcher()
        self.assertEqual(mock_class.call_count, 2)
        mock_sleep.assert_called_once()
        mock_spawn.assert_called_once()

    def test_stop_cert_watcher_when_mon_thread_is_none(self):
        """Test stop_cert_watcher does nothing if mon_thread is None."""

        self.manager.mon_thread = None
        self.manager.stop_cert_watcher()

    def test_monitor_cert_loop_greenlet_exit(self):
        """Test that monitor_cert_loop exits on GreenletExit from start_watch."""

        fake_monitor = mock.Mock()
        fake_monitor.start_watch.side_effect = greenlet.GreenletExit

        self.manager.monitor_cert_loop(fake_monitor)  # Should exit without exception

    def test_monitor_cert_loop_handles_unexpected_exception(self):
        """Test monitor_cert_loop handles exceptions and sleeps before retry."""

        fake_monitor = mock.Mock()
        # Raise Exception once, then GreenletExit to break loop
        fake_monitor.start_watch.side_effect = [Exception("exc"), greenlet.GreenletExit]
        mock_sleep = self._mock_object(time, "sleep")
        self.manager.monitor_cert_loop(fake_monitor)
        self.assertTrue(mock_sleep.called)
