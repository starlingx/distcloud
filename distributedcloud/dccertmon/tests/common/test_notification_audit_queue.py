# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

import eventlet

eventlet.monkey_patch(os=False)

# pylint: disable=wrong-import-position
from keystoneauth1 import session  # noqa: E402

from dccommon.endpoint_cache import EndpointCache  # noqa: E402
from dccertmon.common import (  # noqa: E402
    certificate_monitor_manager as cert_mon_manager,
)
from dccertmon.common.service import CertificateMonitorService  # noqa: E402
from dccertmon.common.subcloud_audit_queue import (  # noqa: E402
    NotificationAuditQueue,
    SubcloudAuditData,
    SubcloudAuditException,
)
from dccertmon.tests.base import DCCertMonTestCase  # noqa: E402

# pylint: enable=wrong-import-position

# Shared function for mocking certificate retrieval
audit_order = []
first_started = eventlet.event.Event()
AUDIT_SLEEP_TIME = 3


def slow_get_cert(*args, **kwargs):
    """Returns a side-effect function that simulates a delayed cert fetch.

    Records the start time of the audit in `audit_order`.
    If `first_started` is provided, it will be triggered once the first audit starts.
    """
    ts = time.time()
    audit_order.append(ts)
    if len(audit_order) == 1:
        first_started.send()
        # Simulate long-running audit for holding the lock
        eventlet.sleep(AUDIT_SLEEP_TIME)
    return None


class NotificationAuditQueueTestCase(DCCertMonTestCase):
    def setUp(self):
        super().setUp()
        self.queue = NotificationAuditQueue()

    def tearDown(self):
        self.queue = None
        super().tearDown()

    def test_enqueue_single(self):
        item = SubcloudAuditData("subcloud1")
        self.queue.enqueue(item)
        self.assertEqual(self.queue.qsize(), 1)
        self.assertTrue(self.queue.contains("subcloud1"))

    def test_enqueue_duplicate_raises(self):
        item = SubcloudAuditData("subcloud1")
        self.queue.enqueue(item)
        self.assertRaises(SubcloudAuditException, self.queue.enqueue, item)

    def test_enqueue_with_timestamp_ordering(self):
        items = [SubcloudAuditData(f"subcloud{i}") for i in range(3)]
        timestamp = int(time.time())

        self.queue.enqueue(items[2], timestamp=timestamp + 20)
        self.queue.enqueue(items[0], timestamp=timestamp + 0)
        self.queue.enqueue(items[1], timestamp=timestamp + 10)

        first = self.queue.get()[1]
        second = self.queue.get()[1]
        third = self.queue.get()[1]

        self.assertEqual(first.name, "subcloud0")
        self.assertEqual(second.name, "subcloud1")
        self.assertEqual(third.name, "subcloud2")

    def test_contains_and_qsize(self):
        self.assertFalse(self.queue.contains("subcloudX"))
        self.assertEqual(self.queue.qsize(), 0)

        item = SubcloudAuditData("subcloudX")
        self.queue.enqueue(item)
        self.assertTrue(self.queue.contains("subcloudX"))
        self.assertEqual(self.queue.qsize(), 1)


class NotificationAuditBehaviorTestCase(DCCertMonTestCase):

    def setUp(self):
        super().setUp()
        global audit_order, first_started
        audit_order = []
        first_started = eventlet.event.Event()
        self.manager = cert_mon_manager.CertificateMonitorManager()
        self.manager.sc_audit_pool = None  # Force serial execution
        self.service = CertificateMonitorService()
        self.service.manager = self.manager
        # Store common mocks as instance attributes
        self.mock_get_subcloud = self._mock_object(
            cert_mon_manager.utils, "get_subcloud"
        )
        self.mock_is_subcloud_online = self._mock_object(
            cert_mon_manager.utils, "is_subcloud_online"
        )
        self._mock_object(EndpointCache, "get_admin_session")
        self.mock_get_token = self._mock_object(session.Session, "get_token")

        self.mock_slow_get_cert = self._mock_object(
            cert_mon_manager.utils, "get_endpoint_certificate"
        )
        self.mock_get_subcloud.return_value = {
            "name": "subcloud",
            "deploy-status": "complete",
            "availability-status": "online",
            "management-start-ip": "1.2.3.4",
        }
        self.mock_is_subcloud_online.return_value = True
        self.mock_get_token.return_value = "fake-token"

    def test_subcloud_added_to_notification_queue(self):
        """Ensure subcloud is enqueued when marked online."""
        subcloud = "subcloud1"
        self.assertFalse(self.manager.sc_notify_audit_queue.contains(subcloud))
        self.manager.audit_subcloud(subcloud, self.manager.sc_notify_audit_queue)
        self.assertTrue(self.manager.sc_notify_audit_queue.contains(subcloud))

    def test_failed_audit_requeues_with_delay(self):
        """Ensure that an audit failure requeues the subcloud with delay."""
        subcloud = "subcloud2"
        audit_data = SubcloudAuditData(subcloud)
        self.manager.sc_notify_audit_queue.enqueue(audit_data)

        # Patch internal utils to simulate failure in cert retrieval
        self.mock_slow_get_cert.side_effect = Exception("fail")

        _, item = self.manager.sc_notify_audit_queue.get()
        self.manager._subcloud_audit(self.manager.sc_notify_audit_queue, item)

        # The item should have been re-enqueued with now+60
        self.assertTrue(self.manager.sc_notify_audit_queue.contains(subcloud))
        next_timestamp, _ = self.manager.sc_notify_audit_queue.queue[0]
        now = int(time.time())
        self.assertGreaterEqual(next_timestamp, now + 59)

    def test_audit_same_subclouds_is_serialized(self):
        """Ensure audits for the same subcloud run sequentially using the lock."""
        subcloud = "subcloud-lock-test"
        item1 = SubcloudAuditData(subcloud)
        item2 = SubcloudAuditData(subcloud)

        self.manager.sc_audit_queue.enqueue(item1)
        self.manager.sc_notify_audit_queue.enqueue(item2)

        self.mock_slow_get_cert.side_effect = slow_get_cert

        # Spawn first audit and wait until it starts (acquires the lock)
        t1 = eventlet.spawn(
            self.manager.do_subcloud_audit, self.manager.sc_audit_queue, item1
        )
        first_started.wait(timeout=5)

        # Spawn second audit while first is still holding the lock
        t2 = eventlet.spawn(
            self.manager.do_subcloud_audit,
            self.manager.sc_notify_audit_queue,
            item2,
        )
        eventlet.sleep(1)

        # Assert that the second audit hasn't started yet
        self.assertEqual(
            len(audit_order),
            1,
            "Second audit should still be waiting for the lock",
        )

        # Wait for both audits to complete
        t1.wait()
        t2.wait()

        self.assertEqual(len(audit_order), 2, "Both audits should have run")
        self.assertLess(
            audit_order[0] + AUDIT_SLEEP_TIME,
            audit_order[1],
            "Second audit should have started after the first released the lock",
        )

    def test_audit_different_subclouds_run_concurrently(self):
        """Ensure audits for different subclouds are not blocked by the lock."""
        subcloud1 = "subcloud-lock-test1"
        subcloud2 = "subcloud-lock-test2"
        item1 = SubcloudAuditData(subcloud1)
        item2 = SubcloudAuditData(subcloud2)

        self.manager.sc_audit_queue.enqueue(item1)
        self.manager.sc_notify_audit_queue.enqueue(item2)

        self.mock_slow_get_cert.side_effect = slow_get_cert

        # Spawn both audits for different subclouds simultaneously
        t1 = eventlet.spawn(
            self.manager.do_subcloud_audit, self.manager.sc_audit_queue, item1
        )
        t2 = eventlet.spawn(
            self.manager.do_subcloud_audit,
            self.manager.sc_notify_audit_queue,
            item2,
        )
        eventlet.sleep(1)

        # Both audits should have started within a short time
        self.assertEqual(len(audit_order), 2, "Both audits should have started")

        t1.wait()
        t2.wait()

        self.assertLess(
            abs(audit_order[0] - audit_order[1]),
            AUDIT_SLEEP_TIME,
            "Audits for different subclouds should run concurrently",
        )
