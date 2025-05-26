# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dccertmon.common.subcloud_audit_queue import (
    SubcloudAuditData,
    SubcloudAuditException,
    SubcloudAuditPriorityQueue,
)
from dccertmon.tests.base import DCCertMonTestCase


class SubcloudAuditQueueTestCase(DCCertMonTestCase):
    def setUp(self):
        super().setUp()
        self.sc_audit_queue = SubcloudAuditPriorityQueue()

    def tearDown(self):
        self.sc_audit_queue = None
        super().tearDown()

    def test_audit_item(self):
        item1 = SubcloudAuditData("item1")
        self.assertEqual(item1.name, "item1")
        self.assertEqual(item1.audit_count, 0)
        self.assertEqual(item1, SubcloudAuditData("item1", 0))
        self.assertEqual(item1, SubcloudAuditData("item1", 1))

    def test_subcloud_audit_queue_single(self):
        sc_name = "subcloud1"
        subcloud = SubcloudAuditData(sc_name)
        self.sc_audit_queue.enqueue(subcloud)
        self.assertTrue(self.sc_audit_queue.contains(sc_name))
        self.assertEqual(self.sc_audit_queue.qsize(), 1)
        # peek using the underlying queue
        _, sc_audit_item1 = self.sc_audit_queue.queue[0]
        self.assertEqual(sc_audit_item1.name, sc_name)
        self.assertEqual(sc_audit_item1.audit_count, 1)

    def test_subcloud_audit_queue_multiple(self):
        subclouds = [SubcloudAuditData("subcloud%s" % i) for i in range(20)]
        delay = 0
        for i in range(20):
            self.sc_audit_queue.enqueue(subclouds[i], delay)
            delay += 10
        self.assertEqual(self.sc_audit_queue.qsize(), 20)

        _, first = self.sc_audit_queue.get()
        self.assertEqual(first.name, subclouds[0].name)
        self.assertFalse(self.sc_audit_queue.contains(subclouds[0].name))
        self.assertEqual(self.sc_audit_queue.qsize(), 19)

        # re-enqueue with no delay; it should come out first again
        self.sc_audit_queue.enqueue(first, 0)
        _, first = self.sc_audit_queue.get()
        self.assertEqual(first.name, subclouds[0].name)

        timestamp, second = self.sc_audit_queue.get()
        self.assertEqual(second.name, subclouds[1].name)
        # The time now should be well under the timestamp for this item
        self.assertLess(int(time.time()), timestamp)

    def test_subcloud_audit_queue_custom_timestamp(self):
        subclouds = [SubcloudAuditData("subcloud%s" % i) for i in range(20)]
        timestamp = 0
        for i in range(20):
            self.sc_audit_queue.enqueue(subclouds[i], timestamp=timestamp)
            timestamp += 10
        self.assertEqual(self.sc_audit_queue.qsize(), 20)

        _, first = self.sc_audit_queue.get()
        self.assertEqual(first.name, subclouds[0].name)
        self.assertFalse(self.sc_audit_queue.contains(subclouds[0].name))
        self.assertEqual(self.sc_audit_queue.qsize(), 19)

        # re-enqueue with no delay; it should come out first again
        self.sc_audit_queue.enqueue(first, timestamp=0)
        _, first = self.sc_audit_queue.get()

        self.assertEqual(first.name, subclouds[0].name)
        self.assertEqual(first, subclouds[0])

        self.sc_audit_queue.enqueue(subclouds[0], timestamp=10000)
        prev_timestamp = 0
        for i in range(19):
            next_timestamp, next_item = self.sc_audit_queue.get()
            self.assertLess(prev_timestamp, next_timestamp)
            self.assertNotEqual(next_item.name, subclouds[0].name)
            prev_timestamp = next_timestamp

        next_timestamp, next_item = self.sc_audit_queue.get()
        self.assertEqual(next_timestamp, 10000)
        self.assertEqual(next_item.name, subclouds[0].name)

    def test_subcloud_audit_requeue(self):
        subclouds = [SubcloudAuditData("subcloud%s" % i, 0) for i in range(20)]
        timestamp = 0
        for i in range(20):
            self.sc_audit_queue.enqueue(subclouds[i], timestamp=timestamp)
            timestamp += 10
        self.assertEqual(self.sc_audit_queue.qsize(), 20)

        self.assertTrue(self.sc_audit_queue.contains(subclouds[0].name))

        got_exception = False
        try:
            self.sc_audit_queue.enqueue(subclouds[0], timestamp=timestamp)
        except SubcloudAuditException:
            got_exception = True
        self.assertTrue(got_exception)

        got_exception = False
        try:
            self.sc_audit_queue.enqueue(
                subclouds[0], timestamp=timestamp, allow_requeue=True
            )
        except SubcloudAuditException:
            got_exception = True
        self.assertFalse(got_exception)
        count = 0
        for name in self.sc_audit_queue.enqueued_subcloud_names:
            if name == subclouds[0].name:
                count += 1
        self.assertEqual(count, 2)
