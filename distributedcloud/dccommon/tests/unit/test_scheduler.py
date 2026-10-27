# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import threading
import time

import mock
from oslotest import base

from dccommon import scheduler


class TestThreadGroupManager(base.BaseTestCase):
    """Tests for the oslo.service ThreadGroupManager class."""

    def setUp(self):
        super(TestThreadGroupManager, self).setUp()
        self.tgm = scheduler.ThreadGroupManager()

    def tearDown(self):
        self.tgm.stop()
        super(TestThreadGroupManager, self).tearDown()

    def test_init(self):
        """Test ThreadGroupManager initialization."""
        self.assertIsNotNone(self.tgm.group)

    def test_init_with_thread_pool_size(self):
        """Test ThreadGroupManager initialization with pool size."""
        tgm = scheduler.ThreadGroupManager(thread_pool_size=10)
        self.assertIsNotNone(tgm.group)
        tgm.stop()

    def test_start(self):
        """Test starting a function in a sub-thread."""
        result_event = threading.Event()
        result_holder = []

        def task():
            result_holder.append("done")
            result_event.set()

        self.tgm.start(task)
        result_event.wait(timeout=5)
        self.assertEqual(["done"], result_holder)

    def test_start_with_args(self):
        """Test starting a function with arguments."""
        result_event = threading.Event()
        result_holder = []

        def task(a, b, key=None):
            result_holder.append((a, b, key))
            result_event.set()

        self.tgm.start(task, 1, 2, key="value")
        result_event.wait(timeout=5)
        self.assertEqual([(1, 2, "value")], result_holder)

    def test_start_returns_thread(self):
        """Test that start() returns a Thread wrapper."""
        thread = self.tgm.start(lambda: 42)
        self.assertIsInstance(thread, scheduler.Thread)

    def test_task_exception_is_logged(self):
        """Test that an unhandled task exception is logged."""

        def task():
            raise RuntimeError("boom")

        with mock.patch("dccommon.scheduler.LOG") as mock_log:
            thread = self.tgm.start(task)
            self.assertRaises(RuntimeError, thread.wait)

            mock_log.exception.assert_called_once_with(
                "Unhandled exception in scheduler task"
            )

    def test_thread_wait(self):
        """Test that Thread.wait() blocks until completion."""
        result_event = threading.Event()

        def task():
            time.sleep(0.1)
            result_event.set()

        thread = self.tgm.start(task)
        thread.wait()
        self.assertTrue(result_event.is_set())

    def test_thread_wait_with_timeout(self):
        """Test Thread.wait() with timeout on a fast task."""
        thread = self.tgm.start(lambda: time.sleep(0.05))
        # Should not raise — task finishes within timeout
        thread.wait(timeout=5)

    def test_thread_wait_timeout_exceeded(self):
        """Test Thread.wait() raises TimeoutError when timeout is exceeded."""
        thread = self.tgm.start(lambda: time.sleep(10))
        self.assertRaises(TimeoutError, thread.wait, timeout=0.1)

    def test_add_timer(self):
        """Test adding a periodic timer."""
        call_count = []
        call_event = threading.Event()

        def timer_func():
            call_count.append(1)
            if len(call_count) >= 2:
                call_event.set()

        self.tgm.add_timer(0.1, timer_func)
        call_event.wait(timeout=5)
        self.assertGreaterEqual(len(call_count), 2)

    def test_stop_timers(self):
        """Test stopping timers."""
        call_count = []

        def timer_func():
            call_count.append(1)

        self.tgm.add_timer(0.1, timer_func)
        time.sleep(0.3)
        self.tgm.stop_timers()
        count_at_stop = len(call_count)
        time.sleep(0.3)
        # After stopping timers, no new calls should be made
        self.assertAlmostEqual(len(call_count), count_at_stop, delta=1)

    def test_stop_graceful(self):
        """Test graceful stop."""
        result_event = threading.Event()

        def long_task():
            time.sleep(0.2)
            result_event.set()

        self.tgm.start(long_task)
        self.tgm.stop(graceful=True)
        # After graceful stop, the task should have completed
        self.assertTrue(result_event.is_set())

    def test_stop_not_graceful(self):
        """Test non-graceful stop does not raise."""
        self.tgm.start(lambda: time.sleep(0.5))
        # Should not raise
        self.tgm.stop(graceful=False)

    def test_task_exception_does_not_affect_other_tasks(self):
        """Test a failing task does not affect concurrent tasks."""
        error = RuntimeError("boom")

        def failing_task():
            raise error

        thread_ok_1 = self.tgm.start(lambda: "result 1")
        thread_failing = self.tgm.start(failing_task)
        thread_ok_2 = self.tgm.start(lambda: "result 2")

        exc = self.assertRaises(RuntimeError, thread_failing.wait)
        self.assertIs(error, exc)
        self.assertEqual("result 1", thread_ok_1.wait())
        self.assertEqual("result 2", thread_ok_2.wait())

    def test_each_thread_raises_only_its_own_exception(self):
        """Test exceptions from concurrent failing tasks are not mixed up."""
        errors = [ValueError(f"error {i}") for i in range(5)]

        def failing_task(exc):
            raise exc

        threads = [self.tgm.start(failing_task, exc) for exc in errors]

        for thread, expected in zip(threads, errors):
            exc = self.assertRaises(ValueError, thread.wait)
            self.assertIs(expected, exc)

    def test_task_exception_releases_thread_slot(self):
        """Test a failed task frees its slot in a full thread group."""
        tgm = scheduler.ThreadGroupManager(thread_pool_size=1)
        self.addCleanup(tgm.stop)

        def failing_task():
            raise RuntimeError("boom")

        self.assertRaises(RuntimeError, tgm.start(failing_task).wait)
        # The only slot was used by the failed task; it must be free again.
        self.assertEqual(42, tgm.start(lambda: 42).wait(timeout=5))

    def test_start_after_task_exception(self):
        """Test the manager accepts new tasks after a task fails."""

        def failing_task():
            raise RuntimeError("boom")

        self.assertRaises(RuntimeError, self.tgm.start(failing_task).wait)
        self.assertEqual(42, self.tgm.start(lambda: 42).wait(timeout=5))

    def test_stop_after_task_exception(self):
        """Test stop() does not raise when a task has failed."""

        def failing_task():
            raise RuntimeError("boom")

        thread = self.tgm.start(failing_task)
        self.assertRaises(RuntimeError, thread.wait)
        # Should not raise
        self.tgm.stop()

    def test_task_exception_is_not_raised_by_stop(self):
        """Test a failing task that was never waited on does not fail stop()."""
        task_done = threading.Event()

        def failing_task():
            task_done.set()
            raise RuntimeError("boom")

        self.tgm.start(failing_task)
        task_done.wait(timeout=5)
        # Should not raise
        self.tgm.stop(graceful=True)

    def test_start_queues_tasks_beyond_pool_size(self):
        """Test tasks beyond the pool size are queued instead of rejected."""
        tgm = scheduler.ThreadGroupManager(thread_pool_size=2)
        self.addCleanup(tgm.stop)

        threads = [tgm.start(lambda i=i: i) for i in range(10)]

        self.assertEqual(list(range(10)), [t.wait(timeout=5) for t in threads])

    def test_start_limits_concurrent_tasks_to_pool_size(self):
        """Test no more than thread_pool_size tasks run at the same time."""
        tgm = scheduler.ThreadGroupManager(thread_pool_size=3)
        self.addCleanup(tgm.stop)
        lock = threading.Lock()
        running = [0]
        max_running = [0]

        def task():
            with lock:
                running[0] += 1
                max_running[0] = max(max_running[0], running[0])
            time.sleep(0.2)
            with lock:
                running[0] -= 1

        threads = [tgm.start(task) for _ in range(10)]
        for thread in threads:
            thread.wait(timeout=10)

        self.assertEqual(3, max_running[0])

    def test_start_blocks_while_pool_is_full(self):
        """Test start() blocks until a running task frees a slot."""
        tgm = scheduler.ThreadGroupManager(thread_pool_size=1)
        self.addCleanup(tgm.stop)
        release_first = threading.Event()
        second_started = threading.Event()

        first = tgm.start(release_first.wait)

        def start_second():
            tgm.start(lambda: None).wait(timeout=5)
            second_started.set()

        starter = threading.Thread(target=start_second)
        starter.start()

        self.assertFalse(second_started.wait(timeout=0.3))
        release_first.set()
        first.wait(timeout=5)
        self.assertTrue(second_started.wait(timeout=5))
        starter.join(timeout=5)

    def test_start_with_timeout_runs_task_when_slot_is_free(self):
        """Test start() with a timeout runs the task when a slot is free."""
        self.assertEqual(42, self.tgm.start(lambda: 42, timeout=1).wait(timeout=5))

    def test_start_timeout_is_not_forwarded_to_task(self):
        """Test the timeout argument is consumed by start() only."""

        def task(a, key=None, **kwargs):
            return a, key, kwargs

        thread = self.tgm.start(task, 1, timeout=1, key="value")

        self.assertEqual((1, "value", {}), thread.wait(timeout=5))

    def test_start_timeout_raises_when_pool_stays_full(self):
        """Test start() raises TimeoutError and skips the task if no slot frees."""
        tgm = scheduler.ThreadGroupManager(thread_pool_size=1)
        self.addCleanup(tgm.stop)
        release_first = threading.Event()
        self.addCleanup(release_first.set)
        task_ran = threading.Event()

        tgm.start(release_first.wait)

        started_at = time.monotonic()
        self.assertRaises(TimeoutError, tgm.start, task_ran.set, timeout=0.2)
        elapsed = time.monotonic() - started_at

        # Allow for timer granularity; the point is that it waited.
        self.assertGreaterEqual(elapsed, 0.15)
        # The task must not run later either, once the pool has a free slot.
        release_first.set()
        self.assertEqual(42, tgm.start(lambda: 42, timeout=5).wait(timeout=5))
        self.assertFalse(task_ran.is_set())

    def test_start_timeout_waits_for_slot_freed_in_time(self):
        """Test start() succeeds if a slot frees before the timeout expires."""
        tgm = scheduler.ThreadGroupManager(thread_pool_size=1)
        self.addCleanup(tgm.stop)
        release_first = threading.Event()

        tgm.start(release_first.wait)
        releaser = threading.Timer(0.2, release_first.set)
        releaser.start()
        self.addCleanup(releaser.cancel)
        self.addCleanup(release_first.set)

        self.assertEqual(42, tgm.start(lambda: 42, timeout=5).wait(timeout=5))

    def test_start_timeout_does_not_take_a_slot(self):
        """Test a timed out start() does not change the pool size."""
        tgm = scheduler.ThreadGroupManager(thread_pool_size=1)
        self.addCleanup(tgm.stop)
        release_first = threading.Event()
        self.addCleanup(release_first.set)

        first = tgm.start(release_first.wait)
        self.assertRaises(TimeoutError, tgm.start, lambda: None, timeout=0.1)

        # The pool is still full while the first task runs.
        self.assertRaises(TimeoutError, tgm.start, lambda: None, timeout=0.1)

        # Once it finishes, exactly one slot is available again.
        release_first.set()
        first.wait(timeout=5)
        release_second = threading.Event()
        self.addCleanup(release_second.set)
        tgm.start(release_second.wait, timeout=5)
        self.assertRaises(TimeoutError, tgm.start, lambda: None, timeout=0.1)


class TestThreadGroupManagerAddThreadFailure(base.BaseTestCase):
    """Tests for ThreadGroupManager when the thread cannot be created."""

    def setUp(self):
        super().setUp()
        self.tgm = scheduler.ThreadGroupManager(thread_pool_size=1)
        self.addCleanup(self.tgm.stop)
        patcher = mock.patch.object(
            self.tgm.group, "add_thread", wraps=self.tgm.group.add_thread
        )
        self.mock_add_thread = patcher.start()
        self.addCleanup(patcher.stop)

    def test_start_releases_slot_when_add_thread_fails(self):
        """Test a failure to create the thread does not leak a pool slot."""
        self.mock_add_thread.side_effect = RuntimeError("can't start new thread")

        exc = self.assertRaises(RuntimeError, self.tgm.start, lambda: None)
        self.assertEqual("can't start new thread", str(exc))

        # The only slot must be free again for the next task.
        self.mock_add_thread.side_effect = None
        self.assertEqual(42, self.tgm.start(lambda: 42).wait(timeout=5))


class TestSchedulerHelpers(base.BaseTestCase):
    """Tests for module-level helper functions."""

    @mock.patch("dccommon.scheduler.time.sleep")
    def test_reschedule(self, mock_sleep):
        """Test reschedule sleeps for specified duration."""
        action = mock.Mock()
        action.id = "test-action"
        scheduler.reschedule(action, sleep_time=5)
        mock_sleep.assert_called_once_with(5)

    @mock.patch("dccommon.scheduler.time.sleep")
    def test_reschedule_none(self, mock_sleep):
        """Test reschedule with None sleep_time does not sleep."""
        action = mock.Mock()
        action.id = "test-action"
        scheduler.reschedule(action, sleep_time=None)
        mock_sleep.assert_not_called()

    @mock.patch("dccommon.scheduler.time.sleep")
    def test_sleep(self, mock_sleep):
        """Test sleep wrapper."""
        scheduler.sleep(3)
        mock_sleep.assert_called_once_with(3)
