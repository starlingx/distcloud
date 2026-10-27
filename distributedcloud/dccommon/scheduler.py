# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import threading
import time
from typing import Any
from typing import Callable
from typing import Optional

from oslo_log import log as logging
from oslo_service import threadgroup

LOG = logging.getLogger(__name__)

wallclock = time.time


class Thread:
    """Wrapper around an ``oslo_service.threadgroup`` thread.

    Provides a ``wait()`` interface that blocks until the submitted
    task completes and re-raises any exception produced by the task.
    """

    def __init__(self, thread, result: dict) -> None:
        self._thread = thread
        self._result = result

    def wait(self, timeout: Optional[float] = None) -> Any:
        """Block until the task completes and return its result.

        Args:
            timeout: Maximum seconds to wait. ``None`` means wait
                indefinitely. If the timeout expires, a
                ``TimeoutError`` is raised.

        Returns:
            The value returned by the callable submitted to
            ``ThreadGroupManager.start``.

        Raises:
            TimeoutError: If *timeout* expires before the task completes.
            Exception: Any exception raised by the callable is
                re-raised to the caller.
        """
        if timeout is not None:
            # oslo.service Thread.wait() does not accept a timeout
            # parameter, so we join the underlying thread directly.
            self._thread.thread.join(timeout)
            if self._thread.thread.is_alive():
                raise TimeoutError(f"Thread did not complete within {timeout} seconds")
        else:
            self._thread.wait()

        if "exception" in self._result:
            raise self._result["exception"]
        return self._result.get("value")


class ThreadGroupManager:
    """Thread group manager backed by ``oslo_service.threadgroup.ThreadGroup``.

    Manages a pool of worker threads and optional periodic timers.

    Args:
        thread_pool_size: Maximum number of threads that can execute
            concurrently.  Defaults to ``100``.  When this many tasks are
            running, ``start`` blocks until one of them finishes.
    """

    def __init__(self, thread_pool_size: int = 100) -> None:
        # The semaphore enforces the pool size and makes start() wait for a
        # free slot. The oslo.service ThreadGroup cannot do that: its
        # threading backend raises RuntimeError once max_threads threads
        # are in the group, instead of queuing.
        #
        # The group is created with sys.maxsize so its limit is never hit.
        # A task releases the semaphore when it returns, but oslo only
        # removes the thread from the group afterwards, in thread_done().
        # In that window a waiting start() can take the freed slot while
        # the finished thread is still counted. Several threads can be in
        # that window at once, so no fixed margin over thread_pool_size is
        # safe.
        self._semaphore = threading.BoundedSemaphore(thread_pool_size)
        try:
            # Threading backend.
            self.group = threadgroup.ThreadGroup(max_threads=sys.maxsize)
        except TypeError:
            # Eventlet backend still uses thread_pool_size.
            self.group = threadgroup.ThreadGroup(thread_pool_size=sys.maxsize)

    def start(
        self,
        func: Callable[..., Any],
        *args: Any,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> Thread:
        """Run *func* in a worker thread from the pool.

        If ``thread_pool_size`` tasks are already running, this blocks
        until one of them finishes.  Do not call it from a task running in
        the same pool, as it can deadlock when the pool is full.

        With the default ``timeout=None`` the wait has no limit, which
        matches eventlet's ``GreenPool.spawn()``.  On a shared pool, pass a
        *timeout* when the caller has its own deadline (for example an RPC
        ``call`` handler).  Otherwise the caller can give up while
        ``start()`` is still waiting, and *func* would run later anyway.

        Args:
            func: The callable to execute.
            *args: Positional arguments forwarded to *func*.
            timeout: Maximum seconds to wait for a free slot.  ``None``
                means wait indefinitely.  It only limits the wait for a
                slot; once *func* starts it runs to completion.  This
                argument is not forwarded to *func*.
            **kwargs: Keyword arguments forwarded to *func*.

        Returns:
            A ``Thread`` handle whose ``wait()`` method blocks until *func*
            completes and propagates its return value or exception.

        Raises:
            TimeoutError: If no slot becomes free within *timeout*.  In
                that case *func* is not started.
        """
        result: dict = {}

        def _run(*run_args: Any, **run_kwargs: Any) -> None:
            try:
                result["value"] = func(*run_args, **run_kwargs)
            except Exception as exc:  # pylint: disable=broad-except
                LOG.exception("Unhandled exception in scheduler task")
                result["exception"] = exc
            finally:
                self._semaphore.release()

        if not self._semaphore.acquire(timeout=timeout):
            raise TimeoutError(f"No free thread in pool within {timeout} seconds")
        try:
            thread = self.group.add_thread(_run, *args, **kwargs)
        except Exception:
            self._semaphore.release()
            raise
        return Thread(thread, result)

    def add_timer(
        self,
        interval: float,
        func: Callable[..., Any],
        *args: Any,
        initial_delay: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        """Schedule *func* to run periodically in its own thread.

        Args:
            interval: Seconds between consecutive executions.
            func: The callable to execute on each tick.
            *args: Positional arguments forwarded to *func*.
            initial_delay: Seconds to wait before the first execution.
                When ``None``, the first execution happens after *interval*
                seconds.
            **kwargs: Keyword arguments forwarded to *func*.
        """
        self.group.add_timer(
            interval, func, *args, initial_delay=initial_delay, **kwargs
        )

    def stop_timers(self) -> None:
        """Signal all periodic timers to stop."""
        self.group.stop_timers()

    def stop(self, graceful: bool = False) -> None:
        """Shut down the thread pool and stop all timers.

        Args:
            graceful: When ``True``, wait for all submitted tasks to
                finish before returning.  When ``False``, cancel pending
                tasks and return immediately (running tasks are still
                allowed to complete).
        """
        self.group.stop(graceful)
        self.group.wait()


def reschedule(action: Any, sleep_time: Optional[float] = 1) -> None:
    """Sleep for the specified number of seconds.

    Intended for spacing out retries of an action.

    Args:
        action: The action being rescheduled (must expose an ``id``
            attribute, used for logging).
        sleep_time: Seconds to sleep.  ``None`` means no sleep.
    """
    if sleep_time is not None:
        LOG.debug("Action %s sleep for %s seconds" % (action.id, sleep_time))
        time.sleep(sleep_time)


def sleep(sleep_time: float) -> None:
    """Sleep for *sleep_time* seconds.

    Args:
        sleep_time: Number of seconds to sleep.
    """
    time.sleep(sleep_time)
