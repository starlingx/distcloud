#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import re
import threading

import mock

from dccommon import consts as dccommon_consts
from dccommon import utils as cutils
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.engine import sync_thread
from dcorch.objects import orchrequest
from dcorch.tests import base

SOURCE_RESOURCE_ID = 2
PENDING_REQUESTS_ERROR = (
    "There are 1 pending requests to sync. Will retry in next sync cycle."
)


class TestSyncThreadSync(base.OrchestratorTestCase):
    """Tests for SyncThread.sync running _sync_requests in a managed thread."""

    def setUp(self):
        super().setUp()

        self._mock_object(dcmanager_rpc_client, "SubcloudStateClient")
        self._mock_object(dcmanager_rpc_client, "ManagerClient")
        self._mock_object(cutils, "get_region_one_name")
        self.mock_log = self._mock_object(sync_thread, "LOG")

        # Use a short timeout so the timeout path runs fast
        mock_patch_timeout = mock.patch.object(sync_thread, "SYNC_TIMEOUT", 0.1)
        mock_patch_timeout.start()
        self.addCleanup(mock_patch_timeout.stop)

        self.request = mock.MagicMock()
        self.request.state = consts.ORCH_REQUEST_QUEUED
        self.request.orch_job.source_resource_id = SOURCE_RESOURCE_ID

        self.mock_get_by_attrs = self._mock_object(
            orchrequest.OrchRequestList, "get_by_attrs"
        )

        self.sync_thread = sync_thread.SyncThread(
            "subcloud1", endpoint_type=dccommon_consts.ENDPOINT_TYPE_IDENTITY
        )
        self.sync_thread.is_subcloud_enabled = mock.MagicMock(return_value=True)
        self.sync_thread.set_sync_status = mock.MagicMock()
        self.sync_thread._sync_requests = mock.MagicMock()

    def _set_pending_requests_after_sync(self, pending_requests):
        """Return the request before the sync and pending_requests after it."""
        self.mock_get_by_attrs.side_effect = [[self.request], pending_requests]

    def test_sync_succeeds_and_sets_in_sync(self):
        self._set_pending_requests_after_sync([])
        self.sync_thread._sync_requests.return_value = False

        self.sync_thread.sync()

        self.sync_thread._sync_requests.assert_called_once_with(
            [self.request], mock.ANY
        )
        # The abort event must only be set when the sync times out
        abort_event = self.sync_thread._sync_requests.call_args.args[1]
        self.assertFalse(abort_event.is_set())
        self.sync_thread.set_sync_status.assert_called_once_with(
            dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        self.mock_log.exception.assert_not_called()

    def test_sync_aborted_request_sets_out_of_sync_without_raising(self):
        # The return value of _sync_requests must be propagated by
        # thread.wait() so the aborted path is followed
        self._set_pending_requests_after_sync([self.request])
        self.sync_thread._sync_requests.return_value = True

        self.sync_thread.sync()

        self.sync_thread.set_sync_status.assert_called_once_with(
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        )
        self.mock_log.exception.assert_not_called()

    def test_sync_endpoint_not_reachable_sets_out_of_sync_and_raises(self):
        # Exceptions raised by _sync_requests must be re-raised by
        # thread.wait() and handled by sync
        self._set_pending_requests_after_sync([self.request])
        self.sync_thread._sync_requests.side_effect = exceptions.EndpointNotReachable()

        self.assertRaisesRegex(
            Exception, f"^{re.escape(PENDING_REQUESTS_ERROR)}$", self.sync_thread.sync
        )

        self.sync_thread.set_sync_status.assert_called_once_with(
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC, alarmable=True
        )
        self.mock_log.info.assert_any_call(
            "EndpointNotReachable, 1 sync requests pending",
            extra=self.sync_thread.log_extra,
        )
        self.mock_log.exception.assert_not_called()

    def test_sync_times_out_sets_out_of_sync_and_raises(self):
        """sync() stops waiting on timeout and signals the worker to stop.

        _sync_requests is mocked to block until the test finishes, so it
        runs past the patched SYNC_TIMEOUT (0.1s). Native threads can't be
        killed, so on timeout sync() sets the abort event passed to the
        worker and returns without waiting for it. Since the request is
        still pending, sync() sets the status to out-of-sync and raises.
        """
        release_sync = threading.Event()
        self.addCleanup(release_sync.set)
        abort_events = []

        def _blocking_sync_requests(requests, abort_event):
            abort_events.append(abort_event)
            release_sync.wait(timeout=10)

        self.sync_thread._sync_requests.side_effect = _blocking_sync_requests
        self._set_pending_requests_after_sync([self.request])

        self.assertRaisesRegex(
            Exception, f"^{re.escape(PENDING_REQUESTS_ERROR)}$", self.sync_thread.sync
        )

        # sync must return on timeout without waiting for the sync thread
        # to finish, and signal the sync thread to stop
        self.assertFalse(release_sync.is_set())
        self.assertEqual(1, len(abort_events))
        self.assertTrue(abort_events[0].is_set())
        self.mock_log.exception.assert_called_once_with(
            "Sync timed out for subcloud1/identity."
        )
        self.sync_thread.set_sync_status.assert_called_once_with(
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC, alarmable=True
        )


class TestSyncThreadSyncRequests(base.OrchestratorTestCase):
    """Tests for the timeout and abort paths in SyncThread._sync_requests.

    The abort tests set the abort event directly, either before the call or
    from inside the mocked sync_resource(), to simulate sync() timing out
    at different points while the worker thread is running.
    """

    def setUp(self):
        super().setUp()

        self._mock_object(dcmanager_rpc_client, "SubcloudStateClient")
        self._mock_object(dcmanager_rpc_client, "ManagerClient")
        self._mock_object(cutils, "get_region_one_name")
        self.mock_log = self._mock_object(sync_thread, "LOG")
        self.mock_should_stop = self._mock_object(db_api, "should_stop_subcloud_sync")
        self.mock_should_stop.return_value = False

        self.request = mock.MagicMock()
        self.request.try_count = 0

        self.sync_thread = sync_thread.SyncThread(
            "subcloud1", endpoint_type=dccommon_consts.ENDPOINT_TYPE_IDENTITY
        )
        self.sync_thread.sync_resource = mock.MagicMock()
        self.abort_event = threading.Event()

    def _assert_aborted_log(self):
        self.mock_log.warning.assert_called_once_with(
            "Sync thread for subcloud1/identity exiting after sync timeout.",
            extra=self.sync_thread.log_extra,
        )

    def test_sync_requests_retries_request_timeout_then_succeeds(self):
        self.sync_thread.sync_resource.side_effect = [
            exceptions.SyncRequestTimeout(),
            None,
        ]

        request_aborted = self.sync_thread._sync_requests(
            [self.request], self.abort_event
        )

        self.assertFalse(request_aborted)
        self.assertEqual(2, self.sync_thread.sync_resource.call_count)
        self.assertEqual(1, self.request.try_count)
        self.assertEqual(consts.ORCH_REQUEST_STATE_COMPLETED, self.request.state)
        self.assertEqual(1, self.request.deleted)

    def test_sync_requests_raises_endpoint_not_reachable_after_max_timeouts(self):
        self.sync_thread.sync_resource.side_effect = exceptions.SyncRequestTimeout()

        self.assertRaises(
            exceptions.EndpointNotReachable,
            self.sync_thread._sync_requests,
            [self.request],
            self.abort_event,
        )

        self.assertEqual(
            sync_thread.SyncThread.MAX_RETRY,
            self.sync_thread.sync_resource.call_count,
        )
        self.assertEqual(sync_thread.SyncThread.MAX_RETRY, self.request.try_count)
        self.assertEqual(consts.ORCH_REQUEST_STATE_IN_PROGRESS, self.request.state)

    def test_sync_requests_does_not_start_when_aborted(self):
        """No request is processed if the sync already timed out.

        The abort event is set before the worker starts. The worker must
        return before syncing or saving the request, leaving it pending
        for the next sync, and log that it exited after the timeout.
        """
        self.abort_event.set()

        request_aborted = self.sync_thread._sync_requests(
            [self.request], self.abort_event
        )

        self.assertFalse(request_aborted)
        self.sync_thread.sync_resource.assert_not_called()
        self.request.save.assert_not_called()
        self._assert_aborted_log()

    def test_sync_requests_stops_before_next_request_when_aborted(self):
        """The worker stops before the next request after a timeout.

        The abort event is set while the first of two requests is syncing.
        An in-flight sync_resource() call can't be interrupted, so the
        first request completes. The worker must then return before
        touching the second request, which stays pending for the next
        sync.
        """
        second_request = mock.MagicMock()
        second_request.state = consts.ORCH_REQUEST_QUEUED
        self.sync_thread.sync_resource.side_effect = (
            lambda request: self.abort_event.set()
        )

        self.sync_thread._sync_requests(
            [self.request, second_request], self.abort_event
        )

        # The in-flight request completes, the next one is left pending
        self.sync_thread.sync_resource.assert_called_once_with(self.request)
        self.assertEqual(consts.ORCH_REQUEST_STATE_COMPLETED, self.request.state)
        self.assertEqual(consts.ORCH_REQUEST_QUEUED, second_request.state)
        second_request.save.assert_not_called()
        self._assert_aborted_log()

    def test_sync_requests_logs_when_last_request_finishes_after_abort(self):
        """The worker logs its exit if the last request ends after a timeout.

        The abort event is set while the only request is syncing. No
        check point is left after it completes, so the warning must be
        logged at the end of _sync_requests. This is the log that shows
        when a timed-out worker actually finished.
        """
        self.sync_thread.sync_resource.side_effect = (
            lambda request: self.abort_event.set()
        )

        self.sync_thread._sync_requests([self.request], self.abort_event)

        self.assertEqual(consts.ORCH_REQUEST_STATE_COMPLETED, self.request.state)
        self._assert_aborted_log()

    def test_sync_requests_stops_retrying_when_aborted(self):
        """A retryable request is not retried after a timeout.

        The abort event is set while the request is syncing, and the
        attempt fails with SyncRequestFailedRetry. The backoff returns at
        once because the event is set, and the check at the start of the
        retry loop makes the worker return without a second attempt. The
        failed attempt was already saved, so the request is left FAILED.
        Like a request that exhausts its retries, the next sync skips it,
        and the next audit creates a new request for the resource.
        """

        def _sync_resource(request):
            self.abort_event.set()
            raise exceptions.SyncRequestFailedRetry()

        self.sync_thread.sync_resource.side_effect = _sync_resource

        self.sync_thread._sync_requests([self.request], self.abort_event)

        self.sync_thread.sync_resource.assert_called_once_with(self.request)
        self.assertEqual(1, self.request.try_count)
        self.assertEqual(consts.ORCH_REQUEST_STATE_FAILED, self.request.state)
        self._assert_aborted_log()

    def test_sync_requests_stops_retrying_timed_out_request_when_aborted(self):
        """A timed-out request is left pending after a sync timeout.

        The abort event is set while the request is syncing, and the
        attempt fails with SyncRequestTimeout. The check at the start of
        the retry loop makes the worker return without a second attempt,
        leaving the request IN_PROGRESS so the next sync retries it.
        """

        def _sync_resource(request):
            self.abort_event.set()
            raise exceptions.SyncRequestTimeout()

        self.sync_thread.sync_resource.side_effect = _sync_resource

        self.sync_thread._sync_requests([self.request], self.abort_event)

        self.sync_thread.sync_resource.assert_called_once_with(self.request)
        self.assertEqual(1, self.request.try_count)
        self.assertEqual(consts.ORCH_REQUEST_STATE_IN_PROGRESS, self.request.state)
        self._assert_aborted_log()

    def test_sync_requests_retry_backoff_waits_on_abort_event(self):
        """The retry backoff waits on the abort event instead of sleeping.

        The first attempt fails with SyncRequestFailedRetry and the second
        succeeds. The backoff must call abort_event.wait() with the 1s
        delay so that a timeout during the backoff wakes the worker up.
        The event is never set, so the request completes normally and
        nothing about an abort is logged.
        """
        abort_event = mock.MagicMock()
        abort_event.is_set.return_value = False
        self.sync_thread.sync_resource.side_effect = [
            exceptions.SyncRequestFailedRetry(),
            None,
        ]

        request_aborted = self.sync_thread._sync_requests([self.request], abort_event)

        self.assertFalse(request_aborted)
        abort_event.wait.assert_called_once_with(1)
        self.assertEqual(2, self.sync_thread.sync_resource.call_count)
        self.assertEqual(consts.ORCH_REQUEST_STATE_COMPLETED, self.request.state)
        self.mock_log.warning.assert_not_called()
