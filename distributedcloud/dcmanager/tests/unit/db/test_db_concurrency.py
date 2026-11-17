# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for DB session thread-isolation under concurrent access.

These tests verify that the threading.local-based DB session management
correctly isolates transactions across threads while allowing nested
transactions within a single thread (e.g. subcloud_create calling
subcloud_status_create_all within the same write_session scope).

Note on SQLite limitations:
    The test DB uses in-memory SQLite (``sqlite://``), which does not
    support truly concurrent writes from multiple threads — concurrent
    commits invalidate each other's cursors.  Therefore the DB-operation
    tests serialise writes with a lock and focus on verifying that the
    *context objects* are correctly isolated.  The thread-local isolation
    itself is validated by ``test_thread_local_context_isolation`` which
    uses a barrier to run all threads simultaneously.

    In production, PostgreSQL handles concurrent writes natively, so the
    per-thread _DBContext pattern works without serialisation.
"""

import concurrent.futures
import threading

from oslo_utils import uuidutils

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import api as db_sqlalchemy_api
from dcmanager.tests import base
from dcmanager.tests import utils

# Number of concurrent threads for parallel tests.
CONCURRENCY = 100

# Lock to serialise SQLite writes (in-memory SQLite doesn't support
# concurrent write transactions from different threads).
_SQLITE_LOCK = threading.Lock()


class TestDBConcurrency(base.DCManagerTestCase):
    """Verify DB session thread-isolation under concurrent access."""

    @staticmethod
    def _make_subcloud_values(index):
        """Return a unique set of subcloud creation kwargs for *index*."""
        return {
            "name": f"subcloud-concurrent-{index}",
            "description": f"concurrent test subcloud {index}",
            "location": "test-location",
            "software_version": "10.04",
            "management_subnet": f"192.168.{index}.0/24",
            "management_gateway_ip": f"192.168.{index}.1",
            "management_start_ip": f"192.168.{index}.2",
            "management_end_ip": f"192.168.{index}.50",
            "systemcontroller_gateway_ip": "192.168.204.101",
            "external_oam_subnet_ip_family": "4",
            "deploy_status": consts.DEPLOY_STATE_NONE,
            "error_description": consts.ERROR_DESC_EMPTY,
            "region_name": uuidutils.generate_uuid().replace("-", ""),
            "openstack_installed": False,
            "group_id": 1,
        }

    def test_thread_local_context_isolation(self):
        """Verify _get_context() returns distinct objects per OS thread.

        Uses a barrier so all threads call _get_context() simultaneously,
        then checks that every distinct OS thread received its own
        _DBContext instance.
        """
        results = {}
        barrier = threading.Barrier(CONCURRENCY)
        lock = threading.Lock()

        def _capture_context(index):
            barrier.wait(timeout=10)
            db_ctx = db_sqlalchemy_api._get_context()
            with lock:
                results[index] = {
                    "ctx_id": id(db_ctx),
                    "thread_id": threading.current_thread().ident,
                }

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_capture_context, i) for i in range(CONCURRENCY)]
            concurrent.futures.wait(futures)

        self.assertEqual(CONCURRENCY, len(results))

        # Group by OS thread — same thread must yield the same _DBContext
        thread_to_ctx = {}
        for info in results.values():
            tid = info["thread_id"]
            cid = info["ctx_id"]
            if tid in thread_to_ctx:
                self.assertEqual(
                    thread_to_ctx[tid],
                    cid,
                    "Same OS thread got different _DBContext objects",
                )
            else:
                thread_to_ctx[tid] = cid

        # Different OS threads must have different _DBContext objects
        ctx_to_threads = {}
        for tid, cid in thread_to_ctx.items():
            self.assertNotIn(
                cid,
                ctx_to_threads,
                f"Threads {ctx_to_threads.get(cid)} and {tid} share the "
                f"same _DBContext (id={cid}) — thread-local isolation broken",
            )
            ctx_to_threads[cid] = tid

    def test_create_100_subclouds_in_parallel(self):
        """Create 100 subclouds from different threads.

        Each subcloud_create internally calls subcloud_status_create_all
        and subcloud_audits_create via nested write_session() calls.
        Verifies:
          - Nested transactions within one thread share the DB context.
          - All FK constraints are satisfied (no FK violations).
          - Each thread uses its own _DBContext.
        """
        errors = []
        created_ids = []
        context_ids = {}
        lock = threading.Lock()

        def _create(index):
            ctx = utils.dummy_context()
            values = self._make_subcloud_values(index)
            db_ctx = db_sqlalchemy_api._get_context()
            thread_name = threading.current_thread().name

            try:
                with _SQLITE_LOCK:
                    sc = db_api.subcloud_create(ctx, **values)
                with lock:
                    created_ids.append(sc.id)
                    context_ids[thread_name] = id(db_ctx)
            except Exception as exc:
                with lock:
                    errors.append((index, str(exc)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_create, i) for i in range(CONCURRENCY)]
            concurrent.futures.wait(futures)

        self.assertEqual(
            [], errors, f"{len(errors)} subcloud creations failed: {errors[:5]}"
        )
        self.assertEqual(CONCURRENCY, len(created_ids))
        self.assertEqual(CONCURRENCY, len(set(created_ids)), "Duplicate IDs detected")

        # Each subcloud must have all 7 status rows
        for sc_id in created_ids:
            statuses = db_api.subcloud_status_get_all(self.ctx, sc_id)
            self.assertEqual(
                len(dccommon_consts.AUDIT_TYPES_LIST),
                len(statuses),
                f"Subcloud {sc_id}: expected "
                f"{len(dccommon_consts.AUDIT_TYPES_LIST)} status rows, "
                f"got {len(statuses)}",
            )

        # Threads on different OS threads must have different _DBContexts
        unique_contexts = set(context_ids.values())
        self.assertGreater(
            len(unique_contexts),
            1,
            "All threads received the same _DBContext — isolation broken",
        )

    def test_update_100_subclouds_in_parallel(self):
        """Update 100 subclouds from different threads.

        Creates subclouds sequentially, then updates them in parallel.
        Each thread sets a unique error_description so we can verify
        there's no cross-thread data contamination.
        """
        subclouds = []
        for i in range(CONCURRENCY):
            values = self._make_subcloud_values(i)
            sc = db_api.subcloud_create(self.ctx, **values)
            subclouds.append(sc)

        errors = []
        lock = threading.Lock()

        def _update(sc):
            ctx = utils.dummy_context()
            try:
                with _SQLITE_LOCK:
                    db_api.subcloud_update(
                        ctx,
                        sc.id,
                        availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                        deploy_status=consts.DEPLOY_STATE_DONE,
                        error_description=f"updated-by-{sc.id}",
                    )
            except Exception as exc:
                with lock:
                    errors.append((sc.id, str(exc)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_update, sc) for sc in subclouds]
            concurrent.futures.wait(futures)

        self.assertEqual([], errors, f"{len(errors)} updates failed: {errors[:5]}")

        for sc in subclouds:
            refreshed = db_api.subcloud_get(self.ctx, sc.id)
            self.assertEqual(
                dccommon_consts.AVAILABILITY_ONLINE,
                refreshed.availability_status,
            )
            self.assertEqual(consts.DEPLOY_STATE_DONE, refreshed.deploy_status)
            self.assertEqual(
                f"updated-by-{sc.id}",
                refreshed.error_description,
                f"Subcloud {sc.id} has wrong error_description — "
                f"cross-thread contamination?",
            )

    def test_update_100_subcloud_statuses_in_parallel(self):
        """Update subcloud sync statuses from different threads.

        Each thread updates the platform status of a different subcloud.
        Verifies writes don't cross-contaminate.
        """
        subclouds = []
        for i in range(CONCURRENCY):
            values = self._make_subcloud_values(i)
            sc = db_api.subcloud_create(self.ctx, **values)
            subclouds.append(sc)

        errors = []
        lock = threading.Lock()

        def _update_status(sc):
            ctx = utils.dummy_context()
            try:
                with _SQLITE_LOCK:
                    db_api.subcloud_status_update(
                        ctx,
                        sc.id,
                        dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                        dccommon_consts.SYNC_STATUS_IN_SYNC,
                    )
            except Exception as exc:
                with lock:
                    errors.append((sc.id, str(exc)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_update_status, sc) for sc in subclouds]
            concurrent.futures.wait(futures)

        self.assertEqual(
            [], errors, f"{len(errors)} status updates failed: {errors[:5]}"
        )

        for sc in subclouds:
            status = db_api.subcloud_status_get(
                self.ctx, sc.id, dccommon_consts.ENDPOINT_TYPE_PLATFORM
            )
            self.assertEqual(dccommon_consts.SYNC_STATUS_IN_SYNC, status.sync_status)

    def test_update_100_backup_statuses_in_parallel(self):
        """Update backup_status on 100 subclouds from different threads.

        Each thread writes a unique value so we can detect cross-thread
        contamination.
        """
        subclouds = []
        for i in range(CONCURRENCY):
            values = self._make_subcloud_values(i)
            sc = db_api.subcloud_create(self.ctx, **values)
            subclouds.append(sc)

        errors = []
        lock = threading.Lock()

        def _update_backup(sc, idx):
            ctx = utils.dummy_context()
            try:
                with _SQLITE_LOCK:
                    db_api.subcloud_update(
                        ctx,
                        sc.id,
                        backup_status=f"backup-complete-{idx}",
                    )
            except Exception as exc:
                with lock:
                    errors.append((sc.id, str(exc)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [
                executor.submit(_update_backup, sc, i) for i, sc in enumerate(subclouds)
            ]
            concurrent.futures.wait(futures)

        self.assertEqual(
            [], errors, f"{len(errors)} backup updates failed: {errors[:5]}"
        )

        for i, sc in enumerate(subclouds):
            refreshed = db_api.subcloud_get(self.ctx, sc.id)
            self.assertEqual(
                f"backup-complete-{i}",
                refreshed.backup_status,
                f"Subcloud {sc.id} has wrong backup_status — "
                f"cross-thread contamination?",
            )

    def test_same_thread_reuses_context(self):
        """Verify context reuse within a single thread.

        Multiple calls to _get_context() on the same thread return the
        exact same _DBContext instance.
        """
        ctx1 = db_sqlalchemy_api._get_context()
        ctx2 = db_sqlalchemy_api._get_context()
        self.assertIs(ctx1, ctx2, "_get_context() returned different objects")

    def test_nested_write_session_same_thread(self):
        """Verify nested write_session shares the transaction.

        Create a subcloud (which nests write_session internally) and
        verify the subcloud plus its status and audit rows all committed
        successfully — proving nested sessions share the transaction.
        """
        ctx = utils.dummy_context()
        values = self._make_subcloud_values(0)
        sc = db_api.subcloud_create(ctx, **values)

        # subcloud_create calls subcloud_status_create_all (7 rows)
        # and subcloud_audits_create (1 row) in nested write_sessions
        statuses = db_api.subcloud_status_get_all(ctx, sc.id)
        self.assertEqual(len(dccommon_consts.AUDIT_TYPES_LIST), len(statuses))

        # Verify each expected endpoint type is present
        status_types = {s.endpoint_type for s in statuses}
        expected_types = set(dccommon_consts.AUDIT_TYPES_LIST)
        self.assertEqual(expected_types, status_types)
