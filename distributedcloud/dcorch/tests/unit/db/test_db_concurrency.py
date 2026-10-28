# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for DB session thread-isolation under concurrent access.

These tests verify that the threading.local-based DB session management
correctly isolates transactions across threads while allowing nested
sessions within a single thread to share the same transaction.

Note on SQLite limitations:
    The test DB uses in-memory SQLite (``sqlite://``), which does not
    support truly concurrent writes from multiple threads. Therefore the
    DB-operation tests serialise SQL execution with a lock and focus on
    verifying that the *context objects* and sessions are correctly
    isolated. The thread-local isolation itself is validated with
    barriers, so all threads hold their context or session at the same
    time.

    In production, PostgreSQL handles concurrent writes natively, so the
    per-thread _DBContext pattern works without serialisation.
"""

import concurrent.futures
import threading

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.db import api as db_api
from dcorch.db.sqlalchemy import api as db_sqlalchemy_api
from dcorch.tests import base
from dcorch.tests import utils

# Number of concurrent threads for parallel tests.
CONCURRENCY = 100

# Lock to serialise SQLite access (in-memory SQLite doesn't support
# concurrent transactions from different threads).
_SQLITE_LOCK = threading.Lock()


class TestDBConcurrency(base.OrchestratorTestCase):
    """Verify DB session thread-isolation under concurrent access."""

    @staticmethod
    def _subcloud_name(index):
        return f"subcloud-concurrent-{index}"

    def _create_subclouds_with_sync(self):
        """Sequentially create CONCURRENCY subclouds with a subcloud_sync row."""
        subclouds = []
        for i in range(CONCURRENCY):
            name = self._subcloud_name(i)
            sc = utils.create_subcloud_static(self.ctx, name)
            utils.create_subcloud_sync_static(
                self.ctx,
                name,
                dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                subcloud_id=sc.id,
            )
            subclouds.append(sc)
        return subclouds

    def test_same_thread_reuses_context(self):
        """Multiple _get_context() calls on one thread return the same object."""
        ctx1 = db_sqlalchemy_api._get_context()
        ctx2 = db_sqlalchemy_api._get_context()
        self.assertIs(ctx1, ctx2, "_get_context() returned different objects")

    def test_thread_local_context_isolation(self):
        """Verify _get_context() returns distinct objects per OS thread.

        Uses a barrier so all threads call _get_context() simultaneously,
        then checks that every OS thread received its own _DBContext and
        that none of them received the main thread's _DBContext.
        """
        main_ctx = db_sqlalchemy_api._get_context()
        results = {}
        barrier = threading.Barrier(CONCURRENCY)
        lock = threading.Lock()

        def _capture_context(index):
            barrier.wait(timeout=10)
            db_ctx = db_sqlalchemy_api._get_context()
            with lock:
                results[index] = (threading.current_thread().ident, db_ctx)

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_capture_context, i) for i in range(CONCURRENCY)]
            for future in futures:
                future.result()

        self.assertEqual(CONCURRENCY, len(results))

        # The barrier forces every task onto its own OS thread
        thread_ids = {tid for tid, _ in results.values()}
        self.assertEqual(CONCURRENCY, len(thread_ids))

        # Every OS thread must have its own _DBContext
        context_ids = {id(db_ctx) for _, db_ctx in results.values()}
        self.assertEqual(
            CONCURRENCY,
            len(context_ids),
            "Some threads share the same _DBContext, thread-local isolation broken",
        )
        self.assertNotIn(id(main_ctx), context_ids)

    def test_nested_read_session_in_write_session_shares_session(self):
        """A read_session nested in a write_session reuses the same session."""
        with db_sqlalchemy_api.write_session() as outer_session:
            with db_sqlalchemy_api.read_session() as inner_session:
                self.assertIs(outer_session, inner_session)

    def test_nested_write_session_shares_session(self):
        """A write_session nested in a write_session reuses the same session."""
        with db_sqlalchemy_api.write_session() as outer_session:
            with db_sqlalchemy_api.write_session() as inner_session:
                self.assertIs(outer_session, inner_session)

    def test_write_session_not_shared_across_threads(self):
        """Concurrently open write_sessions in different threads are distinct.

        Each thread opens a write_session and waits on a barrier inside it,
        so all sessions are open at the same time. No SQL is executed.
        """
        main_ctx = db_sqlalchemy_api._get_context()
        sessions = {}
        barrier = threading.Barrier(CONCURRENCY)
        lock = threading.Lock()

        def _open_session(index):
            with db_sqlalchemy_api.write_session() as session:
                with lock:
                    sessions[index] = session
                barrier.wait(timeout=10)

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_open_session, i) for i in range(CONCURRENCY)]
            for future in futures:
                future.result()

        self.assertEqual(CONCURRENCY, len(sessions))
        self.assertEqual(
            CONCURRENCY,
            len({id(session) for session in sessions.values()}),
            "Some threads share the same session, transaction isolation broken",
        )

        # The worker transactions must not leak into the main thread context
        self.assertIsNone(getattr(main_ctx, "_db_session", None))

    def test_model_query_session_cleaned_up_in_each_thread(self):
        """model_query sessions are stored per thread and cleaned up.

        Connection methods are wrapped by db_session_cleanup. After each
        call, the worker thread's _DBContext must not keep the session
        opened by model_query, so the next task on the same pooled thread
        starts clean. The main thread context must not be touched.
        """
        self._create_subclouds_with_sync()
        main_ctx = db_sqlalchemy_api._get_context()

        errors = []
        results = {}
        lock = threading.Lock()

        def _read(index):
            name = self._subcloud_name(index)
            try:
                with _SQLITE_LOCK:
                    sc = db_api.subcloud_get(utils.dummy_context(), name)
                db_ctx = db_sqlalchemy_api._get_context()
                with lock:
                    results[index] = (
                        sc.region_name,
                        db_ctx._db_session,
                        db_ctx._db_session_context,
                    )
            except Exception as exc:
                with lock:
                    errors.append((index, str(exc)))

        # Fewer workers than tasks so threads are reused across tasks
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_read, i) for i in range(CONCURRENCY)]
            concurrent.futures.wait(futures)

        self.assertEqual([], errors, f"{len(errors)} reads failed: {errors[:5]}")
        self.assertEqual(CONCURRENCY, len(results))
        for index, (region_name, session, session_context) in results.items():
            self.assertEqual(self._subcloud_name(index), region_name)
            self.assertIsNone(session)
            self.assertIsNone(session_context)

        self.assertIsNone(getattr(main_ctx, "_db_session", None))

    def test_create_100_subclouds_in_parallel(self):
        """Create 100 subclouds with their subcloud_sync from different threads.

        Verifies all writes commit, no FK violations happen and each
        subcloud_sync row points to the subcloud created by the same thread.
        """
        errors = []
        created = {}
        lock = threading.Lock()

        def _create(index):
            ctx = utils.dummy_context()
            name = self._subcloud_name(index)
            try:
                with _SQLITE_LOCK:
                    sc = utils.create_subcloud_static(ctx, name)
                    utils.create_subcloud_sync_static(
                        ctx,
                        name,
                        dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                        subcloud_id=sc.id,
                    )
                with lock:
                    created[name] = sc.id
            except Exception as exc:
                with lock:
                    errors.append((index, str(exc)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_create, i) for i in range(CONCURRENCY)]
            concurrent.futures.wait(futures)

        self.assertEqual(
            [], errors, f"{len(errors)} subcloud creations failed: {errors[:5]}"
        )
        self.assertEqual(CONCURRENCY, len(created))
        self.assertEqual(
            CONCURRENCY, len(set(created.values())), "Duplicate IDs detected"
        )
        self.assertEqual(CONCURRENCY, len(db_api.subcloud_get_all(self.ctx)))

        for name, subcloud_id in created.items():
            subcloud_sync = db_api.subcloud_sync_get(
                self.ctx, name, dccommon_consts.ENDPOINT_TYPE_IDENTITY
            )
            self.assertEqual(subcloud_id, subcloud_sync.subcloud_id)

    def test_update_100_subclouds_in_parallel(self):
        """Update 100 subclouds from different threads.

        Each thread writes a unique software_version so cross-thread data
        contamination can be detected.
        """
        self._create_subclouds_with_sync()

        errors = []
        lock = threading.Lock()

        def _update(index):
            ctx = utils.dummy_context()
            try:
                with _SQLITE_LOCK:
                    db_api.subcloud_update(
                        ctx,
                        self._subcloud_name(index),
                        values={
                            "availability_status": (
                                dccommon_consts.AVAILABILITY_OFFLINE
                            ),
                            "software_version": f"version-{index}",
                        },
                    )
            except Exception as exc:
                with lock:
                    errors.append((index, str(exc)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_update, i) for i in range(CONCURRENCY)]
            concurrent.futures.wait(futures)

        self.assertEqual([], errors, f"{len(errors)} updates failed: {errors[:5]}")

        for i in range(CONCURRENCY):
            refreshed = db_api.subcloud_get(self.ctx, self._subcloud_name(i))
            self.assertEqual(
                dccommon_consts.AVAILABILITY_OFFLINE, refreshed.availability_status
            )
            self.assertEqual(
                f"version-{i}",
                refreshed.software_version,
                f"Subcloud {refreshed.region_name} has wrong software_version, "
                "cross-thread contamination?",
            )

    def test_update_100_subcloud_syncs_in_parallel(self):
        """Update the audit status of 100 subcloud_sync rows in parallel.

        Mirrors what GenericSyncWorkerManager._audit_subcloud does when
        audit threads finish. Even subclouds are marked as completed and
        odd subclouds as failed so wrong-row updates can be detected.
        """
        self._create_subclouds_with_sync()

        errors = []
        lock = threading.Lock()

        def _expected_status(index):
            if index % 2:
                return consts.AUDIT_STATUS_FAILED
            return consts.AUDIT_STATUS_COMPLETED

        def _update_sync(index):
            ctx = utils.dummy_context()
            try:
                with _SQLITE_LOCK:
                    db_api.subcloud_sync_update(
                        ctx,
                        self._subcloud_name(index),
                        dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                        values={"audit_status": _expected_status(index)},
                    )
            except Exception as exc:
                with lock:
                    errors.append((index, str(exc)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(_update_sync, i) for i in range(CONCURRENCY)]
            concurrent.futures.wait(futures)

        self.assertEqual(
            [], errors, f"{len(errors)} subcloud_sync updates failed: {errors[:5]}"
        )

        for i in range(CONCURRENCY):
            subcloud_sync = db_api.subcloud_sync_get(
                self.ctx,
                self._subcloud_name(i),
                dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            )
            self.assertEqual(_expected_status(i), subcloud_sync.audit_status)
