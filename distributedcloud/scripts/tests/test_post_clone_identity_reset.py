#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
import subprocess
import threading

import mock
import post_clone_identity_reset

from dccommon.tests import base

# Suppress log output during tests
logging.getLogger("post_clone_identity_reset").setLevel(logging.CRITICAL + 1)


class TestUpdatePlatformConfField(base.DCCommonTestCase):
    """Test class for update_platform_conf_field function."""

    def test_replaces_existing_line(self):
        """Test replaces an existing key=value line."""
        conf = "sw_version=m.n\nUUID=oldval\nsystem_mode=simplex\n"
        m = mock.mock_open(read_data=conf)
        with mock.patch("builtins.open", m):
            post_clone_identity_reset.update_platform_conf_field("UUID", "newval")
        handle = m()
        write_calls = handle.writelines.call_args_list
        self.assertEqual(len(write_calls), 1)
        joined = "".join(write_calls[0].args[0])
        self.assertIn("UUID=newval\n", joined)
        self.assertNotIn("UUID=oldval", joined)
        self.assertIn("sw_version=m.n", joined)

    def test_replaces_indented_line(self):
        """Test replaces a key line with leading whitespace."""
        conf = "sw_version=m.n\n  UUID=old\n"
        m = mock.mock_open(read_data=conf)
        with mock.patch("builtins.open", m):
            post_clone_identity_reset.update_platform_conf_field("UUID", "new")
        handle = m()
        joined = "".join(handle.writelines.call_args_list[0].args[0])
        self.assertIn("UUID=new\n", joined)

    def test_raises_when_missing(self):
        """Test raises RuntimeError when key not present."""
        conf = "sw_version=m.n\nsystem_mode=simplex\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=conf)):
            self.assertRaises(
                RuntimeError,
                post_clone_identity_reset.update_platform_conf_field,
                "UUID",
                "val",
            )


class TestUpdateInstallUuidFeedFile(base.DCCommonTestCase):
    """Test class for update_install_uuid_feed_file function."""

    def test_writes_uuid_with_newline(self):
        """Test rewrites feed file with new UUID and newline."""
        m = mock.mock_open()
        with mock.patch("builtins.open", m):
            post_clone_identity_reset.update_install_uuid_feed_file("m.n", "new-uuid")
        handle = m()
        handle.write.assert_called_once_with("new-uuid\n")

    def test_uses_template_path(self):
        """Test path is built from sw_version template."""
        m = mock.mock_open()
        with mock.patch("builtins.open", m):
            post_clone_identity_reset.update_install_uuid_feed_file("1.0", "uuid-x")
        expected = "/var/www/pages/feed/rel-1.0/install_uuid"
        m.assert_called_once_with(expected, "w", encoding="utf-8")

    def test_propagates_io_error(self):
        """Test IOError from open propagates."""
        with mock.patch("builtins.open", side_effect=IOError("no dir")):
            self.assertRaises(
                IOError,
                post_clone_identity_reset.update_install_uuid_feed_file,
                "m.n",
                "uuid",
            )


class TestGenerateIdentifier(base.DCCommonTestCase):
    """Test class for generate_identifier function."""

    def setUp(self):
        """Set up mock for subprocess.run."""
        super().setUp()
        self.mock_run = self._mock_object(post_clone_identity_reset.subprocess, "run")

    def test_returns_stripped_stdout(self):
        """Test returns stdout stripped of surrounding whitespace."""
        self.mock_run.return_value = mock.Mock(stdout="  value-x \n", returncode=0)
        result = post_clone_identity_reset.generate_identifier(["gen"])
        self.assertEqual(result, "value-x")
        self.mock_run.assert_called_once()
        kwargs = self.mock_run.call_args.kwargs
        self.assertTrue(kwargs.get("check"))
        self.assertTrue(kwargs.get("capture_output"))
        self.assertTrue(kwargs.get("text"))
        self.assertEqual(self.mock_run.call_args[0][0], ["gen"])

    def test_raises_when_output_empty(self):
        """Test raises RuntimeError when command output is empty."""
        self.mock_run.return_value = mock.Mock(stdout="   \n", returncode=0)
        self.assertRaises(
            RuntimeError,
            post_clone_identity_reset.generate_identifier,
            ["gen"],
        )

    def test_propagates_called_process_error(self):
        """Test propagates CalledProcessError from the command."""
        self.mock_run.side_effect = subprocess.CalledProcessError(1, "gen")
        self.assertRaises(
            subprocess.CalledProcessError,
            post_clone_identity_reset.generate_identifier,
            ["gen"],
        )


class TestRewriteIdentityFile(base.DCCommonTestCase):
    """Test class for rewrite_identity_file function."""

    def test_writes_content_verbatim(self):
        """Test writes content to the file in text mode."""
        m = mock.mock_open()
        with mock.patch("builtins.open", m):
            post_clone_identity_reset.rewrite_identity_file(
                "/etc/nvme/hostid", "value\n"
            )
        m.assert_called_once_with("/etc/nvme/hostid", "w", encoding="utf-8")
        m().write.assert_called_once_with("value\n")

    def test_propagates_file_not_found(self):
        """Test FileNotFoundError from open propagates."""
        with mock.patch("builtins.open", side_effect=FileNotFoundError("nope")):
            self.assertRaises(
                FileNotFoundError,
                post_clone_identity_reset.rewrite_identity_file,
                "/etc/nvme/hostid",
                "value\n",
            )


class TestStorageIdentityReset(base.DCCommonTestCase):
    """Test class for the StorageIdentityReset class."""

    def setUp(self):
        """Set up mocks for the generator and file-rewrite helpers."""
        super().setUp()
        self.mock_generate = self._mock_object(
            post_clone_identity_reset,
            "generate_identifier",
        )
        self.mock_rewrite = self._mock_object(
            post_clone_identity_reset,
            "rewrite_identity_file",
        )
        self.mock_run = self._mock_object(post_clone_identity_reset.subprocess, "run")
        self.reset = post_clone_identity_reset.StorageIdentityReset()

    def test_regenerate_iscsi_initiator_name(self):
        """Test generates value and rewrites the iscsi file."""
        self.mock_generate.return_value = "iqn.test"
        self.reset.regenerate_iscsi_initiator_name()
        self.mock_generate.assert_called_once_with(
            [
                "/usr/sbin/iscsi-iname",
                "-p",
                post_clone_identity_reset.ISCSI_INITIATOR_PREFIX,
            ]
        )
        self.mock_rewrite.assert_called_once_with(
            post_clone_identity_reset.ISCSI_INITIATOR_FILE,
            "InitiatorName=iqn.test\n",
        )

    def test_regenerate_nvme_host_id(self):
        """Test generates value and rewrites the hostid file."""
        self.mock_generate.return_value = "host-id-x"
        self.reset.regenerate_nvme_host_id()
        self.mock_generate.assert_called_once_with(["/usr/bin/uuidgen"])
        self.mock_rewrite.assert_called_once_with(
            post_clone_identity_reset.NVME_HOST_ID_FILE,
            "host-id-x\n",
        )

    def test_regenerate_nvme_host_nqn(self):
        """Test generates value and rewrites the hostnqn file."""
        self.mock_generate.return_value = "nqn.test"
        self.reset.regenerate_nvme_host_nqn()
        self.mock_generate.assert_called_once_with(["/usr/sbin/nvme", "gen-hostnqn"])
        self.mock_rewrite.assert_called_once_with(
            post_clone_identity_reset.NVME_HOST_NQN_FILE,
            "nqn.test\n",
        )

    def test_regenerate_propagates_generator_error(self):
        """Test a generator failure propagates from a step."""
        self.mock_generate.side_effect = subprocess.CalledProcessError(1, "iscsi-iname")
        self.assertRaises(
            subprocess.CalledProcessError,
            self.reset.regenerate_iscsi_initiator_name,
        )
        self.mock_rewrite.assert_not_called()

    def test_apply_to_db_updates_all_columns(self):
        """Test apply_to_db issues one UPDATE with all three values."""
        self.mock_generate.side_effect = ["iqn.test", "host-id-x", "nqn.test"]
        self.reset.regenerate_iscsi_initiator_name()
        self.reset.regenerate_nvme_host_id()
        self.reset.regenerate_nvme_host_nqn()
        self.mock_run.reset_mock()

        self.mock_run.return_value = mock.Mock(stdout="UPDATE 1\n", returncode=0)
        self.reset.apply_to_db()

        self.mock_run.assert_called_once()
        cmd = self.mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "su")
        self.assertEqual(cmd[1], "postgres")
        query = cmd[3]
        self.assertIn("UPDATE i_host", query)
        self.assertIn("iscsi_initiator_name='iqn.test'", query)
        self.assertIn("nvme_host_id='host-id-x'", query)
        self.assertIn("nvme_host_nqn='nqn.test'", query)

    def test_apply_to_db_raises_before_values_collected(self):
        """Test apply_to_db raises KeyError if steps did not run."""
        self.assertRaises(KeyError, self.reset.apply_to_db)
        self.mock_run.assert_not_called()

    def test_apply_to_db_propagates_called_process_error(self):
        """Test apply_to_db propagates CalledProcessError from psql."""
        self.mock_generate.side_effect = ["iqn.test", "host-id-x", "nqn.test"]
        self.reset.regenerate_iscsi_initiator_name()
        self.reset.regenerate_nvme_host_id()
        self.reset.regenerate_nvme_host_nqn()

        self.mock_run.side_effect = subprocess.CalledProcessError(1, "psql")
        self.assertRaises(
            subprocess.CalledProcessError,
            self.reset.apply_to_db,
        )

    def test_parallel_steps_populate_values_before_apply(self):
        """Test the three steps run concurrently, then apply_to_db.

        Runs the real regenerate_* methods in separate threads, the way
        main() drives them, and asserts all three values land in
        _values once the threads join. The apply_to_db step then runs
        and its psql query is built from those three values, verifying
        the parallel-then-join-then-apply contract the pipeline relies
        on. A barrier makes the three generators overlap so the test
        exercises genuine concurrency rather than accidental serial
        ordering.
        """
        values = {
            "/usr/sbin/iscsi-iname": "iqn.par",
            "/usr/bin/uuidgen": "host-id-par",
            "/usr/sbin/nvme": "nqn.par",
        }
        barrier = threading.Barrier(3)

        def fake_generate(cmd):
            """Block until all three steps have started, then return."""
            barrier.wait()
            return values[cmd[0]]

        self.mock_generate.side_effect = fake_generate

        steps = [
            self.reset.regenerate_iscsi_initiator_name,
            self.reset.regenerate_nvme_host_id,
            self.reset.regenerate_nvme_host_nqn,
        ]
        threads = [threading.Thread(target=step) for step in steps]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All three values are present on the shared instance after the
        # parallel steps join, before any DB write happens.
        self.assertEqual(
            self.reset._values,
            {
                "iscsi_initiator_name": "iqn.par",
                "nvme_host_id": "host-id-par",
                "nvme_host_nqn": "nqn.par",
            },
        )
        self.mock_run.assert_not_called()

        # apply_to_db then builds its single UPDATE from exactly those
        # three collected values.
        self.mock_run.return_value = mock.Mock(stdout="UPDATE 1\n", returncode=0)
        self.reset.apply_to_db()

        self.mock_run.assert_called_once()
        query = self.mock_run.call_args[0][0][3]
        expected_query = (
            'psql --tuples-only -d sysinv -c "'
            "UPDATE i_host SET "
            "iscsi_initiator_name='iqn.par', "
            "nvme_host_id='host-id-par', "
            "nvme_host_nqn='nqn.par';"
            '"'
        )
        self.assertEqual(query, expected_query)


class TestCheckCloneFlag(base.DCCommonTestCase):
    """Test class for check_clone_flag function."""

    def test_returns_true_when_present(self):
        """Test returns True when sentinel exists."""
        with mock.patch(
            "post_clone_identity_reset.os.path.isfile",
            return_value=True,
        ):
            self.assertTrue(post_clone_identity_reset.check_clone_flag())

    def test_returns_false_when_absent(self):
        """Test returns False when sentinel missing."""
        with mock.patch(
            "post_clone_identity_reset.os.path.isfile",
            return_value=False,
        ):
            self.assertFalse(post_clone_identity_reset.check_clone_flag())

    def test_propagates_oserror(self):
        """Test OSError from isfile propagates."""
        with mock.patch(
            "post_clone_identity_reset.os.path.isfile",
            side_effect=OSError("io"),
        ):
            self.assertRaises(
                OSError,
                post_clone_identity_reset.check_clone_flag,
            )


class TestUpdateSysinvSystemUuid(base.DCCommonTestCase):
    """Test class for update_sysinv_system_uuid function."""

    def setUp(self):
        """Set up mocks for subprocess and uuid generation."""
        super().setUp()
        self.mock_run = self._mock_object(post_clone_identity_reset.subprocess, "run")
        self.mock_uuid = self._mock_object(
            post_clone_identity_reset.uuidutils,
            "generate_uuid",
            return_value="abc-123",
        )

    def test_runs_psql_command(self):
        """Test runs psql UPDATE query as postgres user."""
        self.mock_run.return_value = mock.Mock(stdout=" 1\n", returncode=0)
        post_clone_identity_reset.update_sysinv_system_uuid()
        self.mock_run.assert_called_once()
        call_args = self.mock_run.call_args[0][0]
        self.assertEqual(call_args[0], "su")
        self.assertEqual(call_args[1], "postgres")
        self.assertIn("abc-123", call_args[3])
        self.assertIn("UPDATE i_system", call_args[3])

    def test_propagates_called_process_error(self):
        """Test propagates CalledProcessError from psql."""
        self.mock_run.side_effect = subprocess.CalledProcessError(
            1, "psql", stderr="boom"
        )
        self.assertRaises(
            subprocess.CalledProcessError,
            post_clone_identity_reset.update_sysinv_system_uuid,
        )


class TestRegenerateMachineId(base.DCCommonTestCase):
    """Test class for regenerate_machine_id function."""

    def setUp(self):
        """Set up mocks for subprocess, remove, and lexists."""
        super().setUp()
        self.mock_run = self._mock_object(post_clone_identity_reset.subprocess, "run")
        self.mock_remove = self._mock_object(post_clone_identity_reset.os, "remove")
        self.mock_lexists = self._mock_object(
            post_clone_identity_reset.os.path,
            "lexists",
            return_value=True,
        )

    def test_removes_and_runs_setup(self):
        """Test removes file then runs setup binary."""
        self.mock_run.return_value = mock.Mock(returncode=0)
        post_clone_identity_reset.regenerate_machine_id()
        self.mock_remove.assert_called_once_with(
            post_clone_identity_reset.MACHINE_ID_FILE
        )
        self.mock_run.assert_called_once()
        cmd = self.mock_run.call_args[0][0]
        self.assertEqual(cmd, ["systemd-machine-id-setup"])

    def test_raises_when_missing(self):
        """Test raises FileNotFoundError when file absent."""
        self.mock_lexists.return_value = False
        self.assertRaises(
            FileNotFoundError,
            post_clone_identity_reset.regenerate_machine_id,
        )
        self.mock_remove.assert_not_called()

    def test_propagates_subprocess_error(self):
        """Test propagates CalledProcessError from setup."""
        self.mock_run.side_effect = subprocess.CalledProcessError(
            1, "systemd-machine-id-setup"
        )
        self.assertRaises(
            subprocess.CalledProcessError,
            post_clone_identity_reset.regenerate_machine_id,
        )


class TestRegenerateHostUuid(base.DCCommonTestCase):
    """Test class for regenerate_host_uuid function."""

    def setUp(self):
        """Set up mocks for uuidutils and platform conf."""
        super().setUp()
        self.mock_uuid = self._mock_object(
            post_clone_identity_reset.uuidutils,
            "generate_uuid",
            return_value="new-host-uuid",
        )
        self.mock_update = self._mock_object(
            post_clone_identity_reset,
            "update_platform_conf_field",
        )

    def test_updates_uuid_field(self):
        """Test generates UUID and updates UUID= field."""
        post_clone_identity_reset.regenerate_host_uuid()
        self.mock_uuid.assert_called_once()
        self.mock_update.assert_called_once_with("UUID", "new-host-uuid")

    def test_propagates_runtime_error(self):
        """Test propagates RuntimeError from update."""
        self.mock_update.side_effect = RuntimeError("missing")
        self.assertRaises(
            RuntimeError,
            post_clone_identity_reset.regenerate_host_uuid,
        )


class TestRegenerateInstallUuid(base.DCCommonTestCase):
    """Test class for regenerate_install_uuid function."""

    def setUp(self):
        """Set up mocks for uuidutils and helper functions."""
        super().setUp()
        self.mock_uuid = self._mock_object(
            post_clone_identity_reset.uuidutils,
            "generate_uuid",
            return_value="install-uuid",
        )
        self.mock_sw = self._mock_object(
            post_clone_identity_reset,
            "get_sw_version",
            return_value="m.n",
        )
        self.mock_update = self._mock_object(
            post_clone_identity_reset,
            "update_platform_conf_field",
        )
        self.mock_feed = self._mock_object(
            post_clone_identity_reset,
            "update_install_uuid_feed_file",
        )

    def test_updates_both_sites(self):
        """Test updates platform.conf and feed file."""
        post_clone_identity_reset.regenerate_install_uuid()
        self.mock_uuid.assert_called_once()
        self.mock_update.assert_called_once_with("INSTALL_UUID", "install-uuid")
        self.mock_feed.assert_called_once_with("m.n", "install-uuid")

    def test_propagates_feed_error(self):
        """Test propagates FileNotFoundError from feed."""
        self.mock_feed.side_effect = FileNotFoundError("nope")
        self.assertRaises(
            FileNotFoundError,
            post_clone_identity_reset.regenerate_install_uuid,
        )


class TestRunUpdateRegionName(base.DCCommonTestCase):
    """Test class for run_update_region_name function."""

    def setUp(self):
        """Set up mock for subprocess.run."""
        super().setUp()
        self.mock_run = self._mock_object(post_clone_identity_reset.subprocess, "run")

    def test_runs_with_timeout(self):
        """Test invokes helper with capture and timeout."""
        self.mock_run.return_value = mock.Mock(stdout="ok", stderr="", returncode=0)
        post_clone_identity_reset.run_update_region_name()
        self.mock_run.assert_called_once()
        kwargs = self.mock_run.call_args.kwargs
        self.assertTrue(kwargs.get("check"))
        self.assertTrue(kwargs.get("capture_output"))
        self.assertTrue(kwargs.get("text"))
        self.assertEqual(
            kwargs.get("timeout"),
            post_clone_identity_reset.REGION_SCRIPT_TIMEOUT,
        )
        cmd = self.mock_run.call_args[0][0]
        self.assertEqual(
            cmd,
            [post_clone_identity_reset.UPDATE_REGION_SCRIPT_PATH],
        )

    def test_propagates_timeout(self):
        """Test propagates TimeoutExpired."""
        self.mock_run.side_effect = subprocess.TimeoutExpired("x", 1)
        self.assertRaises(
            subprocess.TimeoutExpired,
            post_clone_identity_reset.run_update_region_name,
        )

    def test_propagates_called_process_error(self):
        """Test propagates CalledProcessError."""
        self.mock_run.side_effect = subprocess.CalledProcessError(1, "x")
        self.assertRaises(
            subprocess.CalledProcessError,
            post_clone_identity_reset.run_update_region_name,
        )

    def test_propagates_file_not_found(self):
        """Test propagates FileNotFoundError."""
        self.mock_run.side_effect = FileNotFoundError("missing")
        self.assertRaises(
            FileNotFoundError,
            post_clone_identity_reset.run_update_region_name,
        )


class TestRemoveCloneFlag(base.DCCommonTestCase):
    """Test class for remove_clone_flag function."""

    def setUp(self):
        """Set up mock for os.remove."""
        super().setUp()
        self.mock_remove = self._mock_object(post_clone_identity_reset.os, "remove")

    def test_removes_flag(self):
        """Test calls os.remove on the sentinel path."""
        post_clone_identity_reset.remove_clone_flag()
        self.mock_remove.assert_called_once_with(
            post_clone_identity_reset.CLONE_FLAG_PATH
        )

    def test_propagates_oserror(self):
        """Test propagates OSError from os.remove."""
        self.mock_remove.side_effect = PermissionError("denied")
        self.assertRaises(
            PermissionError,
            post_clone_identity_reset.remove_clone_flag,
        )


class TestMain(base.DCCommonTestCase):
    """Test class for main pipeline function."""

    def setUp(self):
        """Set up mocks for all pipeline steps."""
        super().setUp()
        # Function-based pipeline steps are collected in a single dict to
        # keep the instance attribute count low; accessed via helper
        # properties below.
        self.mocks = {
            "check": self._mock_object(
                post_clone_identity_reset,
                "check_clone_flag",
                return_value=True,
            ),
            "sysinv": self._mock_object(
                post_clone_identity_reset,
                "update_sysinv_system_uuid",
            ),
            "machine": self._mock_object(
                post_clone_identity_reset,
                "regenerate_machine_id",
            ),
            "host": self._mock_object(
                post_clone_identity_reset,
                "regenerate_host_uuid",
            ),
            "install": self._mock_object(
                post_clone_identity_reset,
                "regenerate_install_uuid",
            ),
            "region": self._mock_object(
                post_clone_identity_reset,
                "run_update_region_name",
            ),
            "remove": self._mock_object(
                post_clone_identity_reset,
                "remove_clone_flag",
            ),
        }
        # main() constructs a StorageIdentityReset instance and uses its
        # bound methods as pipeline steps; patch the class so main() gets
        # a mock instance whose methods can be asserted on.
        self.mock_storage = mock.Mock()
        self._mock_object(
            post_clone_identity_reset,
            "StorageIdentityReset",
            return_value=self.mock_storage,
        )

    @property
    def mock_check(self):
        """Return the check_clone_flag mock."""
        return self.mocks["check"]

    @property
    def mock_sysinv(self):
        """Return the update_sysinv_system_uuid mock."""
        return self.mocks["sysinv"]

    @property
    def mock_machine(self):
        """Return the regenerate_machine_id mock."""
        return self.mocks["machine"]

    @property
    def mock_host(self):
        """Return the regenerate_host_uuid mock."""
        return self.mocks["host"]

    @property
    def mock_install(self):
        """Return the regenerate_install_uuid mock."""
        return self.mocks["install"]

    @property
    def mock_region(self):
        """Return the run_update_region_name mock."""
        return self.mocks["region"]

    @property
    def mock_remove(self):
        """Return the remove_clone_flag mock."""
        return self.mocks["remove"]

    def test_returns_zero_when_flag_absent(self):
        """Test returns 0 immediately when flag is absent."""
        self.mock_check.return_value = False
        self.assertEqual(post_clone_identity_reset.main(), 0)
        self.mock_sysinv.assert_not_called()
        self.mock_machine.assert_not_called()
        self.mock_host.assert_not_called()
        self.mock_storage.regenerate_iscsi_initiator_name.assert_not_called()
        self.mock_storage.regenerate_nvme_host_id.assert_not_called()
        self.mock_storage.regenerate_nvme_host_nqn.assert_not_called()
        self.mock_storage.apply_to_db.assert_not_called()
        self.mock_install.assert_not_called()
        self.mock_region.assert_not_called()
        self.mock_remove.assert_not_called()

    def test_returns_one_when_check_raises(self):
        """Test returns 1 when check_clone_flag raises."""
        self.mock_check.side_effect = OSError("boom")
        self.assertEqual(post_clone_identity_reset.main(), 1)

    def test_runs_full_pipeline_on_success(self):
        """Test runs every step and returns 0 on success."""
        self.assertEqual(post_clone_identity_reset.main(), 0)
        self.mock_sysinv.assert_called_once()
        self.mock_machine.assert_called_once()
        self.mock_host.assert_called_once()
        self.mock_storage.regenerate_iscsi_initiator_name.assert_called_once()
        self.mock_storage.regenerate_nvme_host_id.assert_called_once()
        self.mock_storage.regenerate_nvme_host_nqn.assert_called_once()
        self.mock_storage.apply_to_db.assert_called_once()
        self.mock_install.assert_called_once()
        self.mock_region.assert_called_once()
        self.mock_remove.assert_called_once()

    def test_returns_one_when_parallel_step_fails(self):
        """Test returns 1 when a parallel step raises."""
        self.mock_machine.side_effect = RuntimeError("fail")
        self.assertEqual(post_clone_identity_reset.main(), 1)
        self.mock_storage.apply_to_db.assert_not_called()
        self.mock_install.assert_not_called()
        self.mock_region.assert_not_called()
        self.mock_remove.assert_not_called()

    def test_returns_one_when_storage_step_fails(self):
        """Test returns 1 when a storage-identity step raises."""
        self.mock_storage.regenerate_nvme_host_id.side_effect = (
            subprocess.CalledProcessError(1, "uuidgen")
        )
        self.assertEqual(post_clone_identity_reset.main(), 1)
        self.mock_storage.apply_to_db.assert_not_called()
        self.mock_install.assert_not_called()
        self.mock_region.assert_not_called()
        self.mock_remove.assert_not_called()

    def test_returns_one_when_apply_to_db_fails(self):
        """Test returns 1 when the i_host DB update raises."""
        self.mock_storage.apply_to_db.side_effect = subprocess.CalledProcessError(
            1, "psql"
        )
        self.assertEqual(post_clone_identity_reset.main(), 1)
        self.mock_install.assert_not_called()
        self.mock_region.assert_not_called()
        self.mock_remove.assert_not_called()

    def test_returns_one_when_install_uuid_fails(self):
        """Test returns 1 when install UUID step raises."""
        self.mock_install.side_effect = RuntimeError("fail")
        self.assertEqual(post_clone_identity_reset.main(), 1)
        self.mock_region.assert_not_called()
        self.mock_remove.assert_not_called()

    def test_returns_one_when_region_step_fails(self):
        """Test returns 1 when region rename step raises."""
        self.mock_region.side_effect = subprocess.CalledProcessError(1, "x")
        self.assertEqual(post_clone_identity_reset.main(), 1)
        self.mock_remove.assert_not_called()

    def test_returns_one_when_remove_flag_fails(self):
        """Test returns 1 when sentinel removal raises."""
        self.mock_remove.side_effect = PermissionError("denied")
        self.assertEqual(post_clone_identity_reset.main(), 1)


class TestModuleConstants(base.DCCommonTestCase):
    """Test class for module-level constants and metadata."""

    def test_constants_have_expected_values(self):
        """Test critical path constants are defined."""
        self.assertEqual(
            post_clone_identity_reset.PLATFORM_CONF_PATH,
            "/etc/platform/platform.conf",
        )
        self.assertEqual(
            post_clone_identity_reset.CLONE_FLAG_PATH,
            "/etc/platform/.cloned_install",
        )
        self.assertEqual(
            post_clone_identity_reset.MACHINE_ID_FILE,
            "/etc/machine-id",
        )
        self.assertEqual(
            post_clone_identity_reset.UPDATE_REGION_SCRIPT_PATH,
            "/usr/local/bin/update_region_name.py",
        )
        self.assertIn(
            "{sw_version}",
            post_clone_identity_reset.INSTALL_UUID_FEED_TEMPLATE,
        )
        self.assertIsInstance(
            post_clone_identity_reset.REGION_SCRIPT_TIMEOUT,
            int,
        )
        self.assertEqual(
            post_clone_identity_reset.ISCSI_INITIATOR_FILE,
            "/etc/iscsi/initiatorname.iscsi",
        )
        self.assertEqual(
            post_clone_identity_reset.ISCSI_INITIATOR_PREFIX,
            "iqn.2018-05.io.starlingx",
        )
        self.assertEqual(
            post_clone_identity_reset.NVME_HOST_ID_FILE,
            "/etc/nvme/hostid",
        )
        self.assertEqual(
            post_clone_identity_reset.NVME_HOST_NQN_FILE,
            "/etc/nvme/hostnqn",
        )
