#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
import os
import subprocess
import tempfile

import mock
from oslo_utils import uuidutils
import update_region_name

from dccommon.tests import base

# Suppress log output during tests
logging.getLogger("update_region_name").setLevel(logging.CRITICAL + 1)


def _generate_region():
    """Generate a 32-char hex region name for testing."""
    return uuidutils.generate_uuid().replace("-", "")


class TestGetVersionedFiles(base.DCCommonTestCase):
    """Test class for get_versioned_files function."""

    def test_get_versioned_files_returns_correct_paths(self):
        """Test get_versioned_files returns paths with version."""
        result = update_region_name.get_versioned_files("m.n")
        expected = [
            "/opt/platform/puppet/m.n/hieradata/system.yaml",
            "/opt/platform/puppet/m.n/hieradata/static.yaml",
            "/opt/platform/sysinv/m.n/sysinv.conf.default",
        ]
        self.assertEqual(result, expected)


class TestUpdateFiles(base.DCCommonTestCase):
    """Test class for update_files function."""

    def setUp(self):
        super().setUp()
        self.old_region = _generate_region()
        self.new_region = _generate_region()

    def test_replaces_region_uuid_in_file(self):
        """Test update_files replaces region UUID via regex."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(f"region_name={self.old_region}\n")
            f.write("some_other_config=value\n")
            tmpfile = f.name

        try:
            update_region_name.update_files(self.new_region, [tmpfile])
            with open(tmpfile, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(f"region_name={self.new_region}", content)
            self.assertNotIn(self.old_region, content)
            self.assertIn("some_other_config=value", content)
        finally:
            os.unlink(tmpfile)

    def test_replaces_yaml_colon_format(self):
        """Test handles 'key: value' YAML format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("platform::client::params::auth_region: " f"{self.old_region}\n")
            tmpfile = f.name

        try:
            update_region_name.update_files(self.new_region, [tmpfile])
            with open(tmpfile, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(f"auth_region: {self.new_region}", content)
        finally:
            os.unlink(tmpfile)

    def test_replaces_multiple_patterns(self):
        """Test replaces all region patterns in a file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(f"region_name={self.old_region}\n")
            f.write(f"os_region_name = {self.old_region}\n")
            f.write(f"keystone_region_name = " f"{self.old_region} ; comment\n")
            tmpfile = f.name

        try:
            update_region_name.update_files(self.new_region, [tmpfile])
            with open(tmpfile, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn(self.old_region, content)
            self.assertEqual(content.count(self.new_region), 3)
        finally:
            os.unlink(tmpfile)

    def test_does_not_replace_non_region_hex(self):
        """Test does not replace hex values in non-region keys."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(f"password={self.old_region}\n")
            tmpfile = f.name

        try:
            update_region_name.update_files(self.new_region, [tmpfile])
            with open(tmpfile, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(self.old_region, content)
            self.assertNotIn(self.new_region, content)
        finally:
            os.unlink(tmpfile)

    def test_exits_on_missing_file(self):
        """Test update_files exits when file does not exist."""
        self.assertRaises(
            SystemExit,
            update_region_name.update_files,
            self.new_region,
            ["/nonexistent/path/file.conf"],
        )

    def test_no_change_when_no_region_pattern(self):
        """Test no change when file has no region pattern."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write("some_config=value\n")
            tmpfile = f.name

        try:
            update_region_name.update_files(self.new_region, [tmpfile])
            with open(tmpfile, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertEqual(content, "some_config=value\n")
        finally:
            os.unlink(tmpfile)

    @mock.patch("builtins.open", side_effect=IOError("permission denied"))
    def test_exits_on_io_error(self, mock_open):
        """Test update_files exits on IOError."""
        self.assertRaises(
            SystemExit,
            update_region_name.update_files,
            self.new_region,
            ["/some/file.conf"],
        )


class TestCreateKeystoneRegion(base.DCCommonTestCase):
    """Test class for create_keystone_region function."""

    def setUp(self):
        super().setUp()
        self.mock_keystone = mock.MagicMock()

    def test_creates_region(self):
        """Test creates new region."""
        update_region_name.create_keystone_region(self.mock_keystone, "newregion")
        self.mock_keystone.regions.create.assert_called_once_with(id="newregion")

    def test_skips_if_already_exists(self):
        """Test skips creation if region already exists."""
        from keystoneclient import exceptions as ks_exc

        self.mock_keystone.regions.create.side_effect = ks_exc.Conflict("exists")
        update_region_name.create_keystone_region(self.mock_keystone, "newregion")
        self.mock_keystone.regions.create.assert_called_once()

    def test_exits_on_client_exception(self):
        """Test exits on Keystone API error."""
        from keystoneclient import exceptions as ks_exc

        self.mock_keystone.regions.create.side_effect = ks_exc.ClientException("fail")
        self.assertRaises(
            SystemExit,
            update_region_name.create_keystone_region,
            self.mock_keystone,
            "newregion",
        )


class TestMigrateKeystoneEndpoints(base.DCCommonTestCase):
    """Test class for migrate_keystone_endpoints function."""

    def setUp(self):
        super().setUp()
        self.mock_keystone = mock.MagicMock()

    def test_updates_endpoints_and_deletes_old_regions(self):
        """Test updates endpoints and deletes stale regions."""
        mock_ep = mock.Mock(
            id="ep1",
            region="oldregion",
            url="http://host:5000",
            interface="internal",
            service_id="svc1",
        )
        self.mock_keystone.endpoints.list.return_value = [mock_ep]
        self.mock_keystone.regions.list.return_value = [
            mock.Mock(id="oldregion"),
            mock.Mock(id="newregion"),
        ]

        update_region_name.migrate_keystone_endpoints(self.mock_keystone, "newregion")

        self.mock_keystone.endpoints.update.assert_called_once_with(
            "ep1",
            region="newregion",
            url="http://host:5000",
            interface="internal",
            service="svc1",
        )
        self.mock_keystone.regions.delete.assert_called_once_with("oldregion")

    def test_skips_endpoints_already_on_new_region(self):
        """Test endpoints already on new region are not updated."""
        mock_ep = mock.Mock(
            id="ep1",
            region="newregion",
            url="http://host:5000",
            interface="internal",
            service_id="svc1",
        )
        self.mock_keystone.endpoints.list.return_value = [mock_ep]
        self.mock_keystone.regions.list.return_value = [mock.Mock(id="newregion")]

        update_region_name.migrate_keystone_endpoints(self.mock_keystone, "newregion")

        self.mock_keystone.endpoints.update.assert_not_called()
        self.mock_keystone.regions.delete.assert_not_called()

    def test_handles_stale_region_already_gone(self):
        """Test NotFound on delete is non-fatal."""
        from keystoneclient import exceptions as ks_exc

        self.mock_keystone.endpoints.list.return_value = []
        self.mock_keystone.regions.list.return_value = [
            mock.Mock(id="stale"),
            mock.Mock(id="newregion"),
        ]
        self.mock_keystone.regions.delete.side_effect = ks_exc.NotFound("gone")

        update_region_name.migrate_keystone_endpoints(self.mock_keystone, "newregion")

        self.mock_keystone.regions.delete.assert_called_once()

    def test_exits_on_client_exception(self):
        """Test exits on Keystone API error."""
        from keystoneclient import exceptions as ks_exc

        self.mock_keystone.endpoints.list.side_effect = ks_exc.ClientException("fail")
        self.assertRaises(
            SystemExit,
            update_region_name.migrate_keystone_endpoints,
            self.mock_keystone,
            "newregion",
        )


class TestUpdateSysinvDatabase(base.DCCommonTestCase):
    """Test class for update_sysinv_database function."""

    def setUp(self):
        super().setUp()
        self.mock_run = self._mock_object(update_region_name.subprocess, "run")

    def test_executes_query(self):
        """Test runs correct psql command."""
        self.mock_run.return_value = mock.Mock(stdout="UPDATE 1", returncode=0)
        update_region_name.update_sysinv_database("new_region")
        self.mock_run.assert_called_once()
        call_args = self.mock_run.call_args[0][0]
        self.assertEqual(call_args[0], "su")
        self.assertEqual(call_args[1], "postgres")
        self.assertIn("new_region", call_args[3])

    def test_raises_on_error(self):
        """Test exits on CalledProcessError."""
        self.mock_run.side_effect = subprocess.CalledProcessError(
            1, "psql", stderr="error"
        )
        self.assertRaises(
            SystemExit,
            update_region_name.update_sysinv_database,
            "new_region",
        )

    def test_empty_stdout(self):
        """Test with empty stdout."""
        self.mock_run.return_value = mock.Mock(stdout="", returncode=0)
        update_region_name.update_sysinv_database("new_region")


class TestLoadCredentials(base.DCCommonTestCase):
    """Test class for load_credentials function."""

    @mock.patch("update_region_name.subprocess.Popen")
    def test_sources_openrc(self, mock_popen):
        """Test sources openrc and returns credentials dict."""
        mock_proc = mock.MagicMock()
        mock_proc.stdout = iter(
            [
                "OS_USERNAME=admin\n",
                "OS_PASSWORD=secret\n",
                "OS_AUTH_URL=http://host:5000/v3\n",
                "OS_PROJECT_NAME=admin\n",
                "OS_REGION_NAME=region1\n",
                "OS_USER_DOMAIN_NAME=Default\n",
                "OS_PROJECT_DOMAIN_NAME=Default\n",
            ]
        )
        mock_proc.__enter__ = mock.Mock(return_value=mock_proc)
        mock_proc.__exit__ = mock.Mock(return_value=False)
        mock_popen.return_value = mock_proc

        result = update_region_name.load_credentials()

        self.assertEqual(result["username"], "admin")
        self.assertEqual(result["password"], "secret")
        self.assertEqual(result["auth_url"], "http://host:5000/v3")
        self.assertEqual(result["region_name"], "region1")

    @mock.patch("update_region_name.subprocess.Popen")
    def test_exits_on_subprocess_error(self, mock_popen):
        """Test exits on SubprocessError."""
        mock_popen.side_effect = subprocess.SubprocessError("fail")
        self.assertRaises(SystemExit, update_region_name.load_credentials)


class TestCreateKeystoneClient(base.DCCommonTestCase):
    """Test class for create_keystone_client function."""

    @mock.patch("update_region_name.keystone_client.Client")
    @mock.patch("update_region_name.session.Session")
    @mock.patch("update_region_name.v3.Password")
    def test_returns_client(self, mock_password, mock_session, mock_client):
        """Test creates client with password credentials."""
        creds = {
            "auth_url": "http://host:5000/v3",
            "username": "admin",
            "password": "secret",
            "project_name": "admin",
            "user_domain_name": "Default",
            "project_domain_name": "Default",
        }
        result = update_region_name.create_keystone_client(creds)
        mock_password.assert_called_once()
        mock_session.assert_called_once()
        mock_client.assert_called_once()
        self.assertEqual(result, mock_client.return_value)


class TestRestartMtceService(base.DCCommonTestCase):
    """Test class for restart_mtce_services function."""

    def setUp(self):
        super().setUp()
        self.mock_run = self._mock_object(update_region_name.subprocess, "run")

    def test_calls_all_commands(self):
        """Test calls sm-restart-safe and pmon-restart for agents."""
        self.mock_run.return_value = mock.Mock(returncode=0)
        update_region_name.restart_mtce_services()
        self.assertEqual(self.mock_run.call_count, 4)
        calls = [c[0][0] for c in self.mock_run.call_args_list]
        self.assertEqual(calls[0], ["sm-restart-safe", "service", "mtc-agent"])
        self.assertEqual(calls[1], ["pmon-restart", "hbsAgent"])
        self.assertEqual(calls[2], ["pmon-restart", "hbsClient"])
        self.assertEqual(calls[3], ["pmon-restart", "mtcClient"])

    def test_raises_on_error(self):
        """Test exits on CalledProcessError."""
        self.mock_run.side_effect = subprocess.CalledProcessError(
            1, "sm-restart-safe", stderr="error"
        )
        self.assertRaises(
            SystemExit,
            update_region_name.restart_mtce_services,
        )


class TestRestartPmonServices(base.DCCommonTestCase):
    """Test class for restart_pmon_managed_services function."""

    def setUp(self):
        super().setUp()
        self.mock_run = self._mock_object(update_region_name.subprocess, "run")

    def test_calls_pmon_restart_for_each(self):
        """Test calls pmon-restart for each service in the list."""
        self.mock_run.return_value = mock.Mock(returncode=0)
        update_region_name.restart_pmon_managed_services(
            update_region_name.SERVICES_TO_RESTART_PMON
        )
        expected_calls = [
            mock.call(
                ["pmon-restart", svc],
                capture_output=True,
                text=True,
                check=True,
            )
            for svc in update_region_name.SERVICES_TO_RESTART_PMON
        ]
        self.mock_run.assert_has_calls(expected_calls)
        self.assertEqual(
            self.mock_run.call_count,
            len(update_region_name.SERVICES_TO_RESTART_PMON),
        )

    def test_raises_on_error(self):
        """Test exits on CalledProcessError."""
        self.mock_run.side_effect = subprocess.CalledProcessError(
            1, "pmon-restart", stderr="error"
        )
        self.assertRaises(
            SystemExit,
            update_region_name.restart_pmon_managed_services,
            ["sysinv-agent"],
        )


class TestRestartServicesSm(base.DCCommonTestCase):
    """Test class for restart_services_sm function."""

    def setUp(self):
        super().setUp()
        self.mock_run = self._mock_object(update_region_name.subprocess, "run")

    def test_restarts_all(self):
        """Test calls sm-restart-safe for each service."""
        self.mock_run.return_value = mock.Mock(returncode=0)
        update_region_name.restart_services_sm(["svc1", "svc2"])
        self.assertEqual(self.mock_run.call_count, 2)
        calls = [c[0][0] for c in self.mock_run.call_args_list]
        self.assertEqual(calls[0], ["sm-restart-safe", "service", "svc1"])
        self.assertEqual(calls[1], ["sm-restart-safe", "service", "svc2"])

    def test_raises_on_error(self):
        """Test exits on CalledProcessError."""
        self.mock_run.side_effect = subprocess.CalledProcessError(
            1, "sm-restart-safe", stderr="error"
        )
        self.assertRaises(
            SystemExit,
            update_region_name.restart_services_sm,
            ["svc1"],
        )


class TestRestartServicesSystemd(base.DCCommonTestCase):
    """Test class for restart_services_systemd function."""

    def setUp(self):
        super().setUp()
        self.mock_run = self._mock_object(update_region_name.subprocess, "run")

    def test_restarts_all(self):
        """Test calls systemctl restart for each service."""
        self.mock_run.return_value = mock.Mock(returncode=0)
        update_region_name.restart_services_systemd(["svc1.service", "svc2.service"])
        self.assertEqual(self.mock_run.call_count, 2)
        calls = [c[0][0] for c in self.mock_run.call_args_list]
        self.assertEqual(calls[0], ["systemctl", "restart", "svc1.service"])
        self.assertEqual(calls[1], ["systemctl", "restart", "svc2.service"])

    def test_raises_on_error(self):
        """Test exits on CalledProcessError."""
        self.mock_run.side_effect = subprocess.CalledProcessError(
            1, "systemctl", stderr="error"
        )
        self.assertRaises(
            SystemExit,
            update_region_name.restart_services_systemd,
            ["svc1.service"],
        )


class TestVerifySmServices(base.DCCommonTestCase):
    """Test class for verify_sm_services function."""

    def setUp(self):
        super().setUp()
        self.mock_run = self._mock_object(update_region_name.subprocess, "run")
        self.mock_sleep = self._mock_object(update_region_name.time, "sleep")

    def test_succeeds_immediately(self):
        """Test passes when active on first try."""
        self.mock_run.return_value = mock.Mock(stdout="enabled-active", returncode=0)
        update_region_name.verify_sm_services(["svc1"], max_retries=3)
        self.mock_sleep.assert_not_called()

    def test_retries_then_succeeds(self):
        """Test retries then succeeds."""
        self.mock_run.side_effect = [
            mock.Mock(stdout="disabled-inactive", returncode=0),
            mock.Mock(stdout="enabled-active", returncode=0),
        ]
        update_region_name.verify_sm_services(["svc1"], max_retries=3, delay_seconds=1)
        self.mock_sleep.assert_called_once_with(1)

    def test_raises_timeout(self):
        """Test exits when service never becomes active."""
        self.mock_run.return_value = mock.Mock(stdout="disabled-inactive", returncode=0)
        self.assertRaises(
            SystemExit,
            update_region_name.verify_sm_services,
            ["svc1"],
            2,
            0,
        )

    def test_handles_subprocess_error(self):
        """Test handles CalledProcessError during verification."""
        self.mock_run.side_effect = [
            subprocess.CalledProcessError(1, "sm-query", stderr="err"),
            mock.Mock(stdout="enabled-active", returncode=0),
        ]
        update_region_name.verify_sm_services(["svc1"], max_retries=3, delay_seconds=0)


class TestVerifySystemdServices(base.DCCommonTestCase):
    """Test class for verify_systemd_services function."""

    def setUp(self):
        super().setUp()
        self.mock_run = self._mock_object(update_region_name.subprocess, "run")
        self.mock_sleep = self._mock_object(update_region_name.time, "sleep")

    def test_succeeds_immediately(self):
        """Test passes on first try."""
        self.mock_run.return_value = mock.Mock(stdout="active\n", returncode=0)
        update_region_name.verify_systemd_services(["svc1.service"], max_retries=3)
        self.mock_sleep.assert_not_called()

    def test_raises_timeout(self):
        """Test exits when service never becomes active."""
        self.mock_run.return_value = mock.Mock(stdout="inactive\n", returncode=0)
        self.assertRaises(
            SystemExit,
            update_region_name.verify_systemd_services,
            ["svc1.service"],
            2,
            0,
        )

    def test_handles_subprocess_error(self):
        """Test handles CalledProcessError during verification."""
        self.mock_run.side_effect = [
            subprocess.CalledProcessError(1, "systemctl", stderr="err"),
            mock.Mock(stdout="active\n", returncode=0),
        ]
        update_region_name.verify_systemd_services(
            ["svc1.service"], max_retries=3, delay_seconds=0
        )


class TestRestartServices(base.DCCommonTestCase):
    """Test class for restart_services function."""

    def setUp(self):
        super().setUp()
        self.mock_sm = self._mock_object(update_region_name, "restart_services_sm")
        self.mock_systemd = self._mock_object(
            update_region_name, "restart_services_systemd"
        )
        self.mock_verify_sm = self._mock_object(
            update_region_name, "verify_sm_services"
        )
        self.mock_verify_systemd = self._mock_object(
            update_region_name, "verify_systemd_services"
        )
        self.mock_mtce = self._mock_object(update_region_name, "restart_mtce_services")
        self.mock_pmon = self._mock_object(
            update_region_name, "restart_pmon_managed_services"
        )

    def test_calls_all(self):
        """Test calls all restart and verify functions in order."""
        update_region_name.restart_services(["svc1"])
        self.mock_sm.assert_called_once_with(["svc1"])
        self.mock_systemd.assert_called_once_with(
            update_region_name.SERVICES_TO_RESTART_SYSTEMD
        )
        self.mock_mtce.assert_called_once()
        self.mock_pmon.assert_called_once_with(
            update_region_name.SERVICES_TO_RESTART_PMON
        )


class TestVerifyServices(base.DCCommonTestCase):
    """Test class for verify_services function."""

    def setUp(self):
        super().setUp()
        self.mock_sm = self._mock_object(update_region_name, "verify_sm_services")
        self.mock_systemd = self._mock_object(
            update_region_name, "verify_systemd_services"
        )

    def test_calls_all(self):
        """Test calls all verify functions."""
        update_region_name.verify_services(["svc1"])
        self.mock_sm.assert_called_once_with(["svc1"])
        self.mock_systemd.assert_called_once_with(
            update_region_name.SERVICES_TO_RESTART_SYSTEMD
        )


class TestMain(base.DCCommonTestCase):
    """Test class for main function."""

    def setUp(self):
        super().setUp()
        self.mock_get_sw = self._mock_object(
            update_region_name,
            "get_sw_version",
            return_value="m.n",
        )
        self.mock_load_creds = self._mock_object(update_region_name, "load_credentials")
        self.mock_create_ks = self._mock_object(
            update_region_name, "create_keystone_client"
        )
        self.mock_create_region = self._mock_object(
            update_region_name, "create_keystone_region"
        )
        self.mock_migrate_ep = self._mock_object(
            update_region_name, "migrate_keystone_endpoints"
        )
        self.mock_update_sysinv = self._mock_object(
            update_region_name, "update_sysinv_database"
        )
        self.mock_update_files = self._mock_object(update_region_name, "update_files")
        self.mock_restart = self._mock_object(update_region_name, "restart_services")
        self.mock_verify = self._mock_object(update_region_name, "verify_services")

    def test_generates_uuid_region_name(self):
        """Test generates UUID region name automatically."""
        with mock.patch("sys.argv", ["update_region_name.py"]):
            update_region_name.main()

        # Verify a valid 32-char hex region was passed
        call_args = self.mock_create_region.call_args[0]
        generated_region = call_args[1]
        self.assertRegex(
            generated_region,
            r"^" + update_region_name.REGION_NAME_PATTERN + r"$",
        )
        self.mock_update_sysinv.assert_called_once_with(generated_region)
        self.mock_update_files.assert_called_once()
        self.mock_migrate_ep.assert_called_once_with(
            self.mock_create_ks.return_value, generated_region
        )
        self.mock_restart.assert_called_once()
        self.mock_verify.assert_called_once()

    def test_recovers_after_midway_failure(self):
        """Test script can be re-run after midway failure."""
        # First run: keystone succeeds, sysinv fails
        self.mock_update_sysinv.side_effect = SystemExit(1)
        with mock.patch("sys.argv", ["update_region_name.py"]):
            self.assertRaises(SystemExit, update_region_name.main)

        # Keystone region was created on first run
        self.mock_create_region.assert_called_once()

        # Reset mocks for second run
        self.mock_create_region.reset_mock()
        self.mock_update_sysinv.reset_mock()
        self.mock_update_sysinv.side_effect = None

        # Second run: should succeed
        with mock.patch("sys.argv", ["update_region_name.py"]):
            update_region_name.main()

        # All steps called on second run
        self.mock_create_region.assert_called_once()
        self.mock_update_sysinv.assert_called_once()
        self.mock_update_files.assert_called_once()
        self.mock_migrate_ep.assert_called_once()
        self.mock_restart.assert_called_once()
        self.mock_verify.assert_called_once()
