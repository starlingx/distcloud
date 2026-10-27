#
# Copyright (c) 2022-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import time
from unittest import mock

from dccommon.exceptions import PlaybookExecutionTimeout
from dccommon.tests import base
from dccommon import utils

FAKE_SUBCLOUD_NAME = "subcloud1"
FAKE_LOG_FILE = "/dev/null"


class TestUtils(base.DCCommonTestCase):
    def setUp(self):
        super(TestUtils, self).setUp()

    def tearDown(self):
        super(TestUtils, self).tearDown()

    def test_exec_playbook(self):
        # no timeout:
        testscript = ["dccommon/tests/unit/test_utils_script.sh", "1"]
        ansible = utils.AnsiblePlaybook(FAKE_SUBCLOUD_NAME)
        ansible.run_playbook(FAKE_LOG_FILE, testscript)

    def test_exec_playbook_timeout(self):
        testscript = ["dccommon/tests/unit/test_utils_script.sh", "30"]
        ansible = utils.AnsiblePlaybook(FAKE_SUBCLOUD_NAME)
        self.assertRaises(
            PlaybookExecutionTimeout,
            ansible.run_playbook,
            FAKE_LOG_FILE,
            testscript,
            timeout=2,
        )

    def test_exec_playbook_timeout_requires_kill(self):
        # This option ignores a regular TERM signal, and requires a
        # kill -9 (KILL signal) to terminate. We're using this to simulate
        # a hung process
        script = ["dccommon/tests/unit/test_utils_script.sh", "30", "TERM"]
        ansible = utils.AnsiblePlaybook(FAKE_SUBCLOUD_NAME)
        self.assertRaises(
            PlaybookExecutionTimeout,
            ansible.run_playbook,
            FAKE_LOG_FILE,
            script,
            timeout=2,
        )


class TestBmcIsReachable(base.DCCommonTestCase):
    """Tests for utils.bmc_is_reachable"""

    BMC_ADDR_V4 = "10.0.0.1"
    BMC_ADDR_V6 = "fd00::1"

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(utils.requests, "get")
        self.mock_get = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_get.return_value = mock.MagicMock(status_code=200)

    def _call(self, timeout_seconds=None, **overrides):
        install_values = {
            "bmc_address": self.BMC_ADDR_V4,
            "bmc_username": "root",
            "bmc_password": "secret",
            **overrides,
        }
        kwargs = {}
        if timeout_seconds is not None:
            kwargs["timeout_seconds"] = timeout_seconds
        return utils.bmc_is_reachable(install_values, **kwargs)

    def test_returns_reachable_on_2xx_and_uses_expected_url_options(self):
        result = self._call()
        self.assertTrue(result.reachable)
        self.assertEqual(result.reason, "")
        self.mock_get.assert_called_once_with(
            f"https://{self.BMC_ADDR_V4}/redfish/v1/",
            timeout=3,
            verify=False,
            allow_redirects=False,
        )

    def test_returns_reachable_on_3xx(self):
        self.mock_get.return_value = mock.MagicMock(status_code=301)
        result = self._call()
        self.assertTrue(result.reachable)

    def test_returns_not_reachable_on_error_status_codes(self):
        for code in (401, 403, 404, 500, 503):
            with self.subTest(status_code=code):
                self.mock_get.return_value = mock.MagicMock(status_code=code)
                result = self._call()
                self.assertFalse(result.reachable)
                self.assertIn(str(code), result.reason)

    def test_returns_not_reachable_on_request_exceptions(self):
        for exc in (
            utils.requests.exceptions.ConnectTimeout,
            utils.requests.exceptions.ReadTimeout,
            utils.requests.exceptions.ConnectionError,
            utils.requests.exceptions.SSLError,
        ):
            with self.subTest(exc=exc.__name__):
                self.mock_get.side_effect = exc()
                result = self._call()
                self.assertFalse(result.reachable)
                self.assertNotEqual(result.reason, "")

    def test_uses_brackets_for_ipv6(self):
        utils.bmc_is_reachable(
            {
                "bmc_address": self.BMC_ADDR_V6,
                "bmc_username": "root",
                "bmc_password": "secret",
            }
        )
        url = self.mock_get.call_args[0][0]
        self.assertEqual(url, f"https://[{self.BMC_ADDR_V6}]/redfish/v1/")

    def test_returns_not_reachable_when_install_values_empty_or_none(self):
        result_empty = utils.bmc_is_reachable({})
        result_none = utils.bmc_is_reachable(None)
        self.assertFalse(result_empty.reachable)
        self.assertFalse(result_none.reachable)
        self.mock_get.assert_not_called()

    def test_returns_not_reachable_when_bmc_fields_missing(self):
        result = utils.bmc_is_reachable({"bmc_username": "root"})
        self.assertFalse(result.reachable)
        self.assertIn("bmc_address", result.reason)
        self.assertIn("bmc_password", result.reason)
        self.mock_get.assert_not_called()

    def test_returns_not_reachable_when_bmc_address_invalid(self):
        result = utils.bmc_is_reachable(
            {
                "bmc_address": "not-an-ip",
                "bmc_username": "root",
                "bmc_password": "secret",
            }
        )
        self.assertFalse(result.reachable)
        self.assertIn("not-an-ip", result.reason)
        self.mock_get.assert_not_called()

    def test_propagates_timeout_argument(self):
        self._call(timeout_seconds=5)
        self.assertEqual(self.mock_get.call_args[1]["timeout"], 5)


class TestProbeBmcsInParallel(base.DCCommonTestCase):
    """Tests for utils.probe_bmcs_in_parallel"""

    NUM_SUBCLOUDS = 100

    def setUp(self):
        super().setUp()
        self.mock_get = self._mock_object(utils.requests, "get")
        self.mock_scheduler_log = self._mock_object(utils.scheduler, "LOG")

    @staticmethod
    def _bmc_address(subcloud_id):
        return f"10.0.0.{subcloud_id}"

    def _subcloud(self, subcloud_id):
        install_values = {
            "bmc_address": self._bmc_address(subcloud_id),
            "bmc_username": "root",
            "bmc_password": "secret",
        }
        return mock.MagicMock(id=subcloud_id, data_install=json.dumps(install_values))

    def test_probes_in_parallel_with_failures_and_no_unhandled_errors(self):
        """Test 100 concurrent probes, 10 failing, with varied durations.

        Each probe sleeps between 0 and 1.9 seconds. Every tenth subcloud
        fails to connect. All subclouds must get a result, and no task may
        end with an unhandled exception.
        """
        subclouds = [self._subcloud(i) for i in range(1, self.NUM_SUBCLOUDS + 1)]
        failing_addresses = {
            self._bmc_address(i) for i in range(10, self.NUM_SUBCLOUDS + 1, 10)
        }

        def fake_get(url, **kwargs):
            bmc_address = url.split("/")[2]
            subcloud_id = int(bmc_address.split(".")[-1])
            time.sleep((subcloud_id % 20) * 0.1)
            if bmc_address in failing_addresses:
                raise utils.requests.exceptions.ConnectionError("Connection refused")
            return mock.MagicMock(status_code=200)

        self.mock_get.side_effect = fake_get

        start = time.monotonic()
        results = utils.probe_bmcs_in_parallel(subclouds)
        elapsed = time.monotonic() - start

        expected = {}
        for subcloud in subclouds:
            bmc_address = self._bmc_address(subcloud.id)
            if bmc_address in failing_addresses:
                expected[subcloud.id] = utils.BmcProbeResult(
                    False,
                    f"Could not connect to {bmc_address}: Connection refused",
                )
            else:
                expected[subcloud.id] = utils.BmcProbeResult(True)

        self.assertEqual(expected, results)
        self.assertEqual(
            10, sum(1 for result in results.values() if not result.reachable)
        )
        self.assertEqual(self.NUM_SUBCLOUDS, self.mock_get.call_count)
        self.mock_scheduler_log.exception.assert_not_called()
        # Run sequentially, the sleeps add up to about 95 seconds, so
        # finishing well under that shows the probes ran concurrently.
        self.assertLess(elapsed, 5)

    def test_probes_more_subclouds_than_pool_size(self):
        """Test subclouds beyond the pool size are queued and probed."""
        self.mock_get.return_value = mock.MagicMock(status_code=200)
        subclouds = [self._subcloud(i) for i in range(1, 151)]

        results = utils.probe_bmcs_in_parallel(subclouds, pool_size=10)

        self.assertEqual(
            {i: utils.BmcProbeResult(True) for i in range(1, 151)}, results
        )
        self.assertEqual(150, self.mock_get.call_count)
