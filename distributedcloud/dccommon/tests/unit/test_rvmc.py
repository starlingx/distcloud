#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import datetime
import sys

import mock

from dccommon.exceptions import RvmcExit
from dccommon import rvmc
from dccommon.tests import base


class TestSafeLog(base.DCCommonTestCase):
    """Test class for testing safe_log utility function.

    Tests the safe_log function which converts various input types
    into readable string representations for logging purposes.
    """

    def test_safe_log_none_input(self):
        """Verify safe_log returns 'None' string for None input"""

        self.assertEqual(rvmc.safe_log(None), "None")

    def test_safe_log_empty_list_returns_none(self):
        """Verify safe_log returns 'None' string for empty list"""

        self.assertEqual(rvmc.safe_log([]), "None")

    def test_safe_log_empty_tuple_returns_none(self):
        """Verify safe_log returns 'None' string for empty tuple"""

        self.assertEqual(rvmc.safe_log(tuple()), "None")

    def test_safe_log_list_returns_comma_separated(self):
        """Verify safe_log returns comma-separated string for list with values"""

        self.assertEqual(rvmc.safe_log([1, 2, 3]), "1, 2, 3")

    def test_safe_log_tuple_returns_comma_separated(self):
        """Verify safe_log returns comma-separated string for tuple with values"""

        self.assertEqual(rvmc.safe_log((1, 2, 3)), "1, 2, 3")

    def test_safe_log_string_input(self):
        """Verify safe_log returns string representation for string input"""

        self.assertEqual(rvmc.safe_log("test"), "test")

    def test_safe_log_integer_input(self):
        """Verify safe_log returns string representation for integer input"""

        self.assertEqual(rvmc.safe_log(42), "42")


class TestLoggingUtil(base.DCCommonTestCase):
    """Test class for LoggingUtil utility class.

    Tests the LoggingUtil class which provides logging functionality
    with support for different log levels and optional logger integration.
    """

    def setUp(self):
        super().setUp()

        self.mock_logger = mock.MagicMock()
        self.mock_stdout_write = self._mock_object(sys.stdout, "write")

    def _assert_stdout_write_calls(self, expected_calls):
        call_args_list = self.mock_stdout_write.call_args_list
        calls = [call[0][0] for call in call_args_list]

        self.assertEqual(len(calls), len(expected_calls))
        for i, expected_suffix in enumerate(expected_calls):
            self.assertTrue(calls[i].endswith(expected_suffix))

    def test_init_with_logger_sets_attributes(self):
        """Verify LoggingUtil initialization with logger"""

        util = rvmc.LoggingUtil(
            logger=self.mock_logger,
            subcloud_name="subcloud1",
            debug_level=2,
            mute_on=True,
        )
        self.assertEqual(util.logger, self.mock_logger)
        self.assertEqual(util.subcloud_name, "subcloud1")
        self.assertEqual(util.debug_level, 2)
        self.assertTrue(util.mute_on)

    def test_init_without_logger_uses_defaults(self):
        """Verify LoggingUtil initialization without logger"""

        util = rvmc.LoggingUtil()
        self.assertIsNone(util.logger)
        self.assertEqual(util.subcloud_name, "")
        self.assertEqual(util.debug_level, 0)
        self.assertFalse(util.mute_on)

    def test_t_returns_datetime_without_microseconds(self):
        """Verify t method returns current datetime without microseconds"""

        util = rvmc.LoggingUtil()
        result = util.t()
        self.assertIsInstance(result, datetime.datetime)
        self.assertEqual(result.microsecond, 0)

    def test_logging_with_logger_includes_subcloud_name_when_specified(self):
        """Verify logging methods include subcloud name with logger when specified"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, subcloud_name="subcloud1")

        util.ilog("test message")
        self.mock_logger.info.assert_called_with("subcloud1: test message")

        util.wlog("warning message")
        self.mock_logger.warning.assert_called_with("subcloud1: warning message")

        util.elog("error message")
        self.mock_logger.error.assert_called_with("subcloud1: error message")

        util.alog("action message")
        self.mock_logger.info.assert_called_with("subcloud1: action message")

        util.slog("stage message")
        self.mock_logger.info.assert_called_with("subcloud1: stage message")

    def test_logging_with_logger_without_subcloud_name(self):
        """Verify logging methods only log the message when subcloud is not specified"""

        util = rvmc.LoggingUtil(logger=self.mock_logger)

        util.ilog("test message")
        self.mock_logger.info.assert_called_with("test message")

        util.wlog("warning message")
        self.mock_logger.warning.assert_called_with("warning message")

        util.elog("error message")
        self.mock_logger.error.assert_called_with("error message")

        util.alog("action message")
        self.mock_logger.info.assert_called_with("action message")

        util.slog("stage message")
        self.mock_logger.info.assert_called_with("stage message")

    def test_logging_without_logger_writes_to_stdout(self):
        """Verify all logging methods write to stdout when no logger id provided"""

        util = rvmc.LoggingUtil()

        util.ilog("test message")
        util.wlog("warning message")
        util.elog("error message")
        util.alog("action message")
        util.slog("stage message")

        expected_calls = [
            " Info  : test message",
            " Warn  : warning message",
            " Error : error message",
            " Action: action message",
            " Stage : stage message",
        ]
        self._assert_stdout_write_calls(expected_calls)

    def test_muted_logging_does_not_log(self):
        """Verify muted logging methods do not log"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, mute_on=True)

        util.ilog("test message")
        util.alog("action message")
        util.slog("stage message")

        self.mock_logger.info.assert_not_called()

    def test_dlog1_logs_at_level_1(self):
        """Verify dlog1 logs debug message at level 1"""

        util = rvmc.LoggingUtil(
            logger=self.mock_logger, debug_level=1, subcloud_name="subcloud1"
        )
        util.dlog1("debug message")
        self.mock_logger.debug.assert_called_once_with("subcloud1: debug message")

    def test_dlog1_logs_when_level_higher(self):
        """Verify dlog1 logs debug message when debug_level is higher"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=2)
        util.dlog1("debug message")
        self.mock_logger.debug.assert_called_once_with("debug message")

    def test_dlog1_without_logger_writes_to_stdout(self):
        """Verify dlog1 writes to stdout when no logger is provided"""

        util = rvmc.LoggingUtil(debug_level=1)
        util.dlog1("debug message")

        self._assert_stdout_write_calls([" Debug1: debug message"])

    def test_dlog1_no_output_when_level_insufficient(self):
        """Verify dlog1 does not log when debug_level is 0"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=0)
        util.dlog1("debug message")
        self.mock_logger.debug.assert_not_called()

    def test_dlog1_logs_at_custom_level(self):
        """Verify dlog1 logs at custom level when debug_level is sufficient"""

        util = rvmc.LoggingUtil(
            logger=self.mock_logger, debug_level=3, subcloud_name="subcloud2"
        )
        util.dlog1("debug message", level=2)
        self.mock_logger.debug.assert_called_once_with("subcloud2: debug message")

    def test_dlog1_no_output_when_custom_level_exceeds(self):
        """Verify dlog1 does not log when custom level exceeds debug_level"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=2)
        util.dlog1("debug message", level=3)
        self.mock_logger.debug.assert_not_called()

    def test_debug_logging_at_correct_levels(self):
        """Verify debug logging methods work at their respective levels"""

        debug_methods = [("dlog2", 2), ("dlog3", 3), ("dlog4", 4)]

        for method_name, level in debug_methods:
            util = rvmc.LoggingUtil(
                logger=self.mock_logger,
                debug_level=level,
                subcloud_name="subcloud1",
            )
            getattr(util, method_name)("debug message")
            self.mock_logger.debug.assert_called_with("subcloud1: debug message")
            self.mock_logger.reset_mock()

    def test_debug_logging_without_logger_writes_to_stdout(self):
        """Verify debug logging methods write to stdout when no logger provided"""

        debug_methods = [
            ("dlog2", 2, "Debug2"),
            ("dlog3", 3, "Debug3"),
            ("dlog4", 4, "Debug4"),
        ]

        for method_name, level, expected_prefix in debug_methods:
            util = rvmc.LoggingUtil(debug_level=level)
            getattr(util, method_name)("debug message")

            self._assert_stdout_write_calls([f" {expected_prefix}: debug message"])
            self.mock_stdout_write.reset_mock()

    def test_debug_logging_no_output_when_level_insufficient(self):
        """Verify debug logging methods don't log when debug_level is insufficient"""

        debug_methods = ["dlog2", "dlog3", "dlog4"]

        for method_name in debug_methods:
            util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=1)
            getattr(util, method_name)("debug message")
            self.mock_logger.debug.assert_not_called()
            self.mock_logger.reset_mock()


class TestExitHandler(base.DCCommonTestCase):
    """Test class for ExitHandler utility class.

    Tests the ExitHandler class which manages process exit scenarios
    by raising appropriate exceptions based on exit codes.
    """

    def setUp(self):
        super().setUp()

        self.exit_handler = rvmc.ExitHandler()

    def test_exit_with_zero_code_does_not_raise(self):
        """Verify exit with code 0 does not raise exception"""

        self.assertIsNone(self.exit_handler.exit(0))

    def test_exit_with_non_zero_code_raises_rvmc_exit(self):
        """Verify exit with non-zero codes raises RvmcExit exception"""

        for code in [1, 2, -1]:
            self.assertRaises(RvmcExit, self.exit_handler.exit, code)


class TestIsIpv6Address(base.DCCommonTestCase):
    """Test class for is_ipv6_address utility function.

    Tests the is_ipv6_address function which validates whether a given
    address string is a valid IPv6 address using socket.inet_pton.
    """

    def setUp(self):
        super().setUp()

        self.mock_logger = mock.MagicMock()
        self.logging_util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=3)

    def _validate_ipv6_response(self, address, ip_version="IPv6"):
        """Utility method to validate is_ipv6_address responses.

        :param address: IP address to test
        :type address: str
        :param ip_version: IP version tested, i.e, IPv6 or IPv4
        :type ip_version: str
        """

        result = rvmc.is_ipv6_address(address, self.logging_util)

        expected_result = ip_version == "IPv6"
        self.assertEqual(result, expected_result)
        self.mock_logger.debug.assert_called_once_with(
            f"Address     : {address} is {ip_version}"
        )

    def test_is_ipv6_address_with_valid_ipv6_returns_true(self):
        """Verify is_ipv6_address returns True for valid IPv6 address"""

        self._validate_ipv6_response("2001:db8::1")

    def test_is_ipv6_address_with_ipv6_loopback_returns_true(self):
        """Verify is_ipv6_address returns True for IPv6 loopback address"""

        self._validate_ipv6_response("::1")

    def test_is_ipv6_address_with_ipv6_full_address_returns_true(self):
        """Verify is_ipv6_address returns True for full IPv6 address"""

        self._validate_ipv6_response("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_is_ipv6_address_with_ipv6_compressed_returns_true(self):
        """Verify is_ipv6_address returns True for compressed IPv6 address"""

        self._validate_ipv6_response("fe80::1")

    def test_is_ipv6_address_with_ipv6_all_zeros_returns_true(self):
        """Verify is_ipv6_address returns True for IPv6 all zeros address"""

        self._validate_ipv6_response("::")

    def test_is_ipv6_address_with_ipv4_returns_false(self):
        """Verify is_ipv6_address returns False for IPv4 address"""

        self._validate_ipv6_response("192.168.1.1", "IPv4")

    def test_is_ipv6_address_with_ipv4_loopback_returns_false(self):
        """Verify is_ipv6_address returns False for IPv4 loopback address"""

        self._validate_ipv6_response("127.0.0.1", "IPv4")

    def test_is_ipv6_address_with_invalid_address_returns_false(self):
        """Verify is_ipv6_address returns False for invalid address format"""

        self._validate_ipv6_response("invalid_address", "IPv4")

    def test_is_ipv6_address_with_empty_string_returns_false(self):
        """Verify is_ipv6_address returns False for empty string"""

        self._validate_ipv6_response("", "IPv4")


class TestSupportedDevice(base.DCCommonTestCase):
    """Test class for supported_device utility function.

    Tests the supported_device function which validates whether a device
    in the provided devices list is in the SUPPORTED_VIRTUAL_MEDIA_DEVICES list.
    """

    def test_supported_device_returns_true_for_valid_devices(self):
        """Verify supported_device returns True for supported devices"""

        valid_cases = [
            ["CD"],
            ["DVD"],
            ["CD", "DVD"],
            ["USB", "CD", "Floppy"],
            ["Floppy", "DVD", "USB"],
        ]
        for devices in valid_cases:
            self.assertTrue(rvmc.supported_device(devices))

    def test_supported_device_returns_false_for_invalid_devices(self):
        """Verify supported_device returns False for unsupported or invalid devices"""

        invalid_cases = [
            [],
            ["USB"],
            ["USB", "Floppy", "Network"],
            ["cd"],
            ["dvd"],
            ["Cd"],
            ["Dvd"],
        ]
        for devices in invalid_cases:
            self.assertFalse(rvmc.supported_device(devices))


class BaseTestRvmc(base.DCCommonTestCase):
    """Base test class for RVMC tests.

    Provides common setup functionality for RVMC-related test classes,
    including mock logger, logging utility, exit handler and test data.
    """

    def setUp(self):
        super().setUp()

        self.mock_logger = mock.MagicMock()
        self.logging_util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=3)
        self.exit_handler = rvmc.ExitHandler()
        self.target_name = "subcloud1"
        self.config_file = "/path/to/config.yaml"
        self.target_dict = {
            "bmc_address": "192.168.1.1",
            "bmc_username": "admin",
            "bmc_password": "dGVzdHBhc3N3b3Jk",  # base64 encoded "testpassword"
            "image": "http://example.com/image.iso",
        }

    def _assert_mock_logger_calls(self, expected_calls):
        """Assert the mock logger was called with expected calls."""

        calls = []

        for call in expected_calls:
            # The mock.ANY entries are required because the mock_logger is called
            # in the conditional statement inside LogginUtil, i.e. if self.logger.
            calls.append(mock.ANY)
            calls.append(call)

        self.mock_logger.assert_has_calls(calls)


class TestParseTarget(BaseTestRvmc):
    """Test class for parse_target utility function.

    Tests the parse_target function which parses BMC configuration
    and creates a VmcObject for virtual media control operations.
    """

    def setUp(self):
        super().setUp()

        self.parse_config_file_args = (
            self.target_name,
            self.target_dict,
            self.config_file,
            self.logging_util,
            self.exit_handler,
        )

    def test_parse_target_returns_none_when_password_missing(self):
        """Verify parse_target returns None when bmc_password is missing"""

        del self.target_dict["bmc_password"]

        result = rvmc.parse_target(*self.parse_config_file_args)

        self.assertIsNone(result)
        self.mock_logger.error.assert_called_once_with(
            "Failed get bmc password from config file"
        )

    def test_parse_target_returns_none_when_password_decode_fails(self):
        """Verify parse_target returns None when password decoding fails"""

        self.target_dict["bmc_password"] = "invalid_base64!@#"

        result = rvmc.parse_target(*self.parse_config_file_args)

        self.assertIsNone(result)
        self._assert_mock_logger_calls(
            [
                mock.call.debug(f"Parse Target: {self.target_name}:{self.target_dict}"),
                mock.call.error(
                    "Failed to decode bmc password found in config file (Invalid "
                    "base64-encoded string: number of data characters (13) cannot be 1 "
                    "more than a multiple of 4)"
                ),
                mock.call.info("Verify config file's bmc password is base64 encoded"),
            ]
        )

    def test_parse_target_returns_none_when_address_missing(self):
        """Verify parse_target returns None when bmc_address is missing"""

        del self.target_dict["bmc_address"]

        result = rvmc.parse_target(*self.parse_config_file_args)

        self.assertIsNone(result)
        self._assert_mock_logger_calls(
            [
                mock.call.debug(f"Parse Target: {self.target_name}:{self.target_dict}"),
                mock.call.error(
                    f"Failed to retrieve the bmc_address from {self.config_file}"
                ),
            ]
        )

    def test_parse_target_creates_vmc_object_with_ipv4_address(self):
        """Verify parse_target creates VmcObject for IPv4 address"""

        result = rvmc.parse_target(*self.parse_config_file_args)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, rvmc.VmcObject)
        self.assertFalse(result.ipv6)
        self.assertEqual(result.ip, self.target_dict["bmc_address"])
        self.assertEqual(result.un, self.target_dict["bmc_username"])
        self.assertEqual(result.pw_encoded, self.target_dict["bmc_password"])

    def test_parse_target_creates_vmc_object_with_ipv6_address(self):
        """Verify parse_target creates VmcObject for IPv6 address with brackets"""

        self.target_dict["bmc_address"] = "2001:db8::1"

        result = rvmc.parse_target(*self.parse_config_file_args)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, rvmc.VmcObject)
        self.assertTrue(result.ipv6)
        self.assertEqual(result.ip, f"[{self.target_dict['bmc_address']}]")
        self.assertEqual(result.un, self.target_dict["bmc_username"])
        self.assertEqual(result.pw_encoded, self.target_dict["bmc_password"])

    def test_parse_target_returns_none_when_vmc_object_creation_fails(self):
        """Verify parse_target returns None when VmcObject creation raises exception

        This can occur when either the image or bmc_username keys are no found in the
        target_dict variable.
        """

        del self.target_dict["image"]

        result = rvmc.parse_target(*self.parse_config_file_args)

        self.assertIsNone(result)
        self._assert_mock_logger_calls(
            [
                mock.call.debug(f"Parse Target: {self.target_name}:{self.target_dict}"),
                mock.call.debug(
                    f"Address     : {self.target_dict['bmc_address']} is IPv4"
                ),
                mock.call.error(
                    f"Unable to parse configuration '{self.target_dict}' ('NoneType' "
                    f"object has no attribute 'rstrip') in {self.target_name} config "
                    "file."
                ),
                mock.call.info(
                    f"Check presence and spelling of configuration members in "
                    f"{self.target_name} config file."
                ),
            ]
        )

    def test_parse_target_returns_none_when_vmc_object_is_none(self):
        """Verify parse_target returns None when VmcObject creation returns None

        Note: this does not seem a reacheable code, therfore the VmcObject had to be
        mocked.
        """

        self._mock_object(rvmc, "VmcObject", return_value=None)

        result = rvmc.parse_target(*self.parse_config_file_args)

        self.assertIsNone(result)
        self.mock_logger.error.assert_called_once_with(
            f"Unable to create control object for target:{self.target_dict} ; "
            "skipping ..."
        )


class TestParseConfigFile(BaseTestRvmc):
    """Test class for parse_config_file utility function.

    Tests the parse_config_file function which parses BMC configuration
    from a YAML file and creates a VmcObject through parse_target.
    """

    def setUp(self):
        super().setUp()

        self.config_file = "/tmp/test_config.yaml"
        self.parse_config_file_args = (
            self.target_name,
            self.config_file,
            self.logging_util,
            self.exit_handler,
        )

        self.mock_os_path_exists = self._mock_object(
            rvmc.os.path, "exists", return_value=True
        )
        self.mock_file = mock.MagicMock()
        self.mock_file.__enter__.return_value = self.mock_file
        self.mock_open = self._mock_object(rvmc, "open", return_value=self.mock_file)
        self.mock_yaml_load = self._mock_object(
            rvmc.yaml, "safe_load", return_value=self.target_dict
        )

    def test_parse_config_file_returns_none_when_file_not_exists(self):
        """Verify parse_config_file exits when config file does not exist"""

        self.mock_os_path_exists.return_value = False

        self.assertRaises(
            RvmcExit, rvmc.parse_config_file, *self.parse_config_file_args
        )

        self._assert_mock_logger_calls(
            [
                mock.call.error(
                    f"Unable to find specified config file: {self.config_file}"
                ),
                mock.call.info("Check config file spelling and presence\n\n"),
            ]
        )

    def test_parse_config_file_exits_when_file_open_fails(self):
        """Verify parse_config_file exits when file cannot be opened"""

        self.mock_open.side_effect = PermissionError("Permission denied")

        self.assertRaises(
            RvmcExit, rvmc.parse_config_file, *self.parse_config_file_args
        )

        self.mock_open.assert_called_once_with(self.config_file, "r")
        self._assert_mock_logger_calls(
            [
                mock.call.error(
                    f"Unable to open specified config file: {self.config_file} "
                    "(Permission denied)"
                ),
                mock.call.info("Check config file access and permissions.\n\n"),
            ]
        )

    def test_parse_config_file_exits_when_yaml_parsing_fails(self):
        """Verify parse_config_file exits when YAML parsing fails"""

        self.mock_yaml_load.side_effect = Exception("Invalid YAML")

        self.assertRaises(
            RvmcExit, rvmc.parse_config_file, *self.parse_config_file_args
        )

        self.mock_open.assert_called_once_with(self.config_file, "r")
        self._assert_mock_logger_calls(
            [
                mock.call.debug(f"Config File : {self.config_file}"),
                mock.call.error(
                    f"Unable to open specified config file: {self.config_file} "
                    "(Invalid YAML)"
                ),
                mock.call.info("Check config file access and permissions.\n\n"),
            ]
        )

    def test_parse_config_file_returns_config_and_target_object(self):
        """Verify parse_config_file returns config data and target object"""

        cfg, target_object = rvmc.parse_config_file(*self.parse_config_file_args)

        self.assertEqual(cfg, self.target_dict)
        self.assertIsInstance(target_object, rvmc.VmcObject)
        self.assertEqual(target_object.target, self.target_name)
        self.assertFalse(target_object.ipv6)
        self.assertEqual(target_object.ip, self.target_dict["bmc_address"])
        self.assertEqual(target_object.un, self.target_dict["bmc_username"])
        self.assertEqual(target_object.pw_encoded, self.target_dict["bmc_password"])

    def test_parse_config_file_returns_config_and_target_object_with_ipv6(self):
        """Verify parse_config_file returns config data and target object with ipv6"""

        self.target_dict["bmc_address"] = "2001:db8::1"
        self.mock_yaml_load.return_value = self.target_dict

        cfg, target_object = rvmc.parse_config_file(*self.parse_config_file_args)

        self.assertEqual(cfg, self.target_dict)
        self.assertIsInstance(target_object, rvmc.VmcObject)
        self.assertEqual(target_object.target, self.target_name)
        self.assertTrue(target_object.ipv6)
        self.assertEqual(target_object.ip, f"[{self.target_dict['bmc_address']}]")
        self.assertEqual(target_object.un, self.target_dict["bmc_username"])
        self.assertEqual(target_object.pw_encoded, self.target_dict["bmc_password"])

    def test_parse_config_file_returns_none_target_object_on_parse_target_failure(self):
        """Verify parse_config_file returns None target_object on parse_target failure

        In this scenario, the configuration is parsed appropriately and returned, but
        the target object is returned empty.
        """

        # Create an invalid configuration
        del self.target_dict["bmc_password"]
        self.mock_yaml_load.return_value = self.target_dict

        cfg, target_object = rvmc.parse_config_file(*self.parse_config_file_args)

        self.assertEqual(cfg, self.target_dict)
        self.assertIsNone(target_object)

        self._assert_mock_logger_calls(
            [
                mock.call.debug(f"Config File : {self.config_file}"),
                mock.call.debug(f"Config Data : {self.target_dict}"),
            ]
        )

    def test_parse_config_file_returns_config_for_empty_config_file(self):
        """Verify parse_config_file returns config for an empty config file"""

        self.mock_yaml_load.return_value = {}

        cfg, target_object = rvmc.parse_config_file(*self.parse_config_file_args)

        self.assertEqual(cfg, {})
        self.assertIsNone(target_object)
