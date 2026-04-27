#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
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
        """Test safe_log returns 'None' string for None input"""

        self.assertEqual(rvmc.safe_log(None), "None")

    def test_safe_log_empty_list_returns_none(self):
        """Test safe_log returns 'None' string for empty list"""

        self.assertEqual(rvmc.safe_log([]), "None")

    def test_safe_log_empty_tuple_returns_none(self):
        """Test safe_log returns 'None' string for empty tuple"""

        self.assertEqual(rvmc.safe_log(tuple()), "None")

    def test_safe_log_list_returns_comma_separated(self):
        """Test safe_log returns comma-separated string for list with values"""

        self.assertEqual(rvmc.safe_log([1, 2, 3]), "1, 2, 3")

    def test_safe_log_tuple_returns_comma_separated(self):
        """Test safe_log returns comma-separated string for tuple with values"""

        self.assertEqual(rvmc.safe_log((1, 2, 3)), "1, 2, 3")

    def test_safe_log_string_input(self):
        """Test safe_log returns string representation for string input"""

        self.assertEqual(rvmc.safe_log("test"), "test")

    def test_safe_log_integer_input(self):
        """Test safe_log returns string representation for integer input"""

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
        """Test LoggingUtil initialization with logger"""

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
        """Test LoggingUtil initialization without logger"""

        util = rvmc.LoggingUtil()
        self.assertIsNone(util.logger)
        self.assertEqual(util.subcloud_name, "")
        self.assertEqual(util.debug_level, 0)
        self.assertFalse(util.mute_on)

    def test_t_returns_datetime_without_microseconds(self):
        """Test t method returns current datetime without microseconds"""

        util = rvmc.LoggingUtil()
        result = util.t()
        self.assertIsInstance(result, datetime.datetime)
        self.assertEqual(result.microsecond, 0)

    def test_logging_with_logger_includes_subcloud_name_when_specified(self):
        """Test logging methods include subcloud name with logger when specified"""

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
        """Test logging methods only log the message when subcloud is not specified"""

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
        """Test all logging methods write to stdout when no logger id provided"""

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
        """Test muted logging methods do not log"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, mute_on=True)

        util.ilog("test message")
        util.alog("action message")
        util.slog("stage message")

        self.mock_logger.info.assert_not_called()

    def test_dlog1_logs_at_level_1(self):
        """Test dlog1 logs debug message at level 1"""

        util = rvmc.LoggingUtil(
            logger=self.mock_logger, debug_level=1, subcloud_name="subcloud1"
        )
        util.dlog1("debug message")
        self.mock_logger.debug.assert_called_once_with("subcloud1: debug message")

    def test_dlog1_logs_when_level_higher(self):
        """Test dlog1 logs debug message when debug_level is higher"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=2)
        util.dlog1("debug message")
        self.mock_logger.debug.assert_called_once_with("debug message")

    def test_dlog1_without_logger_writes_to_stdout(self):
        """Test dlog1 writes to stdout when no logger is provided"""

        util = rvmc.LoggingUtil(debug_level=1)
        util.dlog1("debug message")

        self._assert_stdout_write_calls([" Debug1: debug message"])

    def test_dlog1_no_output_when_level_insufficient(self):
        """Test dlog1 does not log when debug_level is 0"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=0)
        util.dlog1("debug message")
        self.mock_logger.debug.assert_not_called()

    def test_dlog1_logs_at_custom_level(self):
        """Test dlog1 logs at custom level when debug_level is sufficient"""

        util = rvmc.LoggingUtil(
            logger=self.mock_logger, debug_level=3, subcloud_name="subcloud2"
        )
        util.dlog1("debug message", level=2)
        self.mock_logger.debug.assert_called_once_with("subcloud2: debug message")

    def test_dlog1_no_output_when_custom_level_exceeds(self):
        """Test dlog1 does not log when custom level exceeds debug_level"""

        util = rvmc.LoggingUtil(logger=self.mock_logger, debug_level=2)
        util.dlog1("debug message", level=3)
        self.mock_logger.debug.assert_not_called()

    def test_debug_logging_at_correct_levels(self):
        """Test debug logging methods work at their respective levels"""

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
        """Test debug logging methods write to stdout when no logger provided"""

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
        """Test debug logging methods don't log when debug_level is insufficient"""

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
        """Test exit with code 0 does not raise exception"""

        self.assertIsNone(self.exit_handler.exit(0))

    def test_exit_with_non_zero_code_raises_rvmc_exit(self):
        """Test exit with non-zero codes raises RvmcExit exception"""

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
        """Test is_ipv6_address returns True for valid IPv6 address"""

        self._validate_ipv6_response("2001:db8::1")

    def test_is_ipv6_address_with_ipv6_loopback_returns_true(self):
        """Test is_ipv6_address returns True for IPv6 loopback address"""

        self._validate_ipv6_response("::1")

    def test_is_ipv6_address_with_ipv6_full_address_returns_true(self):
        """Test is_ipv6_address returns True for full IPv6 address"""

        self._validate_ipv6_response("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_is_ipv6_address_with_ipv6_compressed_returns_true(self):
        """Test is_ipv6_address returns True for compressed IPv6 address"""

        self._validate_ipv6_response("fe80::1")

    def test_is_ipv6_address_with_ipv6_all_zeros_returns_true(self):
        """Test is_ipv6_address returns True for IPv6 all zeros address"""

        self._validate_ipv6_response("::")

    def test_is_ipv6_address_with_ipv4_returns_false(self):
        """Test is_ipv6_address returns False for IPv4 address"""

        self._validate_ipv6_response("192.168.1.1", "IPv4")

    def test_is_ipv6_address_with_ipv4_loopback_returns_false(self):
        """Test is_ipv6_address returns False for IPv4 loopback address"""

        self._validate_ipv6_response("127.0.0.1", "IPv4")

    def test_is_ipv6_address_with_invalid_address_returns_false(self):
        """Test is_ipv6_address returns False for invalid address format"""

        self._validate_ipv6_response("invalid_address", "IPv4")

    def test_is_ipv6_address_with_empty_string_returns_false(self):
        """Test is_ipv6_address returns False for empty string"""

        self._validate_ipv6_response("", "IPv4")


class TestSupportedDevice(base.DCCommonTestCase):
    """Test class for supported_device utility function.

    Tests the supported_device function which validates whether a device
    in the provided devices list is in the SUPPORTED_VIRTUAL_MEDIA_DEVICES list.
    """

    def test_supported_device_returns_true_for_valid_devices(self):
        """Test supported_device returns True for supported devices"""

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
        """Test supported_device returns False for unsupported or invalid devices"""

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
        """Test parse_target returns None when bmc_password is missing"""

        del self.target_dict["bmc_password"]

        result = rvmc.parse_target(*self.parse_config_file_args)

        self.assertIsNone(result)
        self.mock_logger.error.assert_called_once_with(
            "Failed get bmc password from config file"
        )

    def test_parse_target_returns_none_when_password_decode_fails(self):
        """Test parse_target returns None when password decoding fails"""

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
        """Test parse_target returns None when bmc_address is missing"""

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
        """Test parse_target creates VmcObject for IPv4 address"""

        result = rvmc.parse_target(*self.parse_config_file_args)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, rvmc.VmcObject)
        self.assertFalse(result.ipv6)
        self.assertEqual(result.ip, self.target_dict["bmc_address"])
        self.assertEqual(result.un, self.target_dict["bmc_username"])
        self.assertEqual(result.pw_encoded, self.target_dict["bmc_password"])

    def test_parse_target_creates_vmc_object_with_ipv6_address(self):
        """Test parse_target creates VmcObject for IPv6 address with brackets"""

        self.target_dict["bmc_address"] = "2001:db8::1"

        result = rvmc.parse_target(*self.parse_config_file_args)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, rvmc.VmcObject)
        self.assertTrue(result.ipv6)
        self.assertEqual(result.ip, f"[{self.target_dict['bmc_address']}]")
        self.assertEqual(result.un, self.target_dict["bmc_username"])
        self.assertEqual(result.pw_encoded, self.target_dict["bmc_password"])

    def test_parse_target_returns_none_when_vmc_object_creation_fails(self):
        """Test parse_target returns None when VmcObject creation raises exception

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
        """Test parse_target returns None when VmcObject creation returns None

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
        self.mock_open = self._mock_object(rvmc, "open", return_value=self.mock_file)
        self.mock_yaml_load = self._mock_object(
            rvmc.yaml, "safe_load", return_value=self.target_dict
        )

    def test_parse_config_file_returns_none_when_file_not_exists(self):
        """Test parse_config_file exits when config file does not exist"""

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
        """Test parse_config_file exits when file cannot be opened"""

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
        """Test parse_config_file exits when YAML parsing fails"""

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
        """Test parse_config_file returns config data and target object"""

        cfg, target_object = rvmc.parse_config_file(*self.parse_config_file_args)

        self.assertEqual(cfg, self.target_dict)
        self.assertIsInstance(target_object, rvmc.VmcObject)
        self.assertEqual(target_object.target, self.target_name)
        self.assertFalse(target_object.ipv6)
        self.assertEqual(target_object.ip, self.target_dict["bmc_address"])
        self.assertEqual(target_object.un, self.target_dict["bmc_username"])
        self.assertEqual(target_object.pw_encoded, self.target_dict["bmc_password"])

    def test_parse_config_file_returns_config_and_target_object_with_ipv6(self):
        """Test parse_config_file returns config data and target object with ipv6"""

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
        """Test parse_config_file returns None target_object on parse_target failure

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
        """Test parse_config_file returns config for an empty config file"""

        self.mock_yaml_load.return_value = {}

        cfg, target_object = rvmc.parse_config_file(*self.parse_config_file_args)

        self.assertEqual(cfg, {})
        self.assertIsNone(target_object)


class BaseTestVmcObject(BaseTestRvmc):
    """Base test class for VmcObject tests.

    Provides common setup functionality for VmcObject-related test classes.
    """

    def setUp(self):
        super().setUp()

        self.vmc_obj = rvmc.VmcObject(
            hostname=self.target_name,
            address=self.target_dict["bmc_address"],
            username=self.target_dict["bmc_username"],
            password=self.target_dict["bmc_password"],
            password_decoded="testpassword",
            image=self.target_dict["image"],
            logging_util=self.logging_util,
            exit_handler=self.exit_handler,
        )

        self.systems_url = "/redfish/v1/Systems"
        self.systems_members_url = f"{self.systems_url}/v1"

        self.managers_url = "/redfish/v1/Managers"
        self.members_list = [{"@odata.id": f"{self.managers_url}/1/"}]

        self.reset_command_list = [
            "On",
            "ForceOff",
            "ForceOn",
            "GracefulShutdown",
            "ForceRestart",
        ]
        self.reset_command_url = (
            f"{self.systems_members_url}/Actions/ComputerSystem.Reset/"
        )

        self.vm_group_url = f"{self.managers_url}/1/VirtualMedia"
        self.vm_member_url = f"{self.vm_group_url}/1/"

        self.vmc_obj.redfish_obj = mock.MagicMock()
        self.vmc_obj.systems_group_url = self.systems_url
        self.vmc_obj.systems_members = 1
        self.vmc_obj.systems_members_list = [
            {"@odata.id": f"{self.systems_members_url}"}
        ]
        self.vmc_obj.manager_members_list = self.members_list
        # This object is storing data from several different requests
        self.vmc_obj.response_dict = {
            "Systems": {"@odata.id": self.systems_url},
            "Managers": {"@odata.id": self.managers_url},
            "Members": self.members_list,
            "Actions": {
                "#ComputerSystem.Reset": {
                    "target": f"{self.reset_command_url}",
                    "ResetType@Redfish.AllowableValues": self.reset_command_list,
                },
                "#VirtualMedia.InsertMedia": {
                    "target": f"{self.vm_member_url}Actions/VirtualMedia.InsertMedia"
                },
                "#VirtualMedia.EjectMedia": {
                    "target": f"{self.vm_member_url}Actions/VirtualMedia.EjectMedia"
                },
            },
            "PowerState": rvmc.POWER_OFF,
            # VM member response
            "@odata.id": self.vm_member_url,
            "MediaTypes": ["CD"],
            "Inserted": False,
            # Member response
            "VirtualMedia": {"@odata.id": self.vm_group_url},
            "Model": "TestModel",
        }

        # Store the original make_request method for its tests
        self.original_make_request = self.vmc_obj.make_request
        self.mock_make_request = self._mock_object(
            self.vmc_obj, "make_request", return_value=True
        )
        self.original_time_sleep = rvmc.time.sleep
        self.mock_time_sleep = self._mock_object(rvmc.time, "sleep")

    def _generate_log_dump(self, code=1):
        return [
            mock.call.error(f"Code : {code}"),
            mock.call.info(f"IPv6      : {self.vmc_obj.ipv6}"),
            mock.call.info(f"Root Query: {self.vmc_obj.root_query_info}"),
            mock.call.info(f"Manager URL: {self.vmc_obj.managers_group_url}"),
            mock.call.info(
                f"Manager Members List: {self.vmc_obj.manager_members_list}"
            ),
            mock.call.info(f"Systems Group URL: {self.vmc_obj.systems_group_url}"),
            mock.call.info(f"Systems Member URL: {self.vmc_obj.systems_member_url}"),
            mock.call.info(f"Systems Members: {self.vmc_obj.systems_members}"),
            mock.call.info(
                f"Systems Members List: {self.vmc_obj.systems_members_list}"
            ),
            mock.call.info(f"Power State: {self.vmc_obj.power_state}"),
            mock.call.info(f"Reset Actions: {self.vmc_obj.reset_action_dict}"),
            mock.call.info(f"Reset Command URL: {self.vmc_obj.reset_command_url}"),
            mock.call.info(f"Boot Control Dict: {self.vmc_obj.boot_control_dict}"),
            mock.call.info(f"VM Members Array: {self.vmc_obj.vm_members_array}"),
            mock.call.info(f"VM Group URL: {self.vmc_obj.vm_group_url}"),
            mock.call.info(f"VM Group: {self.vmc_obj.vm_group}"),
            mock.call.info(f"VM URL: {self.vmc_obj.vm_url}"),
            mock.call.info(f"VM URL List: {self.vmc_obj.vm_url_list}"),
            mock.call.info(f"VM Media Types: {self.vmc_obj.vm_media_types}"),
            mock.call.info(f"Last Response raw: {self.vmc_obj.response}"),
            mock.call.info(f"Last Response json: {self.vmc_obj.response_json}"),
        ]


class TestVmcObjectMakeRequest(BaseTestVmcObject):
    """Test class for VmcObject make_request method.

    Tests the make_request method which issues Redfish HTTP requests
    and handles responses, retries and error scenarios.
    """

    def setUp(self):
        super().setUp()

        self.mock_make_request.side_effect = self.original_make_request

        self.mock_response = mock.MagicMock()
        self.mock_response.status = 200
        self.mock_response.read = '{"key": "value"}'

        self.vmc_obj.redfish_obj.get.return_value = self.mock_response
        self.vmc_obj.redfish_obj.post.return_value = self.mock_response
        self.vmc_obj.redfish_obj.patch.return_value = self.mock_response

        self.payload = {"key": "value"}

    def _build_request_log(self, operation, path=rvmc.REDFISH_ROOT_PATH, payload=None):
        """Build request log"""

        log = f"Request     : {operation} {path}\nHeaders     : {operation} : "

        if operation == rvmc.GET:
            log += str(rvmc.GET_HEADERS)
        elif operation == rvmc.POST:
            log += f"{rvmc.POST_HEADERS}\nPayload     : {payload}"
        elif operation == rvmc.PATCH:
            log += f"{rvmc.PATCH_HEADERS}\nPayload     : {payload}"
        else:
            log = f"Request     : {operation} {path}"

        return mock.call.debug(log)

    def _build_success_log(self, operation, path=rvmc.REDFISH_ROOT_PATH):
        """Build success log"""

        return mock.call.debug(
            f"HTTP Status : {operation} {path} Ok (200) (took 0 seconds)"
        )

    def _build_error_response_log(self, operation, path=rvmc.REDFISH_ROOT_PATH):
        """Build error response log"""

        return mock.call.error(
            f"Got an error response for: \nRequest     : {operation} {path}\n"
            f"Headers     : {operation} : {rvmc.PATCH_HEADERS}"
        )

    def _assert_mock_logger_calls(self, expected_calls):

        calls = [
            mock.call.debug(f"Target      : {self.vmc_obj.target}"),
            mock.call.debug(f"BMC IP      : {self.vmc_obj.ip}"),
            mock.call.debug(f"Username    : {self.vmc_obj.un}"),
            mock.call.debug(f"Password    : {self.vmc_obj.pw_encoded}"),
            mock.call.debug(f"Image       : {self.vmc_obj.img}"),
        ]
        calls.extend(expected_calls)

        super()._assert_mock_logger_calls(calls)

    def test_make_request_get_operation_returns_true(self):
        """Test make_request's successful GET operation returns True"""

        result = self.vmc_obj.make_request(operation=rvmc.GET)

        self.assertTrue(result)
        self.vmc_obj.redfish_obj.get.assert_called_once_with(
            rvmc.REDFISH_ROOT_PATH, headers=rvmc.GET_HEADERS
        )
        self._assert_mock_logger_calls(
            [self._build_request_log(rvmc.GET), self._build_success_log(rvmc.GET)]
        )

    def test_make_request_get_operation_with_status_204_returns_true(self):
        """Test make_request GET operation with 204 status returns True"""

        self.mock_response.status = 204
        self.vmc_obj.redfish_obj.get.return_value = self.mock_response

        result = self.vmc_obj.make_request(operation=rvmc.GET)

        self.assertTrue(result)
        self.assertEqual(self.vmc_obj.response, "")

    def test_make_request_post_operation_returns_true(self):
        """Test make_request's successful POST operation returns True"""

        result = self.vmc_obj.make_request(operation=rvmc.POST, payload=self.payload)

        self.assertTrue(result)
        self.vmc_obj.redfish_obj.post.assert_called_once_with(
            rvmc.REDFISH_ROOT_PATH, body=self.payload, headers=rvmc.POST_HEADERS
        )
        self._assert_mock_logger_calls(
            [
                self._build_request_log(rvmc.POST, payload=self.payload),
                self._build_success_log(rvmc.POST),
            ]
        )

    def test_make_request_patch_operation_returns_true(self):
        """Test make_request's successful PATCH operation returns True"""

        result = self.vmc_obj.make_request(operation=rvmc.PATCH, payload=self.payload)

        self.assertTrue(result)
        self.vmc_obj.redfish_obj.patch.assert_called_once_with(
            rvmc.REDFISH_ROOT_PATH, body=self.payload, headers=rvmc.PATCH_HEADERS
        )
        self._assert_mock_logger_calls(
            [
                self._build_request_log(rvmc.PATCH, payload=self.payload),
                self._build_success_log(rvmc.PATCH),
            ]
        )

    def test_make_request_unsupported_operation_returns_false(self):
        """Test make_request's unsupported operation returns False"""

        result = self.vmc_obj.make_request(operation="INVALID")

        self.assertFalse(result)
        self._assert_mock_logger_calls(
            [
                self._build_request_log("INVALID"),
                mock.call.error("Unsupported operation: INVALID"),
            ]
        )

    def test_make_request_returns_false_when_exception_occurs_during_request(self):
        """Test make_request returns False when exception occurs during request"""

        self.vmc_obj.redfish_obj.get.side_effect = Exception("Connection error")

        result = self.vmc_obj.make_request(operation=rvmc.GET)

        self.assertFalse(result)
        self._assert_mock_logger_calls(
            [
                mock.call.error(
                    f"Failed operation on '{rvmc.REDFISH_ROOT_PATH}' (Connection error)"
                ),
                mock.call.error(f"No response from GET:{rvmc.REDFISH_ROOT_PATH}"),
            ]
        )

    def test_make_request_uses_custom_path_when_provided(self):
        """Test make_request uses custom path when provided"""

        custom_path = "/custom/path"

        result = self.vmc_obj.make_request(operation=rvmc.GET, path=custom_path)

        self.assertTrue(result)
        self.vmc_obj.redfish_obj.get.assert_called_once_with(
            custom_path, headers=rvmc.GET_HEADERS
        )
        self._assert_mock_logger_calls(
            [
                self._build_request_log(rvmc.GET, custom_path),
                self._build_success_log(rvmc.GET, custom_path),
            ]
        )

    def test_make_request_does_not_retry_on_non_transient_error(self):
        """Test make_request does not retry on non-transient error"""

        self.mock_response.status = 400
        self.mock_response.dict = {"key": "value"}
        self.vmc_obj.redfish_obj.get.return_value = self.mock_response

        self.assertRaises(
            RvmcExit, self.vmc_obj.make_request, operation=rvmc.GET, retry=0
        )

        expected_calls = [
            self._build_request_log(rvmc.GET),
            mock.call.error(
                f"HTTP Status : 400 ; GET {rvmc.REDFISH_ROOT_PATH} failed after 0 "
                'seconds\n{\n    "key": "value"\n}\n'
            ),
            self._build_error_response_log(rvmc.GET),
            mock.call.info("Stop retrying for the non-transient error (400)."),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    @mock.patch.object(rvmc, "MAX_HTTP_TRANSIENT_ERROR_RETRIES", 1)
    @mock.patch.object(rvmc, "HTTP_REQUEST_RETRY_INTERVAL", 0)
    def test_make_request_retries_on_transient_error(self):
        """Test make_request retries on transient error (status >= 500)"""

        self.mock_response.status = 500
        self.mock_response.dict = {"key": "value"}
        self.vmc_obj.redfish_obj.get.return_value = self.mock_response

        self.assertRaises(
            RvmcExit, self.vmc_obj.make_request, operation=rvmc.GET, retry=0
        )
        expected_calls = [
            self._build_request_log(rvmc.GET),
            mock.call.error(
                f"HTTP Status : 500 ; GET {rvmc.REDFISH_ROOT_PATH} failed after 0 "
                'seconds\n{\n    "key": "value"\n}\n'
            ),
            self._build_error_response_log(rvmc.GET),
            mock.call.info("Make request: retry (1 of 1) in 0 secs."),
        ]

        # The request is performed twice due to the retry, so the logs repeat with
        # exception of the last information.
        for i in range(len(expected_calls) - 1):
            expected_calls.append(expected_calls[i])

        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_make_request_returns_false_when_resp_dict_is_empty(self):
        """Test make_request returns False when resp_dict is empty"""

        self.mock_response.read = None
        self.vmc_obj.redfish_obj.get.return_value = self.mock_response

        result = self.vmc_obj.make_request(operation=rvmc.GET)

        self.assertFalse(result)
        expected_calls = [
            self._build_request_log(rvmc.GET),
            self._build_success_log(rvmc.GET),
            mock.call.error("No response from last command"),
        ]
        self._assert_mock_logger_calls(expected_calls)

    def test_make_request_returns_false_when_resp_dict_raises_exception(self):
        """Test make_request returns False when resp_dict raises exception"""

        self.mock_response.read = "not a json"
        self.vmc_obj.redfish_obj.get.return_value = self.mock_response

        result = self.vmc_obj.make_request(operation=rvmc.GET)

        self.assertFalse(result)
        expected_calls = [
            self._build_request_log(rvmc.GET),
            self._build_success_log(rvmc.GET),
            mock.call.error(
                "Got exception key valuing response ; (Expecting value: line 1 column "
                "1 (char 0))"
            ),
            mock.call.error("Response: not a json"),
        ]
        self._assert_mock_logger_calls(expected_calls)


class TestVmcObjectCheckImageUrl(BaseTestVmcObject):
    """Test class for VmcObject check_image_url method.

    Tests the check_image_url method which validates image URL accessibility
    by sending HEAD requests and checking response status codes.
    """

    def setUp(self):
        super().setUp()

        self.mock_requests_head = self._mock_object(rvmc.requests, "head")
        self.mock_response = mock.MagicMock()
        self.mock_response.status_code = 200
        self.mock_response.headers = {rvmc.CONTENT_TYPE: "application/octet-stream"}
        self.mock_requests_head.return_value = self.mock_response
        self.test_url = "http://example.com/image.iso"

    def test_check_image_url_returns_true_for_success_status_codes(self):
        """Test check_image_url returns True for HTTP 200, 202, 204 status codes"""

        for status_code in [200, 202, 204]:
            self.mock_response.status_code = status_code
            self.mock_logger.reset_mock()
            self.mock_requests_head.reset_mock()

            result = self.vmc_obj.check_image_url(self.test_url)

            self.assertTrue(result)
            self.mock_requests_head.assert_called_once_with(
                self.test_url, timeout=10, verify=False
            )
            self.mock_logger.info.assert_called_once_with(
                f"Image URL is accessible: {self.test_url} "
                f"({rvmc.CONTENT_TYPE}=application/octet-stream {status_code})"
            )

    def test_check_image_url_returns_false_for_error_status_codes(self):
        """Test check_image_url returns False for HTTP error status codes"""

        for status_code in [404, 500]:
            self.mock_response.status_code = status_code
            self.mock_logger.reset_mock()

            result = self.vmc_obj.check_image_url(self.test_url)

            self.assertFalse(result)
            self.mock_logger.error.assert_called_once_with(
                f"Checking image failed: HTTP Status {status_code}"
            )

    def test_check_image_url_handles_missing_content_type_header(self):
        """Test check_image_url handles missing Content-Type header"""

        self.mock_response.headers = {}

        result = self.vmc_obj.check_image_url(self.test_url)

        self.assertTrue(result)
        self.mock_logger.info.assert_called_once_with(
            f"Image URL is accessible: {self.test_url} ({rvmc.CONTENT_TYPE}= 200)"
        )

    def test_check_image_url_returns_false_on_exception(self):
        """Test check_image_url returns False on exception"""

        self.mock_requests_head.side_effect = rvmc.requests.exceptions.ConnectionError(
            "Connection refused"
        )

        result = self.vmc_obj.check_image_url(self.test_url)

        self.assertFalse(result)
        self.mock_logger.error.assert_called_once_with(
            "Checking image failed: Connection refused"
        )


class TestVmcObjectExit(BaseTestVmcObject):
    """Test class for VmcObject _exit method.

    Tests the _exit method which handles cleanup operations including
    closing Redfish sessions, dumping debug information and calling
    the exit handler with appropriate exit codes.
    """

    def setUp(self):
        super().setUp()

        self.vmc_obj.session = True

    def test_exit_with_no_session_calls_dump_and_exit_handler(self):
        """Test _exit calls dump and exit handler when no session or redfish object"""

        scenarios = [
            {"session": False, "redfish_obj": None},
            {"session": False, "redfish_obj": self.vmc_obj.redfish_obj},
            {"session": True, "redfish_obj": None},
        ]

        for scenario in scenarios:
            self.vmc_obj.session = scenario["session"]
            self.vmc_obj.redfish_obj = scenario["redfish_obj"]

            self.mock_logger.reset_mock()

            self.assertRaises(RvmcExit, self.vmc_obj._exit, 1)

            self._assert_mock_logger_calls(self._generate_log_dump())

    def test_exit_with_active_session_performs_logout(self):
        """Test _exit performs logout when session is active"""

        self.assertRaises(RvmcExit, self.vmc_obj._exit, 1)

        self.assertIsNone(self.vmc_obj.redfish_obj)
        self.assertFalse(self.vmc_obj.session)

        expected_calls = [
            mock.call.info("Session     : Closed"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_exit_handles_logout_exception(self):
        """Test _exit handles exceptions during logout gracefully"""

        self.vmc_obj.redfish_obj.logout.side_effect = Exception("Logout failed")

        self.vmc_obj._exit(0)

        self.vmc_obj.redfish_obj.logout.assert_called_once()
        # When the exit code is 0, there is no dump logs
        expected_calls = [
            mock.call.error("Session close failed ; Logout failed"),
            mock.call.info("Check BMC username and password in config file"),
        ]
        self._assert_mock_logger_calls(expected_calls)


class TestVmcObjectRedfishClientConnect(BaseTestVmcObject):
    """Test class for VmcObject _redfish_client_connect method.

    Tests the _redfish_client_connect method which establishes connection
    to the target Redfish service by verifying ping response and creating
    a Redfish client object.
    """

    def setUp(self):
        super().setUp()

        self.mock_os_system = self._mock_object(rvmc.os, "system", return_value=0)
        self.mock_redfish_client = self._mock_object(
            rvmc.redfish, "redfish_client", return_value=mock.MagicMock()
        )

    def test_redfish_client_connect_succeeds_with_ipv4_on_first_ping(self):
        """Test _redfish_client_connect succeeds with IPv4 on first ping"""

        self.vmc_obj._redfish_client_connect()

        self.mock_os_system.assert_called_once_with(
            f"ping -c 1 {self.vmc_obj.ip} > /dev/null 2>&1"
        )
        self.mock_redfish_client.assert_called_once_with(
            base_url=self.vmc_obj.uri,
            username=self.vmc_obj.un,
            password=self.vmc_obj.pw,
            default_prefix=rvmc.REDFISH_ROOT_PATH,
        )
        self._assert_mock_logger_calls(
            [
                mock.call.info("Redfish Client Connection"),
                mock.call.info(f"BMC Ping Ok : {self.vmc_obj.ip} (0)"),
            ]
        )

    def test_redfish_client_connect_succeeds_with_ipv6(self):
        """Test _redfish_client_connect succeeds with IPv6

        This test also ensures the execution completes successfully in case the initial
        ping or redfish_client call fail.
        """

        self.vmc_obj.ipv6 = True
        self.vmc_obj.ip = "[2001:db8::1]"
        self.mock_os_system.side_effect = [1, 0]
        self.mock_redfish_client.side_effect = [
            None,
            True,
        ]

        self.vmc_obj._redfish_client_connect()

        self.mock_os_system.assert_called_with(
            f"ping -6 -c 1 {self.vmc_obj.ip[1:-1]} > /dev/null 2>&1"
        )
        self.assertEqual(self.mock_os_system.call_count, 2)
        self.assertEqual(self.mock_redfish_client.call_count, 2)
        self.assertEqual(self.mock_time_sleep.call_count, 2)
        self._assert_mock_logger_calls(
            [
                mock.call.info("Redfish Client Connection"),
                mock.call.info("BMC Ping     : retry (1 of 10)"),
                mock.call.info(f"BMC Ping Ok : {self.vmc_obj.ip} (1)"),
                mock.call.warning(
                    f"Unable to establish Redfish Client Connection to BMC at "
                    f"{self.vmc_obj.uri}. Retry (1/2) in 15 secs."
                ),
            ]
        )

    def test_redfish_client_connect_exits_when_ping_fails_max_times(self):
        """Test _redfish_client_connect exits when ping fails max times"""

        self.mock_os_system.return_value = 1

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_client_connect)

        self.assertEqual(self.mock_os_system.call_count, 10)
        expected_calls = [
            mock.call.info("Redfish Client Connection"),
            mock.call.info("BMC Ping     : retry (1 of 10)"),
            mock.call.info("BMC Ping     : retry (2 of 10)"),
            mock.call.info("BMC Ping     : retry (3 of 10)"),
            mock.call.info("BMC Ping     : retry (4 of 10)"),
            mock.call.info("BMC Ping     : retry (5 of 10)"),
            mock.call.info("BMC Ping     : retry (6 of 10)"),
            mock.call.info("BMC Ping     : retry (7 of 10)"),
            mock.call.info("BMC Ping     : retry (8 of 10)"),
            mock.call.info("BMC Ping     : retry (9 of 10)"),
            mock.call.info("BMC Ping     : retry (10 of 10)"),
            mock.call.error(f"Unable to ping '{self.vmc_obj.ip}' (10)"),
            mock.call.info("Check BMC ip address is pingable"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_client_connect_exits_after_max_connection_attempts(self):
        """Test _redfish_client_connect exits after max connection attempts"""

        self.mock_redfish_client.side_effect = [
            None,
            Exception("Connection error"),
            Exception("Connection error"),
        ]

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_client_connect)

        self.assertEqual(self.mock_redfish_client.call_count, 3)
        self.assertEqual(self.mock_time_sleep.call_count, 2)
        expected_calls = [
            mock.call.info("Redfish Client Connection"),
            mock.call.info(f"BMC Ping Ok : {self.vmc_obj.ip} (0)"),
            mock.call.warning(
                f"Unable to establish Redfish Client Connection to BMC at "
                f"{self.vmc_obj.uri}. Retry (1/2) in 15 secs."
            ),
            mock.call.warning(
                f"Unable to establish Redfish Client Connection to BMC at "
                f"{self.vmc_obj.uri}. Retry (2/2) in 15 secs. (Connection error)"
            ),
            mock.call.error(
                "Unable to establish Redfish Client Connection to BMC at "
                f"{self.vmc_obj.uri}."
            ),
            mock.call.info("Check BMC ip address is pingable and supports Redfish"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)


class TestVmcObjectRedfishRootQuery(BaseTestVmcObject):
    """Test class for VmcObject _redfish_root_query method.

    Tests the _redfish_root_query method which performs the Redfish root
    query to retrieve Systems and Managers URLs from the BMC.
    """

    def test_redfish_root_query_succeeds_and_extracts_urls(self):
        """Test _redfish_root_query succeeds and extracts Systems and Managers URLs"""

        self.vmc_obj.response_json = self.vmc_obj.response_dict

        self.vmc_obj._redfish_root_query()

        self.mock_make_request.assert_called_once_with(operation=rvmc.GET, path=None)
        self.assertEqual(self.vmc_obj.root_query_info, self.vmc_obj.response_json)
        self.assertEqual(self.vmc_obj.systems_group_url, self.systems_url)
        self.assertEqual(self.vmc_obj.managers_group_url, self.managers_url)
        self.mock_logger.info.assert_called_once_with("Root Query")

    def test_redfish_root_query_exits_when_make_request_fails(self):
        """Test _redfish_root_query exits when make_request fails"""

        self.mock_make_request.return_value = False

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_root_query)

        expected_calls = [
            mock.call.info("Root Query"),
            mock.call.error(f"Failed {self.vmc_obj.url} GET request"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_root_query_does_not_set_root_query(self):
        """Test _redfish_root_query does not set root_query_info"""

        self.vmc_obj.response_json = None

        self.vmc_obj._redfish_root_query()

        self.assertIsNone(self.vmc_obj.root_query_info)
        self.mock_logger.info.assert_called_once_with("Root Query")


class TestVmcObjectRedfishCreateSession(BaseTestVmcObject):
    """Test class for VmcObject _redfish_create_session method.

    Tests the _redfish_create_session method which creates a Redfish
    communication session by logging into the BMC with retry logic.
    """

    def test_redfish_create_session_succeeds_on_first_attempt(self):
        """Test _redfish_create_session succeeds on first login attempt"""

        self.vmc_obj._redfish_create_session()

        self.vmc_obj.redfish_obj.login.assert_called_once_with(auth="session")
        self.assertTrue(self.vmc_obj.session)
        self._assert_mock_logger_calls(
            [
                mock.call.info("Create Communication Session"),
                mock.call.debug("Session     : Open"),
            ]
        )

    def test_redfish_create_session_exits_on_invalid_credentials(self):
        """Test _redfish_create_session exits on invalid credentials"""

        self.vmc_obj.redfish_obj.login.side_effect = rvmc.InvalidCredentialsError()

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_create_session)

        expected_calls = [
            mock.call.info("Create Communication Session"),
            mock.call.error("Failed to Create session due to invalid credentials."),
            mock.call.info("Check BMC username and password in config file"),
        ]
        expected_calls.extend(self._generate_log_dump(2))
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_create_session_exits_after_max_retries(self):
        """Test _redfish_create_session exits after max retry attempts"""

        self.vmc_obj.redfish_obj.login.side_effect = Exception("Connection failed")

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_create_session)

        self.assertEqual(self.vmc_obj.redfish_obj.login.call_count, 3)
        self.assertEqual(self.mock_time_sleep.call_count, 2)
        expected_calls = [
            mock.call.info("Create Communication Session"),
            mock.call.warning(
                "Failed to Create session ; Connection failed. Retry (1/2) in 15 secs."
            ),
            mock.call.warning(
                "Failed to Create session ; Connection failed. Retry (2/2) in 15 secs."
            ),
            mock.call.error("Failed to Create session ; Connection failed."),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)


class TestVmcObjectRedfishGetManagers(BaseTestVmcObject):
    """Test class for VmcObject _redfish_get_managers method.

    Tests the _redfish_get_managers method which queries Redfish Managers
    to retrieve the Managers URL and Members list from the BMC.
    """

    def test_redfish_get_managers_succeeds_and_retrieves_members(self):
        """Test _redfish_get_managers succeeds and retrieves manager members"""

        self.vmc_obj._redfish_get_managers()

        self.assertEqual(self.vmc_obj.managers_group_url, self.managers_url)
        self.assertEqual(self.vmc_obj.manager_members_list, self.members_list)
        self.mock_make_request.assert_called_once_with(
            operation=rvmc.GET, path=self.managers_url
        )
        self.mock_logger.info.assert_called_once_with("Get Managers")

    def test_redfish_get_managers_exits_when_managers_url_is_none(self):
        """Test _redfish_get_managers exits when managers_group_url is None"""

        self.vmc_obj.response_dict["Managers"] = {"@odata.id": None}

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_managers)

        expected_calls = [
            mock.call.info("Get Managers"),
            mock.call.error("Failed to learn BMC RedFish Managers link"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_get_managers_exits_when_make_request_fails(self):
        """Test _redfish_get_managers exits when make_request fails"""

        self.mock_make_request.return_value = False

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_managers)

        expected_calls = [
            mock.call.info("Get Managers"),
            mock.call.error(f"Failed GET Managers from {self.managers_url}"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)


class TestVmcObjectRedfishGetSystemsMembers(BaseTestVmcObject):
    """Test class for VmcObject _redfish_get_systems_members method.

    Tests the _redfish_get_systems_members method which queries the Systems
    group URL to retrieve the list of Systems Members from the BMC.
    """

    def test_redfish_get_systems_members_succeeds_and_retrieves_members(self):
        """Test _redfish_get_systems_members succeeds and retrieves systems members"""

        self.vmc_obj._redfish_get_systems_members()

        self.mock_make_request.assert_called_once_with(
            operation=rvmc.GET, path=self.systems_url
        )
        self.assertEqual(self.vmc_obj.systems_members_list, self.members_list)
        self.assertEqual(self.vmc_obj.systems_members, 1)
        self._assert_mock_logger_calls(
            [
                mock.call.info("Get Systems"),
                mock.call.debug(f"Systems Members List: {self.members_list}"),
            ]
        )

    def test_redfish_get_systems_members_exits_when_make_request_fails(self):
        """Test _redfish_get_systems_members exits when make_request fails"""

        self.mock_make_request.return_value = False

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_systems_members)

        expected_calls = [
            mock.call.info("Get Systems"),
            mock.call.error(f"Unable to Get Systems Members from {self.systems_url}"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_get_systems_members_exits_when_members_list_is_none(self):
        """Test _redfish_get_systems_members exits when Members list is None"""

        self.vmc_obj.response_dict = {"Members": None}

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_systems_members)

        expected_calls = [
            mock.call.info("Get Systems"),
            mock.call.debug("Systems Members List: None"),
            mock.call.error(
                f"Systems Members URL GET Response\n{self.vmc_obj.response_json}"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_get_systems_members_exits_when_members_list_is_empty(self):
        """Test _redfish_get_systems_members exits when Members list is empty"""

        self.vmc_obj.response_dict = {"Members": []}

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_systems_members)

        expected_calls = [
            mock.call.info("Get Systems"),
            mock.call.debug("Systems Members List: []"),
            mock.call.error(
                f"BMC not publishing any System Members:\n{self.vmc_obj.response_json}"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)


class TestVmcObjectRedfishPowerctlHost(BaseTestVmcObject):
    """Test class for VmcObject _redfish_powerctl_host method.

    Tests the _redfish_powerctl_host method which powers on or off the host
    by issuing reset commands and optionally verifying the power state.
    """

    def test_redfish_powerctl_host_when_already_in_requested_state(self):
        """Test _redfish_powerctl_host when already in requested state"""

        self.vmc_obj.power_state = rvmc.POWER_ON

        self.vmc_obj._redfish_powerctl_host(rvmc.POWER_ON)

        self.mock_make_request.assert_not_called()
        self.mock_logger.info.assert_called_once_with(f"Power {rvmc.POWER_ON} Host")

    def test_redfish_powerctl_host_exits_with_empty_and_none_systems_members_list(self):
        """Test _redfish_powerctl_host exits with empty and none systems members list"""

        for systems_members_list in [[{}], [{"@odata.id": None}]]:
            self.vmc_obj.systems_members_list = systems_members_list

            self.assertRaises(
                RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON
            )

            expected_calls = [
                mock.call.info("Power On Host"),
                mock.call.error(
                    f"Unable to get Redfish Systems Actions Member URL:\n"
                    f"{self.vmc_obj.response_json}\n"
                ),
            ]
            expected_calls.extend(self._generate_log_dump())
            self._assert_mock_logger_calls(expected_calls)

            self.mock_logger.reset_mock()

    def test_redfish_powerctl_host_exits_when_make_request_fails(self):
        """Test _redfish_powerctl_host exits when make_request fails"""

        self.mock_make_request.return_value = False

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON)

        expected_calls = [
            mock.call.info("Power On Host"),
            mock.call.error(
                "Unable to get Redfish Systems Actions Member from "
                f"{self.systems_members_url}"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_powerctl_host_exits_when_reset_action_dict_is_none(self):
        """Test _redfish_powerctl_host exits when reset action dict is None"""

        self.vmc_obj.response_dict = {"Actions": {}}

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON)

        expected_calls = [
            mock.call.info("Power On Host"),
            mock.call.debug(
                f"No #ComputerSystem.Reset actions from {self.systems_members_url}. "
                "Try other URL."
            ),
            mock.call.error(
                f"BMC not publishing Systems Reset Action Dictionary:\n"
                f"{self.vmc_obj.response_json}\n"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_powerctl_host_exits_when_reset_command_url_is_none(self):
        """Test _redfish_powerctl_host exits when reset command url is None"""

        del self.vmc_obj.response_dict["Actions"]["#ComputerSystem.Reset"]["target"]

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON)

        expected_calls = [
            mock.call.info("Power On Host"),
            mock.call.error(
                f"Unable to get Reset Command URL (members:{len(self.members_list)})\n"
                f"{self.vmc_obj.response_dict['Actions']['#ComputerSystem.Reset']}"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_powerctl_host_exits_when_reset_command_list_is_none(self):
        """Test _redfish_powerctl_host exits when reset command list is none"""

        del self.vmc_obj.response_dict["Actions"]["#ComputerSystem.Reset"][
            "ResetType@Redfish.AllowableValues"
        ]

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON)

        expected_calls = [
            mock.call.info("Power On Host"),
            mock.call.error("BMC is not publishing any Allowable Reset Actions"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_powerctl_host_exits_with_invalid_reset_command_list(self):
        """Test _redfish_powerctl_host exits with invalid reset command list"""

        reset_command_list = ["Nmi"]
        self.vmc_obj.response_dict["Actions"]["#ComputerSystem.Reset"][
            "ResetType@Redfish.AllowableValues"
        ] = reset_command_list

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON)

        expected_calls = [
            mock.call.info("Power On Host"),
            mock.call.info(f"ResetActions: {reset_command_list}"),
            mock.call.error(
                f"Failed to find acceptable Power {rvmc.POWER_ON} command in:\n"
                f"{reset_command_list}"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_powerctl_host_exits_when_post_request_fails(self):
        """Test _redfish_powerctl_host exits when POST request fails"""

        self.mock_make_request.side_effect = [True, False]

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON)

        expected_calls = [
            mock.call.info(f"Power {rvmc.POWER_ON} Host"),
            mock.call.info(f"ResetActions: {self.reset_command_list}"),
            mock.call.info("Selected Command: ForceOn"),
            mock.call.error(f"Failed to Power {rvmc.POWER_ON} Host"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_powerctl_host_skips_verification_when_verify_is_false(self):
        """Test _redfish_powerctl_host skips verification when verify is False"""

        self.vmc_obj._redfish_powerctl_host(rvmc.POWER_ON, verify=False)

        expected_calls = [
            mock.call(operation=rvmc.GET, path=self.systems_members_url, retry=0),
            mock.call(
                operation=rvmc.POST,
                payload={"ResetType": "ForceOn"},
                path=self.vmc_obj.response_dict["Actions"]["#ComputerSystem.Reset"][
                    "target"
                ],
            ),
        ]
        self.mock_make_request.assert_has_calls(expected_calls)

    # The time argument is ignored to avoid having a longer slepp
    def _reduced_sleep(self, _):
        self.original_time_sleep(1)

    @mock.patch.dict(rvmc.os.environ, {"RVMC_POWER_ACTION_TIMEOUT": "1"})
    def test_redfish_powerctl_host_exits_when_verification_timeout(self):
        """Test _redfish_powerctl_host exits when verification timeout"""

        self.mock_time_sleep.side_effect = self._reduced_sleep

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON)

        expected_calls = [
            mock.call.info("Power On Host"),
            mock.call.info(f"ResetActions: {self.reset_command_list}"),
            mock.call.info("Selected Command: ForceOn"),
            mock.call.info("Power On Host timeout is 1 seconds"),
            mock.call.debug("Waiting for Power On (currently Off) (1 secs)"),
            mock.call.error(
                f"Failed to Set System Power State to On after 1 secs "
                f"({self.systems_members_url})"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    @mock.patch.dict(rvmc.os.environ, {"RVMC_POWER_ACTION_TIMEOUT": "1"})
    def test_redfish_powerctl_host_handles_get_failure_during_verification(self):
        """Test _redfish_powerctl_host handles GET failure during verification"""

        self.mock_time_sleep.side_effect = self._reduced_sleep

        self.mock_make_request.side_effect = [True, True, False, False]

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_powerctl_host, rvmc.POWER_ON)
        expected_calls = [
            mock.call.info("Power On Host"),
            mock.call.info(f"ResetActions: {self.reset_command_list}"),
            mock.call.info("Selected Command: ForceOn"),
            mock.call.info("Power On Host timeout is 1 seconds"),
            mock.call.error("Failed to Get System State (after 1 secs)"),
            mock.call.error(
                f"Failed to Set System Power State to On after 1 secs "
                f"({self.systems_members_url})"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_redfish_powerctl_host_returns_without_verification_for_restart(self):
        """Test _redfish_powerctl_host returns without verification for restart"""

        self.vmc_obj._redfish_powerctl_host("Restart")

        expected_calls = [
            mock.call(operation=rvmc.GET, path=self.systems_members_url, retry=0),
            mock.call(
                operation=rvmc.POST,
                payload={"ResetType": "ForceRestart"},
                path=self.reset_command_url,
            ),
        ]
        self.mock_make_request.assert_has_calls(expected_calls)

    def test_redfish_powerctl_host_powers_on_and_off_host_successfully(self):
        """Test _redfish_powerctl_host powers on and off host successfully"""

        for power_state in [rvmc.POWER_ON, rvmc.POWER_OFF]:
            if power_state == rvmc.POWER_OFF:
                self.vmc_obj.response_dict["PowerState"] = rvmc.POWER_ON
                self.vmc_obj.power_state = rvmc.POWER_ON

            self.vmc_obj._redfish_powerctl_host(power_state, verify=False)

            self._assert_mock_logger_calls(
                [
                    mock.call.info(f"Power {power_state} Host"),
                    mock.call.info(f"ResetActions: {self.reset_command_list}"),
                    mock.call.info(f"Selected Command: Force{power_state}"),
                ]
            )
            expected_calls = [
                mock.call(operation=rvmc.GET, path=self.systems_members_url, retry=0),
                mock.call(
                    operation=rvmc.POST,
                    payload={"ResetType": f"Force{power_state}"},
                    path=self.reset_command_url,
                ),
            ]
            self.mock_make_request.assert_has_calls(expected_calls)

            self.mock_make_request.reset_mock()
            self.mock_logger.reset_mock()


class TestVmcObjectRedfishGetVmUrl(BaseTestVmcObject):
    """Test class for VmcObject _redfish_get_vm_url method.

    Tests the _redfish_get_vm_url method which discovers CD/DVD Virtual Media
    URLs by iterating through Systems and Managers members, querying their
    VirtualMedia groups, and identifying supported media devices.
    """

    def setUp(self):
        super().setUp()

        # Reset the value as it would conflict with the one in BaseTestVmcObject
        self.vmc_obj.response_dict["Members"] = [{"@odata.id": self.vm_member_url}]

    def test_get_vm_url_continues_when_both_members_lists_are_none(self):
        """Test _redfish_get_vm_url continues when both members lists are None"""

        self.vmc_obj.systems_members_list = None
        self.vmc_obj.manager_members_list = None

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

        self.mock_make_request.assert_not_called()
        expected_calls = [
            mock.call.info("Get CD/DVD Virtual Media"),
            mock.call.debug("Members: []"),
            mock.call.error("Failed to find CD or DVD Virtual media type"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_get_vm_url_continues_when_member_is_empty_or_has_no_odata_id(self):
        """Test _redfish_get_vm_url continues when member is empty or has no odata.id"""

        self.vmc_obj.systems_members_list = [{}]
        self.vmc_obj.manager_members_list = [{"odata.id": None}]
        members = []
        members.extend(self.vmc_obj.systems_members_list)
        members.extend(self.vmc_obj.manager_members_list)

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

        self.mock_make_request.assert_not_called()
        expected_calls = [
            mock.call.info("Get CD/DVD Virtual Media"),
            mock.call.debug(f"Members: {members}"),
            mock.call.error("Failed to find CD or DVD Virtual media type"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_get_vm_url_exits_when_member_make_request_fails(self):
        """Test _redfish_get_vm_url exits when make_request fails for a member"""

        self.vmc_obj.systems_members_list = None
        self.mock_make_request.return_value = False

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

        expected_calls = [
            mock.call.info("Get CD/DVD Virtual Media"),
            mock.call.debug(f"Members: {self.members_list}"),
            mock.call.error(
                f"Unable to get Member from {self.members_list[0].get('@odata.id')}"
            ),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_get_vm_url_exits_when_vm_group_get_odata_id_raises_exception(self):
        """Test _redfish_get_vm_url exits when vm_group.get raises exception"""

        self.vmc_obj.response_dict["VirtualMedia"] = ""

        self.vmc_obj.manager_members_list = None

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

        expected_calls = [
            mock.call.info("Get CD/DVD Virtual Media"),
            mock.call.debug(f"Members: {self.vmc_obj.systems_members_list}"),
            mock.call.debug(
                f"Systems Data from {self.vmc_obj.systems_members_list[0]}\nNone\n"
            ),
            mock.call.info(f"Server Model: {self.vmc_obj.response_dict['Model']}"),
            mock.call.error("Unable to get Virtual Media Group from None"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_get_vm_url_continues_when_vm_group_is_none(self):
        """Test _redfish_get_vm_url continues when vm_group is none"""

        self.vmc_obj.model = "Test"
        del self.vmc_obj.response_dict["VirtualMedia"]

        members = []
        members.extend(self.vmc_obj.systems_members_list)
        members.extend(self.vmc_obj.manager_members_list)

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

        expected_calls = [
            mock.call.info("Get CD/DVD Virtual Media"),
            mock.call.debug(f"Members: {members}"),
            mock.call.debug("Virtual Media not supported by member 0"),
            mock.call.warning(f"Virtual Media not supported by {self.managers_url}/1/"),
            mock.call.error("Failed to find CD or DVD Virtual media type"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_get_vm_url_continues_when_make_request_to_vm_group_url_fails(self):
        """Test _get_vm_url continues when make_request to vm_group_url fails"""

        self.vmc_obj.model = "Test"
        self.vmc_obj.manager_members_list = None

        requests = [
            (
                [True, False],
                [
                    mock.call.error(
                        "Failed to GET Virtual Media Service group from "
                        f"{self.vm_group_url}"
                    )
                ],
            ),
            (
                [True, True, False],
                [
                    mock.call.debug(f"Full vm_url.list ['{self.vm_member_url}'] "),
                    mock.call.error(
                        "Failed to GET Virtual Media Service group from "
                        f"{self.vm_member_url}"
                    ),
                ],
            ),
        ]

        for request, mock_assertions in requests:
            self.mock_make_request.side_effect = request

            self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

            expected_calls = [
                mock.call.info("Get CD/DVD Virtual Media"),
                mock.call.debug(f"Members: {self.vmc_obj.systems_members_list}"),
            ]
            expected_calls.extend(mock_assertions)
            expected_calls.append(
                mock.call.error("Failed to find CD or DVD Virtual media type")
            )

            expected_calls.extend(self._generate_log_dump())
            self._assert_mock_logger_calls(expected_calls)
            self.mock_logger.reset_mock()

    def test_get_vm_url_exits_when_vm_members_array_is_empty(self):
        """Test _redfish_get_vm_url exits when vm_members_array is empty"""

        self.vmc_obj.response_dict["Model"] = None
        del self.vmc_obj.response_dict["Members"]
        self.vmc_obj.manager_members_list = None

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

        expected_calls = [
            mock.call.info("Get CD/DVD Virtual Media"),
            mock.call.debug(f"Members: {self.vmc_obj.systems_members_list}"),
            mock.call.debug(
                f"Systems Data from {self.vmc_obj.systems_members_list[0]}\nNone\n"
            ),
            mock.call.error(f"No Virtual Media members found at {self.vm_group_url}"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_get_vm_url_warns_when_vm_member_is_not_a_dict_or_is_missing_odata_id(self):
        """Test _redfish_get_vm_url warns when VM member is not a dict or miss odata.id

        The unit test consolidates two scenarios, which is why each needs its unique
        message validation.
        """

        self.vmc_obj.response_dict["Model"] = None
        members = [
            (["not_a_dict"], f"VM member[0] not a dict: {type('not_a_dict')}"),
            ([{"other_key": "value"}], "VM member[0] missing @odata.id"),
        ]

        for member, message in members:
            self.vmc_obj.response_dict["Members"] = member
            self.vmc_obj.manager_members_list = None

            self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

            expected_calls = [
                mock.call.info("Get CD/DVD Virtual Media"),
                mock.call.debug(f"Members: {self.vmc_obj.systems_members_list}"),
                mock.call.debug(
                    f"Systems Data from {self.vmc_obj.systems_members_list[0]}\nNone\n"
                ),
                mock.call.warning(message),
                mock.call.debug("Full vm_url.list [] "),
                mock.call.error("Failed to find CD or DVD Virtual media type"),
            ]
            expected_calls.extend(self._generate_log_dump())
            self._assert_mock_logger_calls(expected_calls)
            self.mock_logger.reset_mock()

    def test_get_vm_url_continues_when_media_types_is_none(self):
        """Test _redfish_get_vm_url continues when MediaTypes is None"""

        self.vmc_obj.response_dict["MediaTypes"] = None
        self.vmc_obj.manager_members_list = None

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

        expected_calls = [
            mock.call.info("Get CD/DVD Virtual Media"),
            mock.call.debug(f"Members: {self.vmc_obj.systems_members_list}"),
            mock.call.debug(
                f"Systems Data from {self.vmc_obj.systems_members_list[0]}\nNone\n"
            ),
            mock.call.info(f"Server Model: {self.vmc_obj.response_dict['Model']}"),
            mock.call.debug(f"Full vm_url.list ['{self.vm_member_url}'] "),
            mock.call.debug(
                f"No Virtual MediaTypes found at {self.vm_member_url} ; "
                "trying other members"
            ),
            mock.call.error("Failed to find CD or DVD Virtual media type"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_get_vm_url_continues_when_no_supported_device_is_found(self):
        """Test _redfish_get_vm_url continues when no supported device is found"""

        self.vmc_obj.manager_members_list = None
        self.vmc_obj.response_dict["MediaTypes"] = ["USB"]

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_get_vm_url)

        expected_calls = [
            mock.call.info("Get CD/DVD Virtual Media"),
            mock.call.debug(f"Members: {self.vmc_obj.systems_members_list}"),
            mock.call.debug(
                f"Systems Data from {self.vmc_obj.systems_members_list[0]}\nNone\n"
            ),
            mock.call.info(f"Server Model: {self.vmc_obj.response_dict['Model']}"),
            mock.call.debug(f"Full vm_url.list ['{self.vm_member_url}'] "),
            mock.call.debug(
                f"Virtual Media {self.vm_member_url} does not support CD/DVD ; "
                "trying other members"
            ),
            mock.call.error("Failed to find CD or DVD Virtual media type"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)

    def test_get_vm_url_succeeds_with_supported_devices(self):
        """Test _redfish_get_vm_url finds supported devices"""

        self.vmc_obj.manager_members_list = None
        self.vmc_obj.response_dict["Model"] = "PowerEdge XR8720t"
        self.vmc_obj.response_dict["MediaTypes"] = ["CD", "DVD"]

        self.vmc_obj._redfish_get_vm_url()

        self._assert_mock_logger_calls(
            [
                mock.call.info("Get CD/DVD Virtual Media"),
                mock.call.debug(f"Members: {self.vmc_obj.systems_members_list}"),
                mock.call.debug(
                    f"Systems Data from {self.vmc_obj.systems_members_list[0]}\nNone\n"
                ),
                mock.call.info(f"Server Model: {self.vmc_obj.response_dict['Model']}"),
                mock.call.debug(f"Full (sorted) vm_url.list ['{self.vm_member_url}'] "),
                mock.call.debug(
                    f"Supported Virtual Media found at {self.vm_member_url} ; "
                    f"{self.vmc_obj.response_dict['MediaTypes']}"
                ),
                mock.call.debug(f"Supported VM URLs ['{self.vm_member_url}']"),
            ]
        )


class TestVmcObjectRedfishPoweroffHost(BaseTestVmcObject):
    """Test class for VmcObject _redfish_poweroff_host method.

    Tests the _redfish_poweroff_host method which powers off the host by delegating to
    _redfish_powerctl_host with the POWER_OFF state and forwarding the verify and
    request_command parameters.
    """

    def setUp(self):
        super().setUp()

        self.mock_powerctl_host = self._mock_object(
            self.vmc_obj, "_redfish_powerctl_host"
        )

    def test_poweroff_host_delegates_parameters(self):
        """Test _redfish_poweroff_host parameters"""

        for verify, request_command in [
            (True, None),
            (False, None),
            (True, "ForceOff"),
            (False, "GracefulShutdown"),
        ]:
            self.vmc_obj._redfish_poweroff_host(verify, request_command)

            self.mock_powerctl_host.assert_called_once_with(
                rvmc.POWER_OFF, verify, request_command
            )
            self.mock_powerctl_host.reset_mock()


@mock.patch.object(rvmc, "MAX_EJECT_POLL_COUNT", 1)
@mock.patch.object(rvmc, "EJECT_POLL_DELAY_SECS", 0)
@mock.patch.object(rvmc, "MAX_EJECT_POST_RETRY_COUNT", 2)
class TestVmcObjectRedfishEjectImage(BaseTestVmcObject):
    """Test class for VmcObject _redfish_eject_image method.

    Tests the _redfish_eject_image method which ejects the currently inserted virtual
    media image by iterating through vm_url_data_list, posting eject requests and
    pooling for completion with retry logic.
    """

    def setUp(self):
        super().setUp()

        self.vm_url_data = {
            "@odata.id": self.vm_member_url,
            "Inserted": True,
            "Image": "http://example.com/image.iso",
            "Actions": {
                "#VirtualMedia.EjectMedia": {
                    "target": f"{self.vm_member_url}Actions/VirtualMedia.EjectMedia",
                }
            },
        }
        self.eject_media_url = self.vm_url_data["Actions"]["#VirtualMedia.EjectMedia"][
            "target"
        ]
        self.vmc_obj.vm_url_data_list = [self.vm_url_data]

    def test_redfish_eject_image_returns_when_vm_url_data_list_is_empty(self):
        """Test _redfish_eject_image returns when vm_url_data_list isempty"""

        self.vmc_obj.vm_url_data_list = []

        self.vmc_obj._redfish_eject_image()

        self.mock_make_request.assert_not_called()
        self._assert_mock_logger_calls(
            [
                mock.call.info("Eject Image"),
            ]
        )

    def test_redfish_eject_image_when_not_inserted(self):
        """Test _redfish_eject_image breaks when not inserted"""

        self.vm_url_data["Inserted"] = False

        for eject_all_images in [True, False]:
            self.vmc_obj.eject_all_images = eject_all_images

            self.vmc_obj._redfish_eject_image()

            self.mock_make_request.assert_not_called()
            self._assert_mock_logger_calls(
                [
                    mock.call.info("Eject Image"),
                    mock.call.info(f"No media found {self.vm_member_url}"),
                ]
            )
            self.mock_logger.reset_mock()

    def test_redfish_eject_image_continues_when_actions_key_is_missing(self):
        """Test _redfish_eject_image continues when Actions key is missing"""

        del self.vm_url_data["Actions"]

        self.vmc_obj._redfish_eject_image()

        self._assert_mock_logger_calls(
            [
                mock.call.info("Eject Image"),
                mock.call.info(f"No vm actions found {self.vm_url_data}"),
            ]
        )

    def test_redfish_eject_image_breaks_when_eject_media_label_is_missing(self):
        """Test _redfish_eject_image breaks when eject media label is missing"""

        self.vm_url_data["Actions"] = {"fake_key": "fake value"}

        self.vmc_obj._redfish_eject_image()

        self._assert_mock_logger_calls(
            [
                mock.call.info("Eject Image"),
                mock.call.debug("Eject Try 1 of 2"),
                mock.call.error(
                    f"Failed to get #VirtualMedia.EjectMedia with {self.vm_member_url}"
                ),
            ]
        )

    def test_redfish_eject_image_breaks_when_eject_target_url_is_missing(self):
        """Test _redfish_eject_image breaks when eject target url is missing"""

        self.vm_url_data["Actions"]["#VirtualMedia.EjectMedia"] = {"target": ""}

        self.vmc_obj._redfish_eject_image()

        self._assert_mock_logger_calls(
            [
                mock.call.info("Eject Image"),
                mock.call.debug("Eject Try 1 of 2"),
                mock.call.error(
                    "Failed to get eject target from "
                    f"{self.vm_url_data['Actions']['#VirtualMedia.EjectMedia']} with "
                    f"{self.vm_member_url}"
                ),
            ]
        )

    def test_redfish_eject_image_sets_skip_managers_on_systems_url_eject_all(self):
        """Test _redfish_eject_image sets skip managers on systems url eject all("""

        self.vmc_obj.eject_all_images = True

        systems_vm_data = copy.deepcopy(self.vm_url_data)
        systems_vm_data["@odata.id"] = f"{self.systems_url}/1/VirtualMedia/1/"
        self.vmc_obj.vm_url_data_list = [
            systems_vm_data,
            self.vm_url_data,
        ]

        self.vmc_obj._redfish_eject_image()

        self._assert_mock_logger_calls(
            [
                mock.call.info("Eject Image"),
                mock.call.debug("Eject Try 1 of 2"),
                mock.call.info(f"Eject Image {self.vm_url_data['Image']}"),
                mock.call.debug(f"Eject URL {self.eject_media_url}"),
                mock.call.debug(
                    f"Polling for Eject complete {systems_vm_data['@odata.id']}"
                ),
                mock.call.info(f"Ejected from {systems_vm_data['@odata.id']}"),
                mock.call.debug("Skipping Managers"),
                mock.call.debug(f"Skipping eject from {self.vm_url_data['@odata.id']}"),
            ]
        )

    def test_redfish_eject_image_logs_eject_request_failure_and_continues_to_poll(self):
        """Test _redfish_eject_image logs eject request failure and continues to poll"""

        self.vmc_obj.response_dict["Inserted"] = True
        self.vmc_obj.response_dict["Image"] = self.vm_url_data["Image"]

        self.mock_make_request.side_effect = [False, True, False, False]
        del self.vm_url_data["Image"]

        self.assertRaises(RvmcExit, self.vmc_obj._redfish_eject_image)

        expected_calls = [
            mock.call.info("Eject Image"),
            mock.call.debug("Eject Try 1 of 2"),
            mock.call.error(f"Eject request failed {self.eject_media_url}"),
            mock.call.debug(
                f"Polling for Eject complete {self.vm_url_data['@odata.id']}"
            ),
            mock.call.debug(
                f"Eject Wait ; Image Present  ; {self.vmc_obj.response_dict['Image']}"
            ),
            mock.call.error(
                f"Eject Image try 1 timeout on {self.vm_url_data['@odata.id']}"
            ),
            mock.call.debug("Eject Try 2 of 2"),
            mock.call.error(f"Eject request failed {self.eject_media_url}"),
            mock.call.debug(
                f"Polling for Eject complete {self.vm_url_data['@odata.id']}"
            ),
            mock.call.error(
                f"Failed to query vm state from {self.vm_url_data['@odata.id']}"
            ),
            mock.call.error(
                f"Eject Image try 2 timeout on {self.vm_url_data['@odata.id']}"
            ),
            mock.call.error(
                f"Eject Image full timeout on {self.vm_url_data['@odata.id']}"
            ),
            mock.call.error("Eject Image overall timeout"),
        ]
        expected_calls.extend(self._generate_log_dump())
        self._assert_mock_logger_calls(expected_calls)
