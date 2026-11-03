#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccertmon.common import utils
from dccertmon.tests.base import DCCertMonTestCase

LEAF_PEM = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
ICA_PEM = "-----BEGIN CERTIFICATE-----\nICA\n-----END CERTIFICATE-----"
S_CLIENT_OUTPUT = f"CONNECTED\n{LEAF_PEM}\nnoise\n{ICA_PEM}\nDone\n"


class TestGetEndpointCertChain(DCCertMonTestCase):

    def setUp(self):
        super().setUp()
        self.mock_popen = self._mock_object(utils.subprocess, "Popen")
        self.proc = self.mock_popen.return_value
        self.proc.communicate.return_value = (S_CLIENT_OUTPUT, "")

    def _connect_target(self):
        cmd = self.mock_popen.call_args.args[0]
        return cmd[cmd.index("-connect") + 1]

    def test_returns_leaf_then_ca(self):
        chain = utils.get_endpoint_cert_chain("https://10.0.0.1:6386/v1")

        self.assertEqual([LEAF_PEM, ICA_PEM], chain)
        self.assertEqual("10.0.0.1:6386", self._connect_target())

    def test_ipv6_host_is_bracketed(self):
        """urlparse strips the brackets, openssl needs them to split the port."""

        utils.get_endpoint_cert_chain("https://[2620:10a:a001::63]:6386/v1")

        self.assertEqual("[2620:10a:a001::63]:6386", self._connect_target())

    def test_failure_returns_empty_and_stops_the_child(self):
        self.proc.communicate.side_effect = [Exception("timed out"), ("", "")]
        self.proc.poll.return_value = None

        chain = utils.get_endpoint_cert_chain("https://10.0.0.1:6386/v1")

        self.assertEqual([], chain)
        self.proc.kill.assert_called_once()
        # communicate() is called again to reap the killed child.
        self.assertEqual(2, self.proc.communicate.call_count)

    def test_failure_does_not_kill_a_child_that_already_exited(self):
        self.proc.communicate.side_effect = Exception("boom")
        self.proc.poll.return_value = 1

        chain = utils.get_endpoint_cert_chain("https://10.0.0.1:6386/v1")

        self.assertEqual([], chain)
        self.proc.kill.assert_not_called()

    def test_popen_failure_returns_empty(self):
        self.mock_popen.side_effect = OSError("no openssl")

        chain = utils.get_endpoint_cert_chain("https://10.0.0.1:6386/v1")

        self.assertEqual([], chain)


class TestGetCertSerial(DCCertMonTestCase):

    def setUp(self):
        super().setUp()
        self.mock_popen = self._mock_object(utils.subprocess, "Popen")
        self.proc = self.mock_popen.return_value
        self.proc.returncode = 0

    def test_parses_and_uppercases_the_serial(self):
        self.proc.communicate.return_value = ("serial=abc123\n", "")

        self.assertEqual("ABC123", utils.get_cert_serial(LEAF_PEM))
        self.proc.communicate.assert_called_once_with(input=LEAF_PEM)

    def test_empty_input_does_not_run_openssl(self):
        self.assertIsNone(utils.get_cert_serial(""))
        self.mock_popen.assert_not_called()

    def test_openssl_failure_returns_none(self):
        self.proc.returncode = 1
        self.proc.communicate.return_value = ("", "unable to load certificate")

        self.assertIsNone(utils.get_cert_serial("not a certificate"))

    def test_popen_failure_returns_none(self):
        self.mock_popen.side_effect = OSError("no openssl")

        self.assertIsNone(utils.get_cert_serial(LEAF_PEM))
