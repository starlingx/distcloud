#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.exceptions import PlaybookExecutionTimeout
from dccommon.tests import base
from dccommon import utils


class TestUtils(base.DCCommonTestCase):

    def setUp(self):
        super(TestUtils, self).setUp()

    def tearDown(self):
        super(TestUtils, self).tearDown()

    def test_run_playbook(self):
        # no timeout:
        testscript = ['dccommon/tests/unit/test_utils_script.sh', '1']
        utils.run_playbook('/dev/null', testscript)

    def test_run_playbook_timeout(self):
        testscript = ['dccommon/tests/unit/test_utils_script.sh', '30']
        self.assertRaises(PlaybookExecutionTimeout,
                          utils.run_playbook_with_timeout,
                          '/dev/null',
                          testscript,
                          timeout=2)

    def test_run_playbook_timeout_requires_kill(self):
        # This option ignores a regular TERM signal, and requires a
        # kill -9 (KILL signal) to terminate. We're using this to simulate
        # a hung process
        script = ['dccommon/tests/unit/test_utils_script.sh', '30', 'TERM']
        self.assertRaises(PlaybookExecutionTimeout,
                          utils.run_playbook_with_timeout,
                          '/dev/null',
                          script,
                          timeout=2)
