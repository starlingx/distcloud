#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

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
