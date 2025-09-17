#
# Copyright (c) 2022-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import builtins
import copy
import os
import threading

from dccommon import ostree_mount
from dccommon.utils import AnsiblePlaybook
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import prestage
from dcmanager.db import api as db_api
from dcmanager.orchestrator.cache import clients
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate

FAKE_PASSWORD = (base64.b64encode("testpass".encode("utf-8"))).decode("ascii")
OAM_FLOATING_IP = "10.10.10.12"
REQUIRED_EXTRA_ARGS = {"sysadmin_password": FAKE_PASSWORD, "force": False}


class TestPrestage(TestSwUpdate):
    def setUp(self):
        super().setUp()

        # Setting strategy_type to prestage will setup the prestage upgrade
        # orchestration worker and will mock away the other orch threads
        self.strategy_type = consts.SW_UPDATE_TYPE_PRESTAGE
        self.strategy_step = None

        # Add the subcloud being processed by this unit test
        # The subcloud is online, managed with deploy_state 'installed'
        self.subcloud = db_api.subcloud_update(
            self.ctx, self.subcloud.id, deploy_status=consts.DEPLOY_STATE_DONE
        )

        # Modify cache helpers to return client mocks
        self._mock_object(clients, "get_software_client")

    def _setup_strategy_step(self, strategy_step):
        self.strategy_step = self.setup_strategy_step(self.subcloud.id, strategy_step)

    def _setup_and_assert(self, next_state, extra_args=None, fill_ip_dict=False):
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.strategy_type, extra_args=extra_args
        )
        # The oam_floating_ip_dict is filled in the prestage pre-check with the
        # subcloud's oam ip, so is necessary to manually fill for the test cases that
        # validates other states
        if fill_ip_dict:
            self.worker.strategies[self.strategy_type].oam_floating_ip_dict[
                self.subcloud.name
            ] = OAM_FLOATING_IP

        super()._setup_and_assert(next_state)


class TestPrestagePreCheckState(TestPrestage):
    def setUp(self):
        super().setUp()

        self.current_state = consts.STRATEGY_STATE_PRESTAGE_PRE_CHECK
        self._setup_strategy_step(self.current_state)

        # The validate_prestage_subcloud method is mocked because the focus is on
        # testing the orchestrator logic only. Any specific prestage functionality is
        # covered on individual tests.
        self.mock_prestage_subcloud = self._mock_object(
            prestage, "validate_prestage_subcloud"
        )
        self.mock_prestage_subcloud.return_value = OAM_FLOATING_IP

        self._mock_object(threading.Thread, "start")

    def test_prestage_pre_check_without_extra_args(self):
        """Test prestage pre check without extra args"""

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Prestage pre-check: missing all mandatory arguments"
        )

    def test_prestage_pre_check_validate_failed_with_orch_skip_false(self):
        """Test prestage pre check validate failed with orch skip as false"""

        self.mock_prestage_subcloud.side_effect = (
            exceptions.PrestagePreCheckFailedException(
                subcloud=None, orch_skip=False, details="test"
            )
        )

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED, REQUIRED_EXTRA_ARGS)
        self._assert_error(f"{self.current_state}: Prestage failed: test")

    def test_prestage_pre_check_validate_failed_with_orch_skip_true(self):
        """Test prestage pre check validate failed with orch skip as true"""

        self.mock_prestage_subcloud.side_effect = (
            exceptions.PrestagePreCheckFailedException(
                subcloud=None, orch_skip=True, details="test"
            )
        )

        self._setup_and_assert(consts.STRATEGY_STATE_COMPLETE, REQUIRED_EXTRA_ARGS)

        new_strategy_step = db_api.strategy_step_get(self.ctx, self.subcloud.id)

        # The strategy step details field should be updated with the Exception
        # string
        self.assertTrue("test" in str(new_strategy_step.details))

    def test_prestage_pre_check_fails_with_generic_exception(self):
        """Test prestage pre check fails with generic exception"""

        self.mock_prestage_subcloud.side_effect = Exception("fake")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED, REQUIRED_EXTRA_ARGS)
        self._assert_error(f"{self.current_state}: fake")

    def test_prestage_pre_check_succeeds(self):
        """Test prestage pre check succeeds"""

        self._setup_and_assert(
            consts.STRATEGY_STATE_PRESTAGE_PACKAGES, REQUIRED_EXTRA_ARGS
        )

    def test_prestage_pre_check_succeeds_with_prestage_software_version(self):
        """Test prestage pre check succeeds with prestage software version"""

        extra_args = copy.copy(REQUIRED_EXTRA_ARGS)
        extra_args["prestage-software-version"] = "22.3"
        extra_args[consts.PRESTAGE_FOR_SW_DEPLOY] = True

        self._setup_and_assert(consts.STRATEGY_STATE_PRESTAGE_PACKAGES, extra_args)


class TestPrestagePackagesState(TestPrestage):
    def setUp(self):
        super().setUp()

        self._setup_strategy_step(consts.STRATEGY_STATE_PRESTAGE_PACKAGES)

        self._mock_object(builtins, "open")
        self._mock_object(AnsiblePlaybook, "run_playbook")
        self._mock_object(ostree_mount, "validate_ostree_iso_mount")

    def test_prestage_package_succeeds(self):
        """Test prestage package succeeds"""

        self._setup_and_assert(
            consts.STRATEGY_STATE_PRESTAGE_IMAGES,
            REQUIRED_EXTRA_ARGS,
            True,
        )

    def test_prestage_package_succeeds_with_prestage_software_version(self):
        """Test prestage package succeeds with prestage software version"""

        extra_args = copy.copy(REQUIRED_EXTRA_ARGS)
        extra_args["prestage-software-version"] = "22.3"

        self._setup_and_assert(consts.STRATEGY_STATE_PRESTAGE_IMAGES, extra_args, True)


class TestPrestageImagesState(TestPrestage):
    def setUp(self):
        super().setUp()

        self._setup_strategy_step(consts.STRATEGY_STATE_PRESTAGE_IMAGES)

        mock_os_path_isdir = self._mock_object(os.path, "isdir")
        mock_os_path_isdir.return_value = False

    def test_prestage_images_succeeds(self):
        """Test prestage images succeeds"""

        self._setup_and_assert(
            consts.STRATEGY_STATE_COMPLETE, REQUIRED_EXTRA_ARGS, True
        )

    def test_prestage_images_succeeds_with_prestage_software_version(self):
        """Test prestage images succeeds with prestage software version"""

        extra_args = copy.copy(REQUIRED_EXTRA_ARGS)
        extra_args["prestage-software-version"] = "22.3"

        self._setup_and_assert(consts.STRATEGY_STATE_COMPLETE, extra_args, True)
