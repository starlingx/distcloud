#
# Copyright (c) 2022-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import mock
import threading

from dcmanager.common import consts
from dcmanager.common import exceptions

from dcmanager.common.consts import DEPLOY_STATE_DONE
from dcmanager.common.consts import STRATEGY_STATE_COMPLETE
from dcmanager.common.consts import STRATEGY_STATE_FAILED
from dcmanager.common.consts import STRATEGY_STATE_PRESTAGE_IMAGES
from dcmanager.common.consts import STRATEGY_STATE_PRESTAGE_PACKAGES
from dcmanager.common.consts import STRATEGY_STATE_PRESTAGE_PRE_CHECK

from dcmanager.db.sqlalchemy import api as db_api

from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate

OAM_FLOATING_IP = "10.10.10.12"
FAKE_PASSWORD = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')


class TestPrestage(TestSwUpdate):
    # Setting DEFAULT_STRATEGY_TYPE to prestage will setup the prestage upgrade
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_PRESTAGE

    def setUp(self):
        super(TestPrestage, self).setUp()


class TestPrestagePreCheckState(TestPrestage):
    def setUp(self):
        super(TestPrestagePreCheckState, self).setUp()

        # Add the subcloud being processed by this unit test
        # The subcloud is online, managed with deploy_state 'installed'
        self.subcloud = self.setup_subcloud()

        p = mock.patch('dcmanager.common.prestage.validate_prestage')
        self.mock_prestage_subcloud = p.start()
        self.mock_prestage_subcloud.return_value = OAM_FLOATING_IP
        self.addCleanup(p.stop)

        t = mock.patch.object(threading.Thread, 'start')
        self.mock_thread_start = t.start()
        self.addCleanup(t.stop)

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, STRATEGY_STATE_PRESTAGE_PRE_CHECK)

    def test_prestage_prepare_no_extra_args(self):
        next_state = STRATEGY_STATE_FAILED
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the transition to the expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

    def test_prestage_prepare_validate_failed(self):
        next_state = STRATEGY_STATE_FAILED
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        self.mock_prestage_subcloud.side_effect = exceptions.PrestagePreCheckFailedException(
            subcloud=None, orch_skip=False, details="test")

        extra_args = {"sysadmin_password": FAKE_PASSWORD,
                      "force": False,
                      'oam_floating_ip': OAM_FLOATING_IP}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)
        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        new_strategy_step = db_api.strategy_step_get(self.ctx,
                                                     self.subcloud.id)
        # Verify the transition to the expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

        # The strategy step details field should be updated with the Exception string
        self.assertTrue('test' in str(new_strategy_step.details))

    def test_prestage_prepare_validate_failed_skipped(self):
        next_state = STRATEGY_STATE_COMPLETE
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        self.mock_prestage_subcloud.side_effect = exceptions.PrestagePreCheckFailedException(
            subcloud=None, orch_skip=True, details="test")

        extra_args = {"sysadmin_password": FAKE_PASSWORD,
                      "force": False,
                      'oam_floating_ip': OAM_FLOATING_IP}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)
        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        new_strategy_step = db_api.strategy_step_get(self.ctx,
                                                     self.subcloud.id)

        # Verify the transition to the expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)

        # The strategy step details field should be updated with the Exception string
        self.assertTrue('test' in str(new_strategy_step.details))


class TestPrestagePackageState(TestPrestage):

    def setUp(self):
        super(TestPrestagePackageState, self).setUp()

        # Add the subcloud being processed by this unit test
        # The subcloud is online, managed with deploy_state 'installed'
        self.subcloud = self.setup_subcloud()

        p = mock.patch('dcmanager.common.prestage.prestage_packages')
        self.mock_prestage_packages = p.start()
        self.addCleanup(p.stop)

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, STRATEGY_STATE_PRESTAGE_PACKAGES)

    def test_prestage_prestage_package(self):

        next_state = STRATEGY_STATE_PRESTAGE_IMAGES
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        oam_floating_ip_dict = {
            self.subcloud.name: OAM_FLOATING_IP
        }
        extra_args = {"sysadmin_password": FAKE_PASSWORD,
                      "force": False,
                      "oam_floating_ip_dict": oam_floating_ip_dict}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the transition to the expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)


class TestPrestageImagesState(TestPrestage):

    def setUp(self):
        super(TestPrestageImagesState, self).setUp()

        # Add the subcloud being processed by this unit test
        # The subcloud is online, managed with deploy_state 'installed'
        self.subcloud = self.setup_subcloud()

        p = mock.patch('dcmanager.common.prestage.prestage_images')
        self.mock_prestage_packages = p.start()
        self.addCleanup(p.stop)

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, STRATEGY_STATE_PRESTAGE_IMAGES)

    def test_prestage_prestage_images(self):

        next_state = STRATEGY_STATE_COMPLETE
        # Update the subcloud to have deploy state as "complete"
        db_api.subcloud_update(self.ctx,
                               self.subcloud.id,
                               deploy_status=DEPLOY_STATE_DONE)

        oam_floating_ip_dict = {
            self.subcloud.name: OAM_FLOATING_IP
        }
        extra_args = {"sysadmin_password": FAKE_PASSWORD,
                      "force": False,
                      "oam_floating_ip_dict": oam_floating_ip_dict}
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            self.DEFAULT_STRATEGY_TYPE,
            extra_args=extra_args)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Verify the transition to the expected next state
        self.assert_step_updated(self.strategy_step.subcloud_id, next_state)
