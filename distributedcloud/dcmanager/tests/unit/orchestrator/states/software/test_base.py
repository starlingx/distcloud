#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.tests.unit.common.consts import RELEASE_ID
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class TestSoftwareOrchestrator(TestSwUpdate):
    def setUp(self):
        super().setUp()

        # Setting strategy_type to software will setup the software
        # orchestration worker, and will mock away the other orch threads
        self.strategy_type = consts.SW_UPDATE_TYPE_SOFTWARE
        extra_args = {
            consts.EXTRA_ARGS_RELEASE_ID: RELEASE_ID,
            consts.EXTRA_ARGS_DELETE_ONLY: False,
            consts.EXTRA_ARGS_SNAPSHOT: False,
            consts.EXTRA_ARGS_ROLLBACK: False,
            consts.EXTRA_ARGS_WITH_DELETE: False,
        }
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, self.strategy_type, extra_args=extra_args
        )
