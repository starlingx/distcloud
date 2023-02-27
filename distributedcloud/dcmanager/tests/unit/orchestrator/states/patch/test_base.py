#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class TestPatchState(TestSwUpdate):
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_PATCH

    def setUp(self):
        super(TestPatchState, self).setUp()
