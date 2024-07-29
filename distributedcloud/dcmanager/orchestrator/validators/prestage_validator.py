#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Class for prestage strategy validations

It defines methods used in dcmanager orchestrator's to handle the strategy
by its type.
"""

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcmanager.orchestrator.validators.base import StrategyValidationBase

LOG = logging.getLogger(__name__)


class PrestageStrategyValidator(StrategyValidationBase):
    """Class for prestage strategy validations"""

    def __init__(self):
        super().__init__()

        # For prestage we reuse the ENDPOINT_TYPE_SOFTWARE.
        # We just need to key off a unique endpoint,
        # so that the strategy is created only once.
        self.endpoint_type = dccommon_consts.ENDPOINT_TYPE_SOFTWARE

    # TODO(rlima): move prestage validations here
    def build_sync_status_filter(self, force):
        """Builds the sync status filter for valid subclouds

        :param force: if the strategy should be forced to execute
        :return: sync status to filter
        :rtype: list
        """

        return None
