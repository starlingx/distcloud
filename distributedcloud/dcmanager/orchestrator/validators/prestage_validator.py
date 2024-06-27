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

from dcmanager.orchestrator.validators.base import StrategyValidationBase

LOG = logging.getLogger(__name__)


class PrestageStrategyValidator(StrategyValidationBase):
    """Class for prestage strategy validations"""

    def __init__(self):
        super().__init__()

        self.endpoint_type = None

    # TODO(rlima): move prestage validations here
