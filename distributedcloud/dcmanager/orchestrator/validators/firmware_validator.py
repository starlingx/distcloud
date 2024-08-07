#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Class for firmware strategy validations.

It defines methods used in dcmanager orchestrator's to handle the strategy
by its type.
"""

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcmanager.orchestrator.validators.base import StrategyValidationBase

LOG = logging.getLogger(__name__)


class FirmwareStrategyValidator(StrategyValidationBase):
    """Class for firmware strategy validations"""

    def __init__(self):
        super().__init__()

        self.endpoint_type = dccommon_consts.ENDPOINT_TYPE_FIRMWARE
