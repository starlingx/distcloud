#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Class for patch strategy validations

It defines methods used in dcmanager orchestrator's to handle the strategy
by its type.
"""

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.orchestrator.validators.base import StrategyValidationBase

LOG = logging.getLogger(__name__)


class PatchStrategyValidator(StrategyValidationBase):
    """Class for patch strategy validations"""

    def __init__(self):
        super().__init__()

        self.endpoint_type = dccommon_consts.ENDPOINT_TYPE_PATCHING

    def build_extra_args(self, payload):
        """Builds the extra args for a strategy

        In case the strategy does not accept extra args, None is returned.

        :param payload: strategy request payload
        """

        upload_only_bool = payload.get(consts.EXTRA_ARGS_UPLOAD_ONLY) == "true"
        return {
            consts.EXTRA_ARGS_UPLOAD_ONLY: upload_only_bool,
            consts.EXTRA_ARGS_PATCH: payload.get(consts.EXTRA_ARGS_PATCH),
        }
