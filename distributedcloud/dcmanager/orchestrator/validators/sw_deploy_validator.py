#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Class for software deploy strategy validations

It defines methods used in dcmanager orchestrator's to handle the strategy
by its type.
"""

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import utils
from dcmanager.orchestrator.validators.base import StrategyValidationBase

LOG = logging.getLogger(__name__)


class SoftwareDeployStrategyValidator(StrategyValidationBase):
    """Class for software deploy strategy validations"""

    def __init__(self):
        super().__init__()

        self.endpoint_type = dccommon_consts.AUDIT_TYPE_SOFTWARE

    def build_extra_args(self, payload):
        """Builds the extra args for a strategy

        In case the strategy does not accept extra args, None is returned.

        :param payload: strategy request payload
        """
        ret_dict = {
            consts.EXTRA_ARGS_DELETE_ONLY: payload.get(
                consts.EXTRA_ARGS_DELETE_ONLY, False
            ),
            consts.EXTRA_ARGS_RELEASE_ID: payload.get(consts.EXTRA_ARGS_RELEASE_ID),
            consts.EXTRA_ARGS_ROLLBACK: payload.get(consts.EXTRA_ARGS_ROLLBACK, False),
            consts.EXTRA_ARGS_SNAPSHOT: payload.get(consts.EXTRA_ARGS_SNAPSHOT, False),
            consts.EXTRA_ARGS_SYSADMIN_PASSWORD: payload.get(
                consts.EXTRA_ARGS_SYSADMIN_PASSWORD
            ),
            consts.EXTRA_ARGS_WITH_PRESTAGE: payload.get(
                consts.EXTRA_ARGS_WITH_PRESTAGE, False
            ),
            consts.EXTRA_ARGS_WITH_DELETE: payload.get(
                consts.EXTRA_ARGS_WITH_DELETE, False
            ),
        }

        # Update sw-deploy extra_args with the required options for prestage.
        if ret_dict.get(consts.EXTRA_ARGS_WITH_PRESTAGE):
            ret_dict[consts.PRESTAGE_FOR_SW_DEPLOY] = True
            # Force is always set to False because allowing prestage to run on a
            # subcloud with management alarms is pointless: prestage may succeed,
            # but the subsequent sw-deploy will still fail under the same alarm
            # conditions.
            ret_dict[consts.EXTRA_ARGS_FORCE] = False
            ret_dict[consts.PRESTAGE_SOFTWARE_VERSION] = utils.get_major_release(
                payload.get(consts.EXTRA_ARGS_RELEASE_ID),
            )

        return ret_dict
