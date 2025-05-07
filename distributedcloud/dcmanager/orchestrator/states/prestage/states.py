#
# Copyright (c) 2022-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging

from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.cache.cache_specifications import (
    REGION_ONE_RELEASE_USM_CACHE_TYPE,
)

LOG = logging.getLogger(__name__)


class PrestagePreCheckState(BaseState):
    """Perform pre check operations"""

    def __init__(self, region_name):
        super().__init__(
            next_state=consts.STRATEGY_STATE_PRESTAGE_PACKAGES, region_name=region_name
        )

    def perform_state_action(self, strategy_step):
        if self.extra_args is None:
            message = "Prestage pre-check: missing all mandatory arguments"
            self.error_log(strategy_step, message)
            raise Exception(message)

        payload = {
            "sysadmin_password": self.extra_args["sysadmin_password"],
            "force": self.extra_args["force"],
        }
        if self.extra_args.get(consts.PRESTAGE_SOFTWARE_VERSION):
            payload.update(
                {
                    consts.PRESTAGE_REQUEST_RELEASE: self.extra_args.get(
                        consts.PRESTAGE_SOFTWARE_VERSION
                    )
                }
            )
        # Taking the for_sw_deploy parameter if it was specified when the
        # strategy was created
        if self.extra_args.get(consts.PRESTAGE_FOR_SW_DEPLOY):
            payload.update(
                {
                    consts.PRESTAGE_FOR_SW_DEPLOY: self.extra_args.get(
                        consts.PRESTAGE_FOR_SW_DEPLOY
                    )
                }
            )

        try:
            system_controller_sw_list = self._read_from_cache(
                REGION_ONE_RELEASE_USM_CACHE_TYPE
            )
            oam_floating_ip = prestage.validate_prestage(
                strategy_step.subcloud, payload, system_controller_sw_list
            )
            self.oam_floating_ip_dict[strategy_step.subcloud.name] = oam_floating_ip
        except exceptions.PrestagePreCheckFailedException as ex:
            # We've either failed precheck or we want to skip this subcloud.
            # Either way, we'll re-raise up to the base class for status
            # update, and then let OrchThread take it from here
            if ex.orch_skip:
                raise exceptions.StrategySkippedException(details=str(ex))

            self.error_log(strategy_step, "Pre-check failed: %s" % ex)
            raise
        else:
            self.info_log(strategy_step, "Pre-check pass")

        return self.next_state


class PrestagePackagesState(BaseState):
    """Perform prestage packages operation"""

    def __init__(self, region_name):
        super().__init__(
            next_state=consts.STRATEGY_STATE_PRESTAGE_IMAGES, region_name=region_name
        )

    def perform_state_action(self, strategy_step):
        payload = {
            "sysadmin_password": self.extra_args["sysadmin_password"],
            "oam_floating_ip": self.oam_floating_ip_dict[strategy_step.subcloud.name],
            "force": self.extra_args["force"],
        }
        if self.extra_args.get(consts.PRESTAGE_SOFTWARE_VERSION):
            payload.update(
                {
                    consts.PRESTAGE_REQUEST_RELEASE: self.extra_args.get(
                        consts.PRESTAGE_SOFTWARE_VERSION
                    )
                }
            )

        prestage_reason = utils.get_prestage_reason(self.extra_args)

        prestage.prestage_packages(
            self.context, strategy_step.subcloud, payload, prestage_reason
        )
        self.info_log(strategy_step, "Packages finished")

        return self.next_state


class PrestageImagesState(BaseState):
    """Perform prestage images operation"""

    def __init__(self, region_name):
        super().__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE, region_name=region_name
        )

    def perform_state_action(self, strategy_step):
        payload = {
            "sysadmin_password": self.extra_args["sysadmin_password"],
            "oam_floating_ip": self.oam_floating_ip_dict[strategy_step.subcloud.name],
            "force": self.extra_args["force"],
        }
        if self.extra_args.get(consts.PRESTAGE_SOFTWARE_VERSION):
            payload.update(
                {
                    consts.PRESTAGE_REQUEST_RELEASE: self.extra_args.get(
                        consts.PRESTAGE_SOFTWARE_VERSION
                    )
                }
            )

        prestage_reason = utils.get_prestage_reason(self.extra_args)

        prestage.prestage_images(
            self.context, strategy_step.subcloud, payload, prestage_reason
        )

        self.info_log(strategy_step, "Images finished")

        return self.next_state
