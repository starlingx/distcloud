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

    def __init__(self, region_name, strategy):
        super().__init__(
            next_state=consts.STRATEGY_STATE_PRESTAGE_PACKAGES,
            region_name=region_name,
            strategy=strategy,
        )

    def perform_state_action(self, strategy_step):
        extra_args = self.strategy.extra_args
        oam_floating_ip_dict = self.strategy.oam_floating_ip_dict

        if not extra_args:
            message = "Prestage pre-check: missing all mandatory arguments"
            self.error_log(strategy_step, message)
            raise Exception(message)

        payload = {
            "sysadmin_password": extra_args["sysadmin_password"],
            "force": extra_args["force"],
        }
        if extra_args.get(consts.PRESTAGE_SOFTWARE_VERSION):
            payload.update(
                {
                    consts.PRESTAGE_REQUEST_RELEASE: extra_args.get(
                        consts.PRESTAGE_SOFTWARE_VERSION
                    )
                }
            )
        # Taking the for_sw_deploy parameter if it was specified when the
        # strategy was created
        if extra_args.get(consts.PRESTAGE_FOR_SW_DEPLOY):
            payload.update(
                {
                    consts.PRESTAGE_FOR_SW_DEPLOY: extra_args.get(
                        consts.PRESTAGE_FOR_SW_DEPLOY
                    )
                }
            )

        try:
            system_controller_sw_list = self._read_from_cache(
                REGION_ONE_RELEASE_USM_CACHE_TYPE
            )
            oam_floating_ip = prestage.validate_prestage_subcloud(
                strategy_step.subcloud, payload, system_controller_sw_list
            )
            oam_floating_ip_dict[strategy_step.subcloud.name] = oam_floating_ip
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

    def __init__(self, region_name, strategy):
        super().__init__(
            next_state=consts.STRATEGY_STATE_PRESTAGE_IMAGES,
            region_name=region_name,
            strategy=strategy,
        )

    def perform_state_action(self, strategy_step):
        extra_args = self.strategy.extra_args
        oam_floating_ip_dict = self.strategy.oam_floating_ip_dict
        oam_floating_ip = oam_floating_ip_dict.get(strategy_step.subcloud.name)

        if not oam_floating_ip:
            oam_floating_ip = prestage.get_subcloud_oam_ip(strategy_step.subcloud)

        payload = {
            "sysadmin_password": extra_args["sysadmin_password"],
            "oam_floating_ip": oam_floating_ip,
            "force": extra_args["force"],
        }
        if extra_args.get(consts.PRESTAGE_SOFTWARE_VERSION):
            payload.update(
                {
                    consts.PRESTAGE_REQUEST_RELEASE: extra_args.get(
                        consts.PRESTAGE_SOFTWARE_VERSION
                    )
                }
            )

        prestage_reason = utils.get_prestage_reason(extra_args)

        prestage.prestage_packages(
            self.context, strategy_step.subcloud, payload, prestage_reason
        )
        self.info_log(strategy_step, "Packages finished")

        return self.next_state


class PrestageImagesState(BaseState):
    """Perform prestage images operation"""

    def __init__(self, region_name, strategy):
        super().__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE,
            region_name=region_name,
            strategy=strategy,
        )

    def perform_state_action(self, strategy_step):
        extra_args = self.strategy.extra_args
        oam_floating_ip_dict = self.strategy.oam_floating_ip_dict
        oam_floating_ip = oam_floating_ip_dict.get(strategy_step.subcloud.name)

        if not oam_floating_ip:
            oam_floating_ip = prestage.get_subcloud_oam_ip(strategy_step.subcloud)

        payload = {
            "sysadmin_password": extra_args["sysadmin_password"],
            "oam_floating_ip": oam_floating_ip,
            "force": extra_args["force"],
        }
        if extra_args.get(consts.PRESTAGE_SOFTWARE_VERSION):
            payload.update(
                {
                    consts.PRESTAGE_REQUEST_RELEASE: extra_args.get(
                        consts.PRESTAGE_SOFTWARE_VERSION
                    )
                }
            )

        prestage_reason = utils.get_prestage_reason(extra_args)

        prestage.prestage_images(
            self.context, strategy_step.subcloud, payload, prestage_reason
        )

        self.info_log(strategy_step, "Images finished")

        if self.strategy.update_type == consts.SW_UPDATE_TYPE_SOFTWARE:
            # We should skip the install_license state if it's a minor release.
            if strategy_step.subcloud.software_version == utils.get_major_release(
                extra_args.get(consts.EXTRA_ARGS_RELEASE_ID)
            ):
                self.override_next_state(consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY)
            else:
                self.override_next_state(consts.STRATEGY_STATE_SW_INSTALL_LICENSE)

        return self.next_state
