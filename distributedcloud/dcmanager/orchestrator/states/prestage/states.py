#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import abc

from oslo_log import log as logging

from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState

LOG = logging.getLogger(__name__)


class PrestageState(BaseState):
    """Perform prepare operation"""

    def __init__(self, next_state, region_name):
        super(PrestageState, self).__init__(
            next_state=next_state, region_name=region_name
        )

    @abc.abstractmethod
    def _do_state_action(self, strategy_step):
        pass

    def perform_state_action(self, strategy_step):
        """Wrapper to ensure proper error handling"""
        try:
            self._do_state_action(strategy_step)
        except exceptions.StrategySkippedException:
            # Move prestage_status back to None (nothing has changed)
            db_api.subcloud_update(
                self.context, strategy_step.subcloud.id, prestage_status=None
            )
            raise
        except Exception:
            prestage.prestage_fail(self.context, strategy_step.subcloud.id)
            raise

        # state machine can proceed to the next state
        return self.next_state


class PrestagePreCheckState(PrestageState):
    """Perform pre check operations"""

    def __init__(self, region_name):
        super(PrestagePreCheckState, self).__init__(
            next_state=consts.STRATEGY_STATE_PRESTAGE_PACKAGES, region_name=region_name
        )

    @utils.synchronized("prestage-update-extra-args", external=True)
    def _update_oam_floating_ip(self, strategy_step, oam_floating_ip):
        # refresh the extra_args
        extra_args = utils.get_sw_update_strategy_extra_args(self.context)
        if "oam_floating_ip_dict" in extra_args:
            LOG.debug(
                "Updating oam_floating_ip_dict: %s: %s",
                strategy_step.subcloud.name,
                oam_floating_ip,
            )
            oam_floating_ip_dict = extra_args["oam_floating_ip_dict"]
            oam_floating_ip_dict[strategy_step.subcloud.name] = oam_floating_ip
        else:
            LOG.debug(
                "Creating oam_floating_ip_dict: %s: %s",
                strategy_step.subcloud.name,
                oam_floating_ip,
            )
            oam_floating_ip_dict = {strategy_step.subcloud.name: oam_floating_ip}
        db_api.sw_update_strategy_update(
            self.context,
            state=None,
            update_type=None,
            additional_args={"oam_floating_ip_dict": oam_floating_ip_dict},
        )

    def _do_state_action(self, strategy_step):
        extra_args = utils.get_sw_update_strategy_extra_args(self.context)
        if extra_args is None:
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
        try:
            oam_floating_ip = prestage.validate_prestage(
                strategy_step.subcloud, payload
            )
            self._update_oam_floating_ip(strategy_step, oam_floating_ip)

            prestage.prestage_start(self.context, strategy_step.subcloud.id)

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


class PrestagePackagesState(PrestageState):
    """Perform prestage packages operation"""

    def __init__(self, region_name):
        super(PrestagePackagesState, self).__init__(
            next_state=consts.STRATEGY_STATE_PRESTAGE_IMAGES, region_name=region_name
        )

    def _do_state_action(self, strategy_step):
        extra_args = utils.get_sw_update_strategy_extra_args(self.context)
        payload = {
            "sysadmin_password": extra_args["sysadmin_password"],
            "oam_floating_ip": extra_args["oam_floating_ip_dict"][
                strategy_step.subcloud.name
            ],
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
        prestage.prestage_packages(self.context, strategy_step.subcloud, payload)
        self.info_log(strategy_step, "Packages finished")


class PrestageImagesState(PrestageState):
    """Perform prestage images operation"""

    def __init__(self, region_name):
        super(PrestageImagesState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE, region_name=region_name
        )

    def _do_state_action(self, strategy_step):
        log_file = utils.get_subcloud_ansible_log_file(strategy_step.subcloud.name)
        # Get the prestage versions from the ansible playbook logs
        # generated by the previous step - prestage packages.
        prestage_versions = utils.get_msg_output_info(
            log_file,
            prestage.PRINT_PRESTAGE_VERSIONS_TASK,
            prestage.PRESTAGE_VERSIONS_KEY_STR,
        )

        extra_args = utils.get_sw_update_strategy_extra_args(self.context)
        payload = {
            "sysadmin_password": extra_args["sysadmin_password"],
            "oam_floating_ip": extra_args["oam_floating_ip_dict"][
                strategy_step.subcloud.name
            ],
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
        prestage.prestage_images(self.context, strategy_step.subcloud, payload)
        self.info_log(strategy_step, "Images finished")
        prestage.prestage_complete(
            self.context, strategy_step.subcloud.id, prestage_versions
        )
