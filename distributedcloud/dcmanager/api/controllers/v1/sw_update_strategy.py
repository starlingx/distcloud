# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
import pecan
from pecan import expose
from pecan import request

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import sw_update_strategy as sw_update_strat_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator import rpcapi as orch_rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

SUPPORTED_STRATEGY_TYPES = [
    consts.SW_UPDATE_TYPE_FIRMWARE,
    consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE,
    consts.SW_UPDATE_TYPE_KUBERNETES,
    consts.SW_UPDATE_TYPE_PATCH,
    consts.SW_UPDATE_TYPE_PRESTAGE,
    consts.SW_UPDATE_TYPE_SOFTWARE,
]

# some strategies allow force for all subclouds
FORCE_ALL_TYPES = [
    consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE,
    consts.SW_UPDATE_TYPE_KUBERNETES,
    consts.SW_UPDATE_TYPE_PRESTAGE,
]

MAX_PARALLEL_SUBCLOUDS_LIMIT = 5000


class SwUpdateStrategyController(object):

    def __init__(self):
        super(SwUpdateStrategyController, self).__init__()
        self.orch_rpc_client = orch_rpc_client.ManagerOrchestratorClient()

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method="GET", template="json")
    def get(self, steps=None, cloud_name=None):
        """Get details about software update strategy.

        :param steps: get the steps for this strategy (optional)
        :param cloud_name: name of cloud (optional)
        """
        policy.authorize(
            sw_update_strat_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        # If 'type' is in the request params, filter the update_type
        update_type_filter = request.params.get("type", None)

        if steps is None:
            # Strategy requested
            strategy = None
            try:
                strategy = db_api.sw_update_strategy_get(
                    context, update_type=update_type_filter
                )
            except exceptions.NotFound:
                if update_type_filter is None:
                    pecan.abort(404, _("Strategy not found"))
                else:
                    pecan.abort(
                        404, _("Strategy of type '%s' not found" % update_type_filter)
                    )

            strategy_dict = db_api.sw_update_strategy_db_model_to_dict(strategy)
            return strategy_dict

        elif steps == "steps":
            # Steps for the strategy requested
            if cloud_name is None:
                # List of steps requested
                result = dict()
                result["strategy-steps"] = list()
                strategy_steps = db_api.strategy_step_get_all(context)
                for strategy_step in strategy_steps:
                    result["strategy-steps"].append(
                        db_api.strategy_step_db_model_to_dict(strategy_step)
                    )

                return result
            else:
                # Single step requested
                strategy_step = None
                if cloud_name == dccommon_consts.SYSTEM_CONTROLLER_NAME:
                    # The system controller step does not map to a subcloud,
                    # so has no name.
                    try:
                        strategy_step = db_api.strategy_step_get(context, None)
                    except exceptions.StrategyStepNotFound:
                        pecan.abort(404, _("Strategy step not found"))
                else:
                    try:
                        strategy_step = db_api.strategy_step_get_by_name(
                            context, cloud_name
                        )
                    except exceptions.StrategyStepNameNotFound:
                        pecan.abort(404, _("Strategy step not found"))

                strategy_step_dict = db_api.strategy_step_db_model_to_dict(
                    strategy_step
                )
                return strategy_step_dict

    @index.when(method="POST", template="json")
    def post(self, actions=None):
        """Create a new software update strategy."""
        context = restcomm.extract_context_from_environ()

        payload = eval(request.body)
        if not payload:
            pecan.abort(400, _("Body required"))

        if actions is None:
            policy.authorize(
                sw_update_strat_policy.POLICY_ROOT % "create",
                {},
                restcomm.extract_credentials_for_policy(),
            )

            # Validate any options that were supplied
            strategy_type = payload.get("type")
            if not strategy_type:
                pecan.abort(400, _("type required"))
            if strategy_type not in SUPPORTED_STRATEGY_TYPES:
                pecan.abort(400, _("type invalid"))

            subcloud_apply_type = payload.get("subcloud-apply-type")
            if subcloud_apply_type is not None:
                if subcloud_apply_type not in [
                    consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
                    consts.SUBCLOUD_APPLY_TYPE_SERIAL,
                ]:
                    pecan.abort(400, _("subcloud-apply-type invalid"))

            # TODO(nicodemos): Remove once sw-patch is deprecated
            if strategy_type == consts.SW_UPDATE_TYPE_PATCH:
                utils.validate_patch_strategy(payload)
            elif strategy_type == consts.SW_UPDATE_TYPE_SOFTWARE:
                utils.validate_software_strategy(payload.get("release_id"))
            elif strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                prestaged_sw_version, message = (
                    utils.get_validated_sw_version_for_prestage(payload)
                )
                if not prestaged_sw_version:
                    pecan.abort(400, _(message))
                payload.update({consts.PRESTAGE_REQUEST_RELEASE: prestaged_sw_version})

            max_parallel_subclouds_str = payload.get("max-parallel-subclouds")
            if max_parallel_subclouds_str is not None:
                max_parallel_subclouds = None
                try:
                    max_parallel_subclouds = int(max_parallel_subclouds_str)
                except ValueError:
                    pecan.abort(400, _("max-parallel-subclouds invalid"))
                if (
                    max_parallel_subclouds < 1
                    or max_parallel_subclouds > MAX_PARALLEL_SUBCLOUDS_LIMIT
                ):
                    pecan.abort(400, _("max-parallel-subclouds invalid"))

            stop_on_failure = payload.get("stop-on-failure")
            if stop_on_failure is not None:
                if stop_on_failure not in ["true", "false"]:
                    pecan.abort(400, _("stop-on-failure invalid"))

            force_flag = payload.get("force")
            if force_flag is not None:
                if force_flag not in ["true", "false"]:
                    pecan.abort(400, _("force invalid"))
                elif strategy_type not in FORCE_ALL_TYPES:
                    if payload.get("cloud_name") is None:
                        pecan.abort(
                            400,
                            _(
                                "The --force option can only be applied for a single "
                                "subcloud. Please specify the subcloud name."
                            ),
                        )

            subcloud_group = payload.get("subcloud_group")
            # prevents passing both cloud_name and subcloud_group options
            # from REST APIs and checks if the group exists
            if subcloud_group is not None:
                if payload.get("cloud_name") is not None:
                    pecan.abort(
                        400,
                        _("cloud_name and subcloud_group are mutually exclusive"),
                    )

                if (
                    subcloud_apply_type is not None
                    or max_parallel_subclouds_str is not None
                ):
                    pecan.abort(
                        400,
                        _(
                            "subcloud-apply-type and max-parallel-subclouds are not "
                            "supported when subcloud_group is applied"
                        ),
                    )

                group = utils.subcloud_group_get_by_ref(context, subcloud_group)
                if group is None:
                    pecan.abort(400, _("Invalid group_id"))

            # Not adding validation for extra args. Passing them through.
            try:
                # Ask dcmanager-manager to create the strategy.
                # It will do all the real work...
                return self.orch_rpc_client.create_sw_update_strategy(context, payload)
            except RemoteError as e:
                pecan.abort(
                    422,
                    _("Unable to create strategy of type '%s': %s")
                    % (strategy_type, e.value),
                )
            except Exception as e:
                LOG.exception(e)
                pecan.abort(500, _("Unable to create strategy"))
        elif actions == "actions":
            # If 'type' is in the request params, filter the update_type
            update_type_filter = request.params.get("type", None)

            # Apply or abort a strategy
            action = payload.get("action")
            if not action:
                pecan.abort(400, _("action required"))
            if action == consts.SW_UPDATE_ACTION_APPLY:
                policy.authorize(
                    sw_update_strat_policy.POLICY_ROOT % "apply",
                    {},
                    restcomm.extract_credentials_for_policy(),
                )
                try:
                    # Ask dcmanager-manager to apply the strategy.
                    # It will do all the real work...
                    return self.orch_rpc_client.apply_sw_update_strategy(
                        context, update_type=update_type_filter
                    )
                except RemoteError as e:
                    pecan.abort(
                        422,
                        _("Unable to apply strategy of type '%s': %s")
                        % (update_type_filter, e.value),
                    )
                except Exception as e:
                    LOG.exception(e)
                    pecan.abort(500, _("Unable to apply strategy"))
            elif action == consts.SW_UPDATE_ACTION_ABORT:
                policy.authorize(
                    sw_update_strat_policy.POLICY_ROOT % "abort",
                    {},
                    restcomm.extract_credentials_for_policy(),
                )
                try:
                    # Ask dcmanager-manager to abort the strategy.
                    # It will do all the real work...
                    return self.orch_rpc_client.abort_sw_update_strategy(
                        context, update_type=update_type_filter
                    )
                except RemoteError as e:
                    pecan.abort(
                        422,
                        _("Unable to abort strategy of type '%s': %s")
                        % (update_type_filter, e.value),
                    )
                except Exception as e:
                    LOG.exception(e)
                    pecan.abort(500, _("Unable to abort strategy"))

    @index.when(method="delete", template="json")
    def delete(self):
        """Delete the software update strategy."""
        policy.authorize(
            sw_update_strat_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        # If 'type' is in the request params, filter the update_type
        update_type_filter = request.params.get("type", None)

        try:
            # Ask dcmanager-manager to delete the strategy.
            # It will do all the real work...
            return self.orch_rpc_client.delete_sw_update_strategy(
                context, update_type=update_type_filter
            )
        except RemoteError as e:
            pecan.abort(
                422,
                _("Unable to delete strategy of type '%s': %s")
                % (update_type_filter, e.value),
            )
        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _("Unable to delete strategy"))
