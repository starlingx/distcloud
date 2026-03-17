# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2026 Wind River Systems, Inc.
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

import json
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
    consts.SW_UPDATE_TYPE_PRESTAGE,
    consts.SW_UPDATE_TYPE_SOFTWARE,
]


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
        ---
                /v1.0/sw-update-strategy:
                  get:
                    summary: Get software update strategy
                    description: Retrieve software update strategy details
                    operationId: getSwUpdateStrategy
                    tags:
                    - sw-update-strategy
                    parameters:
                    - name: type
                      in: query
                      description: |
                        Strategy type filter.
                        Valid values: firmware,
                        kube-rootca-update, kubernetes,
                        prestage, sw-deploy
                      required: false
                      schema:
                        type: string
                        enum:
                        - firmware
                        - kube-rootca-update
                        - kubernetes
                        - prestage
                        - sw-deploy
                    responses:
                      200:
                        description: Strategy retrieved successfully
                      404:
                        description: Strategy not found
                      500:
                        description: Internal server error
                /v1.0/sw-update-strategy/steps:
                  get:
                    summary: Get software update strategy steps
                    description: Retrieve strategy steps
                    operationId: getSwUpdateStrategySteps
                    tags:
                    - sw-update-strategy
                    parameters:
                    - name: type
                      in: query
                      description: |
                        Strategy type filter.
                        Valid values: firmware,
                        kube-rootca-update, kubernetes,
                        prestage, sw-deploy
                      required: false
                      schema:
                        type: string
                        enum:
                        - firmware
                        - kube-rootca-update
                        - kubernetes
                        - prestage
                        - sw-deploy
                    responses:
                      200:
                        description: Strategy steps retrieved successfully
                        content:
                          application/json:
                            schema:
                              type: object
                            example:
                              strategy-steps:
                              - id: 1
                                cloud: subcloud2
                                stage: Create
                                state: initial
                                details: ''
                                started-at: null
                                finished-at: null
                                created-at: '2026-03-04 14:24:47.700836'
                                updated-at: null
                      404:
                        description: Strategy not found
                      500:
                        description: Internal server error
                /v1.0/sw-update-strategy/steps/{cloud_name}:
                  get:
                    summary: Get specific strategy step for cloud
                    description: Retrieve strategy step for a specific cloud
                    operationId: getSwUpdateStrategyStepByCloud
                    tags:
                    - sw-update-strategy
                    parameters:
                    - name: cloud_name
                      in: path
                      description: Name of cloud for specific step
                      required: true
                      schema:
                        type: string
                    - name: type
                      in: query
                      description: |
                        Strategy type filter.
                        Valid values: firmware,
                        kube-rootca-update, kubernetes,
                        prestage, sw-deploy
                      required: false
                      schema:
                        type: string
                        enum:
                        - firmware
                        - kube-rootca-update
                        - kubernetes
                        - prestage
                        - sw-deploy
                    responses:
                      200:
                        description: Strategy step retrieved successfully
                        content:
                          application/json:
                            schema:
                              type: object
                            example:
                              id: 1
                              cloud: subcloud2
                              stage: Create
                              state: initial
                              details: ''
                              started-at: null
                              finished-at: null
                              created-at: '2026-03-04 14:24:47.700836'
                              updated-at: null
                      404:
                        description: Strategy step not found
                      500:
                        description: Internal server error
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
                    db_dict = db_api.strategy_step_db_model_to_dict(strategy_step)
                    db_dict["stage"] = consts.STAGE_MAP.get(
                        str(db_dict["stage"]), db_dict["stage"]
                    )
                    result["strategy-steps"].append(db_dict)

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

                if "stage" in strategy_step_dict.keys():
                    if str(strategy_step_dict["stage"]) in consts.STAGE_MAP.keys():
                        strategy_step_dict["stage"] = consts.STAGE_MAP[
                            str(strategy_step_dict["stage"])
                        ]

                return strategy_step_dict

    @index.when(method="POST", template="json")
    def post(self, actions=None):
        """Create a new software update strategy.

        ---
                /v1.0/sw-update-strategy:
                  post:
                    summary: Create software update strategy
                    description: |
                      Create a new software update strategy.
                      Strategy type values: firmware,
                      kube-rootca-update, kubernetes, prestage,
                      sw-deploy.
                      Subcloud apply type values: parallel, serial.
                    operationId: createSwUpdateStrategy
                    tags:
                    - sw-update-strategy
                    requestBody:
                      required: true
                      content:
                        application/json:
                          schema:
                            type: object
                            required:
                            - type
                            properties:
                              type:
                                type: string
                                enum:
                                - firmware
                                - kube-rootca-update
                                - kubernetes
                                - prestage
                                - sw-deploy
                                description: |
                                  Strategy type.
                                  Valid values: firmware,
                                  kube-rootca-update, kubernetes,
                                  prestage, sw-deploy
                              subcloud-apply-type:
                                type: string
                                enum:
                                - parallel
                                - serial
                                description: |
                                  Apply type for subclouds.
                                  Valid values: parallel, serial
                              max-parallel-subclouds:
                                $ref: '#/components/schemas/max_parallel_subclouds'
                              stop-on-failure:
                                $ref: '#/components/schemas/stop_on_failure'
                              force:
                                $ref: '#/components/schemas/force'
                              subcloud_group:
                                type: string
                                description: Name or ID of subcloud group
                              cloud_name:
                                type: string
                                description: Name of specific cloud
                              release:
                                type: string
                                description: |
                                  Software release version for prestage operations.
                                  Required when type is 'prestage'.
                                  Format: MM.mm (e.g., "26.03")
                              release_id:
                                type: string
                                description: |
                                  Release ID for software deployment operations.
                                  Required when type is 'sw-deploy'
                                  (unless rollback or delete_only
                                  is true).
                                  Example: "starlingx-11"
                              rollback:
                                type: boolean
                                description: |
                                  Rollback to previous software release.
                                  Only applicable for sw-deploy strategy type.
                              snapshot:
                                type: boolean
                                description: |
                                  Create snapshot before software deployment.
                                  Only applicable for sw-deploy strategy type.
                              with_delete:
                                type: boolean
                                description: |
                                  Delete the software deployment post successful
                                  strategy application.
                                  Only applicable for sw-deploy strategy type.
                              delete_only:
                                type: boolean
                                description: |
                                  Delete the software deployment without
                                  performing deployment.
                                  Only applicable for sw-deploy strategy type.
                              with_prestage:
                                type: boolean
                                description: |
                                  Prestage software before deployment.
                                  Only applicable for sw-deploy strategy type.
                              sysadmin_password:
                                type: string
                                description: |
                                  Base64 encoded sysadmin password for subcloud access.
                                  Required when with_prestage is true
                                  for sw-deploy strategy.
                              to-version:
                                type: string
                                description: |
                                  Target Kubernetes version for upgrade.
                                  Only applicable for kubernetes strategy type.
                              expiry-date:
                                type: string
                                format: date
                                description: |
                                  Certificate expiry date in YYYY-MM-DD format.
                                  Only applicable for kube-rootca-update strategy type.
                              subject:
                                type: string
                                description: |
                                  Certificate subject specification.
                                  Only applicable for kube-rootca-update strategy type.
                                  Format: >-
                                    C=<Country> ST=<State/Province>
                                    L=<Locality> O=<Organization>
                                    OU=<OrganizationUnit>
                                    CN=<commonName>
                          examples:
                            sw_deploy_strategy:
                              summary: Create SW Deploy Strategy
                              description: >-
                                Create a software deployment
                                strategy with delete option
                              value:
                                type: "sw-deploy"
                                release_id: "starlingx-26.03.0"
                                subcloud_group: "21"
                                with_delete: "true"
                            prestage_strategy:
                              summary: Create Prestage Strategy
                              description: >-
                                Create a prestage strategy
                                for software preparation
                              value:
                                type: "prestage"
                                release: "26.03"
                                subcloud_group: "1"
                                sysadmin_password: "cGFzc3dvcmQK"
                                for_sw_deploy: "true"
                                for_install: "false"
                                stop-on-failure: "true"
                            kubernetes_upgrade:
                              summary: Create Kubernetes Upgrade Strategy
                              description: Create a Kubernetes upgrade strategy
                              value:
                                type: "kubernetes"
                                to-version: "v1.24.4"
                                subcloud-apply-type: "parallel"
                                max-parallel-subclouds: "3"
                                stop-on-failure: "false"
                            kube_rootca_update:
                              summary: Create Kube Root CA Update Strategy
                              description: >-
                                Create a Kubernetes root CA
                                certificate update strategy
                              value:
                                type: "kube-rootca-update"
                                expiry-date: "2025-12-31"
                                subject: >-
                                  C=CA ST=Ontario L=Ottawa
                                  O=WindRiver OU=Engineering
                                  CN=StarlingX
                                subcloud-apply-type: "serial"
                                stop-on-failure: true
                    responses:
                      200:
                        description: Strategy created successfully
                      400:
                        description: Bad request
                      422:
                        description: Unprocessable entity
                      500:
                        description: Internal server error
                /v1.0/sw-update-strategy/actions:
                  post:
                    summary: Apply or abort software update strategy
                    description: |
                      Apply or abort an existing strategy.
                      Valid action values: apply, abort.
                    operationId: applySwUpdateStrategy
                    tags:
                    - sw-update-strategy
                    requestBody:
                      required: true
                      content:
                        application/json:
                          schema:
                            type: object
                            required:
                            - action
                            properties:
                              action:
                                $ref: '#/components/schemas/sw_update_strategy_action'
                    responses:
                      200:
                        description: Action applied successfully
                        content:
                          application/json:
                            schema:
                              type: object
                            example:
                              id: 1
                              type: sw-deploy
                              subcloud-apply-type: parallel
                              max-parallel-subclouds: 2
                              stop-on-failure: false
                              state: applying
                              created-at: '2026-03-04T14:24:47.698157'
                              updated-at: '2026-03-04T14:57:18.049556'
                              extra-args:
                                delete_only: false
                                release_id: starlingx-11
                                rollback: false
                                snapshot: false
                                sysadmin_password: null
                                with_prestage: false
                                with_delete: true
                      400:
                        description: Bad request
                      422:
                        description: Unprocessable entity
                      500:
                        description: Internal server error
        """
        context = restcomm.extract_context_from_environ()

        payload = json.loads(request.body.decode("utf-8"))
        if not payload:
            pecan.abort(400, _("Body required"))

        if actions is None:
            context.is_admin = policy.authorize(
                sw_update_strat_policy.POLICY_ROOT % "create",
                {},
                restcomm.extract_credentials_for_policy(),
            )

            # Validate strategy parameters
            utils.validate_strategy_payload(context, payload)
            # Validate any options that were supplied
            strategy_type = payload.get("type")
            if not strategy_type:
                pecan.abort(400, _("type required"))
            if strategy_type not in SUPPORTED_STRATEGY_TYPES:
                pecan.abort(400, _("type invalid"))
            if strategy_type == consts.SW_UPDATE_TYPE_SOFTWARE:
                utils.validate_software_strategy(payload)
            elif strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                prestaged_sw_version, message = (
                    utils.get_validated_sw_version_for_prestage(payload)
                )
                utils.validate_prestage(payload)
                if not prestaged_sw_version:
                    pecan.abort(400, _(message))
                payload.update({consts.PRESTAGE_REQUEST_RELEASE: prestaged_sw_version})

            stop_on_failure = payload.get("stop-on-failure")
            if stop_on_failure is not None:
                if stop_on_failure not in ["true", "false"]:
                    pecan.abort(400, _("stop-on-failure invalid"))

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
                context.is_admin = policy.authorize(
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
                context.is_admin = policy.authorize(
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
        """Delete the software update strategy.

        ---
                delete:
                  summary: Delete software update strategy
                  description: Delete an existing software update strategy
                  operationId: deleteSwUpdateStrategy
                  tags:
                  - sw-update-strategy
                  parameters:
                  - name: type
                    in: query
                    description: |
                      Strategy type filter.
                      Valid values: firmware,
                      kube-rootca-update, kubernetes,
                      prestage, sw-deploy
                    required: false
                    schema:
                      type: string
                      enum:
                      - firmware
                      - kube-rootca-update
                      - kubernetes
                      - prestage
                      - sw-deploy
                  responses:
                    200:
                      description: Strategy deleted successfully
                      content:
                        application/json:
                          schema:
                            type: object
                    422:
                      description: Unprocessable entity
                    500:
                      description: Internal server error
        """

        context = restcomm.extract_context_from_environ()
        context.is_admin = policy.authorize(
            sw_update_strat_policy.POLICY_ROOT % "delete",
            {},
            restcomm.extract_credentials_for_policy(),
        )

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
