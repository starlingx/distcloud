# Copyright 2016 Ericsson AB
# Copyright (c) 2017-2022, 2024 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

from functools import wraps
import json

from keystoneauth1 import session as ks_session
from nfv_client.openstack import rest_api
from nfv_client.openstack import sw_update
from oslo_log import log

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions

LOG = log.getLogger(__name__)

STRATEGY_NAME_FW_UPDATE = "fw-update"
STRATEGY_NAME_KUBE_ROOTCA_UPDATE = "kube-rootca-update"
STRATEGY_NAME_KUBE_UPGRADE = "kube-upgrade"
STRATEGY_NAME_SW_PATCH = "sw-patch"
# TODO(nicodemos): Change this to 'sw-deploy' once the new strategy is created
STRATEGY_NAME_SW_USM = "sw-upgrade"
STRATEGY_NAME_SYS_CONFIG_UPDATE = "system-config-update"

APPLY_TYPE_SERIAL = "serial"
APPLY_TYPE_PARALLEL = "parallel"
APPLY_TYPE_IGNORE = "ignore"

INSTANCE_ACTION_MIGRATE = "migrate"
INSTANCE_ACTION_STOP_START = "stop-start"

ALARM_RESTRICTIONS_STRICT = "strict"
ALARM_RESTRICTIONS_RELAXED = "relaxed"

SW_UPDATE_OPTS_CONST_DEFAULT = {
    "name": consts.SW_UPDATE_DEFAULT_TITLE,
    "storage-apply-type": APPLY_TYPE_PARALLEL,
    "worker-apply-type": APPLY_TYPE_PARALLEL,
    "max-parallel-workers": 10,
    "default-instance-action": INSTANCE_ACTION_MIGRATE,
    "alarm-restriction-type": ALARM_RESTRICTIONS_RELAXED,
    "created-at": None,
    "updated-at": None,
}

STATE_INITIAL = "initial"
STATE_BUILDING = "building"
STATE_BUILD_FAILED = "build-failed"
STATE_BUILD_TIMEOUT = "build-timeout"
STATE_READY_TO_APPLY = "ready-to-apply"
STATE_APPLYING = "applying"
STATE_APPLY_FAILED = "apply-failed"
STATE_APPLY_TIMEOUT = "apply-timeout"
STATE_APPLIED = "applied"
STATE_ABORTING = "aborting"
STATE_ABORT_FAILED = "abort-failed"
STATE_ABORT_TIMEOUT = "abort-timeout"
STATE_ABORTED = "aborted"

TRANSITORY_STATES = [
    STATE_INITIAL,
    STATE_BUILDING,
    STATE_READY_TO_APPLY,
    STATE_APPLYING,
    STATE_ABORTING,
]

# The exception message when vim authorization fails
VIM_AUTHORIZATION_FAILED = "Authorization failed"


# VIM API returns a 403 instead of a 401 for unauthenticated requests, so we
# can't use the internal re-auth functionality of the keystone session, we must
# manually check for the VIM_AUTHORIZATION_FAILED string in the raised exception
def retry_on_auth_failure():
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except Exception as e:
                # Invalidate token cache and retry
                if VIM_AUTHORIZATION_FAILED in str(e):
                    self.session.invalidate()
                    return func(self, *args, **kwargs)
                # Raise any other type of exception
                raise e

        return wrapper

    return decorator


# TODO(gherzmann): Enhance VIM client to use session-based connections,
# enabling TCP connection reuse for improved efficiency
class VimClient(base.DriverBase):
    """VIM driver."""

    @property
    def token(self):
        # The property is used to guarantee we always get the most recent token
        return self.session.get_token()

    def __init__(self, region: str, session: ks_session.Session, endpoint: str = None):
        self.session = session

        # The nfv_client doesn't support a session, so we need to
        # get an endpoint and token.
        if endpoint is None:
            self.endpoint = session.get_endpoint(
                service_type="nfv",
                region_name=region,
                interface=consts.KS_ENDPOINT_ADMIN,
            )
        else:
            self.endpoint = endpoint

        # session.get_user_id() returns a UUID
        # that always corresponds to 'dcmanager'
        self.username = consts.DCMANAGER_USER_NAME
        # session object does not provide a domain query
        # The only domain used for dcmanager is 'default'
        self.user_domain_name = "default"
        # session.get_project_id() returns a UUID
        # that always corresponds to 'services'
        self.tenant = consts.SERVICES_USER_NAME

    @retry_on_auth_failure()
    def create_strategy(
        self,
        strategy_name,
        storage_apply_type,
        worker_apply_type,
        max_parallel_worker_hosts,
        default_instance_action,
        alarm_restrictions,
        **kwargs,
    ):
        """Create VIM orchestration strategy"""

        url = self.endpoint

        try:
            # TODO(nicodemos): Remove once sw-patch is deprecated
            # Use the REST Api directly to the subcloud to create the strategy for
            # legacy patch orchestration
            if strategy_name == STRATEGY_NAME_SW_PATCH:
                return self._create_strategy_sw_patch(
                    default_instance_action,
                    storage_apply_type,
                    worker_apply_type,
                    max_parallel_worker_hosts,
                    alarm_restrictions,
                )

            strategy = sw_update.create_strategy(
                self.token,
                url,
                strategy_name=strategy_name,
                controller_apply_type=APPLY_TYPE_SERIAL,
                storage_apply_type=storage_apply_type,
                swift_apply_type=APPLY_TYPE_IGNORE,
                worker_apply_type=worker_apply_type,
                max_parallel_worker_hosts=max_parallel_worker_hosts,
                default_instance_action=default_instance_action,
                alarm_restrictions=alarm_restrictions,
                username=self.username,
                user_domain_name=self.user_domain_name,
                tenant=self.tenant,
                **kwargs,
            )
        except Exception as e:
            raise exceptions.VIMClientException(e)
        if not strategy:
            raise exceptions.VIMClientException(
                f"Strategy: {strategy_name} creation failed."
            )

        LOG.debug("Strategy created: %s" % strategy)
        return strategy

    # TODO(nicodemos): Delete this method once sw-patch is deprecated
    def _create_strategy_sw_patch(
        self,
        default_instance_action,
        storage_apply_type,
        worker_apply_type,
        max_parallel_worker_hosts,
        alarm_restrictions,
    ):
        """Create strategy for legacy SW patch orchestration"""

        api_cmd_payload = {
            "controller-apply-type": APPLY_TYPE_SERIAL,
            "swift-apply-type": APPLY_TYPE_IGNORE,
            "default-instance-action": default_instance_action,
            "storage-apply-type": storage_apply_type,
            "worker-apply-type": worker_apply_type,
            "alarm-restrictions": alarm_restrictions,
        }

        if max_parallel_worker_hosts is not None:
            api_cmd_payload["max-parallel-worker-hosts"] = max_parallel_worker_hosts

        response = self._send_api_request(
            "POST",
            f"/api/orchestration/{STRATEGY_NAME_SW_PATCH}/strategy",
            api_cmd_payload,
        )
        return self._add_strategy_response(response)

    @retry_on_auth_failure()
    def get_strategy(self, strategy_name, raise_error_if_missing=True):
        """Get VIM orchestration strategy"""

        url = self.endpoint
        try:
            # TODO(nicodemos): Remove once sw-patch is deprecated
            # Use the REST Api directly to the subcloud to get the strategy for
            # legacy patch orchestration
            if strategy_name == STRATEGY_NAME_SW_PATCH:
                return self._get_strategy_sw_patch()
            strategy = sw_update.get_strategies(
                self.token,
                url,
                strategy_name=strategy_name,
                username=self.username,
                user_domain_name=self.user_domain_name,
                tenant=self.tenant,
            )
        except Exception as e:
            raise exceptions.VIMClientException(e)
        if not strategy:
            if raise_error_if_missing:
                raise exceptions.VIMClientException(
                    f"Get strategy: {strategy_name} failed."
                )

        LOG.debug("Strategy: %s" % strategy)
        return strategy

    # # TODO(nicodemos): Delete this method once sw-patch is deprecated
    def _get_strategy_sw_patch(self):
        """Get legacy SW patch strategy"""

        response = self._send_api_request(
            "GET", f"/api/orchestration/{STRATEGY_NAME_SW_PATCH}/strategy"
        )
        return self._add_strategy_response(response)

    @retry_on_auth_failure()
    def get_current_strategy(self):
        """Get the current active VIM orchestration strategy"""

        url = self.endpoint
        try:
            strategy = sw_update.get_current_strategy(self.token, url)
        except Exception as e:
            raise exceptions.VIMClientException(e)

        LOG.debug("Strategy: %s" % strategy)
        return strategy

    @retry_on_auth_failure()
    def delete_strategy(self, strategy_name):
        """Delete the current VIM orchestration strategy"""

        url = self.endpoint
        try:
            success = sw_update.delete_strategy(
                self.token,
                url,
                strategy_name=strategy_name,
                username=self.username,
                user_domain_name=self.user_domain_name,
                tenant=self.tenant,
            )
        except Exception as e:
            raise exceptions.VIMClientException(e)
        if not success:
            raise exceptions.VIMClientException(
                f"Delete strategy: {strategy_name} failed."
            )

        LOG.debug("Strategy deleted")

    @retry_on_auth_failure()
    def apply_strategy(self, strategy_name):
        """Apply the current orchestration strategy"""

        url = self.endpoint
        try:
            # TODO(nicodemos): Remove once sw-patch is deprecated
            # Use the REST Api directly to the subcloud to apply the strategy for
            # legacy patch orchestration
            if strategy_name == STRATEGY_NAME_SW_PATCH:
                return self._apply_strategy_sw_patch()
            strategy = sw_update.apply_strategy(
                self.token,
                url,
                strategy_name=strategy_name,
                username=self.username,
                user_domain_name=self.user_domain_name,
                tenant=self.tenant,
            )
        except Exception as e:
            raise exceptions.VIMClientException(e)
        if not strategy:
            raise exceptions.VIMClientException(
                f"Strategy: {strategy_name} apply failed."
            )

        LOG.debug("Strategy applied: %s" % strategy)
        return strategy

    # # TODO(nicodemos): Delete this method once sw-patch is deprecated
    def _apply_strategy_sw_patch(self):
        """Apply strategy for legacy SW patch orchestration"""

        api_cmd_payload = {"action": "apply-all"}
        response = self._send_api_request(
            "POST",
            f"/api/orchestration/{STRATEGY_NAME_SW_PATCH}/strategy/actions",
            api_cmd_payload,
        )
        return self._add_strategy_response(response)

    # # TODO(nicodemos): Delete this method once sw-patch is deprecated
    def _send_api_request(self, method, api_path, payload=None):
        """Helper to send an API request to the VIM orchestration system"""
        api_cmd = f"{self.endpoint}{api_path}"

        headers = {
            "Content-Type": "application/json",
            "X-User": self.username,
            "X-Tenant": self.tenant,
            "X-User-Domain-Name": self.user_domain_name,
            "X-Auth-Token": self.token,
        }

        if method == "POST" and payload:
            payload = json.dumps(payload)

        return rest_api.request(self.token, method, api_cmd, headers, payload)

    # # TODO(nicodemos): Delete this method once sw-patch is deprecated
    def _add_strategy_response(self, response):
        """Add response for all strategy phases"""
        if response.get("strategy"):
            for phase in ["build-phase", "apply-phase", "abort-phase"]:
                response["strategy"][phase]["response"] = "success"

        return sw_update._get_strategy_object_from_response(response)

    @retry_on_auth_failure()
    def abort_strategy(self, strategy_name):
        """Abort the current orchestration strategy"""

        url = self.endpoint
        strategy = sw_update.abort_strategy(
            self.token,
            url,
            strategy_name=strategy_name,
            stage_id=None,
            username=self.username,
            user_domain_name=self.user_domain_name,
            tenant=self.tenant,
        )
        if not strategy:
            raise Exception("Strategy abort failed")

        LOG.debug("Strategy aborted: %s" % strategy)
        return strategy
