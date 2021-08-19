# Copyright 2016 Ericsson AB

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
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from oslo_log import log

from nfv_client.openstack import sw_update

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions


LOG = log.getLogger(__name__)

STRATEGY_NAME_FW_UPDATE = 'fw-update'
STRATEGY_NAME_KUBE_UPGRADE = 'kube-upgrade'
STRATEGY_NAME_SW_PATCH = 'sw-patch'
STRATEGY_NAME_SW_UPGRADE = 'sw-upgrade'

APPLY_TYPE_SERIAL = 'serial'
APPLY_TYPE_PARALLEL = 'parallel'
APPLY_TYPE_IGNORE = 'ignore'

INSTANCE_ACTION_MIGRATE = 'migrate'
INSTANCE_ACTION_STOP_START = 'stop-start'

ALARM_RESTRICTIONS_STRICT = 'strict'
ALARM_RESTRICTIONS_RELAXED = 'relaxed'

SW_UPDATE_OPTS_CONST_DEFAULT = {
    "name": consts.SW_UPDATE_DEFAULT_TITLE,
    "storage-apply-type": APPLY_TYPE_PARALLEL,
    "worker-apply-type": APPLY_TYPE_PARALLEL,
    "max-parallel-workers": 10,
    "default-instance-action": INSTANCE_ACTION_MIGRATE,
    "alarm-restriction-type": ALARM_RESTRICTIONS_RELAXED,
    "created-at": None,
    "updated-at": None}

STATE_INITIAL = 'initial'
STATE_BUILDING = 'building'
STATE_BUILD_FAILED = 'build-failed'
STATE_BUILD_TIMEOUT = 'build-timeout'
STATE_READY_TO_APPLY = 'ready-to-apply'
STATE_APPLYING = 'applying'
STATE_APPLY_FAILED = 'apply-failed'
STATE_APPLY_TIMEOUT = 'apply-timeout'
STATE_APPLIED = 'applied'
STATE_ABORTING = 'aborting'
STATE_ABORT_FAILED = 'abort-failed'
STATE_ABORT_TIMEOUT = 'abort-timeout'
STATE_ABORTED = 'aborted'

# The exception message when vim authorization fails
VIM_AUTHORIZATION_FAILED = "Authorization failed"


class VimClient(base.DriverBase):
    """VIM driver."""

    def __init__(self, region, session, endpoint=None):
        try:
            # The nfv_client doesn't support a session, so we need to
            # get an endpoint and token.
            if endpoint is None:
                self.endpoint = session.get_endpoint(
                    service_type='nfv',
                    region_name=region,
                    interface=consts.KS_ENDPOINT_ADMIN)
            else:
                self.endpoint = endpoint

            self.token = session.get_token()

        except exceptions.ServiceUnavailable:
            raise

    def create_strategy(self,
                        strategy_name,
                        storage_apply_type,
                        worker_apply_type,
                        max_parallel_worker_hosts,
                        default_instance_action,
                        alarm_restrictions,
                        **kwargs):
        """Create orchestration strategy"""

        url = self.endpoint
        strategy = sw_update.create_strategy(
            self.token, url,
            strategy_name=strategy_name,
            controller_apply_type=APPLY_TYPE_SERIAL,
            storage_apply_type=storage_apply_type,
            swift_apply_type=APPLY_TYPE_IGNORE,
            worker_apply_type=worker_apply_type,
            max_parallel_worker_hosts=max_parallel_worker_hosts,
            default_instance_action=default_instance_action,
            alarm_restrictions=alarm_restrictions,
            **kwargs)
        if not strategy:
            raise Exception("Strategy:(%s) creation failed" % strategy_name)

        LOG.debug("Strategy created: %s" % strategy)
        return strategy

    def get_strategy(self, strategy_name, raise_error_if_missing=True):
        """Get the current orchestration strategy"""

        url = self.endpoint
        strategy = sw_update.get_strategies(
            self.token, url,
            strategy_name=strategy_name)
        if not strategy:
            if raise_error_if_missing:
                raise Exception("Get strategy failed")

        LOG.debug("Strategy: %s" % strategy)
        return strategy

    def delete_strategy(self, strategy_name):
        """Delete the current orchestration strategy"""

        url = self.endpoint
        success = sw_update.delete_strategy(
            self.token, url,
            strategy_name=strategy_name)
        if not success:
            raise Exception("Delete strategy failed")

        LOG.debug("Strategy deleted")

    def apply_strategy(self, strategy_name):
        """Apply the current orchestration strategy"""

        url = self.endpoint
        strategy = sw_update.apply_strategy(
            self.token, url,
            strategy_name=strategy_name)
        if not strategy:
            raise Exception("Strategy apply failed")

        LOG.debug("Strategy applied: %s" % strategy)
        return strategy

    def abort_strategy(self, strategy_name):
        """Abort the current orchestration strategy"""

        url = self.endpoint
        strategy = sw_update.abort_strategy(
            self.token, url,
            strategy_name=strategy_name,
            stage_id=None)
        if not strategy:
            raise Exception("Strategy abort failed")

        LOG.debug("Strategy aborted: %s" % strategy)
        return strategy
