#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import abc

from oslo_log import log
from retrying import retry

from dcmanager.common import consts
from dcmanager.common.exceptions import InUse
from dcmanager.orchestrator.states.base import BaseState

LOG = log.getLogger(__name__)

# Add extra attempt considering that the client might have already been locked by another worker
CLIENT_LOCKED_MAX_ATTEMPTS = 2


class PatchingState(BaseState):
    def __init__(self, next_state, region_name):
        super(PatchingState, self).__init__(
            next_state=next_state, region_name=region_name)
        self.region_one_patching_cache = None

    @retry(retry_on_exception=lambda ex: isinstance(ex, InUse),
           stop_max_attempt_number=CLIENT_LOCKED_MAX_ATTEMPTS,
           wait_fixed=consts.PLATFORM_RETRY_SLEEP_MILLIS)
    def get_region_one_patches(self, patch_state=None):
        if self.region_one_patching_cache is not None:
            return self.region_one_patching_cache.get_patches(patch_state)
        else:
            LOG.warning("RegionOne patching cache not found. Retrieving patches from client")
            return self.get_patching_client(consts.DEFAULT_REGION_NAME).query(state=patch_state)

    @abc.abstractmethod
    def perform_state_action(self, strategy_step):
        pass
