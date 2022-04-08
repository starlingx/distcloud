#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from contextlib import contextmanager

from oslo_log import log

from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dcmanager.common import consts
from dcmanager.common.exceptions import InUse
from dcmanager.orchestrator.states.base import BaseState

import threading

LOG = log.getLogger(__name__)


class RegionOnePatchingCache(object):
    def __init__(self):
        self._client_lock = threading.Lock()
        self._patches = None

    def get_patches(self, patch_state=None):
        # Use currently stored patches, if present
        if self._patches is None:
            with nonblocking(self._client_lock) as with_lock:
                if with_lock:
                    # Atomically fetch the patches and update the cache
                    LOG.info("Fetching patches from RegionOne client for caching")
                    self._patches = self._get_patching_client().query()
                else:
                    # Raise exception if another worker is already updating the cache
                    raise InUse()

        # Filter patches by the desired state, if any was provided
        return {patch_id: patch for patch_id, patch in self._patches.items()
                if patch_state is None or patch['repostate'] == patch_state}

    @staticmethod
    def _get_patching_client():
        ks_client = BaseState.get_keystone_client()
        return PatchingClient(consts.DEFAULT_REGION_NAME, ks_client.session,
                              endpoint=ks_client.endpoint_cache.get_endpoint('patching'))


@contextmanager
def nonblocking(lock):
    with_lock = lock.acquire(False)
    try:
        yield with_lock
    finally:
        if with_lock:
            lock.release()
