#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log

from dcmanager.common.exceptions import InvalidParameterValue
from dcmanager.orchestrator.cache import cache_specifications
from dcmanager.orchestrator.cache.shared_client_cache import SharedClientCache

LOG = log.getLogger(__name__)


class SharedCacheRepository(object):

    def __init__(self, operation_type):
        self._shared_caches = {}
        self._operation_type = operation_type

    def initialize_caches(self):
        # Retrieve specifications for each cache type required by the operation
        operation_specifications = (
            cache_specifications.get_specifications_for_operation(self._operation_type)
        )

        # Create shared caches mapping
        self._shared_caches = {
            cache_type: SharedClientCache(cache_type, cache_specification)
            for cache_type, cache_specification in operation_specifications.items()
        }

    def read(self, cache_type: str, **filter_params):
        cache = self._shared_caches.get(cache_type)
        if cache:
            return cache.read(**filter_params)
        raise InvalidParameterValue(
            err=f"Specified cache type '{cache_type}' not present"
        )
