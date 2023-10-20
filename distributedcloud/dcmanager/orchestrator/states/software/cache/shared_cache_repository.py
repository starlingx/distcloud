#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log

from dcmanager.common.exceptions import InvalidParameterValue
from dcmanager.orchestrator.states.software.cache import cache_specifications
from dcmanager.orchestrator.states.software.cache.shared_client_cache import \
    SharedClientCache

LOG = log.getLogger(__name__)


class SharedCacheRepository(object):

    def __init__(self, operation_type):
        self._shared_caches = {}
        self._operation_type = operation_type

    def initialize_caches(self):
        # Retrieve specifications for each cache type required by the operation
        # Return mapping between each required type to a single cache instance of it
        self._shared_caches = {
            cache_type: SharedClientCache(cache_type, cache_specification)
            for cache_type, cache_specification in
            cache_specifications.get_specifications_for_operation(
                self._operation_type).items()
        }

    def read(self, cache_type, **filter_params):
        cache = self._shared_caches.get(cache_type)
        if cache:
            return cache.read(**filter_params)
        else:
            raise InvalidParameterValue(err="Specified cache type '%s' not "
                                            "present" % cache_type)
