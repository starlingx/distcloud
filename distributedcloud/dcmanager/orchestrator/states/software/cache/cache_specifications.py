#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.orchestrator.states.software.cache import clients
from dcmanager.orchestrator.states.software.cache.clients import \
    CLIENT_READ_EXCEPTIONS
from dcmanager.orchestrator.states.software.cache.clients import \
    CLIENT_READ_MAX_ATTEMPTS


class CacheSpecification(object):
    def __init__(self, fetch_implementation,
                 post_filter_implementation=None, valid_filters=frozenset(),
                 retry_on_exception=CLIENT_READ_EXCEPTIONS,
                 max_attempts=CLIENT_READ_MAX_ATTEMPTS,
                 retry_sleep_msecs=consts.PLATFORM_RETRY_SLEEP_MILLIS):
        """Create cache specification.

        :param fetch_implementation: implementation on how to retrieve data from
        client
        :type fetch_implementation: function
        :param post_filter_implementation: implementation on how to post-filter
        cached data, if any
        :type post_filter_implementation: function
        :param valid_filters: valid post-filter parameters
        :type valid_filters: set
        :param retry_on_exception: exceptions to be retried on client read
        :type retry_on_exception: type|tuple
        :param max_attempts: Maximum number of client read attempts if retryable
        exceptions occur
        :param retry_sleep_msecs: Fixed backoff interval
        """
        self.fetch_implementation = fetch_implementation
        self.post_filter_implementation = post_filter_implementation
        self.valid_filters = valid_filters

        # Retry configurations
        self.retry_on_exception = retry_on_exception
        self.max_attempts = max_attempts
        self.retry_sleep_msecs = retry_sleep_msecs


"""Cache types"""

REGION_ONE_LICENSE_CACHE_TYPE = 'RegionOne system license'
REGION_ONE_SYSTEM_INFO_CACHE_TYPE = 'RegionOne system info'
REGION_ONE_RELEASE_USM_CACHE_TYPE = 'RegionOne release usm'

"""Cache specifications"""

REGION_ONE_LICENSE_CACHE_SPECIFICATION = CacheSpecification(
    lambda: clients.get_sysinv_client().get_license())

REGION_ONE_SYSTEM_INFO_CACHE_SPECIFICATION = CacheSpecification(
    lambda: clients.get_sysinv_client().get_system())

REGION_ONE_RELEASE_USM_CACHE_SPECIFICATION = CacheSpecification(
    lambda: clients.get_software_client().list(),
    # Filter results by release_id and/or state, if any is given
    lambda patches, **filter_params: [
        patch
        for patch in patches
        if (
            filter_params.get("release_id") is None
            or patch.get("release_id") == filter_params.get("release_id")
        )
        and (
            filter_params.get("state") is None
            or patch.get("state") == filter_params.get("state")
        )
    ],
    {"release_id", "state"},
)

# Map each expected operation type to its required cache types
CACHE_TYPES_BY_OPERATION_TYPE = {
    consts.SW_UPDATE_TYPE_SOFTWARE: {REGION_ONE_LICENSE_CACHE_TYPE,
                                     REGION_ONE_SYSTEM_INFO_CACHE_TYPE,
                                     REGION_ONE_RELEASE_USM_CACHE_TYPE}
}

# Map each cache type to its corresponding cache specification
SPECIFICATION_BY_CACHE_TYPE = {
    REGION_ONE_LICENSE_CACHE_TYPE: REGION_ONE_LICENSE_CACHE_SPECIFICATION,
    REGION_ONE_SYSTEM_INFO_CACHE_TYPE: REGION_ONE_SYSTEM_INFO_CACHE_SPECIFICATION,
    REGION_ONE_RELEASE_USM_CACHE_TYPE: REGION_ONE_RELEASE_USM_CACHE_SPECIFICATION
}


def get_specifications_for_operation(operation_type):
    # Retrieve all cache specifications required by a given operation type
    # Return a mapping between each required type to its corresponding specification
    return {cache_type: SPECIFICATION_BY_CACHE_TYPE.get(cache_type)
            for cache_type in CACHE_TYPES_BY_OPERATION_TYPE.get(operation_type)}
