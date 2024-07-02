#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dataclasses import dataclass
import typing

from dcmanager.common import consts
from dcmanager.orchestrator.cache import clients


@dataclass
class CacheSpecification(object):
    """A cache specification.

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

    fetch_implementation: typing.Callable
    post_filter_implementation: typing.Optional[typing.Callable] = None
    valid_filters: typing.Set = frozenset()
    retry_on_exception: typing.Tuple[typing.Type[Exception], ...] = (
        clients.CLIENT_READ_EXCEPTIONS
    )
    max_attempts: int = clients.CLIENT_READ_MAX_ATTEMPTS
    retry_sleep_msecs: int = consts.PLATFORM_RETRY_SLEEP_MILLIS


# Cache types
REGION_ONE_LICENSE_CACHE_TYPE = "RegionOne system license"
REGION_ONE_SYSTEM_INFO_CACHE_TYPE = "RegionOne system info"
REGION_ONE_RELEASE_USM_CACHE_TYPE = "RegionOne release usm"
REGION_ONE_KUBERNETES_CACHE_TYPE = "RegionOne kubernetes version"

# Cache specifications
REGION_ONE_KUBERNETES_CACHE_SPECIFICATION = CacheSpecification(
    lambda: clients.get_sysinv_client().get_kube_versions()
)

# Map each expected operation type to its required cache types
CACHE_TYPES_BY_OPERATION_TYPE = {
    consts.SW_UPDATE_TYPE_KUBERNETES: {
        REGION_ONE_KUBERNETES_CACHE_TYPE: REGION_ONE_KUBERNETES_CACHE_SPECIFICATION
    }
}


def get_specifications_for_operation(operation_type: str):
    """Retrieve all cache specifications required by an operation type

    :param str operation_type: The software update strategy type
    :return dict: A mapping between each cache type to its specification
    """
    return CACHE_TYPES_BY_OPERATION_TYPE.get(operation_type, {})
