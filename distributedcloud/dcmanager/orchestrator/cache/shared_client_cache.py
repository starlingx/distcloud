#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from oslo_concurrency import lockutils
from oslo_log import log
import retrying

from dcmanager.common.exceptions import InvalidParameterValue
from dcmanager.orchestrator.cache.cache_specifications import CacheSpecification

LOG = log.getLogger(__name__)


class SharedClientCache(object):
    """Data cache for sharing client or API data between concurrent threads

    Used to avoid repeated requests and prevent client overload.

    Cache is not self refreshing. User of the cache is responsible for triggering
    the refresh.

    """

    def __init__(self, cache_type: str, cache_specification: CacheSpecification):
        """Create cache instance.

        :param cache_type: type of data being cached, for logging
        :param cache_specification: specifications on how the cache should operate
        """
        self._client_lock = lockutils.ReaderWriterLock()
        self._cache = None

        # Cache configurations
        self._cache_type = cache_type
        self._valid_filters = cache_specification.valid_filters

        # Retry configurations
        self._max_attempts = cache_specification.max_attempts
        self._retry_sleep_msecs = cache_specification.retry_sleep_msecs

        # Add retry to client read if any retryable exception is provided
        self._load_data_from_client = cache_specification.fetch_implementation
        retry_on_exception = cache_specification.retry_on_exception
        if retry_on_exception:
            retry = retrying.retry(
                retry_on_exception=lambda ex: isinstance(ex, retry_on_exception),
                stop_max_attempt_number=self._max_attempts,
                wait_fixed=self._retry_sleep_msecs,
                wait_func=self._retry_client_read,
            )
            self._load_data_from_client = retry(
                cache_specification.fetch_implementation
            )

        # Use default implementation with no filtering if none is provided
        self._post_filter_impl = cache_specification.post_filter_implementation or (
            lambda data, **filter_params: data
        )

    def read(self, **filter_params):
        """Retrieve data from cache, if available.

        Read from client and (re)populate cache, if not.

        Only one thread may access the client at a time to prevent overload.

        Concurrent reads are blocked until client read completes/fails. A recheck
        for updates on the cache is performed afterwards.

        Post-filtering can be applied to the results before returning. Data saved to
        the cache will not include any filtering applied to returned data.

        :param filter_params: parameters to be used for post-filtering
        :type filter_params: string
        :return: Cached data, filtered according to parameters given
        :raises RuntimeError: If cache read fails due to concurrent client read error
        :raises InvalidParameterError: If invalid filter parameters are given
        """
        # Use data stored in the cache, if present. Otherwise, read and cache
        # data from client
        if self._cache is None:
            self._cache_data_from_client()

        # Filter cached data and return results
        return self._post_filter(self._cache, **filter_params)

    def _cache_data_from_client(self):
        # Read from the client and update cache if no concurrent write is in progress
        if self._client_lock.owner != lockutils.ReaderWriterLock.WRITER:
            with self._client_lock.write_lock():
                # Atomically fetch data from client and update the cache
                LOG.info(f"Reading data from {self._cache_type} client for caching")
                self._cache = self._load_data_from_client()
        else:
            # If a concurrent write is in progress, wait for it and recheck cache
            with self._client_lock.read_lock():
                if self._cache is None:
                    raise RuntimeError(
                        f"Failed to retrieve data from {self._cache_type} cache. "
                        "Possible failure on concurrent client read."
                    )

    def _retry_client_read(self, attempt: int, _: int):
        """Determines the retry interval

        This function should return the interval between retries in milliseconds,
        The retrying module calls it passing the attempt number and the delay
        since the first attempt in milliseconds.

        It is used here as a way to add a log message during retries

        :param int attempt: Number of attempts
        :param int _: Delay since the first attempt in milliseconds (not used)
        :return int: Expected delay between attempts in milliseconds
        """
        # To be called when a client read operation fails with a retryable error
        # After this, read operation should be retried
        LOG.warn(
            f"Retryable error occurred while reading from {self._cache_type} client "
            f"(Attempt {attempt}/{self._max_attempts})"
        )
        return self._retry_sleep_msecs

    def _post_filter(self, data, **filter_params):
        # Validate the parameters and apply specified filter implementation
        self._validate_filter_params(**filter_params)
        return self._post_filter_impl(data, **filter_params)

    def _validate_filter_params(self, **filter_params):
        # Compare each passed parameter against the specified valid parameters
        # Raise an exception if any unexpected parameter is found
        if filter_params:
            invalid_params = set(filter_params.keys()) - self._valid_filters
            if invalid_params:
                raise InvalidParameterValue(
                    err=f"Invalid filter parameters: {invalid_params}"
                )
