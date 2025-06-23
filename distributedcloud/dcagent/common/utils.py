#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import threading

from oslo_config import cfg
from oslo_log import log as logging
from tsconfig import tsconfig as tsc

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.endpoint_cache import EndpointCache


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


# TODO(vgluzrom): Implement lru_cache from functools to handle described case
def cache_wrapper(cls):
    """Decorator to cache the results of the methods in the class.

    Note: This decorator only caches the results based on the function name.
    It cannot handle the case where the same function is called with different
    arguments and the result is different.
    """

    def wrap_method(method):
        def wrapper(self, *args, **kwargs):
            # Return the cached result if available
            use_cache = getattr(self, "use_cache", False)
            if use_cache and method.__name__ in self.__class__._results:
                response = self.__class__._results[method.__name__]
                LOG.debug(
                    f"Returning cached response for {method.__name__} "
                    f"from {self.__class__.__name__}. Response: {response}"
                )
                return response

            try:
                result = method(self, *args, **kwargs)
                # Cache the results in the '_result' class variable
                LOG.debug(
                    f"Saving new response for {method.__name__} "
                    f"in {self.__class__.__name__}. Response: {result}"
                )
                with self.__class__._lock:
                    self.__class__._results[method.__name__] = result
                return result
            except Exception as e:
                LOG.exception(
                    f"Error in {method.__name__} from {self.__class__.__name__}: {e}"
                )
                # Clear the cached result if an exception occurs
                with self.__class__._lock:
                    if method.__name__ in self.__class__._results:
                        del self.__class__._results[method.__name__]
                raise

        return wrapper

    # Apply the wrapper to all non private functions in the class
    for attr_name in dir(cls):
        if not attr_name.startswith("_"):
            attr = getattr(cls, attr_name)
            if callable(attr):
                setattr(cls, attr_name, wrap_method(attr))
    return cls


@cache_wrapper
class CachedSysinvClient(SysinvClient):
    _results = {}
    _lock = threading.Lock()


@cache_wrapper
class CachedFmClient(FmClient):
    _results = {}
    _lock = threading.Lock()


@cache_wrapper
class CachedSoftwareClient(SoftwareClient):
    _results = {}
    _lock = threading.Lock()


class BaseAuditManager(object):
    def __init__(self):
        self.keystone_client = None
        self.sysinv_client = None
        self.fm_client = None
        self.software_client = None

    def initialize_clients(
        self,
        use_cache: bool = True,
        request_token: str = None,
    ):

        region_name = tsc.region_1_name
        admin_session = EndpointCache.get_admin_session()

        self.sysinv_client = CachedSysinvClient(
            region_name,
            admin_session,
            endpoint_type=dccommon_consts.KS_ENDPOINT_INTERNAL,
            token=request_token,
        )
        self.fm_client = CachedFmClient(
            region_name,
            admin_session,
            endpoint_type=dccommon_consts.KS_ENDPOINT_INTERNAL,
            token=request_token,
        )
        self.software_client = CachedSoftwareClient(
            admin_session,
            region=region_name,
            endpoint_type=dccommon_consts.KS_ENDPOINT_INTERNAL,
            token=request_token,
        )
        self.sysinv_client.use_cache = use_cache
        self.fm_client.use_cache = use_cache
        self.software_client.use_cache = use_cache
        return self.sysinv_client, self.fm_client, self.software_client
