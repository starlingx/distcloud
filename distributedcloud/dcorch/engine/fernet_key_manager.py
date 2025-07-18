# Copyright (c) 2018-2022, 2024-2025 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from eventlet.green import subprocess
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.endpoint_cache import EndpointCache
from dccommon import utils as cutils
from dcorch.common import consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.common.i18n import _
from dcorch.common import manager
from dcorch.common import utils
from dcorch.rpc import client


FERNET_REPO_MASTER_ID = "keys"
KEY_ROTATE_CMD = "/usr/bin/keystone-fernet-keys-rotate-active"

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class FernetKeyManager(manager.Manager):
    """Manages tasks related to fernet key management"""

    def __init__(self, *args, **kwargs):
        LOG.debug(_("FernetKeyManager initialization..."))

        super(FernetKeyManager, self).__init__(
            service_name="fernet_manager", *args, **kwargs
        )
        self.rpc_client = client.EngineWorkerClient()
        self.context = context.get_admin_context()
        self.endpoint_type = dccommon_consts.ENDPOINT_TYPE_PLATFORM
        self.resource_type = consts.RESOURCE_TYPE_SYSINV_FERNET_REPO

    @classmethod
    def to_resource_info(cls, key_list):
        return dict((getattr(key, "id"), getattr(key, "key")) for key in key_list)

    @classmethod
    def from_resource_info(cls, keys):
        key_list = [dict(id=k, key=v) for k, v in keys.items()]
        return key_list

    @classmethod
    def get_resource_hash(cls, resource_info):
        return hash(tuple(sorted(hash(x) for x in resource_info.items())))

    def _schedule_work(self, operation_type, subcloud=None):
        keys = self._get_master_keys()
        if not keys:
            LOG.info(
                _("No fernet keys returned from %s") % cutils.get_region_one_name()
            )
            return
        try:
            resource_info = FernetKeyManager.to_resource_info(keys)
            utils.enqueue_work(
                self.context,
                self.endpoint_type,
                self.resource_type,
                FERNET_REPO_MASTER_ID,
                operation_type,
                resource_info=jsonutils.dumps(resource_info),
                subcloud=subcloud,
            )
            # wake up sync thread
            if self.rpc_client:
                self.rpc_client.sync_request(self.context, self.endpoint_type)
        except Exception as e:
            LOG.error(_("Exception in schedule_work: %s") % str(e))

    @staticmethod
    def _get_master_keys():
        """get the keys from the local fernet key repo"""
        keys = []
        local_region = cutils.get_region_one_name()
        try:
            # No cached client is required as it is called during the initial
            # sync and after weekly key rotation
            ks_client = KeystoneClient(local_region)
            sysinv_client = SysinvClient(
                local_region,
                ks_client.session,
                endpoint=ks_client.endpoint_cache.get_endpoint("sysinv"),
            )
            keys = sysinv_client.get_fernet_keys()
        except (
            exceptions.ConnectionRefused,
            exceptions.NotAuthorized,
            exceptions.TimeOut,
        ):
            LOG.exception(
                _("Retrieving the fernet keys from %s timeout") % local_region
            )
        except Exception as e:
            LOG.exception(_("Fail to retrieve the master fernet keys: %s") % str(e))
        return keys

    def rotate_fernet_keys(self):
        """Rotate fernet keys."""

        with open(os.devnull, "w") as fnull:
            try:
                # pylint: disable-next=E1102
                subprocess.check_call(KEY_ROTATE_CMD, stdout=fnull, stderr=fnull)
            except subprocess.CalledProcessError:
                msg = _("Failed to rotate the keys")
                LOG.exception(msg)
                raise exceptions.InternalError(message=msg)

        self._schedule_work(consts.OPERATION_TYPE_PUT)

    @staticmethod
    def distribute_keys(subcloud_name, management_ip):
        keys = FernetKeyManager._get_master_keys()
        if not keys:
            LOG.info(
                _("No fernet keys returned from %s") % cutils.get_region_one_name()
            )
            return
        resource_info = FernetKeyManager.to_resource_info(keys)
        key_list = FernetKeyManager.from_resource_info(resource_info)
        FernetKeyManager.update_fernet_repo(subcloud_name, management_ip, key_list)

    @staticmethod
    def update_fernet_repo(subcloud_name, management_ip, key_list=None):
        try:
            keystone_endpoint = cutils.build_subcloud_endpoint(
                management_ip, dccommon_consts.ENDPOINT_NAME_KEYSTONE
            )
            admin_session = EndpointCache.get_admin_session(auth_url=keystone_endpoint)
            sysinv_client = SysinvClient(
                region=subcloud_name,
                session=admin_session,
                endpoint=cutils.build_subcloud_endpoint(
                    management_ip, dccommon_consts.ENDPOINT_NAME_SYSINV
                ),
            )
            sysinv_client.post_fernet_repo(key_list)
        except (
            exceptions.ConnectionRefused,
            exceptions.NotAuthorized,
            exceptions.TimeOut,
        ):
            LOG.exception(_("Update the fernet repo on %s timeout") % subcloud_name)
        except Exception as e:
            error_msg = "subcloud: {}, {}".format(subcloud_name, str(e))
            LOG.exception(_("Fail to update fernet repo %s") % error_msg)
