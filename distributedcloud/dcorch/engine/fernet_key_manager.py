# Copyright 2018-2021 Wind River
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

from eventlet.green import subprocess
import os

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dcorch.common import consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.common.i18n import _
from dcorch.common import manager
from dcorch.common import utils


FERNET_REPO_MASTER_ID = "keys"
KEY_ROTATE_CMD = "/usr/bin/keystone-fernet-keys-rotate-active"

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class FernetKeyManager(manager.Manager):
    """Manages tasks related to fernet key management"""

    def __init__(self, gsm, *args, **kwargs):
        LOG.debug(_('FernetKeyManager initialization...'))

        super(FernetKeyManager, self).__init__(service_name="fernet_manager",
                                               *args, **kwargs)
        self.gsm = gsm
        self.context = context.get_admin_context()
        self.endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        self.resource_type = consts.RESOURCE_TYPE_SYSINV_FERNET_REPO

    @classmethod
    def to_resource_info(cls, key_list):
        return dict((getattr(key, 'id'), getattr(key, 'key'))
                    for key in key_list)

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
            LOG.info(_("No fernet keys returned from %s") %
                     dccommon_consts.CLOUD_0)
            return
        try:
            resource_info = FernetKeyManager.to_resource_info(keys)
            utils.enqueue_work(self.context,
                               self.endpoint_type,
                               self.resource_type,
                               FERNET_REPO_MASTER_ID,
                               operation_type,
                               resource_info=jsonutils.dumps(resource_info),
                               subcloud=subcloud)
            # wake up sync thread
            if self.gsm:
                self.gsm.sync_request(self.context, self.endpoint_type)
        except Exception as e:
            LOG.error(_("Exception in schedule_work: %s") % str(e))

    @staticmethod
    def _get_master_keys():
        """get the keys from the local fernet key repo"""
        keys = []
        try:
            # No cached client is required as it is called during the initial
            # sync and after weekly key rotation
            ks_client = KeystoneClient(dccommon_consts.CLOUD_0)
            sysinv_client = SysinvClient(dccommon_consts.CLOUD_0,
                                         ks_client.session,
                                         ks_client.endpoint_cache.get_endpoint('sysinv'))
            keys = sysinv_client.get_fernet_keys()
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info(_("Retrieving the fernet keys from %s timeout") %
                     dccommon_consts.CLOUD_0)
        except Exception as e:
            LOG.info(_("Fail to retrieve the master fernet keys: %s") %
                     str(e))
        return keys

    def rotate_fernet_keys(self):
        """Rotate fernet keys."""

        with open(os.devnull, "w") as fnull:
            try:
                subprocess.check_call(KEY_ROTATE_CMD,  # pylint: disable=E1102
                                      stdout=fnull,
                                      stderr=fnull)
            except subprocess.CalledProcessError:
                msg = _("Failed to rotate the keys")
                LOG.exception(msg)
                raise exceptions.InternalError(message=msg)

        self._schedule_work(consts.OPERATION_TYPE_PUT)

    def distribute_keys(self, ctxt, subcloud_name):
        keys = self._get_master_keys()
        if not keys:
            LOG.info(_("No fernet keys returned from %s") %
                     dccommon_consts.CLOUD_0)
            return
        resource_info = FernetKeyManager.to_resource_info(keys)
        key_list = FernetKeyManager.from_resource_info(resource_info)
        self.update_fernet_repo(subcloud_name, key_list)

    def reset_keys(self, subcloud_name):
        self.update_fernet_repo(subcloud_name)

    @staticmethod
    def update_fernet_repo(subcloud_name, key_list=None):
        try:
            # No cached client is required as it is only called during the
            # initial sync
            ks_client = KeystoneClient(subcloud_name)
            sysinv_client = SysinvClient(subcloud_name, ks_client.session,
                                         ks_client.endpoint_cache.get_endpoint('sysinv'))
            sysinv_client.post_fernet_repo(key_list)
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info(_("Update the fernet repo on %s timeout") %
                     subcloud_name)
        except Exception as e:
            error_msg = "subcloud: {}, {}".format(subcloud_name, str(e))
            LOG.info(_("Fail to update fernet repo %s") % error_msg)
