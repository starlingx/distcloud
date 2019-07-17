# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import six
import time

import functools
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from dcmanager.common import consts as dcm_consts
from dcorch.common import consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.common.i18n import _
from dcorch.common import messaging as rpc_messaging
from dcorch.engine.alarm_aggregate_manager import AlarmAggregateManager
from dcorch.engine.fernet_key_manager import FernetKeyManager
from dcorch.engine.generic_sync_manager import GenericSyncManager
from dcorch.engine.quota_manager import QuotaManager
from dcorch.engine import scheduler
from dcorch.objects import service as service_obj
from oslo_service import service
from oslo_utils import timeutils
from oslo_utils import uuidutils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def request_context(func):
    @functools.wraps(func)
    def wrapped(self, ctx, *args, **kwargs):
        if ctx is not None and not isinstance(ctx, context.RequestContext):
            ctx = context.RequestContext.from_dict(ctx.to_dict())
        try:
            return func(self, ctx, *args, **kwargs)
        except exceptions.OrchestratorException:
            raise oslo_messaging.rpc.dispatcher.ExpectedException()

    return wrapped


class EngineService(service.Service):
    """Lifecycle manager for a running service engine.

    - All the methods in here are called from the RPC client.
    - If a RPC call does not have a corresponding method here, an exceptions
      will be thrown.
    - Arguments to these calls are added dynamically and will be treated as
      keyword arguments by the RPC client.
    """

    def __init__(self, host, topic, manager=None):

        super(EngineService, self).__init__()
        self.host = cfg.CONF.host
        self.rpc_api_version = consts.RPC_API_VERSION
        self.topic = consts.TOPIC_ORCH_ENGINE
        # The following are initialized here, but assigned in start() which
        # happens after the fork when spawning multiple worker processes
        self.engine_id = None
        self.TG = None
        self.periodic_enable = cfg.CONF.scheduler.periodic_enable
        self.periodic_interval = cfg.CONF.scheduler.periodic_interval
        self.target = None
        self._rpc_server = None
        self.qm = None
        self.gsm = None
        self.aam = None
        self.fkm = None

    def init_tgm(self):
        self.TG = scheduler.ThreadGroupManager()

    def init_qm(self):
        self.qm = QuotaManager()

    def init_gsm(self):
        ctxt = context.get_admin_context()
        self.gsm = GenericSyncManager()
        self.gsm.init_from_db(ctxt)

    def init_aam(self):
        self.aam = AlarmAggregateManager()

    def init_fkm(self):
        self.fkm = FernetKeyManager(self.gsm)

    def start(self):
        self.engine_id = uuidutils.generate_uuid()
        self.init_tgm()
        self.init_qm()
        self.init_gsm()
        self.init_aam()
        self.init_fkm()
        target = oslo_messaging.Target(version=self.rpc_api_version,
                                       server=self.host,
                                       topic=self.topic)
        self.target = target
        self._rpc_server = rpc_messaging.get_rpc_server(self.target, self)
        self._rpc_server.start()

        self.service_registry_cleanup()

        self.TG.add_timer(cfg.CONF.report_interval,
                          self.service_registry_report)

        super(EngineService, self).start()
        if self.periodic_enable:
            LOG.info("Adding periodic tasks for the engine to perform")
            self.TG.add_timer(self.periodic_interval,
                              self.periodic_sync_audit,
                              initial_delay=self.periodic_interval / 2)
            self.TG.add_timer(CONF.fernet.key_rotation_interval *
                              consts.SECONDS_IN_HOUR,
                              self.periodic_key_rotation,
                              initial_delay=(CONF.fernet.key_rotation_interval
                                             * consts.SECONDS_IN_HOUR))

    def service_registry_report(self):
        ctx = context.get_admin_context()
        try:
            svc = service_obj.Service.update(ctx, self.engine_id)
            # if svc is None, means it's not created.
            if svc is None:
                service_obj.Service.create(ctx, self.engine_id, self.host,
                                           'dcorch-engine', self.topic)
        except Exception as ex:
            LOG.error('Service %(service_id)s update failed: %(error)s',
                      {'service_id': self.engine_id, 'error': ex})

    def service_registry_cleanup(self):
        ctx = context.get_admin_context()
        time_window = (2 * cfg.CONF.report_interval)
        services = service_obj.Service.get_all(ctx)
        for svc in services:
            if svc['id'] == self.engine_id:
                continue
            if timeutils.is_older_than(svc['updated_at'], time_window):
                # < time_line:
                # hasn't been updated, assuming it's died.
                LOG.info('Service %s was aborted', svc['id'])
                service_obj.Service.delete(ctx, svc['id'])

    def periodic_balance_all(self, engine_id):
        # Automated Quota Sync for all the keystone projects
        LOG.info("Periodic quota sync job started at: %s",
                 time.strftime("%c"))
        self.qm.periodic_balance_all(engine_id)

    @request_context
    def get_usage_for_project_and_user(self, context, endpoint_type,
                                       project_id, user_id=None):
        # Returns cached usage as of last quota sync audit so will be
        # slightly stale.
        return self.qm.get_usage_for_project_and_user(endpoint_type,
                                                      project_id, user_id)

    @request_context
    def quota_sync_for_project(self, context, project_id):
        # On Demand Quota Sync for a project, will be triggered by KB-API
        LOG.info("On Demand Quota Sync Called for: %s",
                 project_id)
        self.qm.quota_sync_for_project(project_id)

    @request_context
    def add_subcloud(self, ctxt, subcloud_name, sw_version):

        self.gsm.add_subcloud(ctxt, subcloud_name, sw_version)

    @request_context
    # todo: add authentication since ctxt not actually needed later
    def del_subcloud(self, ctxt, subcloud_name):
        self.gsm.del_subcloud(ctxt, subcloud_name)

    @request_context
    # todo: add authentication since ctxt not actually needed later
    def update_subcloud_states(self, ctxt, subcloud_name,
                               management_state,
                               availability_status):
        # keep equivalent functionality for now
        if (management_state == dcm_consts.MANAGEMENT_MANAGED) and \
                (availability_status == dcm_consts.AVAILABILITY_ONLINE):
            # Initial identity sync. It's synchronous so that identity
            # get synced before fernet token keys are synced. This is
            # necessary since we want to revoke all existing tokens on
            # this subcloud after its services user IDs and project
            # IDs are changed. Otherwise subcloud services will fail
            # authentication since they keep on using their existing tokens
            # issued before these IDs change, until these tokens expires.
            try:
                self.gsm.initial_sync(ctxt, subcloud_name)
                self.fkm.distribute_keys(ctxt, subcloud_name)
                self.aam.enable_snmp(ctxt, subcloud_name)
                self.gsm.enable_subcloud(ctxt, subcloud_name)
            except Exception as ex:
                LOG.warning('Update subcloud state failed for %s: %s',
                            subcloud_name, six.text_type(ex))
                raise
        else:
            self.gsm.disable_subcloud(ctxt, subcloud_name)
            if (management_state == dcm_consts.MANAGEMENT_UNMANAGED):
                self.fkm.reset_keys(subcloud_name)

    @request_context
    def add_subcloud_sync_endpoint_type(self, ctxt, subcloud_name,
                                        endpoint_type_list=None):
        try:
            self.gsm.add_subcloud_sync_endpoint_type(
                ctxt, subcloud_name,
                endpoint_type_list=endpoint_type_list)
        except Exception as ex:
            LOG.warning('Add subcloud endpoint type failed for %s: %s',
                        subcloud_name, six.text_type(ex))
            raise

    @request_context
    def remove_subcloud_sync_endpoint_type(self, ctxt, subcloud_name,
                                           endpoint_type_list=None):
        try:
            self.gsm.remove_subcloud_sync_endpoint_type(
                ctxt, subcloud_name,
                endpoint_type_list=endpoint_type_list)
        except Exception as ex:
            LOG.warning('Remove subcloud endpoint type failed for %s: %s',
                        subcloud_name, six.text_type(ex))
            raise

    @request_context
    # todo: add authentication since ctxt not actually needed later
    def update_subcloud_version(self, ctxt, subcloud_name, sw_version):
        self.gsm.update_subcloud_version(ctxt, subcloud_name, sw_version)

    @request_context
    def update_alarm_summary(self, ctxt, region_name):
        self.aam.update_alarm_summary(ctxt, region_name)

    @request_context
    def get_alarm_summary(self, ctxt):
        return self.aam.get_alarm_summary(ctxt)

    @request_context
    # The sync job info has been written to the DB, alert the sync engine
    # that there is work to do.
    # todo: add authentication since ctxt not actually needed later
    def sync_request(self, ctxt, endpoint_type):
        self.gsm.sync_request(ctxt, endpoint_type)

    def periodic_sync_audit(self):
        # subcloud sync audit
        LOG.info("Periodic sync audit started at: %s",
                 time.strftime("%c"))
        self.gsm.run_sync_audit()

    def _stop_rpc_server(self):
        # Stop RPC connection to prevent new requests
        LOG.debug(_("Attempting to stop engine service..."))
        try:
            self._rpc_server.stop()
            self._rpc_server.wait()
            LOG.info('Engine service stopped successfully')
        except Exception as ex:
            LOG.error('Failed to stop engine service: %s',
                      six.text_type(ex))

    def stop(self):
        self._stop_rpc_server()

        self.TG.stop()
        if self.aam:
            self.aam.shutdown()
        # Terminate the engine process
        LOG.info("All threads were gone, terminating engine")
        super(EngineService, self).stop()

    def periodic_key_rotation(self):
        """Periodic key rotation."""
        LOG.info("Periodic key rotation started at: %s", time.strftime("%c"))
        return self.fkm.rotate_fernet_keys()
