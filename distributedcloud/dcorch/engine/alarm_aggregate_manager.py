# Copyright 2016 Ericsson AB
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

import datetime
from dccommon import consts as dccommon_consts
from dccommon import exceptions as dccommon_exceptions
from dcmanager.common import consts as dcm_consts
from dcorch.common import consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.common.i18n import _
from dcorch.common import manager
from dcorch.db import api as db_api

from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack import sdk_platform as sdk
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

from oslo_config import cfg
from oslo_log import log as logging

import threading
import time

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class AlarmAggregateManager(manager.Manager):
    """Manages tasks related to alarm aggregation"""

    def __init__(self, *args, **kwargs):
        LOG.debug(_('AlarmAggregateManager initialization...'))

        super(AlarmAggregateManager, self).\
            __init__(service_name="alarm_aggregate_manager", *args, **kwargs)
        self.context = context.get_admin_context()
        self.alarm_update_thread = PeriodicAlarmUpdate(self)
        self.alarm_update_thread.start()

    def shutdown(self):
        self.alarm_update_thread.stop()
        self.alarm_update_thread.join()

    def enable_snmp(self, ctxt, subcloud_name):
        LOG.info("Enabling fm-aggregation trap for region_name=%s" %
                 subcloud_name)

        payload = {"ip_address": CONF.snmp.snmp_ip,
                   "community": CONF.snmp.snmp_comm_str}
        try:
            ks_client = KeystoneClient(subcloud_name)
            sysinv_client = SysinvClient(subcloud_name, ks_client.session)
            fm_client = FmClient(subcloud_name, ks_client.session,
                                 dccommon_consts.KS_ENDPOINT_DEFAULT)
            sysinv_client.snmp_trapdest_create(payload)
            self.update_alarm_summary(self.context, subcloud_name,
                                      fm_client=fm_client)
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("snmp_trapdest_create exception Timeout region_name=%s" %
                     subcloud_name)
            pass
        except AttributeError:
            LOG.info("snmp_trapdest_create AttributeError region_name=%s" %
                     subcloud_name)
            pass
        except dccommon_exceptions.TrapDestAlreadyExists:
            LOG.info("snmp_trapdest_create TrapDestAlreadyExists "
                     "region_name=%s payload %s" % (subcloud_name, payload))
            pass
        except Exception:
            LOG.info("snmp_trapdest_create exception region_name=%s" %
                     subcloud_name)
            pass

    def update_alarm_summary(self, cntx, region_name, thread_name=None,
                             fm_client=None):
        LOG.info("Updating alarm summary for %s" % region_name)
        try:
            if fm_client is not None:
                alarms = fm_client.get_alarm_summary()
            else:
                os_client = sdk.OpenStackDriver(region_name=region_name,
                                                thread_name=thread_name)
                alarms = os_client.fm_client.get_alarm_summary()
            alarm_updates = {'critical_alarms': alarms[0].critical,
                             'major_alarms': alarms[0].major,
                             'minor_alarms': alarms[0].minor,
                             'warnings': alarms[0].warnings}
            alarm_updates = self._set_cloud_status(alarm_updates)
            db_api.subcloud_alarms_update(self.context, region_name,
                                          alarm_updates)
        except Exception:
            LOG.error('Failed to update alarms for %s' % region_name)

    def _set_cloud_status(self, alarm_dict):
        status = consts.ALARM_OK_STATUS
        if (alarm_dict.get('major_alarms') > 0) or\
           (alarm_dict.get('minor_alarms') > 0):
            status = consts.ALARM_DEGRADED_STATUS
        if (alarm_dict.get('critical_alarms') > 0):
            status = consts.ALARM_CRITICAL_STATUS
        alarm_dict['cloud_status'] = status
        return alarm_dict

    def get_alarm_summary(self, ctxt):
        alarms = db_api.subcloud_alarms_get_all(self.context)
        summary = []
        for alarm in alarms:
            alarm_dict = {'region_name': alarm['region_name'],
                          'uuid': alarm['uuid'],
                          'critical_alarms': alarm['critical_alarms'],
                          'major_alarms': alarm['major_alarms'],
                          'minor_alarms': alarm['minor_alarms'],
                          'warnings': alarm['warnings'],
                          'cloud_status': alarm['cloud_status']}
            summary.append(alarm_dict)
        return summary


class PeriodicAlarmUpdate(threading.Thread):
    def __init__(self, parent):
        super(PeriodicAlarmUpdate, self).__init__()
        self.parent = parent
        self.context = context.get_admin_context()
        self._stop = threading.Event()
        self.interval = CONF.snmp.alarm_audit_interval_time
        self.system_last_update = datetime.datetime.now()

    def run_updates(self):
        while not self.stopped():
            delta = (datetime.datetime.now() -
                     self.system_last_update).total_seconds()
            if delta < self.interval:
                time.sleep(1.0)
                continue
            try:
                LOG.info('Running alarm summary update sync')
                self.system_last_update = datetime.datetime.now()
                subclouds = db_api.subcloud_get_all(self.context)
                for subcloud in subclouds:
                    if self.stopped():
                        break
                    if subcloud['availability_status'] ==\
                            dcm_consts.AVAILABILITY_ONLINE:
                        self.parent.\
                            update_alarm_summary(self.context,
                                                 subcloud['region_name'],
                                                 self.name)
            except Exception:
                pass
            time.sleep(1.0)
        LOG.info("Periodic Alarm Update Thread Stopped")

    def stopped(self):
        return self._stop.isSet()

    def stop(self):
        LOG.info("Periodic Alarm Update Thread Stopping")
        self._stop.set()

    def run(self):
        self.run_updates()
