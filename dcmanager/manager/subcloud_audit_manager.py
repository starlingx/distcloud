# Copyright 2017 Ericsson AB.
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
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from oslo_log import log as logging


from dcorch.drivers.openstack.keystone_v3 import KeystoneClient
from dcorch.rpc import client as dcorch_rpc_client

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.db import api as db_api

from dcmanager.drivers.openstack.sysinv_v1 import SysinvClient
from keystoneauth1 import exceptions as keystone_exceptions

from fm_api import constants as fm_const
from fm_api import fm_api

LOG = logging.getLogger(__name__)


class SubcloudAuditManager(manager.Manager):
    """Manages tasks related to audits."""

    def __init__(self, *args, **kwargs):
        LOG.debug(_('SubcloudAuditManager initialization...'))

        super(SubcloudAuditManager, self).__init__(
            service_name="subcloud_audit_manager")
        self.context = context.get_admin_context()
        self.dcorch_rpc_client = dcorch_rpc_client.EngineClient()
        self.fm_api = fm_api.FaultAPIs()
        self.subcloud_manager = kwargs['subcloud_manager']

    def periodic_subcloud_audit(self):
        """Audit availability of subclouds."""

        # Blanket catch all exceptions in the audit so that the audit
        # does not die.
        try:
            self._periodic_subcloud_audit_loop()
        except Exception as e:
            LOG.exception(e)

    def _periodic_subcloud_audit_loop(self):
        """Audit availability of subclouds loop."""
        # We will be running in our own green thread here.
        LOG.info('Triggered subcloud audit.')

        # For each subcloud, if at least one service is active in
        # each service of servicegroup-list then declare the subcloud online.

        for subcloud in db_api.subcloud_get_all(self.context):
            subcloud_name = subcloud.name
            subcloud_id = subcloud.id
            management_state = subcloud.management_state
            avail_status_current = subcloud.availability_status
            audit_fail_count = subcloud.audit_fail_count

            # Set defaults to None and disabled so we will still set disabled
            # status if we encounter an error.

            sysinv_client = None
            svc_groups = None
            avail_to_set = consts.AVAILABILITY_OFFLINE

            try:
                ks_client = KeystoneClient(subcloud_name)
                sysinv_client = SysinvClient(subcloud_name,
                                             ks_client.session)
            except (keystone_exceptions.EndpointNotFound,
                    keystone_exceptions.ConnectFailure, IndexError) as e:
                if avail_status_current == consts.AVAILABILITY_OFFLINE:
                    LOG.info("Identity or Platform endpoint for %s not "
                             "found, ignoring for offline "
                             "subcloud." % subcloud_name)
                    continue
                else:
                    LOG.error("Identity or Platform endpoint for online "
                              "subcloud: %s not found." % subcloud_name)

            except Exception as e:
                LOG.exception(e)

            if sysinv_client:
                try:
                    svc_groups = sysinv_client.get_service_groups()
                except Exception as e:
                    svc_groups = None
                    LOG.warn('Cannot retrieve service groups for '
                             'subcloud:%s, %s' % (subcloud_name, e))

            if svc_groups:
                active_sgs = []
                inactive_sgs = []

                # Build 2 lists, 1 of active service groups,
                # one with non-active.
                for sg in svc_groups:
                    if sg.state != consts.SERVICE_GROUP_STATUS_ACTIVE:
                        inactive_sgs.append(sg.service_group_name)
                    else:
                        active_sgs.append(sg.service_group_name)

                # Create a list of service groups that are only present
                # in non-active list
                inactive_only = [sg for sg in inactive_sgs if
                                 sg not in active_sgs]

                # An empty inactive only list and a non-empty active list
                # means we're good to go.
                if not inactive_only and active_sgs:
                    avail_to_set = \
                        consts.AVAILABILITY_ONLINE
                else:
                    LOG.info("Subcloud:%s has non-active "
                             "service groups: %s" %
                             (subcloud_name, inactive_only))

            if avail_to_set == consts.AVAILABILITY_OFFLINE:
                if audit_fail_count < consts.AVAIL_FAIL_COUNT_MAX:
                    audit_fail_count = audit_fail_count + 1

                if (avail_status_current == consts.AVAILABILITY_ONLINE) and \
                        (audit_fail_count < consts.AVAIL_FAIL_COUNT_TO_ALARM):
                    # Do not set offline until we have failed audit
                    # the requisite number of times
                    avail_to_set = consts.AVAILABILITY_ONLINE
            else:
                # In the case of a one off blip, we may need to set the
                # fail count back to 0
                audit_fail_count = 0

            if avail_to_set != avail_status_current:

                if avail_to_set == consts.AVAILABILITY_ONLINE:
                    audit_fail_count = 0

                LOG.info('Setting new availability status: %s '
                         'on subcloud: %s' %
                         (avail_to_set, subcloud_name))

                entity_instance_id = "subcloud=%s" % subcloud_name
                fault = self.fm_api.get_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                    entity_instance_id)

                if fault and (avail_to_set == consts.AVAILABILITY_ONLINE):
                    try:
                        self.fm_api.clear_fault(
                            fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                            entity_instance_id)
                    except Exception as e:
                        LOG.exception(e)

                elif not fault and \
                        (avail_to_set == consts.AVAILABILITY_OFFLINE):
                    try:
                        fault = fm_api.Fault(
                            alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                            alarm_state=fm_const.FM_ALARM_STATE_SET,
                            entity_type_id=fm_const.FM_ENTITY_TYPE_SUBCLOUD,
                            entity_instance_id=entity_instance_id,
                            severity=fm_const.FM_ALARM_SEVERITY_CRITICAL,
                            reason_text=('%s is offline' % subcloud_name),
                            alarm_type=fm_const.FM_ALARM_TYPE_0,
                            probable_cause=fm_const.ALARM_PROBABLE_CAUSE_29,
                            proposed_repair_action="Wait for subcloud to "
                                                   "become online; if "
                                                   "problem persists contact "
                                                   "next level of support.",
                            service_affecting=True)

                        self.fm_api.set_fault(fault)
                    except Exception as e:
                        LOG.exception(e)

                try:
                    db_api.subcloud_update(self.context, subcloud_id,
                                           management_state=None,
                                           availability_status=avail_to_set,
                                           software_version=None,
                                           description=None, location=None,
                                           audit_fail_count=audit_fail_count)
                except exceptions.SubcloudNotFound:
                    # slim possibility subcloud could have been deleted since
                    # we found it in db, ignore this benign error.
                    LOG.info('Ignoring SubcloudNotFound when attempting state'
                             ' update: %s' % subcloud_name)
                    continue

                try:
                    self.dcorch_rpc_client.\
                        update_subcloud_states(self.context,
                                               subcloud_name,
                                               management_state,
                                               avail_to_set)

                    LOG.info('Notifying dcorch, subcloud:%s management: %s, '
                             'availability:%s' % (subcloud_name,
                                                  management_state,
                                                  avail_to_set))
                except Exception as e:
                    LOG.exception(e)
                    LOG.warn('Problem informing dcorch of subcloud '
                             'state change, subcloud: %s' % subcloud_name)

                if avail_to_set == consts.AVAILABILITY_OFFLINE:
                    # Subcloud is going offline, set all endpoint statuses to
                    # unknown.
                    try:
                        self.subcloud_manager.update_subcloud_endpoint_status(
                            self.context,
                            subcloud_name=subcloud_name,
                            endpoint_type=None,
                            sync_status=consts.SYNC_STATUS_UNKNOWN)
                    except exceptions.SubcloudNotFound:
                        LOG.info('Ignoring SubcloudNotFound when attempting '
                                 'sync_status update: %s' % subcloud_name)
                        continue

            elif audit_fail_count != subcloud.audit_fail_count:

                try:
                    db_api.subcloud_update(self.context, subcloud_id,
                                           management_state=None,
                                           availability_status=None,
                                           software_version=None,
                                           description=None, location=None,
                                           audit_fail_count=audit_fail_count)
                except exceptions.SubcloudNotFound:
                    # slim possibility subcloud could have been deleted since
                    # we found it in db, ignore this benign error.
                    LOG.info('Ignoring SubcloudNotFound when attempting '
                             'audit_fail_count update: %s' % subcloud_name)
                    continue
