#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon import consts as dccommon_consts
from dcmanager.audit import kube_rootca_update_audit
from dcmanager.audit.subcloud_audit_manager import SubcloudAuditManager
from dcmanager.audit import subcloud_audit_worker_manager
from dcmanager.tests import base


class FakeKubeRootcaData(object):
    def __init__(self, cert_id, error_msg):
        self.cert_id = cert_id
        self.error = error_msg


class FakeAlarm(object):
    def __init__(self, entity_instance_id):
        self.entity_instance_id = entity_instance_id


class FakeSubcloudObj(object):
    def __init__(self, subcloud_dict):
        self.name = subcloud_dict['name']
        self.region_name = subcloud_dict['region_name']
        self.rehomed = subcloud_dict['rehomed']
        self.software_version = subcloud_dict['software_version']


class TestKubeRootcaUpdateAudit(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_openstack_driver(kube_rootca_update_audit)
        self._mock_openstack_driver(subcloud_audit_worker_manager)
        self._mock_sysinv_client(kube_rootca_update_audit)
        self.mock_region_one_sysinv_client = self.mock_sysinv_client
        self._mock_sysinv_client(subcloud_audit_worker_manager)
        self._mock_fm_client(subcloud_audit_worker_manager)
        self._mock_rpc_subcloud_state_client()
        self._mock_rpc_api_manager_audit_worker_client()
        self._mock_subcloud_audit_manager_context()

        # Set the Kubeernetes Root CA cert identifier as cert1 for all regions
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")

        # Set get_alarms_by_ids returns none by default
        self.mock_fm_client().get_alarms_by_ids.return_value = None

        self.mock_subcloud_audit_manager_context.\
            get_admin_context.return_value = self.ctx

    def get_rootca_audit_data(self, am):
        (_, _, _, kube_rootca_audit_data, _) = \
            am._get_audit_data(True, True, True, True, True)

        return kube_rootca_audit_data

    def test_init(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        self.assertIsNotNone(audit)
        self.assertEqual(self.ctx, audit.context)
        self.assertEqual(
            self.mock_rpc_subcloud_state_client, audit.state_rpc_client
        )

    def test_no_kube_rootca_update_audit_data_to_sync(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("", "error")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)

        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    def test_kube_rootca_update_audit_in_sync_cert_based(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return same kube root ca ID in the subclouds
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.\
                return_value = True, FakeKubeRootcaData("cert1", "")
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = \
                True, FakeKubeRootcaData("cert1", "")
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    def test_kube_rootca_update_audit_out_of_sync_cert_based(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return different kube root ca ID in the subclouds
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.\
                return_value = True, FakeKubeRootcaData("cert2", "")
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = \
                True, FakeKubeRootcaData("cert2", "")
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(mock.ANY, subcloud_name=subcloud.name,
                          subcloud_region=subcloud.region_name,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                          sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    def test_kube_rootca_update_audit_in_sync_alarm_based(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.\
                return_value = False, None
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = \
                False, None
            self.mock_fm_client().get_alarms_by_ids.return_value = None
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    def test_kube_rootca_update_audit_out_of_sync_alarm_based(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.\
                return_value = False, None
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = \
                False, None
            self.mock_fm_client().get_alarms_by_ids.return_value = \
                [FakeAlarm('system.certificate.kubernetes-root-ca'), ]
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    def test_kube_rootca_update_audit_in_sync_old_release(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_3, base.SUBCLOUD_4]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.\
                return_value = False, None
            self.mock_fm_client().get_alarms_by_ids.return_value = None
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    def test_kube_rootca_update_audit_out_of_sync_old_release(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_3, base.SUBCLOUD_4]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.\
                return_value = False, None
            self.mock_fm_client().get_alarms_by_ids.return_value = \
                [FakeAlarm('system.certificate.kubernetes-root-ca'), ]
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    def test_kube_rootca_update_audit_in_sync_not_rehomed(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_5, base.SUBCLOUD_6]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.\
                return_value = False, None
            self.mock_fm_client().get_alarms_by_ids.return_value = None
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    def test_kube_rootca_update_audit_out_of_sync_not_rehomed(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctx, self.mock_rpc_subcloud_state_client
        )
        am = SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_5, base.SUBCLOUD_6]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id.\
                return_value = False, None
            self.mock_fm_client().get_alarms_by_ids.return_value = \
                [FakeAlarm('system.certificate.kubernetes-root-ca'), ]
            audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(), self.mock_fm_client(), subcloud,
                kube_rootca_update_audit_data
            )

            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.mock_rpc_subcloud_state_client.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)
