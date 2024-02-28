#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon import consts as dccommon_consts
from dcmanager.audit import kube_rootca_update_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.tests import base
from dcmanager.tests import utils


class FakeDCManagerStateAPI(object):
    def __init__(self):
        self.update_subcloud_availability = mock.MagicMock()
        self.update_subcloud_endpoint_status = mock.MagicMock()


class FakeAuditWorkerAPI(object):

    def __init__(self):
        self.audit_subclouds = mock.MagicMock()


class FakeSysinvClient(object):
    def __init__(self):
        self.region = None
        self.session = None
        self.get_kube_rootca_cert_id = mock.MagicMock()


class FakeFmClient(object):
    def __init__(self):
        self.region = None
        self.session = None
        self.get_alarms_by_ids = mock.MagicMock()


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
        super(TestKubeRootcaUpdateAudit, self).setUp()
        self.ctxt = utils.dummy_context()

        # Mock the DCManager subcloud state API
        self.fake_dcmanager_state_api = FakeDCManagerStateAPI()
        p = mock.patch('dcmanager.rpc.client.SubcloudStateClient')
        self.mock_dcmanager_state_api = p.start()
        self.mock_dcmanager_state_api.return_value = \
            self.fake_dcmanager_state_api
        self.addCleanup(p.stop)

        # Mock the Audit Worker API
        self.fake_audit_worker_api = FakeAuditWorkerAPI()
        p = mock.patch('dcmanager.audit.rpcapi.ManagerAuditWorkerClient')
        self.mock_audit_worker_api = p.start()
        self.mock_audit_worker_api.return_value = self.fake_audit_worker_api
        self.addCleanup(p.stop)

        # Note: mock where an item is used, not where it comes from
        p = mock.patch.object(kube_rootca_update_audit, 'OpenStackDriver')
        self.rootca_openstack_driver = mock.MagicMock()
        self.mock_rootca_audit_driver = p.start()
        self.mock_rootca_audit_driver.return_value = self.rootca_openstack_driver
        self.addCleanup(p.stop)

        p = mock.patch.object(kube_rootca_update_audit, 'SysinvClient')
        self.rootca_sysinv_client = FakeSysinvClient()
        self.mock_rootca_audit_sys = p.start()
        self.mock_rootca_audit_sys.return_value = self.rootca_sysinv_client
        self.addCleanup(p.stop)

        p = mock.patch.object(kube_rootca_update_audit, 'FmClient')
        self.rootca_fm_client = FakeFmClient()
        self.mock_rootca_audit_fm = p.start()
        self.mock_rootca_audit_fm.return_value = self.rootca_fm_client
        self.addCleanup(p.stop)

        # Set the Kubeernetes Root CA cert identifier as cert1 for all regions
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")

        # Set get_alarms_by_ids returns none by default
        self.rootca_fm_client.get_alarms_by_ids.return_value = None

    def get_rootca_audit_data(self, am):
        (
            _,
            _,
            _,
            kube_rootca_audit_data,
            _
        ) = am._get_audit_data(True, True, True, True, True)

        return kube_rootca_audit_data

    def test_init(self):
        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        self.assertIsNotNone(audit)
        self.assertEqual(self.ctxt, audit.context)
        self.assertEqual(self.fake_dcmanager_state_api,
                         audit.state_rpc_client)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_no_kube_rootca_update_audit_data_to_sync(self, mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("", "error")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)

        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kube_rootca_update_audit_in_sync_cert_based(self,
                                                         mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return same kube root ca ID in the subclouds
            self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
                True, FakeKubeRootcaData("cert1", "")
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kube_rootca_update_audit_out_of_sync_cert_based(self,
                                                             mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return different kube root ca ID in the subclouds
            self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
                True, FakeKubeRootcaData("cert2", "")
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(mock.ANY, subcloud_name=subcloud.name,
                          subcloud_region=subcloud.region_name,
                          endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                          sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kube_rootca_update_audit_in_sync_alarm_based(self,
                                                          mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
                False, None
            self.rootca_fm_client.get_alarms_by_ids.return_value = None
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kube_rootca_update_audit_out_of_sync_alarm_based(self,
                                                              mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
                False, None
            self.rootca_fm_client.get_alarms_by_ids.return_value = \
                [FakeAlarm('system.certificate.kubernetes-root-ca'), ]
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kube_rootca_update_audit_in_sync_old_release(self,
                                                          mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_3, base.SUBCLOUD_4]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
                False, None
            self.rootca_fm_client.get_alarms_by_ids.return_value = None
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kube_rootca_update_audit_out_of_sync_old_release(self,
                                                              mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_3, base.SUBCLOUD_4]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
                False, None
            self.rootca_fm_client.get_alarms_by_ids.return_value = \
                [FakeAlarm('system.certificate.kubernetes-root-ca'), ]
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kube_rootca_update_audit_in_sync_not_rehomed(self,
                                                          mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_5, base.SUBCLOUD_6]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
                False, None
            self.rootca_fm_client.get_alarms_by_ids.return_value = None
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)

    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_kube_rootca_update_audit_out_of_sync_not_rehomed(self,
                                                              mock_context):
        mock_context.get_admin_context.return_value = self.ctxt

        audit = kube_rootca_update_audit.KubeRootcaUpdateAudit(
            self.ctxt, self.fake_dcmanager_state_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.kube_rootca_update_audit = audit

        # Set the region one data
        self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
            True, FakeKubeRootcaData("cert1", "")
        kube_rootca_update_audit_data = self.get_rootca_audit_data(am)
        subclouds = [base.SUBCLOUD_5, base.SUBCLOUD_6]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)
            # return API cert ID request failed
            self.rootca_sysinv_client.get_kube_rootca_cert_id.return_value = \
                False, None
            self.rootca_fm_client.get_alarms_by_ids.return_value = \
                [FakeAlarm('system.certificate.kubernetes-root-ca'), ]
            audit.subcloud_kube_rootca_audit(subcloud,
                                             kube_rootca_update_audit_data)
            expected_calls = [
                mock.call(
                    mock.ANY, subcloud_name=subcloud.name,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                    sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_state_api.update_subcloud_endpoint_status.\
                assert_has_calls(expected_calls)
