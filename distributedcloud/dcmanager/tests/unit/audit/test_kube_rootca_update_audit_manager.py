#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon import consts as dccommon_consts
from dcmanager.audit import kube_rootca_update_audit
from dcmanager.audit import rpcapi
from dcmanager.audit import subcloud_audit_manager
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
        self.name = subcloud_dict["name"]
        self.region_name = subcloud_dict["region_name"]
        self.rehomed = subcloud_dict["rehomed"]
        self.software_version = subcloud_dict["software_version"]


class TestKubeRootcaUpdateAudit(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_object(kube_rootca_update_audit, "OpenStackDriver")
        self._mock_object(subcloud_audit_worker_manager, "OpenStackDriver")
        self.mock_region_one_sysinv_client = self._mock_object(
            kube_rootca_update_audit, "SysinvClient"
        )
        self.mock_sysinv_client = self._mock_object(
            subcloud_audit_worker_manager, "SysinvClient"
        )
        self.mock_fm_client = self._mock_object(
            subcloud_audit_worker_manager, "FmClient"
        )
        self._mock_object(rpcapi, "ManagerAuditWorkerClient")
        self.mock_subcloud_audit_manager_context = self._mock_object(
            subcloud_audit_manager, "context"
        )

        # Set the Kubeernetes Root CA cert identifier as cert1 for all regions
        self.kube_rootca_cert_id = (
            self.mock_region_one_sysinv_client().get_kube_rootca_cert_id
        )
        self.kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )

        # Set get_alarms_by_ids returns none by default
        self.mock_fm_client().get_alarms_by_ids.return_value = None

        self.mock_subcloud_audit_manager_context.get_admin_context.return_value = (
            self.ctx
        )

        self.audit = kube_rootca_update_audit.KubeRootcaUpdateAudit()
        self.am = subcloud_audit_manager.SubcloudAuditManager()
        self.am.kube_rootca_update_audit = self.audit

    def get_rootca_audit_data(self):
        (_, _, _, kube_rootca_audit_data, _) = self.am._get_audit_data(
            True, True, True, True, True
        )

        return kube_rootca_audit_data

    def test_no_kube_rootca_update_audit_data_to_sync(self):
        # Set the region one data
        self.kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("", "error"),
        )
        kube_rootca_update_audit_data = self.get_rootca_audit_data()

        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)

            response = self.audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(),
                self.mock_fm_client(),
                subcloud,
                kube_rootca_update_audit_data,
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kube_rootca_update_audit_in_sync_cert_based(self):
        # Set the region one data
        self.kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )
        kube_rootca_update_audit_data = self.get_rootca_audit_data()

        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)

            # return same kube root ca ID in the subclouds
            self.kube_rootca_cert_id.return_value = True, FakeKubeRootcaData(
                "cert1", ""
            )
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = (
                True,
                FakeKubeRootcaData("cert1", ""),
            )

            response = self.audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(),
                self.mock_fm_client(),
                subcloud,
                kube_rootca_update_audit_data,
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kube_rootca_update_audit_out_of_sync_cert_based(self):
        # Set the region one data
        self.kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )
        kube_rootca_update_audit_data = self.get_rootca_audit_data()

        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)

            # return different kube root ca ID in the subclouds
            self.kube_rootca_cert_id.return_value = True, FakeKubeRootcaData(
                "cert2", ""
            )
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = (
                True,
                FakeKubeRootcaData("cert2", ""),
            )
            response = self.audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(),
                self.mock_fm_client(),
                subcloud,
                kube_rootca_update_audit_data,
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_kube_rootca_update_audit_in_sync_alarm_based(self):
        # Set the region one data
        self.kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )
        kube_rootca_update_audit_data = self.get_rootca_audit_data()

        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)

            # return API cert ID request failed
            self.kube_rootca_cert_id.return_value = (
                False,
                None,
            )
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = False, None
            self.mock_fm_client().get_alarms_by_ids.return_value = None

            response = self.audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(),
                self.mock_fm_client(),
                subcloud,
                kube_rootca_update_audit_data,
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kube_rootca_update_audit_out_of_sync_alarm_based(self):
        # Set the region one data
        self.kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )
        kube_rootca_update_audit_data = self.get_rootca_audit_data()

        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)

            # return API cert ID request failed
            self.kube_rootca_cert_id.return_value = (
                False,
                None,
            )
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = False, None
            self.mock_fm_client().get_alarms_by_ids.return_value = [
                FakeAlarm("system.certificate.kubernetes-root-ca"),
            ]

            response = self.audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(),
                self.mock_fm_client(),
                subcloud,
                kube_rootca_update_audit_data,
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_kube_rootca_update_audit_fail_to_get_audit_data(self):
        # Set the region one data
        self.kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )
        kube_rootca_update_audit_data = self.get_rootca_audit_data()

        subclouds = [base.SUBCLOUD_3, base.SUBCLOUD_4]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)

            # return API cert ID request failed
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = (
                base.FakeException("API cert ID request failed")
            )
            self.mock_fm_client().get_alarms_by_ids.side_effect = base.FakeException(
                "get_alarms_by_ids failed"
            )

            response = self.audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(),
                self.mock_fm_client(),
                subcloud,
                kube_rootca_update_audit_data,
            )

            self.assertEqual(response, None)

    def test_kube_rootca_update_audit_method(self):
        """Test if kube-rootca is auditing correctly based using alarm or cert_id"""
        # Set the region one data
        self.kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )
        kube_rootca_update_audit_data = self.get_rootca_audit_data()

        subclouds = [base.SUBCLOUD_1, base.SUBCLOUD_2]
        for subcloud_dict in subclouds:
            subcloud = FakeSubcloudObj(subcloud_dict)

            self.kube_rootca_cert_id.return_value = True, FakeKubeRootcaData(
                "cert1", ""
            )
            self.mock_sysinv_client().get_kube_rootca_cert_id.return_value = (
                True,
                FakeKubeRootcaData("cert1", ""),
            )
            self.mock_fm_client().get_alarms_by_ids.return_value = None

            self.audit.subcloud_kube_rootca_audit(
                self.mock_sysinv_client(),
                self.mock_fm_client(),
                subcloud,
                kube_rootca_update_audit_data,
            )
            if subcloud.rehomed:
                self.mock_sysinv_client().get_kube_rootca_cert_id.assert_called()
            else:
                self.mock_fm_client().get_alarms_by_ids.assert_called()
