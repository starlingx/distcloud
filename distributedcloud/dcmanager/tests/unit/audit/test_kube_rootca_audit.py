#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon import consts as dccommon_consts
from dccommon.endpoint_cache import EndpointCache
from dcmanager.audit import kube_rootca_update_audit
from dcmanager.audit import rpcapi
from dcmanager.audit import subcloud_audit_manager
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


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


class BaseTestKubeRootCAUpdateAudit(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_object(rpcapi, "ManagerAuditWorkerClient")
        self.mock_regionone_sysinvclient = self._mock_object(
            kube_rootca_update_audit, "SysinvClient"
        )
        self._mock_object(EndpointCache, "get_admin_session")
        self.mock_log = self._mock_object(kube_rootca_update_audit, "LOG")

        self.mock_subcloud_sysinvclient = mock.MagicMock()
        self.mock_subcloud_fmclient = mock.MagicMock()

        self.kube_rootca_audit = kube_rootca_update_audit.KubeRootcaUpdateAudit()
        self.audit_manager = subcloud_audit_manager.SubcloudAuditManager()
        self.audit_manager.kube_rootca_update_audit = self.kube_rootca_audit

        self.subcloud = create_fake_subcloud(self.ctx)

    def _get_rootca_audit_data(self):
        (_, _, kube_rootca_audit_data, _) = self.audit_manager._get_audit_data(
            False, False, True, False
        )
        return kube_rootca_audit_data

    def _test_kube_rootca_update_audit(self, rehomed, sync_status):
        response = self.kube_rootca_audit.get_subcloud_sync_status(
            self.mock_subcloud_sysinvclient(),
            self.mock_subcloud_fmclient(),
            self._get_rootca_audit_data(),
            rehomed,
            self.subcloud.name,
        )

        self.assertEqual(response, sync_status)


class TestKubeRootCAUpdateAudit(BaseTestKubeRootCAUpdateAudit):
    def setUp(self):
        super().setUp()

    def test_kube_rootca_update_audit_region_one_client_exception(self):
        self.mock_regionone_sysinvclient().get_kube_rootca_cert_id.side_effect = (
            Exception("fake")
        )

        response = self._get_rootca_audit_data()

        self.assertIsNone(response)
        self.mock_log.exception.assert_called_with(
            "Failed to get Kubernetes root CA from Region One, "
            "skip Kubernetes root CA audit."
        )


class TestKubeRootCAUpdateAuditCertBased(BaseTestKubeRootCAUpdateAudit):
    def setUp(self):
        super().setUp()

        # Set the Kubeernetes Root CA cert identifier as cert1 for all regions
        self.mock_regionone_sysinvclient().get_kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )

    def test_kube_rootca_update_audit_cert_based_skipped_on_error(self):
        self.mock_subcloud_sysinvclient().get_kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("", "error"),
        )

        self._test_kube_rootca_update_audit(True, None)
        self.mock_log.error.assert_called_with(
            "Subcloud: subcloud1. Failed to get Kubernetes root CA cert id, error: "
            "error, skip kube rootca update audit."
        )

    def test_kube_rootca_update_audit_cert_based_skipped_on_client_exception(self):
        self.mock_subcloud_sysinvclient().get_kube_rootca_cert_id.side_effect = (
            Exception("fake")
        )

        self._test_kube_rootca_update_audit(True, None)
        self.mock_log.exception.assert_called_with(
            "Subcloud: subcloud1. Failed to get Kubernetes root CA status, skip kube "
            "rootca update audit."
        )

    def test_kube_rootca_update_audit_cert_based_in_sync(self):
        # Return the same kube root ca ID in the subclouds
        self.mock_subcloud_sysinvclient().get_kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert1", ""),
        )

        self._test_kube_rootca_update_audit(True, dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kube_rootca_update_audit_cert_based_out_of_sync(self):
        self.mock_subcloud_sysinvclient().get_kube_rootca_cert_id.return_value = (
            True,
            FakeKubeRootcaData("cert2", ""),
        )

        self._test_kube_rootca_update_audit(
            True, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        )


class TestKubeRootCAUpdateAuditAlarmBased(BaseTestKubeRootCAUpdateAudit):
    def setUp(self):
        super().setUp()

        self.mock_subcloud_sysinvclient().get_kube_rootca_cert_id.return_value = (
            False,
            None,
        )

    def test_kube_rootca_update_audit_alarm_based_in_sync_without_alarms(self):
        self.mock_subcloud_fmclient().get_alarms_by_ids.return_value = None

        self._test_kube_rootca_update_audit(False, dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kube_rootca_update_audit_alarm_based_in_sync_rehomed_without_alarms(self):
        self.mock_subcloud_fmclient().get_alarms_by_ids.return_value = None

        self._test_kube_rootca_update_audit(True, dccommon_consts.SYNC_STATUS_IN_SYNC)

    # A rehomed subcloud would only affect the execution by avoiding the
    # get_kube_rootca_cert_id call from get_subcloud_audit_data. Because that is
    # already tested above, it won't be tested in the subsequent tests.
    def test_kube_rootca_update_audit_alarm_based_in_sync_unmonitored_alarm(self):
        self.mock_subcloud_fmclient().get_alarms_by_ids.return_value = [
            FakeAlarm("k8s_application=platform-integ-apps"),
        ]

        self._test_kube_rootca_update_audit(False, dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kube_rootca_update_audit_alarm_based_out_of_sync(self):
        self.mock_subcloud_fmclient().get_alarms_by_ids.return_value = [
            FakeAlarm("system.certificate.kubernetes-root-ca"),
        ]

        self._test_kube_rootca_update_audit(
            False, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        )

    def test_kube_rootca_update_audit_alarm_based_skipped_on_client_exception(self):
        self.mock_subcloud_fmclient().get_alarms_by_ids.side_effect = Exception("fake")

        self._test_kube_rootca_update_audit(False, None)
        self.mock_log.exception.assert_called_with(
            "Subcloud: subcloud1. Failed to get alarms by id, skip kube rootca "
            "update audit."
        )
