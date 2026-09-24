# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from oslotest import base

from dccommon import consts as dccommon_consts
from dcorch.common import consts
import dcorch.engine.sync_services.sysinv as sysinv_service

SSL_CA_SIGNATURE = "ssl_ca_10076021394652733954"
OTHER_SIGNATURE = "ssl_ca_623117754837484817035895062893536539420358452298"


class FakeCertificate(object):
    """Minimal stand-in for a cgtsclient certificate resource."""

    def __init__(self, signature, certtype="ssl_ca"):
        self.signature = signature
        self.certtype = certtype


class TestSysinvSyncThreadMapSubcloudResource(base.BaseTestCase):
    """Tests for SysinvSyncThread.map_subcloud_resource."""

    def _mock_object(self, target, attribute, wraps=None):
        """Mock a specified target's attribute and return the mock object"""

        mock_patch_object = mock.patch.object(target, attribute, wraps=wraps)
        self.addCleanup(mock_patch_object.stop)

        return mock_patch_object.start()

    def setUp(self):
        super().setUp()

        self.mock_log = self._mock_object(sysinv_service, "LOG")

        self.thread = sysinv_service.SysinvSyncThread.__new__(
            sysinv_service.SysinvSyncThread
        )
        self.thread.log_extra = {"instance": "subcloud-test/platform: "}
        self.thread.ctxt = mock.MagicMock()
        self.thread.persist_db_subcloud_resource = mock.MagicMock()

        # Master resource DB entry already exists, so the override should not
        # need to create one.
        self.m_rsrc_db = mock.MagicMock()
        self.m_rsrc_db.id = 1

        self.master_cert = FakeCertificate(SSL_CA_SIGNATURE)

    def _call(self, sc_resources, resource_type=None, m_r=None, m_rsrc_db=None):
        return self.thread.map_subcloud_resource(
            resource_type or consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
            m_r if m_r is not None else self.master_cert,
            m_rsrc_db if m_rsrc_db is not None else self.m_rsrc_db,
            sc_resources,
        )

    def test_returns_false_for_non_certificate_resource(self):
        result = self._call(
            {SSL_CA_SIGNATURE: dccommon_consts.SYNC_STATUS_IN_SYNC},
            resource_type=consts.RESOURCE_TYPE_SYSINV_USER,
        )

        self.assertFalse(result)
        self.thread.persist_db_subcloud_resource.assert_not_called()

    def test_returns_false_for_non_ssl_ca_certtype(self):
        # openstack_ca is intentionally out of scope: it is tied to the
        # OpenStack application lifecycle and is not assumed to be present
        # from bootstrap.
        openstack_ca = FakeCertificate(SSL_CA_SIGNATURE, certtype="openstack_ca")

        result = self._call(
            {SSL_CA_SIGNATURE: dccommon_consts.SYNC_STATUS_IN_SYNC},
            m_r=openstack_ca,
        )

        self.assertFalse(result)
        self.thread.persist_db_subcloud_resource.assert_not_called()

    def test_dcagent_in_sync_creates_mapping_and_skips_install(self):
        # dcagent reports the certificate already present on the subcloud, so
        # the mapping is created and the redundant install is skipped.
        result = self._call({SSL_CA_SIGNATURE: dccommon_consts.SYNC_STATUS_IN_SYNC})

        self.assertTrue(result)
        self.thread.persist_db_subcloud_resource.assert_called_once_with(
            self.m_rsrc_db.id, SSL_CA_SIGNATURE
        )

    def test_dcagent_out_of_sync_returns_false(self):
        result = self._call({SSL_CA_SIGNATURE: dccommon_consts.SYNC_STATUS_OUT_OF_SYNC})

        self.assertFalse(result)
        self.thread.persist_db_subcloud_resource.assert_not_called()

    def test_dcagent_signature_absent_returns_false(self):
        # A different certificate being in-sync must not map this one.
        result = self._call({OTHER_SIGNATURE: dccommon_consts.SYNC_STATUS_IN_SYNC})

        self.assertFalse(result)
        self.thread.persist_db_subcloud_resource.assert_not_called()

    def test_non_certificate_payload_shape_returns_false(self):
        # is_resource_present_in_subcloud only understands the dcagent audit
        # payload. Any other shape must not produce a mapping.
        result = self._call([FakeCertificate(SSL_CA_SIGNATURE)])

        self.assertFalse(result)
        self.thread.persist_db_subcloud_resource.assert_not_called()

    def test_null_signature_returns_false(self):
        null_cert = FakeCertificate(None)

        result = self._call(
            {SSL_CA_SIGNATURE: dccommon_consts.SYNC_STATUS_IN_SYNC}, m_r=null_cert
        )

        self.assertFalse(result)
        self.thread.persist_db_subcloud_resource.assert_not_called()
