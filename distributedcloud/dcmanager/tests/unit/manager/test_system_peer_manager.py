#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import uuid

import mock

from dccommon import exceptions as dccommon_exceptions
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.manager import system_peer_manager
from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_subcloud

# FAKE SYSINV DATA
FAKE_SITE0_SYSTEM_UUID = str(uuid.uuid4())
FAKE_SITE1_SYSTEM_UUID = str(uuid.uuid4())

# FAKE SYSTEM PEER DATA
FAKE_SYSTEM_PEER_ID = 1
FAKE_SYSTEM_PEER_UUID = FAKE_SITE1_SYSTEM_UUID
FAKE_SYSTEM_PEER_NAME = 'PeerSite1'
FAKE_MANAGER_ENDPOINT = 'http://128.128.128.128:5000/v3'
FAKE_MANAGER_USERNAME = 'admin'
FAKE_MANAGER_PASSWORD = 'cGFzc3dvcmQ='
FAKE_PEER_CONTROLLER_GATEWAY_IP = '128.128.1.1'

# FAKE SUBCLOUD PEER GROUP DATA (SITE0)
FAKE_SITE0_PEER_GROUP_ID = 1
FAKE_SITE0_PEER_GROUP_NAME = 'PeerGroup1'
FAKE_SITE0_PEER_GROUP_SYSTEM_LEADER_ID = FAKE_SITE0_SYSTEM_UUID
FAKE_SITE0_PEER_GROUP_SYSTEM_LEADER_NAME = 'site0'
FAKE_SITE0_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 50
FAKE_SITE0_PEER_GROUP_PRIORITY = 0
FAKE_SITE0_PEER_GROUP_STATE = 'enabled'

# FAKE SUBCLOUD PEER GROUP DATA (SITE1)
FAKE_SITE1_PEER_GROUP_ID = 9
FAKE_SITE1_PEER_GROUP_NAME = 'PeerGroup2'
FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 20
FAKE_SITE1_PEER_GROUP_STATE = 'enabled'

# FAKE SYSTEM PEER DATA (SITE1)
FAKE_SITE1_SYSTEM_PEER_ID = 10

FAKE_SITE1_SUBCLOUD1_REGION_NAME = str(uuid.uuid4())
FAKE_SITE1_SUBCLOUD2_REGION_NAME = str(uuid.uuid4())

# FAKE PEER GROUP ASSOCIATION DATA (SITE0)
FAKE_ASSOCIATION_PEER_GROUP_ID = \
    FAKE_SITE0_PEER_GROUP_ID
FAKE_ASSOCIATION_SYSTEM_PEER_ID = \
    FAKE_SYSTEM_PEER_ID
FAKE_ASSOCIATION_PEER_GROUP_PRIORITY = 1
FAKE_ASSOCIATION_SYNC_STATUS = 'in-sync'
FAKE_ASSOCIATION_SYNC_MESSAGE = 'None'
FAKE_ASSOCIATION_TYPE = 'primary'

# FAKE PEER GROUP ASSOCIATION DATA (SITE1)
FAKE_SITE1_ASSOCIATION_ID = 10


class FakeSystem(object):
    def __init__(self, uuid):
        self.uuid = uuid


class FakeSysinvClient(object):
    def __init__(self):
        self.system = FakeSystem(FAKE_SITE1_SYSTEM_UUID)

    def get_system(self):
        return self.system


class TestSystemPeerManager(base.DCManagerTestCase):
    """Test class for testing system peer manager"""

    def setUp(self):
        super().setUp()

        self._mock_sysinv_client(system_peer_manager)
        self._mock_audit_rpc_client()
        self._mock_get_local_system()
        self._mock_system_peer_manager_dcmanagerclient()
        self._mock_system_peer_manager_peersitedriver()
        self._mock_log(system_peer_manager)

        self.spm = system_peer_manager.SystemPeerManager(mock.MagicMock())
        self.mock_sysinv_client.return_value = FakeSysinvClient()
        self.data_install = json.dumps(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)

        self.peer_subcloud1 = self._fake_site_data(1)
        self.peer_subcloud2 = self._fake_site_data(2)
        self.peer_subcloud3 = self._fake_site_data(3)

        self.peer = self.create_system_peer_static(
            self.ctx, peer_name='SystemPeer1'
        )
        self.peer_group = self.create_subcloud_peer_group_static(
            self.ctx, peer_group_name='SubcloudPeerGroup1'
        )
        self.association = self.create_peer_group_association_static(
            self.ctx,
            system_peer_id=self.peer.id,
            peer_group_id=self.peer_group.id)

    def _fake_site_data(self, subcloud_id):
        # FAKE SITE SUBCLOUD DATA
        region_name = {
            1: FAKE_SITE1_SUBCLOUD1_REGION_NAME,
            2: FAKE_SITE1_SUBCLOUD2_REGION_NAME
        }
        deploy_status = {
            1: consts.DEPLOY_STATE_SECONDARY,
            2: consts.DEPLOY_STATE_SECONDARY_FAILED,
            3: consts.DEPLOY_STATE_SECONDARY,
        }
        return {
            'id': subcloud_id,
            'name': f'subcloud{subcloud_id}',
            'region-name': region_name.get(subcloud_id, 'subcloud3'),
            'deploy-status': deploy_status.get(
                subcloud_id, consts.DEPLOY_STATE_REHOMING)
        }

    def _create_subcloud(self, subcloud_name, data_install=None, **kwargs):
        return self.create_subcloud_with_pg_static(
            self.ctx,
            peer_group_id=self.peer_group.id,
            name=subcloud_name,
            region_name=subcloud_name,
            data_install=data_install, **kwargs)

    def _mock_system_peer_manager_dcmanagerclient(self):
        """Mock system_peer_manager's DcmanagerClient"""

        mock_patch = mock.patch.object(system_peer_manager, 'DcmanagerClient')
        self.mock_dc_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def _mock_system_peer_manager_peersitedriver(self):
        """Mock system_peer_manager's PeerSiteDriver"""

        mock_patch = mock.patch.object(system_peer_manager, 'PeerSiteDriver')
        self.mock_keystone_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    @staticmethod
    def create_subcloud_with_pg_static(ctxt, peer_group_id,
                                       rehome_data=None, **kwargs):
        subcloud = fake_subcloud.create_fake_subcloud(ctxt, **kwargs)
        return db_api.subcloud_update(ctxt, subcloud.id,
                                      peer_group_id=peer_group_id,
                                      rehome_data=rehome_data)

    @staticmethod
    def create_system_peer_static(ctxt, **kwargs):
        values = {
            'peer_uuid': FAKE_SYSTEM_PEER_UUID,
            'peer_name': FAKE_SYSTEM_PEER_NAME,
            'endpoint': FAKE_MANAGER_ENDPOINT,
            'username': FAKE_MANAGER_USERNAME,
            'password': FAKE_MANAGER_PASSWORD,
            'gateway_ip': FAKE_PEER_CONTROLLER_GATEWAY_IP,
            'availability_state':
                consts.SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE
        }
        values.update(kwargs)
        return db_api.system_peer_create(ctxt, **values)

    @staticmethod
    def create_subcloud_peer_group_static(ctxt, **kwargs):
        values = {
            "peer_group_name": FAKE_SITE0_PEER_GROUP_NAME,
            "system_leader_id": FAKE_SITE0_PEER_GROUP_SYSTEM_LEADER_ID,
            "system_leader_name": FAKE_SITE0_PEER_GROUP_SYSTEM_LEADER_NAME,
            "group_priority": FAKE_SITE0_PEER_GROUP_PRIORITY,
            "group_state": FAKE_SITE0_PEER_GROUP_STATE,
            "max_subcloud_rehoming":
            FAKE_SITE0_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            "migration_status": None
        }
        values.update(kwargs)
        return db_api.subcloud_peer_group_create(ctxt, **values)

    @staticmethod
    def create_peer_group_association_static(ctxt, **kwargs):
        values = {
            "system_peer_id": FAKE_ASSOCIATION_SYSTEM_PEER_ID,
            "peer_group_id": FAKE_ASSOCIATION_PEER_GROUP_ID,
            "peer_group_priority": FAKE_ASSOCIATION_PEER_GROUP_PRIORITY,
            "sync_status": FAKE_ASSOCIATION_SYNC_STATUS,
            "sync_message": FAKE_ASSOCIATION_SYNC_MESSAGE,
            "association_type": FAKE_ASSOCIATION_TYPE
        }
        values.update(kwargs)
        return db_api.peer_group_association_create(ctxt, **values)

    def test_init(self):
        self.assertIsNotNone(self.spm)
        self.assertEqual('system_peer_manager', self.spm.service_name)
        self.assertEqual('localhost', self.spm.host)

    def test_sync_subclouds(self):
        self.mock_dc_client().add_subcloud_with_secondary_status.return_value = {
            "region-name": FAKE_SITE1_SUBCLOUD2_REGION_NAME}
        rehome_data = {
            "saved_payload": {
                "bootstrap-address": "192.168.10.10",
                "systemcontroller_gateway_address": "192.168.204.101"
            }
        }
        # Create local dc subcloud1 mock data in database
        self._create_subcloud(
            'subcloud1', self.data_install, rehome_data=json.dumps(rehome_data))
        self._create_subcloud('subcloud2', rehome_data=json.dumps(rehome_data))
        self.mock_dc_client().get_subcloud.side_effect = [
            self.peer_subcloud1, dccommon_exceptions.SubcloudNotFound,
            self.peer_subcloud1, dccommon_exceptions.SubcloudNotFound,
            self.peer_subcloud3]
        self.mock_dc_client().get_subcloud_list_by_peer_group.return_value = [
            self.peer_subcloud1, self.peer_subcloud2, self.peer_subcloud3]
        self.mock_dc_client().update_subcloud.side_effect = [
            self.peer_subcloud1, self.peer_subcloud1, self.peer_subcloud2]

        self.spm._sync_subclouds(self.ctx, self.peer, self.peer_group.id,
                                 FAKE_SITE1_PEER_GROUP_ID)

        self.mock_dc_client().get_subcloud.assert_has_calls([
            mock.call(self.peer_subcloud1.get('name')),
            mock.call(self.peer_subcloud2.get('name')),
            mock.call(self.peer_subcloud3.get('name'))
        ])
        self.mock_dc_client().update_subcloud.assert_has_calls([
            mock.call('subcloud1', mock.ANY, mock.ANY, is_region_name=True),
            mock.call(FAKE_SITE1_SUBCLOUD1_REGION_NAME, files=None,
                      data={'peer_group': str(FAKE_SITE1_PEER_GROUP_ID)},
                      is_region_name=True),
            mock.call(FAKE_SITE1_SUBCLOUD2_REGION_NAME, files=None,
                      data={'peer_group': str(FAKE_SITE1_PEER_GROUP_ID)},
                      is_region_name=True)
        ])
        self.mock_dc_client().add_subcloud_with_secondary_status. \
            assert_called_once()
        self.mock_dc_client().delete_subcloud.assert_called_once_with('subcloud3')

    def test_sync_subcloud_peer_group(self):
        self.mock_get_local_system().get_local_system = mock.MagicMock()

        self.spm.sync_subcloud_peer_group(self.ctx, self.association.id, False)

        self.mock_dc_client().get_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().update_subcloud_peer_group.assert_called_once()

    def test_sync_subcloud_peer_group_not_exist(self):
        self.mock_dc_client().add_subcloud_peer_group = mock.MagicMock()
        self.mock_get_local_system().get_local_system = mock.MagicMock()
        self.mock_dc_client().get_subcloud_peer_group.side_effect = \
            dccommon_exceptions.SubcloudPeerGroupNotFound

        self.spm.sync_subcloud_peer_group(self.ctx, self.association.id, False)

        self.mock_dc_client().get_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().add_subcloud_peer_group.assert_called_once_with(**{
            'peer-group-name': self.peer_group.peer_group_name,
            'group-priority': self.association.peer_group_priority,
            'group-state': self.peer_group.group_state,
            'system-leader-id': self.peer_group.system_leader_id,
            'system-leader-name': self.peer_group.system_leader_name,
            'max-subcloud-rehoming': self.peer_group.max_subcloud_rehoming
        })

    def test_delete_peer_group_association(self):
        # Create local dc subcloud1 mock data in database
        subcloud1 = self._create_subcloud('subcloud1')
        # Create local dc subcloud2 mock data in database
        subcloud2 = self._create_subcloud('subcloud2')
        self.mock_dc_client().get_subcloud.side_effect = [
            self.peer_subcloud1, self.peer_subcloud2]
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            return_value = {'id': FAKE_SITE1_ASSOCIATION_ID}

        self.spm.delete_peer_group_association(self.ctx, self.association.id)

        self.mock_dc_client().delete_subcloud.assert_has_calls([
            mock.call(subcloud1.name),
            mock.call(subcloud2.name)
        ])
        self.mock_dc_client().delete_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().delete_peer_group_association.assert_called_once_with(
            FAKE_SITE1_ASSOCIATION_ID)

        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(0, len(associations))

    def test_delete_peer_group_association_peer_site_association_not_exist(self):
        # Create local dc subcloud1 mock data in database
        subcloud1 = self._create_subcloud('subcloud1')
        self.mock_dc_client().get_subcloud.side_effect = [
            self.peer_subcloud1, dccommon_exceptions.SubcloudNotFound]
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            side_effect = [dccommon_exceptions.PeerGroupAssociationNotFound]

        self.spm.delete_peer_group_association(self.ctx, self.association.id)

        self.mock_dc_client().delete_subcloud.assert_has_calls([
            mock.call(subcloud1.name)])
        self.mock_dc_client().delete_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().delete_peer_group_association.assert_not_called()

        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(0, len(associations))

    @mock.patch('dcmanager.manager.system_peer_manager.'
                'SystemPeerManager.get_peer_dc_client')
    def test_update_sync_status(self, mock_client):
        mock_client.return_value = self.mock_dc_client()
        self.mock_get_local_system.return_value = FakeSystem(FAKE_SITE0_SYSTEM_UUID)

        db_api.peer_group_association_update(
            self.ctx, associate_id=self.association.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_UNKNOWN)

        self.mock_dc_client().get_subcloud_peer_group.return_value = \
            {'id': FAKE_SITE1_PEER_GROUP_ID}
        self.mock_dc_client().get_system_peer.return_value = \
            {'id': FAKE_SITE1_SYSTEM_PEER_ID}
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            return_value = {'id': FAKE_SITE1_ASSOCIATION_ID}

        self.spm.update_sync_status(
            self.ctx, self.peer, consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)

        self.mock_dc_client().get_subcloud_peer_group.assert_called_once_with(
            self.peer_group.peer_group_name)
        self.mock_dc_client().get_system_peer.assert_called_once_with(
            FAKE_SITE0_SYSTEM_UUID)
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            assert_called_once_with(FAKE_SITE1_SYSTEM_PEER_ID,
                                    FAKE_SITE1_PEER_GROUP_ID)
        self.mock_dc_client().update_peer_group_association_sync_status.\
            assert_called_once_with(FAKE_SITE1_ASSOCIATION_ID,
                                    consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)

        association_new = db_api.peer_group_association_get(
            self.ctx, self.association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                         association_new.sync_status)

    @mock.patch.object(system_peer_manager.SystemPeerManager,
                       'update_sync_status')
    def test_update_association_sync_status(self, mock_update_sync_status):

        db_api.peer_group_association_update(
            self.ctx, associate_id=self.association.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)

        self.spm.update_association_sync_status(
            self.ctx, self.peer_group.id,
            consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC)

        mock_update_sync_status.assert_called_once_with(
            self.ctx, mock.ANY, consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
            mock.ANY, None, 'None', mock.ANY)

    @mock.patch.object(system_peer_manager.SystemPeerManager,
                       'update_sync_status')
    def test_update_association_sync_status_when_peer_site_down(
            self, mock_update_sync_status):

        db_api.peer_group_association_update(
            self.ctx, associate_id=self.association.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_UNKNOWN)

        self.spm.update_association_sync_status(
            self.ctx, self.peer_group.id,
            consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC)

        association = db_api. \
            peer_group_association_get_by_peer_group_and_system_peer_id(
                self.ctx, self.peer_group.id, self.peer.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_FAILED,
                         association.sync_status)
        self.assertEqual("Failed to update sync_status, "
                         "because the peer site is unreachable.",
                         association.sync_message)

        mock_update_sync_status.assert_not_called()

    def test_update_subcloud_peer_group(self):
        self.spm.update_subcloud_peer_group(
            self.ctx, self.peer_group.id,
            FAKE_SITE1_PEER_GROUP_STATE,
            FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            FAKE_SITE0_PEER_GROUP_NAME,
            FAKE_SITE1_PEER_GROUP_NAME)

        peer_group_kwargs = {
            'peer-group-name': FAKE_SITE1_PEER_GROUP_NAME,
            'group-state': FAKE_SITE1_PEER_GROUP_STATE,
            'max-subcloud-rehoming':
                FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING
        }
        self.mock_dc_client().update_subcloud_peer_group.assert_called_once_with(
            FAKE_SITE0_PEER_GROUP_NAME, **peer_group_kwargs)

    @mock.patch('dcmanager.manager.system_peer_manager.'
                'SystemPeerManager.get_peer_dc_client')
    def test_update_sync_status_exception(self, mock_client):
        mock_client.return_value = Exception('boom')
        self.spm.update_sync_status(
            self.ctx, self.peer, consts.ASSOCIATION_SYNC_STATUS_IN_SYNC)
        association_new = db_api.peer_group_association_get(
            self.ctx, self.association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_FAILED,
                         association_new.sync_status)

    def test_update_subcloud_peer_group_exception(self):
        self.mock_dc_client().update_subcloud_peer_group = Exception('boom')
        _, failed_peer_ids = self.spm.update_subcloud_peer_group(
            self.ctx, self.peer_group.id,
            FAKE_SITE1_PEER_GROUP_STATE,
            FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            FAKE_SITE0_PEER_GROUP_NAME,
            FAKE_SITE1_PEER_GROUP_NAME)
        self.mock_log.error.assert_called_once_with(
            f"Failed to update Subcloud Peer Group {FAKE_SITE0_PEER_GROUP_NAME}"
            f" on peer site {self.peer.id} with the values: "
            f"{{'peer-group-name': '{FAKE_SITE1_PEER_GROUP_NAME}', "
            f"'group-state': '{FAKE_SITE1_PEER_GROUP_STATE}', "
            "'max-subcloud-rehoming': "
            f"{FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING}}}"
        )
        self.assertEqual({self.peer.id}, failed_peer_ids)

    def test_update_subcloud_peer_group_offline(self):
        db_api.system_peer_update(
            self.ctx, self.peer.id,
            availability_state=consts.SYSTEM_PEER_AVAILABILITY_STATE_UNAVAILABLE
        )
        _, failed_peer_ids = self.spm.update_subcloud_peer_group(
            self.ctx, self.peer_group.id,
            FAKE_SITE1_PEER_GROUP_STATE,
            FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            FAKE_SITE0_PEER_GROUP_NAME)
        self.mock_log.warning.assert_called_once_with(
            f'Peer system {self.peer_group.id} offline')
        self.assertEqual({self.peer.id}, failed_peer_ids)

    def test_update_subcloud_peer_group_associations_notfound(self):
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx, peer_group_name='SubcloudPeerGroup2'
        )
        ret = self.spm.update_subcloud_peer_group(
            self.ctx, peer_group.id,
            FAKE_SITE1_PEER_GROUP_STATE,
            FAKE_SITE1_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            FAKE_SITE0_PEER_GROUP_NAME)
        self.mock_log.info.assert_called_once_with(
            'No association found for peer group 2'
        )
        self.assertEqual((set(), set()), ret)

    def test_handle_association_operations_in_progress(self):

        db_api.peer_group_association_update(
            self.ctx,
            self.peer.id,
            sync_status=consts.ASSOCIATION_SYNC_STATUS_SYNCING)
        self.spm.handle_association_operations_in_progress()
        associations = db_api.peer_group_association_get(self.ctx,
                                                         self.association.id)
        self.assertEqual(consts.ASSOCIATION_SYNC_STATUS_FAILED,
                         associations.sync_status)
        Calls = [mock.call('Identifying associations in transitory stages.'),
                 mock.call('Changing association 1 '
                           'sync status from syncing to failed')]
        self.mock_log.info.assert_has_calls(Calls)

    def test_get_peer_ks_client_fail(self):
        self.mock_keystone_client.side_effect = base.FakeException('BOOM')
        self.assertRaises(base.FakeException, self.spm.get_peer_ks_client, self.peer)
        self.mock_log.warn.assert_called_once_with(
            'Failure initializing KeystoneClient for system peer '
            f'{self.peer.peer_name}')

    def test_valid_for_subcloud_sync_deploy_status_secondary(self):

        subcloud1 = self._create_subcloud(
            'subcloud1', json.dumps(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES),
            deploy_status=consts.DEPLOY_STATE_SECONDARY_FAILED)
        ret = self.spm._is_valid_for_subcloud_sync(subcloud1)
        self.mock_log.info.assert_called_once_with(
            'Ignoring the Subcloud subcloud1 (region_name: subcloud1)'
            ' in secondary status to sync with peer site.')
        self.assertEqual(system_peer_manager.VERIFY_SUBCLOUD_SYNC_IGNORE, ret)

    def test_is_valid_for_subcloud_sync_missing_rehome_data(self):
        # Create local dc subcloud1 mock data in database
        subcloud1 = self._create_subcloud(
            'subcloud1', data_install=self.data_install)
        ret_msg = self.spm._is_valid_for_subcloud_sync(subcloud1)
        msg = 'Subcloud subcloud1 (region_name: subcloud1)'\
              ' does not have rehome_data.'
        self.assertEqual(msg, ret_msg)

    def test_is_valid_for_subcloud_sync_missing_saved_payload_empty(self):
        # Create local dc subcloud1 mock data in database
        rehome_data = {
            "saved_payload": {}
        }
        # Create local dc subcloud1 mock data in database
        subcloud1 = self._create_subcloud(
            'subcloud1', data_install=self.data_install,
            rehome_data=json.dumps(rehome_data))
        ret_msg = self.spm._is_valid_for_subcloud_sync(subcloud1)
        msg = f'Subcloud {subcloud1.name}'\
            f' (region_name: {subcloud1.region_name}) saved_payload is empty.'
        self.assertEqual(msg, ret_msg)

    def test_is_valid_for_subcloud_sync_missing_bootstrap_address(self):
        # Create local dc subcloud1 mock data in database
        rehome_data = {
            "saved_payload": {
                "systemcontroller_gateway_address": "192.168.204.101"
            }
        }
        # Create local dc subcloud1 mock data in database
        subcloud1 = self._create_subcloud(
            'subcloud1', rehome_data=json.dumps(rehome_data),
            data_install=self.data_install)
        ret_msg = self.spm._is_valid_for_subcloud_sync(subcloud1)
        msg = f'Subcloud {subcloud1.name} (region_name: {subcloud1.region_name})'\
              ' does not have bootstrap-address in saved_payload.'
        self.assertEqual(msg, ret_msg)

    def test_is_valid_for_subcloud_sync_missing_saved_payload(self):
        # Create local dc subcloud1 mock data in database
        rehome_data = {}
        # Create local dc subcloud1 mock data in database
        subcloud1 = self._create_subcloud(
            'subcloud1', rehome_data=json.dumps(rehome_data),
            data_install=self.data_install)
        ret_msg = self.spm._is_valid_for_subcloud_sync(subcloud1)
        msg = f'Subcloud {subcloud1.name} (region_name: subcloud1) '\
              'does not have saved_payload.'
        self.assertEqual(msg, ret_msg)

    def test_valid_for_subcloud_sync_missing_systemcontroller_gateway_addr(self):
        # Create local dc subcloud1 mock data in database
        rehome_data = {
            "saved_payload": {
                "bootstrap-address": "192.168.10.10"
            }
        }
        # Create local dc subcloud1 mock data in database
        subcloud1 = self._create_subcloud(
            'subcloud1', rehome_data=json.dumps(rehome_data),
            data_install=self.data_install)
        ret_msg = self.spm._is_valid_for_subcloud_sync(subcloud1)
        msg = f'Subcloud {subcloud1.name} (region_name: {subcloud1.region_name})'\
            ' does not have systemcontroller_gateway_address in saved_payload.'
        self.assertEqual(msg, ret_msg)

    def test_sync_subclouds_update_subcloud_exception(self):
        rehome_data = {
            "saved_payload": {
                "bootstrap-address": "192.168.10.10",
                "systemcontroller_gateway_address": "192.168.204.101"
            }
        }
        # Create local dc subcloud1 mock data in database
        subcloud1 = self._create_subcloud(
            'subcloud1', rehome_data=json.dumps(rehome_data),
            data_install=self.data_install)
        peer_subcloud1 = self._fake_site_data(1)
        self.mock_dc_client().get_subcloud.side_effect = [
            peer_subcloud1, dccommon_exceptions.SubcloudNotFound]
        self.mock_dc_client().update_subcloud.side_effect = Exception('boom')
        self.spm._sync_subclouds(self.ctx, self.peer, self.peer_group.id,
                                 FAKE_SITE1_PEER_GROUP_ID)
        self.mock_log.error.assert_called_once_with(
            f'Failed to add/update Subcloud {subcloud1.name} '
            f'(region_name: {subcloud1.region_name}) on peer site: boom'
        )

    def test_sync_subclouds_delete_subcloud_exception(self):
        peer_subcloud1 = self._fake_site_data(1)
        self.mock_dc_client().get_subcloud.side_effect = [peer_subcloud1]
        self.mock_dc_client().get_subcloud_list_by_peer_group.return_value = [
            peer_subcloud1]
        self.mock_dc_client().delete_subcloud.side_effect = Exception('boom')
        self.spm._sync_subclouds(self.ctx, self.peer, self.peer_group.id,
                                 FAKE_SITE1_PEER_GROUP_ID)
        self.mock_log.error.assert_called_once_with(
            'Subcloud delete failed: boom')

    def test_sync_subcloud_peer_group_association_notfound(self):
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            side_effect = [dccommon_exceptions.PeerGroupAssociationNotFound]
        self.spm.sync_subcloud_peer_group(self.ctx, self.association.id, True)
        self.mock_dc_client().add_peer_group_association.assert_called_once()
        self.mock_dc_client().update_subcloud_peer_group.assert_called_once()

    def test_sync_subcloud_peer_group_fail(self):
        # system_uuid of the peer site not matches with the peer_uuid
        peer = self.create_system_peer_static(
            self.ctx,
            peer_uuid=111,
            peer_name='SystemPeer')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx,
            peer_group_name='SubcloudPeerGroup3')
        association = self.create_peer_group_association_static(
            self.ctx,
            system_peer_id=peer.id,
            peer_group_id=peer_group.id)
        self.assertRaises(exceptions.PeerGroupAssociationTargetNotMatch,
                          self.spm.sync_subcloud_peer_group, self.ctx,
                          association.id, False)

    def test_sync_subcloud_peer_group_failed_sp_notfound(self):
        self.mock_dc_client().get_system_peer.side_effect = \
            dccommon_exceptions.SystemPeerNotFound
        self.spm.sync_subcloud_peer_group(self.ctx, self.association.id)
        self.mock_log.error.assert_called_once_with(
            'Peer Site System Peer '
            f'{self.mock_get_local_system().uuid} does not exist.')

    def test_sync_subcloud_peer_group_priority(self):
        self.mock_dc_client().get_subcloud_peer_group.return_value = self.peer_group
        self.assertRaisesRegex(
            exceptions.SubcloudPeerGroupHasWrongPriority,
            'Subcloud Peer group of peer site has wrong priority 0',
            self.spm.sync_subcloud_peer_group,
            self.ctx, self.association.id)

    def test_delete_peer_group_association_secondary(self):
        # Delete secondary subcloud on peer site
        # Create local dc subcloud1 mock data in database
        subcloud = self._create_subcloud('subcloud4')
        peer_subcloud4 = self._fake_site_data(4)
        self.mock_dc_client().get_subcloud.side_effect = [
            peer_subcloud4]
        self.mock_dc_client().get_peer_group_association_with_peer_id_and_pg_id.\
            return_value = {'id': FAKE_SITE1_ASSOCIATION_ID}
        self.spm.delete_peer_group_association(self.ctx, self.association.id)
        Calls = [mock.call('Deleting association peer group 1.'),
                 mock.call(
                     f'Ignoring delete Peer Site Subcloud {subcloud.name} as '
                     'is not in secondary or rehome failed state.'),
                 mock.call(
                     f'Processed subcloud {subcloud.name} for peer subcloud clean '
                     '(operation 100% complete, 0 subcloud(s) remaining)'),
                 mock.call('Deleted Subcloud Peer Group '
                           f'{self.peer_group.peer_group_name} on peer site.')]
        self.mock_log.info.assert_has_calls(Calls)

    def test_delete_peer_group_association_uuid_does_not_match(self):
        peer = self.create_system_peer_static(
            self.ctx,
            peer_uuid=111,
            peer_name='SystemPeer')
        peer_group = self.create_subcloud_peer_group_static(
            self.ctx,
            peer_group_name='SubcloudPeerGroup3')
        association = self.create_peer_group_association_static(
            self.ctx,
            system_peer_id=peer.id,
            peer_group_id=peer_group.id)
        self.spm.delete_peer_group_association(self.ctx, association.id)
        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(1, len(associations))
        self.mock_log.warning.assert_called_once_with(
            f'Peer site system uuid {FAKE_SITE1_SYSTEM_UUID} '
            f'does not match with the peer_uuid {peer.peer_uuid}'
        )

    def test_delete_peer_group_association_failed_sp_notfound(self):
        self.mock_dc_client().get_system_peer.side_effect = \
            dccommon_exceptions.SystemPeerNotFound
        self.spm.delete_peer_group_association(self.ctx, self.association.id)
        self.mock_log.error.assert_called_once_with(
            f'Peer Site System Peer {self.mock_get_local_system().uuid}'
            ' does not exist.')

    def test_delete_peer_group_association_priority(self):
        self.mock_dc_client().get_subcloud_peer_group.return_value = self.peer_group
        self.assertRaisesRegex(
            exceptions.SubcloudPeerGroupHasWrongPriority,
            'Subcloud Peer group of peer site has wrong priority 0',
            self.spm.delete_peer_group_association,
            self.ctx, self.association.id)

    def test_delete_peer_group_association_exception(self):
        # Failed to delete subcloud on peer site in parallel.
        self.mock_dc_client().get_subcloud.side_effect = Exception('boom')
        self._create_subcloud('subcloud1')
        self.spm.delete_peer_group_association(self.ctx, self.association.id)
        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(1, len(associations))
        self.mock_log.exception.assert_called_once_with(
            'Failed to delete Subcloud subcloud1 on peer site: boom')

    def test_delete_peer_group_association_failed(self):
        self.mock_dc_client().delete_subcloud_peer_group.side_effect = \
            dccommon_exceptions.SubcloudPeerGroupDeleteFailedAssociated
        self.assertRaises(dccommon_exceptions.
                          SubcloudPeerGroupDeleteFailedAssociated,
                          self.spm.delete_peer_group_association,
                          self.ctx, self.association.id)
        self.mock_log.error.assert_called_once_with(
            f'Subcloud Peer Group {self.peer_group.peer_group_name} '
            'delete failed as it is associated with system peer on peer site.')

    def test_delete_peer_group_association_subcloud_pg_notfound(self):
        self.mock_dc_client().get_subcloud_peer_group.side_effect = \
            dccommon_exceptions.SubcloudPeerGroupNotFound
        self.spm.delete_peer_group_association(self.ctx, self.association.id)
        self.mock_log.warning.assert_called_once_with(
            f'Subcloud Peer Group {self.peer_group.peer_group_name} '
            'does not exist on peer site.')
        associations = db_api.peer_group_association_get_all(self.ctx)
        self.assertEqual(0, len(associations))
