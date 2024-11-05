# Copyright (c) 2017-2024 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import os.path
import sys

import mock
from oslo_config import cfg
from oslo_utils import uuidutils

from dccommon import consts as dccommon_consts
from dcmanager.audit import rpcapi
from dcmanager.common import consts
from dcmanager.manager import service
from dcmanager.tests.base import DCManagerTestCase

sys.modules["fm_core"] = mock.Mock()
CONF = cfg.CONF


class BaseTestDCManagerService(DCManagerTestCase):
    """Base class for testing DCManagerService"""

    def setUp(self):
        super().setUp()
        self.service_obj = service.DCManagerService("dcmanager", "dcmanager")
        self.payload = {}
        self._mock_object(rpcapi, "ManagerAuditClient")
        self.mock_subcloud_manager = self._mock_object(service, "SubcloudManager")
        self.mock_peer_monitor_manager = self._mock_object(
            service, "PeerMonitorManager"
        )


class TestDCManagerServiceInit(BaseTestDCManagerService):
    """Test class for testing init managers in DCManagerService"""

    def setUp(self):
        super().setUp()

    def test_init(self):
        self.assertEqual(self.service_obj.host, "localhost")
        self.assertEqual(self.service_obj.topic, "dcmanager")

    def test_init_managers(self):
        self.service_obj.init_managers()
        self.assertIsNotNone(self.service_obj.subcloud_manager)
        self.assertIsNotNone(self.service_obj.system_peer_manager)
        self.assertIsNotNone(self.service_obj.peer_monitor_manager)


@mock.patch.object(service, "rpc_messaging")
class TestDCManagerService(BaseTestDCManagerService):
    """Test class for testing DCManagerService"""

    def setUp(self):
        super().setUp()

    def test_start(self, mock_rpc):
        os.path.isdir = mock.Mock(return_value=True)
        self.service_obj.start()
        mock_rpc.get_rpc_server.assert_called_once_with(
            self.service_obj.target, self.service_obj
        )
        mock_rpc.get_rpc_server().start.assert_called_once()


class TestSubcloudManager(BaseTestDCManagerService):
    """Test class for testing SubcloudManager"""

    def setUp(self):
        super().setUp()

    def test_add_subcloud(self):
        payload = {
            "name": "testname",
            "region_name": uuidutils.generate_uuid().replace("-", ""),
        }
        self.service_obj.init_managers()
        self.service_obj.add_subcloud(self.ctx, subcloud_id=1, payload=payload)
        self.mock_subcloud_manager().add_subcloud.assert_called_once_with(
            self.ctx, 1, payload
        )

    def test_add_secondary_subcloud(self):
        payload = {
            "name": "testname",
            "region_name": uuidutils.generate_uuid().replace("-", ""),
        }
        self.service_obj.init_managers()
        self.service_obj.add_secondary_subcloud(
            self.ctx, subcloud_id=2, payload=payload
        )
        self.mock_subcloud_manager().add_subcloud.assert_called_once_with(
            self.ctx, 2, payload
        )

    def test_delete_subcloud(self):
        self.service_obj.init_managers()
        self.service_obj.delete_subcloud(self.ctx, subcloud_id=1)
        self.mock_subcloud_manager().delete_subcloud.assert_called_once_with(
            self.ctx, 1
        )

    def test_rename_subcloud(self):
        self.service_obj.init_managers()
        self.service_obj.rename_subcloud(
            self.ctx,
            subcloud_id=1,
            curr_subcloud_name="fake_subcloud",
            new_subcloud_name="subcloud1",
        )
        self.mock_subcloud_manager().rename_subcloud.assert_called_once_with(
            self.ctx, 1, "fake_subcloud", "subcloud1"
        )

    def test_get_subcloud_name_by_region_name(self):
        self.service_obj.init_managers()
        self.service_obj.get_subcloud_name_by_region_name(
            self.ctx, subcloud_region="test_region"
        )
        get_subcloud_name = (
            self.mock_subcloud_manager().get_subcloud_name_by_region_name
        )
        get_subcloud_name.assert_called_once_with(self.ctx, "test_region")

    def test_update_subcloud(self):
        self.service_obj.init_managers()
        self.service_obj.update_subcloud(
            self.ctx, subcloud_id=1, management_state="testmgmtstatus"
        )
        self.mock_subcloud_manager().update_subcloud.assert_called_once_with(
            self.ctx,
            1,
            "testmgmtstatus",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )

    def test_update_subcloud_with_network_reconfig(self):
        payload = {"name": "testname", "bootstrap-address": "10.10.10.12"}
        self.service_obj.init_managers()
        self.service_obj.update_subcloud_with_network_reconfig(
            self.ctx, subcloud_id=1, payload=payload
        )
        update_subcloud_with_network_reconfig = (
            self.mock_subcloud_manager().update_subcloud_with_network_reconfig
        )
        update_subcloud_with_network_reconfig.assert_called_once_with(
            self.ctx, 1, payload
        )

    def test_redeploy_subcloud(self):
        payload = {"DEPLOY_PHASE_CONFIG": "configure"}
        self.service_obj.init_managers()
        self.service_obj.redeploy_subcloud(
            self.ctx, subcloud_id=1, payload=payload, previous_version="22.12"
        )
        self.mock_subcloud_manager().redeploy_subcloud.assert_called_once_with(
            self.ctx, 1, payload, "22.12"
        )

    def test_backup_subclouds(self):
        payload = {"subcloud": "subcloud1"}
        self.service_obj.init_managers()
        self.service_obj.backup_subclouds(self.ctx, payload=payload)
        self.mock_subcloud_manager().create_subcloud_backups.assert_called_once_with(
            self.ctx, payload
        )

    def test_delete_subcloud_backups(self):
        payload = {"subcloud": "subcloud2"}
        self.service_obj.init_managers()
        self.service_obj.delete_subcloud_backups(
            self.ctx, release_version=23.09, payload=payload
        )
        self.mock_subcloud_manager().delete_subcloud_backups.assert_called_once_with(
            self.ctx, 23.09, payload
        )

    def test_restore_subcloud_backups(self):
        payload = {"subcloud": "subcloud2"}
        self.service_obj.init_managers()
        self.service_obj.restore_subcloud_backups(self.ctx, payload=payload)
        self.mock_subcloud_manager().restore_subcloud_backups.assert_called_once_with(
            self.ctx, payload
        )

    def test_update_subcloud_sync_endpoint_type(self):
        self.service_obj.init_managers()
        self.service_obj.update_subcloud_sync_endpoint_type(
            self.ctx,
            subcloud_name="testname",
            endpoint_type_list=dccommon_consts.ENDPOINT_TYPES_LIST_OS,
            openstack_installed=True,
        )
        update_subcloud_sync_endpoint_type = (
            self.mock_subcloud_manager().update_subcloud_sync_endpoint_type
        )
        update_subcloud_sync_endpoint_type.assert_called_once_with(
            self.ctx, "testname", dccommon_consts.ENDPOINT_TYPES_LIST_OS, True
        )

    def test_prestage_subcloud(self):
        payload = {"subcloud_name": "subcloud1"}
        self.service_obj.init_managers()
        self.service_obj.prestage_subcloud(self.ctx, payload=payload)
        self.mock_subcloud_manager().prestage_subcloud.assert_called_once_with(
            self.ctx, payload
        )

    def test_subcloud_deploy_create(self):
        payload = {"name": "subcloud1"}
        self.service_obj.init_managers()
        self.service_obj.subcloud_deploy_create(
            self.ctx, subcloud_id=1, payload=payload
        )
        self.mock_subcloud_manager().subcloud_deploy_create.assert_called_once_with(
            self.ctx, 1, payload
        )

    def test_subcloud_deploy_bootstrap(self):
        payload = {"name": "subcloud1"}
        self.service_obj.init_managers()
        self.service_obj.subcloud_deploy_bootstrap(
            self.ctx, subcloud_id=1, payload=payload, initial_deployment=True
        )
        self.mock_subcloud_manager().subcloud_deploy_bootstrap.assert_called_once_with(
            self.ctx, 1, payload, True
        )

    def test_subcloud_deploy_config(self):
        payload = {"name": "testname"}
        self.service_obj.init_managers()
        self.service_obj.subcloud_deploy_config(
            self.ctx, subcloud_id=1, payload=payload, initial_deployment=True
        )
        self.mock_subcloud_manager().subcloud_deploy_config.assert_called_once_with(
            self.ctx, 1, payload, True
        )

    def test_subcloud_deploy_install(self):
        payload = {"name": "testname"}
        self.service_obj.init_managers()
        self.service_obj.subcloud_deploy_install(
            self.ctx,
            subcloud_id=1,
            payload=payload,
            initial_deployment=True,
            previous_version="22.12",
        )
        self.mock_subcloud_manager().subcloud_deploy_install.assert_called_once_with(
            self.ctx, 1, payload, True, "22.12"
        )

    def test_subcloud_deploy_complete(self):
        self.service_obj.init_managers()
        self.service_obj.subcloud_deploy_complete(self.ctx, subcloud_id=1)
        self.mock_subcloud_manager().subcloud_deploy_complete.assert_called_once_with(
            self.ctx, 1
        )

    def test_subcloud_deploy_abort(self):
        self.service_obj.init_managers()
        self.service_obj.subcloud_deploy_abort(
            self.ctx, subcloud_id=1, deploy_status=consts.DEPLOY_STATE_ABORTING_CONFIG
        )
        self.mock_subcloud_manager().subcloud_deploy_abort.assert_called_once_with(
            self.ctx, 1, consts.DEPLOY_STATE_ABORTING_CONFIG
        )

    def test_subcloud_deploy_resume(self):

        deploy_states_to_run = [
            consts.DEPLOY_PHASE_INSTALL,
            consts.DEPLOY_PHASE_BOOTSTRAP,
            consts.DEPLOY_PHASE_CONFIG,
        ]

        fake_payload = {
            "fake_payload_install": "fake_install_values",
            "fake_payload_bootstrap": "fake_bootstrap_values",
            "fake_payload_config": "fake_config",
        }

        self.service_obj.init_managers()
        self.service_obj.subcloud_deploy_resume(
            self.ctx,
            subcloud_id=1,
            subcloud_name="testname",
            payload=fake_payload,
            deploy_states_to_run=deploy_states_to_run,
            previous_version="22.12",
        )
        self.mock_subcloud_manager().subcloud_deploy_resume.assert_called_once_with(
            self.ctx, 1, "testname", fake_payload, deploy_states_to_run, "22.12"
        )

    def test_batch_migrate_subcloud(self):
        payload = {"peer_group": "fake_peer_group"}
        self.service_obj.init_managers()
        self.service_obj.batch_migrate_subcloud(self.ctx, payload=payload)
        self.mock_subcloud_manager().batch_migrate_subcloud.assert_called_once_with(
            self.ctx, payload
        )


class TestPeerMonitorManager(BaseTestDCManagerService):
    """Test class for testing PeerMonitorManager"""

    def setUp(self):
        super().setUp()

    def test_peer_monitor_notify(self):
        self.service_obj.init_managers()
        self.service_obj.peer_monitor_notify(self.ctx)
        self.mock_peer_monitor_manager().peer_monitor_notify.assert_called_once_with(
            self.ctx
        )

    def test_peer_group_audit_notify(self):
        payload = {"peer_uuid": 2}
        self.service_obj.init_managers()
        self.service_obj.peer_group_audit_notify(
            self.ctx, peer_group_name="fake_peer_group", payload=payload
        )
        peer_group_audit_notify = (
            self.mock_peer_monitor_manager().peer_group_audit_notify
        )
        peer_group_audit_notify.assert_called_once_with(
            self.ctx, "fake_peer_group", payload
        )


@mock.patch.object(service, "SystemPeerManager")
class TestSystemPeerManager(BaseTestDCManagerService):
    """Test class for testing SystemPeerManager"""

    def setUp(self):
        super().setUp()

    def test_sync_subcloud_peer_group(self, mock_system_peer_manager):
        self.service_obj.init_managers()
        self.service_obj.sync_subcloud_peer_group(
            self.ctx, association_id=2, sync_subclouds=True
        )
        mock_system_peer_manager().sync_subcloud_peer_group.assert_called_once_with(
            self.ctx, 2, True
        )

    def test_delete_peer_group_association(self, mock_system_peer_manager):
        self.service_obj.init_managers()
        self.service_obj.delete_peer_group_association(self.ctx, association_id=2)
        delete_peer_group_association = (
            mock_system_peer_manager().delete_peer_group_association
        )
        delete_peer_group_association.assert_called_once_with(self.ctx, 2)
