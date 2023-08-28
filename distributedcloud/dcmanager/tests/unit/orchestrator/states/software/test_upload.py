#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os

import mock

from oslo_config import cfg

from dcmanager.common import consts
from dcmanager.orchestrator.states.software.upload import UploadState
from dcmanager.tests.unit.orchestrator.states.software.test_base \
    import TestSoftwareOrchestrator

REGION_ONE_RELEASES = {"DC_20.12.1": {"sw_version": "20.12.1",
                                      "state": "deployed"},
                       "DC_20.12.2": {"sw_version": "20.12.2",
                                      "state": "deployed"},
                       "DC_20.12.3": {"sw_version": "20.12.3",
                                      "state": "committed"},
                       "DC_20.12.4": {"sw_version": "20.12.4",
                                      "state": "committed"}}


REGION_ONE_RELEASES_2 = {"DC_20.12.1": {"sw_version": "20.12.1",
                                        "state": "deployed"},
                         "DC_22.12.0": {"sw_version": "22.12.0",
                                        "state": "deployed"},
                         "DC_20.12.2": {"sw_version": "20.12.2",
                                        "state": "deployed"}}

REGION_ONE_RELEASES_3 = {"DC_22.12.1": {"sw_version": "22.12.1",
                                        "state": "deployed"},
                         "DC_22.12.0": {"sw_version": "22.12.0",
                                        "state": "deployed"}}

SUBCLOUD_RELEASES = {"DC_20.12.1": {"sw_version": "20.12.1",
                                    "state": "deployed"},
                     "DC_20.12.2": {"sw_version": "20.12.2",
                                    "state": "deployed"}}


@mock.patch("dcmanager.orchestrator.states.software.upload."
            "DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.software.upload"
            ".DEFAULT_SLEEP_DURATION", 1)
class TestUploadState(TestSoftwareOrchestrator):
    def setUp(self):
        p = mock.patch.object(cfg.CONF, 'use_usm')
        self.mock_use_usm = p.start()
        self.mock_use_usm.return_value = True
        self.addCleanup(p.stop)
        super(TestUploadState, self).setUp()
        self.on_success_state = consts.STRATEGY_STATE_SW_DEPLOY_PRE_CHECK

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_UPLOAD)

        # Add mock API endpoints for software client calls
        # invoked by this state
        self.software_client.query = mock.MagicMock()
        self.software_client.upload = mock.MagicMock()
        self._read_from_cache = mock.MagicMock()

    @mock.patch.object(UploadState, '_read_from_cache')
    @mock.patch.object(os.path, 'isfile')
    def test_software_upload_strategy_success(self, mock_is_file,
                                              mock_read_from_cache):
        """Test software upload when the API call succeeds."""
        mock_read_from_cache.side_effect = [REGION_ONE_RELEASES, False]
        mock_is_file.return_value = True
        self.software_client.query.side_effect = [SUBCLOUD_RELEASES]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.upload.assert_called_once_with([
            consts.RELEASE_VAULT_DIR + '/20.12/DC_20.12.3.patch',
            consts.RELEASE_VAULT_DIR + '/20.12/DC_20.12.4.patch'
        ])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch.object(UploadState, '_read_from_cache')
    @mock.patch.object(os.path, 'isfile')
    def test_software_upload_strategy_upload_only(self, mock_is_file,
                                                  mock_read_from_cache):
        """Test software upload when the API call succeeds."""
        mock_read_from_cache.side_effect = [REGION_ONE_RELEASES, True]
        mock_is_file.return_value = True
        self.software_client.query.side_effect = [SUBCLOUD_RELEASES]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.upload.assert_called_once_with([
            consts.RELEASE_VAULT_DIR + '/20.12/DC_20.12.3.patch',
            consts.RELEASE_VAULT_DIR + '/20.12/DC_20.12.4.patch'
        ])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.SW_UPDATE_STATE_COMPLETE)

    @mock.patch.object(UploadState, '_read_from_cache')
    def test_software_upload_strategy_no_operation_required(self,
                                                            mock_read_from_cache):
        """Test software upload when no software operation is required."""
        mock_read_from_cache.side_effect = [REGION_ONE_RELEASES, False]

        self.software_client.query.side_effect = [REGION_ONE_RELEASES]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.upload.assert_not_called()
        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch.object(UploadState, '_read_from_cache')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(os.path, 'isdir')
    def test_software_upload_strategy_missing_sig(self, mock_is_dir, mock_listdir,
                                                  mock_read_from_cache):
        """Test software upload when release is missing signature"""
        mock_read_from_cache.side_effect = [REGION_ONE_RELEASES_2, False]
        mock_is_dir.return_value = True
        mock_listdir.return_value = ["DC_22.12.0.iso"]
        self.software_client.query.side_effect = [SUBCLOUD_RELEASES]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.upload.assert_not_called()

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    @mock.patch.object(UploadState, '_read_from_cache')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(os.path, 'isdir')
    def test_software_upload_strategy_success_load(self, mock_is_dir, mock_listdir,
                                                   mock_read_from_cache):
        """Test software upload when the API call succeeds."""
        mock_read_from_cache.side_effect = [REGION_ONE_RELEASES_2, False]
        mock_is_dir.return_value = True
        mock_listdir.return_value = ["DC_22.12.0.iso", "DC_22.12.0.sig"]
        self.software_client.query.side_effect = [
            SUBCLOUD_RELEASES, REGION_ONE_RELEASES_2]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.upload.assert_called_once_with([
            consts.RELEASE_VAULT_DIR + '/22.12/DC_22.12.0.iso',
            consts.RELEASE_VAULT_DIR + '/22.12/DC_22.12.0.sig'
        ])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch.object(UploadState, '_read_from_cache')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os.path, 'isfile')
    def test_software_upload_prepatched_load(self, mock_isfile,
                                             mock_is_dir, mock_listdir,
                                             mock_read_from_cache):
        """Test software upload when release is a prepatched iso."""
        mock_read_from_cache.side_effect = [REGION_ONE_RELEASES_3, False]
        mock_is_dir.return_value = True
        mock_isfile.return_value = False
        mock_listdir.return_value = ["DC_22.12.0.iso", "DC_22.12.0.sig"]
        self.software_client.query.side_effect = [{}, REGION_ONE_RELEASES_3]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.upload.assert_called_once_with([
            consts.RELEASE_VAULT_DIR + '/22.12/DC_22.12.0.iso',
            consts.RELEASE_VAULT_DIR + '/22.12/DC_22.12.0.sig'
        ])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch.object(UploadState, '_read_from_cache')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os.path, 'isfile')
    def test_software_upload_patch_and_load(self, mock_isfile,
                                            mock_is_dir, mock_listdir,
                                            mock_read_from_cache):
        """Test software upload when both patch and load is uploaded."""
        mock_read_from_cache.side_effect = [REGION_ONE_RELEASES_3, False]
        mock_is_dir.return_value = True
        mock_isfile.return_value = True
        mock_listdir.return_value = ["DC_22.12.0.iso", "DC_22.12.0.sig"]
        self.software_client.query.side_effect = [{}, REGION_ONE_RELEASES_3]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        self.software_client.upload.assert_called_once_with([
            consts.RELEASE_VAULT_DIR + '/22.12/DC_22.12.1.patch',
            consts.RELEASE_VAULT_DIR + '/22.12/DC_22.12.0.iso',
            consts.RELEASE_VAULT_DIR + '/22.12/DC_22.12.0.sig'
        ])

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
