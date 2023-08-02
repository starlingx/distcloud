#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
import os


@mock.patch.object(os, 'listdir')
def test_check_deploy_files_in_alternate_location_with_all_file_exists(self, mock_os_isdir, mock_os_listdir):
    payload = {}
    mock_os_isdir.return_value = True
    mock_os_listdir.return_value = ['deploy-chart-fake-deployment-manager.tgz',
                                    'deploy-overrides-fake-overrides-subcloud.yaml',
                                    'deploy-playbook-fake-deployment-manager.yaml']

    response = self.check_deploy_files_in_alternate_location(payload)
    self.assertEqual(response, True)


def test_check_deploy_files_in_alternate_location_with_deploy_chart_not_exists(self, mock_os_isdir, mock_os_listdir):
    payload = {}
    mock_os_isdir.return_value = True
    mock_os_listdir.return_value = ['deploy-chart-fake.tgz',
                                    'deploy-overrides-fake-overrides-subcloud.yaml',
                                    'deploy-playbook-fake-deployment-manager.yaml']

    response = self.check_deploy_files_in_alternate_location(payload)
    self.assertEqual(response, False)


def test_check_deploy_files_in_alternate_location_with_deploy_overrides_not_exists(self, mock_os_isdir, mock_os_listdir):
    payload = {}
    mock_os_isdir.return_value = True
    mock_os_listdir.return_value = ['deploy-chart-fake-deployment-manager.tgz',
                                    'deploy-overrides.yaml',
                                    'deploy-playbook-fake-deployment-manager.yaml']

    response = self.check_deploy_files_in_alternate_location(payload)
    self.assertEqual(response, False)


def test_check_deploy_files_in_alternate_location_with_deploy_playbook_not_exists(self, mock_os_isdir, mock_os_listdir):
    payload = {}
    mock_os_isdir.return_value = True
    mock_os_listdir.return_value = ['deploy-chart-fake-deployment-manager.tgz',
                                    'deploy-overrides-fake-overrides-subcloud.yaml',
                                    'deploy-playbook.yaml']

    response = self.check_deploy_files_in_alternate_location(payload)
    self.assertEqual(response, False)
