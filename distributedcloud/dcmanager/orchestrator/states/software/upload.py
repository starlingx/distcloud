#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import time

from dccommon.drivers.openstack import software_v1
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.software.cache.cache_specifications import \
    REGION_ONE_RELEASE_USM_CACHE_TYPE
from dcmanager.orchestrator.states.software.cache.cache_specifications import \
    STRATEGY_EXTRA_ARGS_CACHE_TYPE

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10


class UploadState(BaseState):
    """Software orchestration state for uploading releases"""

    def __init__(self, region_name):
        super(UploadState, self).__init__(
            next_state=consts.STRATEGY_STATE_SW_DEPLOY_PRE_CHECK,
            region_name=region_name)
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def _get_major_minor_versions(self, release_sw_version):
        return release_sw_version.rsplit('.', 1)

    def _find_missing_patches(self, subcloud_releases,
                              potential_missing_patches):

        return [potential_missing_patch for potential_missing_patch
                in potential_missing_patches
                if potential_missing_patch not in subcloud_releases]

    def perform_state_action(self, strategy_step):
        """Upload releases in this subcloud"""
        self.info_log(strategy_step, "Uploading releases")
        regionone_releases = self._read_from_cache(REGION_ONE_RELEASE_USM_CACHE_TYPE)
        applied_releases_ids = list()
        for release_id in regionone_releases:
            if regionone_releases[release_id]['state'] in [
                    software_v1.DEPLOYED,
                    software_v1.COMMITTED]:
                applied_releases_ids.append(release_id)

        upload_only = self._read_from_cache(STRATEGY_EXTRA_ARGS_CACHE_TYPE)

        # Retrieve all subcloud releases
        try:
            subcloud_releases = self.get_software_client(
                self.region_name).query()
        except Exception:
            message = ("Cannot retrieve subcloud releases. Please "
                       "see /var/log/software.log for details.")
            self.exception_log(strategy_step, message)
            raise Exception(message)

        releases_to_upload = []

        # RegionOne applied releases not present on the subcloud needs to be uploaded
        for release_id in applied_releases_ids:
            if release_id not in subcloud_releases:
                self.info_log(strategy_step, (f"Release {release_id} missing from "
                                              "subloud"))
                releases_to_upload.append(release_id)

        if releases_to_upload:
            self.info_log(strategy_step,
                          f"Uploading releases {releases_to_upload} to subcloud")

            files_to_upload = []
            potential_missing_patches = []
            iso_release = None
            for release in releases_to_upload:
                major_sw_version, minor_sw_version = self._get_major_minor_versions(
                    regionone_releases[release]['sw_version'])

                # when minor is 0, it means that the release is an iso
                if minor_sw_version == consts.ISO_VERSION:
                    iso_path, sig_path = utils.get_vault_load_files(major_sw_version)
                    files_to_upload.extend([iso_path, sig_path])
                    iso_release = release
                else:
                    patch_path = (f"{consts.RELEASE_VAULT_DIR}/"
                                  f"{major_sw_version}/{release}.patch")
                    if not os.path.isfile(patch_path):
                        # patch wasn't found but it may be included in an iso
                        potential_missing_patches.append(release)
                    else:
                        files_to_upload.append(patch_path)
            if files_to_upload:
                try:
                    self.get_software_client(
                        self.region_name).upload(files_to_upload)
                except Exception:
                    message = ("Cannot upload releases to subcloud. Please "
                               "see /var/log/software.log for details.")
                    self.exception_log(strategy_step, message)
                    raise Exception(message)

            if self.stopped():
                self.info_log(strategy_step, "Exiting because task was stopped")
                raise StrategyStoppedException()

            if iso_release:
                audit_counter = 0
                while True:
                    time.sleep(self.sleep_duration)

                    if self.stopped():
                        raise StrategyStoppedException()

                    try:
                        subcloud_releases = self.get_software_client(
                            self.region_name).query()
                    except Exception:
                        self.debug_log(strategy_step, "failed to retrieve releases.")

                    if iso_release in subcloud_releases:
                        if potential_missing_patches:
                            # Retrieve patches that are present in the system
                            # controller and not in the subcloud after uploading
                            # load to the subcloud.
                            missing_patches = self. \
                                _find_missing_patches(subcloud_releases,
                                                      potential_missing_patches)

                            if missing_patches:
                                message = \
                                    (f"Release files {missing_patches} are missing")
                                self.error_log(strategy_step, message)
                                raise Exception(message)
                        break
                    audit_counter += 1
                    if audit_counter >= self.max_queries:
                        details = ("Timeout waiting for load import to complete. "
                                   "Please check software.log on the subcloud.")
                        self.exception_log(strategy_step, details)
                        raise Exception(details)
            else:
                # No load was uploaded therefore the patches are really missing.
                if potential_missing_patches:
                    message = \
                        (f"Release files {potential_missing_patches} are missing")
                    self.error_log(strategy_step, message)
                    raise Exception(message)

        if upload_only:
            self.info_log(
                strategy_step,
                (
                    f"{consts.EXTRA_ARGS_UPLOAD_ONLY} option enabled, skipping"
                    f" forward to state:({consts.STRATEGY_STATE_COMPLETE})"
                )
            )
            return consts.STRATEGY_STATE_COMPLETE

        return self.next_state
