#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
import pecan
from pecan import expose
from pecan import request

from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import subcloud_backup_config as config_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common.i18n import _
from dcmanager.db import api as db_api


LOG = logging.getLogger(__name__)


class SubcloudBackupConfigController:
    """REST API controller for subcloud backup configuration"""

    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods
        pass

    @index.when(method="GET", template="json")
    def get(self):
        policy.authorize(
            config_policy.POLICY_ROOT % "get",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        try:
            config = db_api.subcloud_backup_config_get(context)

            result = {
                "storage_location": config.storage_location,
                "retention_count": config.retention_count,
                "updated_at": (
                    config.updated_at.isoformat() if config.updated_at else None
                ),
            }

            LOG.debug(
                f"Retrieved backup configuration: "
                f"storage={config.storage_location}, retention={config.retention_count}"
            )

            return result

        except Exception as e:
            LOG.exception(f"Failed to get backup configuration: {e}")
            pecan.abort(500, _("Failed to retrieve backup configuration"))

    @index.when(method="PATCH", template="json")
    def patch(self):
        policy.authorize(
            config_policy.POLICY_ROOT % "modify",
            {},
            restcomm.extract_credentials_for_policy(),
        )
        context = restcomm.extract_context_from_environ()

        payload = self._get_payload()
        if not payload:
            pecan.abort(400, _("Body required"))

        storage_location = payload.get("storage_location")
        retention_count = payload.get("retention_count")

        if not storage_location and retention_count is None:
            pecan.abort(400, _("At least one parameter must be provided"))

        if storage_location:
            storage_location = self._validate_storage_location(storage_location)

        if retention_count is not None:
            retention_count = self._validate_retention_count(retention_count)

        if storage_location == consts.BACKUP_STORAGE_SEAWEEDFS:
            self._validate_seaweedfs_state()

        return self._update_config(context, storage_location, retention_count)

    @staticmethod
    def _get_payload():
        try:
            payload = request.json
            if not isinstance(payload, dict):
                pecan.abort(400, _("Invalid request body format"))
            return payload
        except Exception:
            pecan.abort(400, _("Request body must be valid JSON"))

    @staticmethod
    def _validate_storage_location(storage_location: str):
        storage_location = storage_location.lower()
        if storage_location not in consts.BACKUP_STORAGE_LOCATIONS:
            pecan.abort(
                400,
                _("Invalid storage_location. Must be one of: %s")
                % ", ".join(consts.BACKUP_STORAGE_LOCATIONS),
            )
        return storage_location

    @staticmethod
    def _validate_retention_count(retention_count):
        if not str(retention_count).isdigit():
            pecan.abort(400, _("retention_count must be a positive integer"))

        retention_count = int(retention_count)
        if not (
            consts.MIN_BACKUP_RETENTION_COUNT
            <= retention_count
            <= consts.MAX_BACKUP_RETENTION_COUNT
        ):
            pecan.abort(
                400,
                _("retention_count must be between %s and %s")
                % (
                    consts.MIN_BACKUP_RETENTION_COUNT,
                    consts.MAX_BACKUP_RETENTION_COUNT,
                ),
            )

        return retention_count

    @staticmethod
    def _validate_seaweedfs_state():
        try:
            # TODO(gherzmann): Add SeaweedFS state/connectivity check here
            LOG.info("SeaweedFS storage location requested (validation skipped)")
        except Exception as e:
            LOG.warning(f"SeaweedFS validation failed: {e}")
            pecan.abort(400, _("Cannot switch to SeaweedFS: service not available"))

    @staticmethod
    def _update_config(context, storage_location, retention_count):
        try:
            values = {}
            if storage_location:
                values["storage_location"] = storage_location
            if retention_count is not None:
                values["retention_count"] = retention_count

            config = db_api.subcloud_backup_config_update(context, values)

            result = {
                "storage_location": config.storage_location,
                "retention_count": config.retention_count,
                "updated_at": (
                    config.updated_at.isoformat() if config.updated_at else None
                ),
            }

            LOG.info(
                f"Updated backup configuration: "
                f"storage={config.storage_location}, retention={config.retention_count}"
            )

            return result

        except Exception as e:
            LOG.exception(f"Failed to update backup configuration: {e}")
            pecan.abort(500, _("Failed to update backup configuration"))
