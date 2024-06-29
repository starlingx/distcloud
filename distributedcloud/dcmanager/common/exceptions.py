# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright 2015 Ericsson AB.
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

"""
DC Manager base exception handling.
"""

from oslo_utils import excutils

from dcmanager.common.i18n import _


class DCManagerException(Exception):
    """Base DC Manager Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(DCManagerException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs  # pylint: disable=W1645
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(DCManagerException, self).__init__(self.message)

    def use_fatal_exceptions(self):
        return False


class BadRequest(DCManagerException):
    message = _("Bad %(resource)s request: %(msg)s")


class ValidateFail(DCManagerException):
    def __init__(self, message):
        self.message = message
        super(ValidateFail, self).__init__()


class NotFound(DCManagerException):
    message = _("Not found")


class Conflict(DCManagerException):
    message = _("Conflict: %(msg)s")


class NotAuthorized(DCManagerException):
    message = _("Not authorized.")


class Forbidden(DCManagerException):
    message = _("Requested API is forbidden")


class ServiceUnavailable(DCManagerException):
    message = _("The service is unavailable")


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges: %(reason)s")


class InUse(DCManagerException):
    message = _("The resource is inuse")


class InvalidConfigurationOption(DCManagerException):
    message = _("An invalid value was provided for %(opt_name)s: %(opt_value)s")


class InvalidParameterValue(DCManagerException):
    message = _("%(err)s")


class SubcloudAlreadyExists(Conflict):
    message = _("Subcloud with region_name=%(region_name)s already exists")


class SubcloudNotFound(NotFound):
    message = _("Subcloud with id %(subcloud_id)s doesn't exist.")


class SubcloudNameNotFound(NotFound):
    message = _("Subcloud with name %(name)s doesn't exist.")


class SubcloudRegionNameNotFound(NotFound):
    message = _("Subcloud with region name %(region_name)s doesn't exist.")


class SubcloudNameOrRegionNameNotFound(NotFound):
    message = _("Subcloud with name or region name %(name)s doesn't exist.")


class SubcloudOrRegionNameAlreadyExists(Conflict):
    message = _("Subcloud with name or region name %(name)s already exist.")


class SubcloudNotOnline(DCManagerException):
    message = _("Subcloud is not online.")


class SubcloudStatusNotFound(NotFound):
    message = _(
        "SubcloudStatus with subcloud_id %(subcloud_id)s and "
        "endpoint_type %(endpoint_type)s doesn't exist."
    )


class SubcloudNotUnmanaged(DCManagerException):
    message = _("Subcloud must be unmanaged to perform this operation.")


class SubcloudNotOffline(DCManagerException):
    message = _("Subcloud must be powered down to perform this operation.")


class SubcloudPatchOptsNotFound(NotFound):
    message = _(
        "No options found for Subcloud with id %(subcloud_id)s, "
        "defaults will be used."
    )


class SystemPeerNotFound(NotFound):
    message = _("System Peer with id %(peer_id)s doesn't exist.")


class SystemPeerNameNotFound(NotFound):
    message = _("System Peer with peer_name %(name)s doesn't exist.")


class SystemPeerUUIDNotFound(NotFound):
    message = _("System Peer with peer_uuid %(uuid)s doesn't exist.")


class SubcloudGroupNotFound(NotFound):
    message = _("Subcloud Group with id %(group_id)s doesn't exist.")


class SubcloudGroupNameNotFound(NotFound):
    message = _("Subcloud Group with name %(name)s doesn't exist.")


class SubcloudPeerGroupNameNotFound(NotFound):
    message = _("Subcloud Peer Group with name %(name)s doesn't exist.")


class SubcloudPeerGroupNotFound(NotFound):
    message = _("Subcloud Peer Group with id %(group_id)s doesn't exist.")


class PeerGroupAssociationCombinationNotFound(NotFound):
    message = _(
        "Peer Group Association between peer group: %(peer_group_id)s "
        "and system peer: %(system_peer_id)s doesn't exist."
    )


class PeerGroupAssociationTargetNotMatch(NotFound):
    message = _(
        "Peer Group Association with peer site controller "
        "UUID %(uuid)s doesn't match."
    )


class SubcloudPeerGroupHasWrongPriority(DCManagerException):
    message = _("Subcloud Peer group of peer site has wrong priority %(priority)s.")


class PeerGroupAssociationNotFound(NotFound):
    message = _("Peer Group Association with id %(association_id)s doesn't exist.")


class SubcloudGroupNameViolation(DCManagerException):
    message = _("Default Subcloud Group name cannot be changed or reused.")


class SubcloudGroupDefaultNotDeletable(DCManagerException):
    message = _("Default Subcloud Group %(group_id)s may not be deleted.")


class SubcloudBackupOperationFailed(DCManagerException):
    message = _(
        "Failed to run subcloud-backup %(operation)s. Please run "
        "'dcmanager subcloud error' command for details"
    )


class SubcloudSyncFailedException(DCManagerException):
    message = _("Failed to sync subcloud update to peer site %(peer_id)s")


class ConnectionRefused(DCManagerException):
    message = _("Connection to the service endpoint is refused")


class TimeOut(DCManagerException):
    message = _("Timeout when connecting to OpenStack Service")


class InternalError(DCManagerException):
    message = _("Error when performing operation")


class InvalidInputError(DCManagerException):
    message = _("An invalid value was provided")


class CertificateUploadError(DCManagerException):
    message = _("Error while uploading rootca certificate. %(err)s")


class LicenseInstallError(DCManagerException):
    message = _(
        "Error while installing license on subcloud: "
        "%(subcloud_id)s. %(error_message)s"
    )


class LicenseMissingError(DCManagerException):
    message = _("License does not exist on subcloud: %(subcloud_id)s")


class KubeUpgradeFailedException(DCManagerException):
    message = _("Subcloud: %(subcloud)s kube upgrade failed: %(details)s")


class ManualRecoveryRequiredException(DCManagerException):
    message = _("Subcloud: %(subcloud)s needs manual recovery from %(error_message)s")


class PreCheckFailedException(DCManagerException):
    message = _("Subcloud %(subcloud)s upgrade precheck failed: %(details)s")


class SoftwarePreCheckFailedException(DCManagerException):
    message = _("Subcloud %(subcloud)s software deploy precheck failed: %(details)s")


class SoftwareListFailedException(DCManagerException):
    message = _("Subcloud %(subcloud)s software list failed: %(details)s")


class SoftwareDeleteFailedException(DCManagerException):
    message = _("Subcloud %(subcloud)s sofware delete failed: %(details)s")


class SoftwareDeployCommitFailedException(DCManagerException):
    message = _("Subcloud %(subcloud)s sofware deploy commit failed: %(details)s")


class SoftwareDeployDeleteFailedException(DCManagerException):
    message = _("Subcloud %(subcloud)s sofware deploy delete failed: %(details)s")


class PrestagePreCheckFailedException(DCManagerException):
    """PrestagePreCheckFailedException

    Extended to include 'orch_skip' property, indicating that the subcloud
    can be skipped during orchestrated prestage operations.
    """

    def __init__(self, subcloud, details, orch_skip=False):
        self.orch_skip = orch_skip
        # Subcloud can be none if we are failing
        # during global prestage validation
        if subcloud is None:
            self.message = _("Prestage failed: %s" % details)
        elif orch_skip:
            self.message = _("Prestage skipped '%s': %s" % (subcloud, details))
        else:
            self.message = _("Prestage failed '%s': %s" % (subcloud, details))
        super(PrestagePreCheckFailedException, self).__init__()


class VaultLoadMissingError(DCManagerException):
    message = _("No matching: %(file_type)s found in vault: %(vault_dir)s")


class StrategyStepNotFound(NotFound):
    message = _("StrategyStep with subcloud_id %(subcloud_id)s doesn't exist.")


class StrategyStepNameNotFound(NotFound):
    message = _("StrategyStep with name %(name)s doesn't exist.")


class StrategySkippedException(DCManagerException):
    def __init__(self, details):
        self.details = details
        self.message = _(details)
        super(StrategySkippedException, self).__init__()


class StrategyStoppedException(DCManagerException):
    message = _("Strategy has been stopped")


class PlaybookNotFound(NotFound):
    message = _("Playbook %(playbook_name)s not found")
