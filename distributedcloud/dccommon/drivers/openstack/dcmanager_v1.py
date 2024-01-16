# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log
import requests
from requests_toolbelt import MultipartEncoder

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions


LOG = log.getLogger(__name__)

DCMANAGER_CLIENT_REST_DEFAULT_TIMEOUT = 600


class DcmanagerClient(base.DriverBase):
    """Dcmanager V1 driver."""

    def __init__(self, region, session,
                 timeout=DCMANAGER_CLIENT_REST_DEFAULT_TIMEOUT,
                 endpoint_type=consts.KS_ENDPOINT_PUBLIC,
                 endpoint=None):
        if endpoint is None:
            endpoint = session.get_endpoint(
                service_type='dcmanager',
                region_name=region,
                interface=endpoint_type)
        self.endpoint = endpoint
        self.token = session.get_token()
        self.timeout = timeout

    def get_system_peer(self, system_peer_uuid):
        """Get system peer."""
        if system_peer_uuid is None:
            raise ValueError("system_peer_uuid is required.")
        url = f"{self.endpoint}/system-peers/{system_peer_uuid}"

        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'System Peer not found' in response.text:
                raise exceptions.SystemPeerNotFound(
                    system_peer=system_peer_uuid)
            message = "Get SystemPeer: system_peer_uuid %s failed with RC: %d" \
                % (system_peer_uuid, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def get_subcloud(self, subcloud_ref, is_region_name=False):
        """Get subcloud."""
        if subcloud_ref is None:
            raise ValueError("subcloud_ref is required.")
        url = f"{self.endpoint}/subclouds/{subcloud_ref}/detail"

        headers = {"X-Auth-Token": self.token}
        if is_region_name:
            headers["User-Agent"] = consts.DCMANAGER_V1_HTTP_AGENT
        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Subcloud not found' in response.text:
                raise exceptions.SubcloudNotFound(subcloud_ref=subcloud_ref)
            message = "Get Subcloud: subcloud_ref %s failed with RC: %d" % \
                (subcloud_ref, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def get_subcloud_list(self):
        """Get subcloud list."""
        url = f"{self.endpoint}/subclouds"

        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code == 200:
            data = response.json()
            return data.get('subclouds', [])
        else:
            message = "Get Subcloud list failed with RC: %d" % \
                response.status_code
            LOG.error(message)
            raise Exception(message)

    def get_subcloud_group_list(self):
        """Get subcloud group list."""
        url = f"{self.endpoint}/subcloud-groups"

        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code == 200:
            data = response.json()
            return data.get('subcloud_groups', [])
        else:
            message = "Get Subcloud Group list: failed with RC: %d" % \
                response.status_code
            LOG.error(message)
            raise Exception(message)

    def get_subcloud_peer_group_list(self):
        """Get subcloud peer group list."""
        url = f"{self.endpoint}/subcloud-peer-groups"

        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code == 200:
            data = response.json()
            return data.get('subcloud_peer_groups', [])
        else:
            message = "Get Subcloud Peer Group list: failed with RC: %d" % \
                response.status_code
            LOG.error(message)
            raise Exception(message)

    def get_subcloud_peer_group(self, peer_group_ref):
        """Get subcloud peer group."""
        if peer_group_ref is None:
            raise ValueError("peer_group_ref is required.")
        url = f"{self.endpoint}/subcloud-peer-groups/{peer_group_ref}"

        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Subcloud Peer Group not found' in response.text:
                raise exceptions.SubcloudPeerGroupNotFound(
                    peer_group_ref=peer_group_ref)
            message = "Get Subcloud Peer Group: peer_group_ref %s " \
                "failed with RC: %d" % (peer_group_ref, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def get_subcloud_list_by_peer_group(self, peer_group_ref):
        """Get subclouds in the specified subcloud peer group."""
        if peer_group_ref is None:
            raise ValueError("peer_group_ref is required.")
        url = f"{self.endpoint}/subcloud-peer-groups/{peer_group_ref}/" \
            "subclouds"

        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code == 200:
            data = response.json()
            return data.get('subclouds', [])
        else:
            if response.status_code == 404 and \
                    'Subcloud Peer Group not found' in response.text:
                raise exceptions.SubcloudPeerGroupNotFound(
                    peer_group_ref=peer_group_ref)
            message = "Get Subcloud list by Peer Group: peer_group_ref %s " \
                "failed with RC: %d" % (peer_group_ref, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def get_peer_group_association_with_peer_id_and_pg_id(self, peer_id,
                                                          pg_id):
        """Get peer group association with peer id and PG id."""
        for association in self.get_peer_group_association_list():
            if peer_id == association.get('system-peer-id') and \
                    pg_id == association.get('peer-group-id'):
                return association
        raise exceptions.PeerGroupAssociationNotFound(
            association_id=None)

    def get_peer_group_association_list(self):
        """Get peer group association list."""
        url = f"{self.endpoint}/peer-group-associations"

        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=self.timeout)

        if response.status_code == 200:
            data = response.json()
            return data.get('peer_group_associations', [])
        else:
            message = "Get Peer Group Association list failed with RC: %d" % \
                response.status_code
            LOG.error(message)
            raise Exception(message)

    def add_subcloud_peer_group(self, **kwargs):
        """Add a subcloud peer group."""
        url = f"{self.endpoint}/subcloud-peer-groups"

        headers = {"X-Auth-Token": self.token,
                   "Content-Type": "application/json"}
        response = requests.post(url, json=kwargs, headers=headers,
                                 timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            message = "Add Subcloud Peer Group: %s, failed with RC: %d" % \
                (kwargs, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def add_subcloud_with_secondary_status(self, files, data):
        """Add a subcloud with secondary status."""
        url = f"{self.endpoint}/subclouds"

        # If not explicitly specified, set 'secondary' to true by default.
        # This action adds a secondary subcloud with rehoming data in the
        # peer site without creating an actual subcloud.
        if 'secondary' in data and data['secondary'] != "true":
            raise ValueError("secondary in data must true.")
        data['secondary'] = "true"

        fields = dict()
        if files is not None:
            # If files are specified, add them to the fields.
            for k, v in files.items():
                fields.update({k: (v, open(v, 'rb'),)})

        fields.update(data)
        enc = MultipartEncoder(fields=fields)
        headers = {"X-Auth-Token": self.token,
                   "Content-Type": enc.content_type,
                   "User-Agent": consts.DCMANAGER_V1_HTTP_AGENT}
        response = requests.post(url, headers=headers, data=enc,
                                 timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            message = "Add Subcloud with secondary status: files: %s, " \
                "data: %s, failed with RC: %d" % (files, data,
                                                  response.status_code)
            LOG.error(message)
            raise Exception(message)

    def add_peer_group_association(self, **kwargs):
        """Add a peer group association."""
        url = f"{self.endpoint}/peer-group-associations"

        headers = {"X-Auth-Token": self.token,
                   "Content-Type": "application/json"}
        response = requests.post(url, json=kwargs, headers=headers,
                                 timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            message = "Add Peer Group Association: %s, failed with RC: %d" % \
                (kwargs, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def update_peer_group_association_sync_status(self, association_id,
                                                  sync_status):
        """Update the peer group association sync_status."""
        if association_id is None:
            raise ValueError("association_id is required.")
        url = f"{self.endpoint}/peer-group-associations/{association_id}"
        update_kwargs = {"sync_status": sync_status}

        headers = {"X-Auth-Token": self.token,
                   "Content-Type": "application/json"}
        response = requests.patch(url, json=update_kwargs, headers=headers,
                                  timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Peer Group Association not found' in response.text:
                raise exceptions.PeerGroupAssociationNotFound(
                    association_id=association_id)
            message = "Update Peer Group Association: association_id %s, " \
                "sync_status %s, failed with RC: %d" % (
                    association_id, sync_status, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def update_subcloud_peer_group(self, peer_group_ref, **kwargs):
        """Update the subcloud peer group."""
        if peer_group_ref is None:
            raise ValueError("peer_group_ref is required.")
        url = f"{self.endpoint}/subcloud-peer-groups/{peer_group_ref}"

        headers = {"X-Auth-Token": self.token,
                   "Content-Type": "application/json"}
        response = requests.patch(url, json=kwargs, headers=headers,
                                  timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Subcloud Peer Group not found' in response.text:
                raise exceptions.SubcloudPeerGroupNotFound(
                    peer_group_ref=peer_group_ref)
            message = "Update Subcloud Peer Group: peer_group_ref %s, %s, " \
                "failed with RC: %d" % (peer_group_ref, kwargs,
                                        response.status_code)
            LOG.error(message)
            raise Exception(message)

    def audit_subcloud_peer_group(self, peer_group_ref, **kwargs):
        """Audit the subcloud peer group."""
        if peer_group_ref is None:
            raise ValueError("peer_group_ref is required.")
        url = f"{self.endpoint}/subcloud-peer-groups/{peer_group_ref}/audit"

        headers = {"X-Auth-Token": self.token,
                   "Content-Type": "application/json"}
        response = requests.patch(url, json=kwargs, headers=headers,
                                  timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Subcloud Peer Group not found' in response.text:
                raise exceptions.SubcloudPeerGroupNotFound(
                    peer_group_ref=peer_group_ref)
            message = "Audit Subcloud Peer Group: peer_group_ref %s, %s, " \
                "failed with RC: %d" % (peer_group_ref, kwargs,
                                        response.status_code)
            LOG.error(message)
            raise Exception(message)

    def update_subcloud(self, subcloud_ref, files, data, is_region_name=False):
        """Update the subcloud."""
        if subcloud_ref is None:
            raise ValueError("subcloud_ref is required.")
        url = f"{self.endpoint}/subclouds/{subcloud_ref}"

        fields = dict()
        if files is not None:
            # If files are specified, add them to the fields.
            for k, v in files.items():
                fields.update({k: (v, open(v, 'rb'),)})

        fields.update(data)
        enc = MultipartEncoder(fields=fields)
        headers = {"X-Auth-Token": self.token,
                   "Content-Type": enc.content_type}
        # Add header to flag the request is from another DC,
        # server will treat subcloud_ref as a region_name
        if is_region_name:
            headers["User-Agent"] = consts.DCMANAGER_V1_HTTP_AGENT
        response = requests.patch(url, headers=headers, data=enc,
                                  timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Subcloud not found' in response.text:
                raise exceptions.SubcloudNotFound(subcloud_ref=subcloud_ref)
            message = "Update Subcloud: subcloud_ref: %s files: %s, " \
                "data: %s, failed with RC: %d" % (subcloud_ref, files, data,
                                                  response.status_code)
            LOG.error(message)
            raise Exception(message)

    def delete_peer_group_association(self, association_id):
        """Delete the peer group association."""
        if association_id is None:
            raise ValueError("association_id is required.")
        url = f"{self.endpoint}/peer-group-associations/{association_id}"

        headers = {"X-Auth-Token": self.token}
        response = requests.delete(url, headers=headers,
                                   timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Peer Group Association not found' in response.text:
                raise exceptions.PeerGroupAssociationNotFound(
                    association_id=association_id)
            message = "Delete Peer Group Association: association_id %s " \
                "failed with RC: %d" % (association_id, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def delete_subcloud_peer_group(self, peer_group_ref):
        """Delete the subcloud peer group."""
        if peer_group_ref is None:
            raise ValueError("peer_group_ref is required.")
        url = f"{self.endpoint}/subcloud-peer-groups/{peer_group_ref}"

        headers = {"X-Auth-Token": self.token}
        response = requests.delete(url, headers=headers,
                                   timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Subcloud Peer Group not found' in response.text:
                raise exceptions.SubcloudPeerGroupNotFound(
                    peer_group_ref=peer_group_ref)
            elif response.status_code == 400 and \
                'a peer group which is associated with a system peer' in \
                    response.text:
                raise exceptions.SubcloudPeerGroupDeleteFailedAssociated(
                    peer_group_ref=peer_group_ref
                )
            message = "Delete Subcloud Peer Group: peer_group_ref %s " \
                "failed with RC: %d" % (peer_group_ref, response.status_code)
            LOG.error(message)
            raise Exception(message)

    def delete_subcloud(self, subcloud_ref):
        """Delete the subcloud."""
        if subcloud_ref is None:
            raise ValueError("subcloud_ref is required.")
        url = f"{self.endpoint}/subclouds/{subcloud_ref}"

        headers = {"X-Auth-Token": self.token}
        response = requests.delete(url, headers=headers,
                                   timeout=self.timeout)

        if response.status_code == 200:
            return response.json()
        else:
            if response.status_code == 404 and \
                    'Subcloud not found' in response.text:
                raise exceptions.SubcloudNotFound(subcloud_ref=subcloud_ref)
            message = "Delete Subcloud: subcloud_ref %s failed with RC: %d" % \
                (subcloud_ref, response.status_code)
            LOG.error(message)
            raise Exception(message)
