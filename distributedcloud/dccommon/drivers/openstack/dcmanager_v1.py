# Copyright (c) 2023 Wind River Systems, Inc.
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

    def get_subcloud(self, subcloud_ref):
        """Get subcloud."""
        if subcloud_ref is None:
            raise ValueError("subcloud_ref is required.")
        url = f"{self.endpoint}/subclouds/{subcloud_ref}"

        headers = {"X-Auth-Token": self.token}
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
        url = self.endpoint + '/subclouds'

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
        url = self.endpoint + '/subcloud-groups'

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
        url = self.endpoint + '/subcloud-peer-groups'

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

    def add_subcloud_peer_group(self, **kwargs):
        """Add a subcloud peer group."""
        url = self.endpoint + '/subcloud-peer-groups'

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
        url = self.endpoint + '/subclouds'

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
                   "Content-Type": enc.content_type}
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

    def update_subcloud(self, subcloud_ref, files, data):
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
