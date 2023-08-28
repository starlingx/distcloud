# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os

from oslo_log import log
import requests
from requests_toolbelt import MultipartEncoder

from dccommon import consts
from dccommon.drivers import base
from dccommon import exceptions

LOG = log.getLogger(__name__)

# Proposed States
ABORTING = 'aborting'
AVAILABLE = 'available'
COMMITTED = 'committed'
DEPLOYED = 'deployed'
DEPLOYING_ACTIVATE = 'deploying-activate'
DEPLOYING_COMPLETE = 'deploying-complete'
DEPLOYING_HOST = 'deploying-host'
DEPLOYING_START = 'deploying-start'
REMOVING = 'removing'
UNAVAILABLE = 'unavailable'
REST_DEFAULT_TIMEOUT = 900


class SoftwareClient(base.DriverBase):
    """Software V1 driver."""

    def __init__(self, region, session, endpoint=None):
        # Get an endpoint and token.
        if not endpoint:
            self.endpoint = session.get_endpoint(
                service_type='usm',
                region_name=region,
                interface=consts.KS_ENDPOINT_ADMIN)
        else:
            self.endpoint = endpoint

        # The usm systemcontroller endpoint ends with a slash but the regionone
        # and the subcloud endpoint don't. The slash is removed to standardize
        # with the other endpoints.
        self.endpoint = self.endpoint.rstrip('/') + '/software'
        self.token = session.get_token()

    def query(self, state='all', release=None, timeout=REST_DEFAULT_TIMEOUT):
        """Query releases"""
        extra_opts = ""
        if release:
            extra_opts = "&release=%s" % release
        url = self.endpoint + '/query?show=%s%s' % (state, extra_opts)

        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            LOG.error("Query failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Query",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Query failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])

    def delete(self, releases, timeout=REST_DEFAULT_TIMEOUT):
        """Delete"""
        release_str = "/".join(releases)
        url = self.endpoint + '/delete/%s' % release_str
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers, timeout=timeout)

        if response.status_code != 200:
            LOG.error("Delete failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Delete",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Delete failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])

    def deploy_activate(self, deployment, timeout=REST_DEFAULT_TIMEOUT):
        """Deploy activate"""
        url = self.endpoint + '/deploy_activate/%s' % deployment
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers, timeout=timeout)

        if response.status_code != 200:
            LOG.error("Deploy activate failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Deploy activate",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Deploy activate failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])

    def deploy_complete(self, deployment, timeout=REST_DEFAULT_TIMEOUT):
        """Deploy complete"""
        url = self.endpoint + '/deploy_complete/%s' % deployment
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers, timeout=timeout)

        if response.status_code != 200:
            LOG.error("Deploy complete failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Deploy complete",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Deploy complete failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])

    def deploy_start(self, deployment, timeout=REST_DEFAULT_TIMEOUT):
        """Deploy start"""
        url = self.endpoint + '/deploy_start/%s' % deployment
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers, timeout=timeout)

        if response.status_code != 200:
            LOG.error("Deploy start failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Deploy start",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Deploy start failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])

    def deploy_host(self, host, timeout=REST_DEFAULT_TIMEOUT):
        """Deploy host"""
        url = self.endpoint + '/deploy_host/%s' % host
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers, timeout=timeout)

        if response.status_code != 200:
            LOG.error("Deploy host failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Deploy host",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Deploy host failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])

    def upload_dir(self, release_dirs, timeout=REST_DEFAULT_TIMEOUT):
        """Upload dir"""
        dirlist = {}
        i = 0
        for d in sorted(set(release_dirs)):
            dirlist["dir%d" % i] = os.path.abspath(d)
            i += 1
            url = self.endpoint + '/upload_dir'
            headers = {"X-Auth-Token": self.token}
        response = requests.post(
            url, params=dirlist, headers=headers, timeout=timeout)
        if response.status_code != 200:
            LOG.error("Upload dir failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Upload dir",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Upload dir failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])

    def upload(self, releases, timeout=REST_DEFAULT_TIMEOUT):
        """Upload"""
        to_upload_files = {}
        for software_file in sorted(set(releases)):
            if os.path.isdir(software_file):
                message = ("Error: %s is a directory. Please use upload-dir" %
                           software_file)
                LOG.error(message)
                raise IsADirectoryError(message)

            if not os.path.isfile(software_file):
                message = "Error: %s doesn't exist" % software_file
                LOG.error(message)
                raise FileNotFoundError(message)

            to_upload_files[software_file] = (
                software_file, open(software_file, 'rb')
            )

        enc = MultipartEncoder(fields=to_upload_files)
        url = self.endpoint + '/upload'
        headers = {"X-Auth-Token": self.token, "Content-Type": enc.content_type}
        response = requests.post(url,
                                 data=enc,
                                 headers=headers,
                                 timeout=timeout)
        if response.status_code != 200:
            LOG.error("Upload failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Upload",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Upload failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])

    def query_hosts(self, timeout=REST_DEFAULT_TIMEOUT):
        """Query hosts"""
        url = self.endpoint + '/query_hosts'
        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            LOG.error("Query hosts failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Query hosts",
                                          rc=response.status_code)
        data = response.json()
        if not data.get('data'):
            message = "Invalid data returned: %s" % data
            LOG.error(message)
            raise Exception(message)
        return data.get('data', [])

    def commit_patch(self, releases, timeout=REST_DEFAULT_TIMEOUT):
        """Commit patch"""
        release_str = "/".join(releases)
        url = self.endpoint + '/commit_patch/%s' % release_str
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers, timeout=timeout)

        if response.status_code != 200:
            LOG.error("Commit patch failed with RC: %d" % response.status_code)
            raise exceptions.ApiException(endpoint="Commit patch",
                                          rc=response.status_code)
        data = response.json()
        if data.get('error'):
            message = "Commit patch failed with error: %s" % data["error"]
            LOG.error(message)
            raise Exception(message)
        return data.get('sd', [])
