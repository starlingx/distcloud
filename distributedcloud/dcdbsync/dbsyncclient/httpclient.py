# Copyright 2013 - Mirantis, Inc.
# Copyright 2016 - StackStorm, Inc.
# Copyright 2016 - Ericsson AB.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# Copyright (c) 2019, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import logging
import os
import requests

from oslo_utils import importutils

from dcdbsync.dbsyncclient import exceptions

osprofiler_web = importutils.try_import("osprofiler.web")

LOG = logging.getLogger(__name__)


def log_request(func):
    def decorator(self, *args, **kwargs):
        resp = func(self, *args, **kwargs)
        LOG.debug("HTTP %s %s %d" % (resp.request.method, resp.url,
                                     resp.status_code))
        return resp

    return decorator


class HTTPClient(object):
    def __init__(self, base_url, token=None, project_id=None, user_id=None,
                 cacert=None, insecure=False, request_timeout=None):
        self.base_url = base_url
        self.token = token
        self.project_id = project_id
        self.user_id = user_id
        self.ssl_options = {}
        self.request_timeout = request_timeout

        if self.base_url.startswith('https'):
            if cacert and not os.path.exists(cacert):
                raise ValueError('Unable to locate cacert file '
                                 'at %s.' % cacert)

            if cacert and insecure:
                LOG.warning('Client is set to not verify even though '
                            'cacert is provided.')

            self.ssl_options['verify'] = not insecure
            self.ssl_options['cert'] = cacert

    @log_request
    def get(self, url, headers=None):
        options = self._get_request_options('get', headers)

        try:
            url = self.base_url + url
            timeout = self.request_timeout
            return requests.get(url, timeout=timeout, **options)
        except requests.exceptions.Timeout:
            msg = 'Request to %s timed out' % url
            raise exceptions.ConnectTimeout(msg)
        except requests.exceptions.ConnectionError as e:
            msg = 'Unable to establish connection to %s: %s' % (url, e)
            raise exceptions.ConnectFailure(msg)
        except requests.exceptions.RequestException as e:
            msg = 'Unexpected exception for %s: %s' % (url, e)
            raise exceptions.UnknownConnectionError(msg)

    @log_request
    def post(self, url, body, headers=None):
        options = self._get_request_options('post', headers)

        try:
            url = self.base_url + url
            timeout = self.request_timeout
            return requests.post(url, body, timeout=timeout, **options)
        except requests.exceptions.Timeout:
            msg = 'Request to %s timed out' % url
            raise exceptions.ConnectTimeout(msg)
        except requests.exceptions.ConnectionError as e:
            msg = 'Unable to establish connection to %s: %s' % (url, e)
            raise exceptions.ConnectFailure(msg)
        except requests.exceptions.RequestException as e:
            msg = 'Unexpected exception for %s: %s' % (url, e)
            raise exceptions.UnknownConnectionError(msg)

    @log_request
    def put(self, url, body, headers=None):
        options = self._get_request_options('put', headers)

        try:
            url = self.base_url + url
            timeout = self.request_timeout
            return requests.put(url, body, timeout=timeout, **options)
        except requests.exceptions.Timeout:
            msg = 'Request to %s timed out' % url
            raise exceptions.ConnectTimeout(msg)
        except requests.exceptions.ConnectionError as e:
            msg = 'Unable to establish connection to %s: %s' % (url, e)
            raise exceptions.ConnectFailure(msg)
        except requests.exceptions.RequestException as e:
            msg = 'Unexpected exception for %s: %s' % (url, e)
            raise exceptions.UnknownConnectionError(msg)

    @log_request
    def patch(self, url, body, headers=None):
        options = self._get_request_options('patch', headers)

        try:
            url = self.base_url + url
            timeout = self.request_timeout
            return requests.patch(url, body, timeout=timeout, **options)
        except requests.exceptions.Timeout:
            msg = 'Request to %s timed out' % url
            raise exceptions.ConnectTimeout(msg)
        except requests.exceptions.ConnectionError as e:
            msg = 'Unable to establish connection to %s: %s' % (url, e)
            raise exceptions.ConnectFailure(msg)
        except requests.exceptions.RequestException as e:
            msg = 'Unexpected exception for %s: %s' % (url, e)
            raise exceptions.UnknownConnectionError(msg)

    @log_request
    def delete(self, url, headers=None):
        options = self._get_request_options('delete', headers)

        try:
            url = self.base_url + url
            timeout = self.request_timeout
            return requests.delete(url, timeout=timeout, **options)
        except requests.exceptions.Timeout:
            msg = 'Request to %s timed out' % url
            raise exceptions.ConnectTimeout(msg)
        except requests.exceptions.ConnectionError as e:
            msg = 'Unable to establish connection to %s: %s' % (url, e)
            raise exceptions.ConnectFailure(msg)
        except requests.exceptions.RequestException as e:
            msg = 'Unexpected exception for %s: %s' % (url, e)
            raise exceptions.UnknownConnectionError(msg)

    def _get_request_options(self, method, headers):
        headers = self._update_headers(headers)

        if method in ['post', 'put', 'patch']:
            content_type = headers.get('content-type', 'application/json')
            headers['content-type'] = content_type

        options = copy.deepcopy(self.ssl_options)
        options['headers'] = headers

        return options

    def _update_headers(self, headers):
        if not headers:
            headers = {}

        token = headers.get('x-auth-token', self.token)
        if token:
            headers['x-auth-token'] = token

        project_id = headers.get('X-Project-Id', self.project_id)
        if project_id:
            headers['X-Project-Id'] = project_id

        user_id = headers.get('X-User-Id', self.user_id)
        if user_id:
            headers['X-User-Id'] = user_id

        # Add headers for osprofiler.
        if osprofiler_web:
            headers.update(osprofiler_web.get_trace_id_headers())

        return headers
