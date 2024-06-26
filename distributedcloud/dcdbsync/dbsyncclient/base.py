# Copyright (c) 2016 Ericsson AB
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

import json

from bs4 import BeautifulSoup

from dcdbsync.dbsyncclient import exceptions


class Resource(object):
    # This will be overridden by the actual resource
    resource_name = "Something"


class ResourceManager(object):
    resource_class = None

    def __init__(self, http_client):
        self.http_client = http_client

    def _generate_resource(self, json_response_key):
        json_objects = [json_response_key[item] for item in json_response_key]
        resource = []
        for json_object in json_objects:
            for resource_data in json_object:
                resource.append(
                    self.resource_class(  # pylint: disable=E1102
                        self, resource_data, json_object[resource_data]
                    )
                )
        return resource

    def _list(self, url, response_key=None):
        resp = self.http_client.get(url)
        if resp.status_code != 200:
            self._raise_api_exception(resp)
        json_response_key = get_json(resp)
        resource = self._generate_resource(json_response_key)
        return resource

    def _update(self, url, data):
        data = json.dumps(data)
        resp = self.http_client.put(url, data)
        if resp.status_code != 200:
            self._raise_api_exception(resp)
        json_response_key = get_json(resp)
        result = self._generate_resource(json_response_key)
        return result

    def _sync(self, url, data=None):
        resp = self.http_client.put(url, data)
        if resp.status_code != 200:
            self._raise_api_exception(resp)

    def _detail(self, url):
        resp = self.http_client.get(url)
        if resp.status_code != 200:
            self._raise_api_exception(resp)
        json_response_key = get_json(resp)
        json_objects = [json_response_key[item] for item in json_response_key]
        resource = []
        for json_object in json_objects:
            for values in json_object.get("usage").keys():
                resource.append(
                    self.resource_class(  # pylint: disable=E1102
                        self,
                        values,
                        json_object["limits"][values],
                        json_object["usage"][values],
                    )
                )
        return resource

    def _delete(self, url):
        resp = self.http_client.delete(url)
        if resp.status_code != 200:
            self._raise_api_exception(resp)

    def _raise_api_exception(self, resp):
        error_html = resp.content
        soup = BeautifulSoup(error_html, "html.parser")
        # Get the raw html with get_text, strip out the blank lines on
        # front and back, then get rid of the 2 lines of error code number
        # and error code explanation so that we are left with just the
        # meaningful error text.
        try:
            error_msg = soup.body.get_text().lstrip().rstrip().split("\n")[2]
        except Exception:
            error_msg = resp.content

        raise exceptions.APIException(
            error_code=resp.status_code, error_message=error_msg
        )


def get_json(response):
    """Get JSON representation of response."""
    json_field_or_function = getattr(response, "json", None)
    if callable(json_field_or_function):
        return response.json()
    else:
        return json.loads(response.content)
