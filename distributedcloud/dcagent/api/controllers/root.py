#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan

from dcagent.api.controllers.v1 import root as v1_root


class RootController(object):
    @pecan.expose("json")
    def _lookup(self, version, *remainder):
        version = str(version)
        minor_version = version[-1]
        major_version = version[1]
        remainder = remainder + (minor_version,)
        if major_version == "1":
            return v1_root.Controller(), remainder

    @pecan.expose(generic=True, template="json")
    def index(self):
        return {
            "versions": [
                {
                    "status": "CURRENT",
                    "links": [
                        {"rel": "self", "href": pecan.request.application_url + "/v1/"}
                    ],
                    "id": "v1",
                    "updated": "2024-06-20",
                }
            ]
        }

    @index.when(method="POST")
    @index.when(method="PUT")
    @index.when(method="DELETE")
    @index.when(method="HEAD")
    @index.when(method="PATCH")
    def not_supported(self):
        pecan.abort(405)
