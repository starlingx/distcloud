# Copyright (c) 2021, 2024 Wind River Systems, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from xml import etree as et

from oslo_log import log
import webob

from dcorch.api.proxy.common.service import Middleware

LOG = log.getLogger(__name__)

# As per webob.exc code:
# https://github.com/Pylons/webob/blob/master/src/webob/exc.py
# The explanation field is added to the HTTP exception as following:
# ${explanation}<br /><br />
WEBOB_EXPL_SEP = "<br /><br />"


class ParseError(Middleware):
    """WSGI middleware to replace the plain text message body of an

    error response with one formatted so the client can parse it.

    Based on pecan.middleware.errordocument

    """

    def __init__(self, app, conf):
        self.app = app

    def __call__(self, environ, start_response):
        # Request for this state, modified by replace_start_response()
        # and used when an error is being reported.
        state = {}

        def replacement_start_response(status, headers, exc_info=None):
            """Overrides the default response to make errors parsable."""
            try:
                status_code = int(status.split(" ")[0])
                state["status_code"] = status_code
            except (ValueError, TypeError):  # pragma: nocover
                raise Exception(
                    ("ErrorDocumentMiddleware received an invalid status %s" % status)
                )
            else:
                if (state["status_code"] // 100) not in (2, 3):
                    # Remove some headers so we can replace them later
                    # when we have the full error message and can
                    # compute the length.
                    headers = [
                        (h, v)
                        for (h, v) in headers
                        if h not in ("Content-Length", "Content-Type")
                    ]
                # Save the headers in case we need to modify them.
                state["headers"] = headers
                return start_response(status, headers, exc_info)

        app_iter = self.app(environ, replacement_start_response)
        if (state["status_code"] // 100) not in (2, 3):
            req = webob.Request(environ)
            if (
                req.accept.best_match(["application/json", "application/xml"])
                == "application/xml"
            ):

                try:
                    # simple check xml is valid
                    body = [
                        et.ElementTree.tostring(
                            et.ElementTree.fromstring(
                                "<error_message>"
                                + "\n".join(app_iter)
                                + "</error_message>"
                            )
                        )
                    ]
                except et.ElementTree.ParseError as err:
                    LOG.error("Error parsing HTTP response: %s" % err)
                    body = [
                        "<error_message>%s" % state["status_code"] + "</error_message>"
                    ]
                state["headers"].append(("Content-Type", "application/xml"))
            else:
                app_iter = [i.decode("utf-8") for i in app_iter]
                # Parse explanation field from webob.exc and add it as
                # 'faulstring' to be processed by cgts-client
                fault = None
                app_data = "\n".join(app_iter)
                for data in app_data.split("\n"):
                    if WEBOB_EXPL_SEP in str(data):
                        # Remove separator, trailing and leading white spaces
                        fault = str(data).replace(WEBOB_EXPL_SEP, "").strip()
                        break
                if fault is None:
                    body = [json.dumps({"error_message": app_data})]
                else:
                    body = [
                        json.dumps(
                            {"error_message": json.dumps({"faultstring": fault})}
                        )
                    ]
                body = [item.encode("utf-8") for item in body]
                state["headers"].append(("Content-Type", "application/json"))
            state["headers"].append(("Content-Length", str(len(body[0]))))
        else:
            body = app_iter
        return body
