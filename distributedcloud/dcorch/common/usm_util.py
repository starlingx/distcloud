# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
from oslo_log import log as logging

# pylint: disable=unused-import
from software.utils import get_component_and_versions  # noqa: F401

# pylint: disable=unused-import
from software.utils import get_major_release_version  # noqa: F401

LOG = logging.getLogger(__name__)
__ALL__ = ("get_major_release_version", "get_component_and_versions", "parse_upload")


def parse_upload(resp):
    files = []
    resp_str = str(resp)
    try:
        data = json.loads(resp_str)
    except json.JSONDecodeError:
        LOG.error("invalid json format. %s" % resp_str)
        return files

    upload_info = data.get("upload_info")
    if upload_info is None:
        return files

    for upload_file in upload_info:
        for filename in upload_file:
            filedata = upload_file[filename]
            sw_release = filedata.get("sw_release")
            release_id = filedata.get("id")
            if sw_release and release_id:
                files.append(
                    {
                        "filename": filename,
                        "release_id": release_id,
                        "sw_release": sw_release,
                    }
                )
    return files
