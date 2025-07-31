#!/usr/bin/env python3
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Monitors the IPMI System Event Log (SEL) for a specific target event and
associated event data.

The script periodically checks the SEL for the desired event. If the event
is found, the script returns a return code of 0 and the matched event in
json format. If the event is not found after the maximum number of checks,
a non-zero return code is returned.

It only monitors new events, existing events are ignored.
"""

import argparse
import base64
import json
import logging
import os
import re
import subprocess
import sys
import time
from typing import Optional

import netaddr
import yaml

# Configure logging to stderr so stdout stays clean for Ansible JSON output
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)


def hex_to_int(hex_str: str) -> int:
    return int(hex_str, 16)


def run_command(cmd: list[str]) -> Optional[str]:
    """Run a shell command and return its output"""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return result.stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {' '.join(cmd)}")
        logging.error(f"stderr: {e.stderr.strip()}")
        return None


def exit_script(
    success: bool, message: str, matched_data: Optional[str] = None
) -> None:
    if not success:
        logging.error(message)

    # Output as JSON to stdout for Ansible to parse
    result = {"success": success, "message": message}

    # Add additional info if an event was matched
    if matched_data:
        result["matched_data"] = matched_data

    print(json.dumps(result))
    sys.exit(0 if success else 1)


class IpmiTool:
    def __init__(self, host, user, password):
        self.base_cmd = [
            "ipmitool",
            "-I",
            "lanplus",
            "-H",
            host,
            "-U",
            user,
            "-P",
            password,
        ]

    @classmethod
    def from_config(cls, path: str) -> "IpmiTool":
        """Instantiates IpmiTool using a BMC config file"""

        logging.info(f"Parsing BMC config from {path}")

        if not os.path.isfile(path):
            exit_script(False, f"BMC config file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as yaml_config:
                cfg = yaml.safe_load(yaml_config)

        except Exception as ex:
            exit_script(
                False,
                f"Unable to open or parse the BMC configuration file: {path} ({ex})",
            )

        for key in ("bmc_password", "bmc_address", "bmc_username"):
            if key not in cfg:
                exit_script(False, f"{key} is missing from the BMC configuration file")
        try:
            cfg["bmc_password"] = base64.b64decode(cfg["bmc_password"]).decode("utf-8")
        except Exception as ex:
            exit_script(
                False, f"Failed to decode BMC password found in config file ({ex})"
            )

        # Validate IP address
        try:
            netaddr.IPAddress(cfg["bmc_address"])
        except Exception as ex:
            exit_script(
                False,
                "Invalid bmc_address found in the BMC configuration "
                f"file: {cfg['bmc_address']} ({ex})",
            )

        return cls(cfg["bmc_address"], cfg["bmc_username"], cfg["bmc_password"])

    @staticmethod
    def get_id_from_line(event_line: str) -> str:
        return hex_to_int(event_line.split("|")[0].strip())

    def get_event_details(self, event_id: str) -> str:
        """Get detailed information for a specific event"""
        cmd = self.base_cmd + ["sel", "get", str(event_id)]
        return run_command(cmd)

    def get_all_events(self) -> list[str]:
        """Get all events in the SEL"""
        cmd = self.base_cmd + ["sel", "list"]

        output = run_command(cmd)
        if not output:
            return []
        return output.strip().splitlines()

    def get_last_event_id(self) -> Optional[str]:
        """Get the ID of the most recent event in the SEL"""
        lines = self.get_all_events()

        if not lines:
            return None

        return self.get_id_from_line(lines[-1])

    def extract_event_data(self, event_details: str) -> Optional[str]:
        """Extract the Event Data field from event details"""
        match = re.search(r"Event Data\s+:\s+(\S+)", event_details)
        if match:
            return match.group(1)
        return None


def monitor_events(
    ipmi_tool: IpmiTool,
    target_pattern: str,
    event_data_values: list[str],
    interval: float,
    timeout: int,
) -> tuple[bool, str, Optional[str]]:
    """Monitor IPMI SEL for target events"""

    last_event_id = ipmi_tool.get_last_event_id()
    if not last_event_id:
        message = "Failed to get initial event ID, SEL might be empty"
        logging.warning(message)
        # If the SEL is empty, we set the starting event ID to -1 because
        # the first event will always be >= 0
        last_event_id = -1

    logging.info(f"Starting monitoring from event ID: {last_event_id}")
    logging.info(
        f"Looking for event pattern '{target_pattern}' with "
        f"data values: {event_data_values}"
    )

    last_event_id_int = last_event_id
    event_data_values = [d.lower() for d in event_data_values]
    max_checks = max(1, int(timeout / interval))

    for check_num in range(max_checks):
        logging.info(f"Check {check_num + 1}/{max_checks}: Checking for new events...")

        current_event_id = ipmi_tool.get_last_event_id()
        if not current_event_id:
            logging.warning("Failed to get current event ID")
            time.sleep(interval)
            continue

        current_event_id_int = current_event_id
        logging.info(
            f"Current last event ID: {current_event_id}, previous: {last_event_id}"
        )

        if current_event_id_int == last_event_id_int:
            # There's no new events, wait for the next check attempt
            time.sleep(interval)
            continue

        if current_event_id_int < last_event_id_int:
            logging.info(
                "Current last event ID is smaller than the previous ID, "
                "assuming SEL was cleared..."
            )
            last_event_id_int = 0

        logging.info("New events detected! Fetching all events...")
        all_events = ipmi_tool.get_all_events()

        new_events = []
        for event_line in all_events:
            if not event_line.strip():
                continue
            event_id = ipmi_tool.get_id_from_line(event_line)
            if event_id > last_event_id_int:
                new_events.append(event_line)

        logging.info(f"Found {len(new_events)} new events")

        matching_events = [
            e for e in new_events if re.search(re.escape(target_pattern), e)
        ]
        logging.info(f"Found {len(matching_events)} matching events")

        for event_line in matching_events:
            event_id = ipmi_tool.get_id_from_line(event_line)
            logging.info(f"Checking event ID {event_id} for target data...")

            event_details = ipmi_tool.get_event_details(event_id)
            if not event_details:
                continue

            event_data = ipmi_tool.extract_event_data(event_details)
            if not event_data:
                continue

            logging.info(f"Event {event_id} data: {event_data}")

            # Check if this matches any of the target event data values
            if event_data.lower() in event_data_values:
                message = (
                    f"Target event found! Event ID: {event_id}, "
                    f"Event Data: {event_data}"
                )
                logging.info(message)
                return True, message, event_data

            logging.info(
                f"Event {event_id} matches pattern but data doesn't match "
                f"any expected values"
            )

        last_event_id = current_event_id
        last_event_id_int = current_event_id_int

        time.sleep(interval)

    message = f"Monitoring timed out after {timeout} seconds"
    logging.warning(message)
    return False, message, None


def main():
    parser = argparse.ArgumentParser(description="Monitor IPMI SEL for target events")
    parser.add_argument(
        "--config-file",
        required=True,
        help="Path to BMC configuration file containing host, username, and password",
    )
    parser.add_argument(
        "--pattern", required=True, help="Target event pattern to match"
    )

    parser.add_argument(
        "--data-values",
        required=True,
        help="Comma-separated list of event data values to match",
    )
    parser.add_argument(
        "--interval", type=int, default=30, help="Check interval in seconds"
    )
    parser.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")

    args = parser.parse_args()

    event_data_values = [d.strip() for d in args.data_values.split(",")]
    try:
        ipmi_tool = IpmiTool.from_config(args.config_file)

        success, message, matched_data = monitor_events(
            ipmi_tool,
            args.pattern,
            event_data_values,
            args.interval,
            args.timeout,
        )

        exit_script(success, message, matched_data)

    except Exception as e:
        exit_script(
            False,
            f"Unexpected exception while monitoring IPMI SEL for target events: {e}",
        )


if __name__ == "__main__":
    main()
