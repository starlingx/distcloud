#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os

from dcmanager.common.exceptions import VaultLoadMissingError

VAULT_LOADS_PATH = '/opt/dc-vault/loads'


def get_vault_load_files(target_version):
    """Return a tuple for the ISO and SIG for this load version from the vault.

    The files can be imported to the vault using any name, but must end
    in 'iso' or 'sig'.
    : param target_version: The software version to search under the vault
    """
    vault_dir = "{}/{}/".format(VAULT_LOADS_PATH, target_version)

    matching_iso = None
    matching_sig = None
    for a_file in os.listdir(vault_dir):
        if a_file.lower().endswith(".iso"):
            matching_iso = os.path.join(vault_dir, a_file)
            continue
        elif a_file.lower().endswith(".sig"):
            matching_sig = os.path.join(vault_dir, a_file)
            continue
    # If no .iso or .sig is found, raise an exception
    if matching_iso is None:
        raise VaultLoadMissingError(file_type='.iso', vault_dir=vault_dir)
    if matching_sig is None:
        raise VaultLoadMissingError(file_type='.sig', vault_dir=vault_dir)

    # return the iso and sig for this load
    return (matching_iso, matching_sig)
