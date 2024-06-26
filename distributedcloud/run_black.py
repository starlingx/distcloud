# noqa: H102

import subprocess
import sys

# List of module directories to check
modules = [
    "dccommon",
    "dcdbsync",
    "dcorch/api",
    "dcorch/common",
    "dcorch/db",
    "dcorch/engine",
    "dcorch",
    "dcmanager/api",
    "dcmanager/audit",
    "dcmanager/common",
    "dcmanager/db",
    "dcmanager/orchestrator",
    "dcmanager/tests",
    "dcmanager",
]

# List of modules that are already formatted with black
formatted_modules = [
    "dccommon",
    "dcdbsync",
    "dcorch/api",
    "dcorch/common",
]


# Function to run black check
def run_black_check(module):
    try:
        subprocess.run(["black", "--check", "--quiet", f"./{module}"], check=True)
        print(f"Black check passed for {module}")
    except subprocess.CalledProcessError as e:
        print(f"Black check failed for {module}")
        # If the module is in formatted_modules, stx-distcloud-tox-black will fail
        if module in formatted_modules:
            sys.exit(e.returncode)


# Iterate over modules and run black check
for module in modules:
    run_black_check(module)
