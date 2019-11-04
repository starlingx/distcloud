# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
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

import os
import setuptools
# In python < 2.7.4, a lazy loading of package `pbr` will break
# setuptools if some other modules registered functions in `atexit`.
# solution from: http://bugs.python.org/issue15881#msg170215
try:
    import multiprocessing  # noqa
except ImportError:
    pass


def get_data_repo():
    tmp_dir = os.environ['DATA_DIRECTORY']
    return os.path.abspath(tmp_dir)


# Search the data repository to get all sub repositories
# Each sub repository will contain a configuration to run tests with
def get_cfgs():
    return [d for d in os.listdir(data_dir)
            if os.path.isdir(os.path.join(data_dir, d))]


# Some data sets may not have the correct database sources needed for the
# unit tests, this is specified in the tox file and filtered out here
def filter_cfgs(cfgs_full):
    cfgs_usable = []
    required = os.environ.get('REQUIRED_REPOS')
    if required:
        for cfg in cfgs_full:
            subdirs = os.listdir('%s/%s' % (data_dir, cfg))
            include = True
            for d in required.split(','):
                if d not in subdirs:
                    include = False
                    break
            if include:
                cfgs_usable.append(cfg)
    else:
        cfgs_usable = cfgs
    return cfgs_usable


# writes the current data set source to a file within the tests default data
# repo this will be picked up when running  tests to create the path to the
# current test configuration of the ddt framework to unpack
def set_current_test_data(cfg):
    file = open('.current.cfg', 'w')
    file.write('%s/%s' % (data_dir, cfg))
    file.close()


def print_divider(width, txt):
    width_new = (int(width) - len(txt)) // 2
    width_dash = '_' * width_new
    print('%(width_dash)s%(txt)s%(width_dash)s', {'width_dash': width_dash,
                                                  'txt': txt,
                                                  'width_dash': width_dash})


def get_divider_size():
    width = 80
    try:
        rows, width = os.popen('stty size', 'r').read().split()
    except Exception:
        pass
    return width

# Get all repository information
data_dir = get_data_repo()
print('Using %(data_dir)s as data directory', {'data_dir': data_dir})

cfgs = get_cfgs()
cfgs_usable = filter_cfgs(cfgs)
repo = os.environ.get('REQUIRED_REPOS')
print('Required repo databases: %(repo)s', {'repo': repo})
print("Test data folder(s) found: %(cfgs)s", {'cfgs': cfgs})
if len(cfgs_usable) == 0:
    print('No usable data sets found')
    exit

print('Usable data folder(s): %(cfgs_usable)s', {'cfgs_usable': cfgs_usable})
if os.environ.get('SINGLE_REPO') == 'True':
    cfgs_usable = [cfgs_usable[0]]
    print('Restricting to single data set: %(cfgs)s', {'cfgs': cfgs_usable})

# Loop through all configurations and run unit tests with each
columns = get_divider_size()
for cfg in cfgs_usable:
    print_divider(columns, cfg)
    print('Running unit tests with test data: %(cfg)s', {'cfg': cfg})
    set_current_test_data(cfg)
    setuptools.setup(
        setup_requires=['pbr>=1.8.0'],
        pbr=True)
