"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

import os.path
from setuptools import setup

# The directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(HERE, "telfhash", "VERSION")) as version_file:
    VERSION = version_file.read().strip()

def readme():
    with open(os.path.join(HERE, "README.md")) as f:
        return f.read()

def requires():
    requirements = []

    with open(os.path.join(HERE, "requirements.txt")) as f:
        for line in f:
            if len(line) > 0:
                requirements.append(line.strip())

    return requirements

setup(
    name="telfhash",
    version=VERSION,
    description="Generates hash for ELF files",
    long_description=readme(),
    url="https://github.com/trendmicro/telfhash",
    author="Fernando Merces, Joey Costoya",
    license="Apache",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.7"
    ],
    keywords="telfhash elf linux hash symbols",
    packages=["telfhash"],
    include_package_data=True,
    install_requires=requires(),
    entry_points={
        "console_scripts": ["telfhash=telfhash.__main__:main"]
    },
    test_suite="nose.collector",
    tests_require=["nose"],
    zip_safe=False
)
