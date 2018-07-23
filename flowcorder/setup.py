"""Install this using `pip install [-e '.']`."""

import os
from subprocess import check_output, SubprocessError
from setuptools import setup, find_packages

VERSION = '0.8'
HERE = os.path.dirname(__file__)

modname = distname = 'flowcorder'
descr = ('Daemons and libraries to instrument end host and export flow-level '
         'statistics over IPFIX.')

UNITS = ['systemd/%s' % unit
         for unit in os.listdir(os.path.join(HERE, 'systemd'))]
try:
    UNIT_DIR = check_output(['rpm', '--eval', '%{_unitdir}']
                            ).decode('utf8').strip(' \n\r\t')
except (FileNotFoundError, IOError, SubprocessError):
    # taken from Fedora packaging doc as default
    UNIT_DIR = '/lib/systemd/system'


setup(
    name=distname,
    version=VERSION,
    description=descr,
    long_description=descr,
    author='Olivier Tilmans',
    author_email='olivier.tilmans@uclouvain.be',
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Programming Language :: Python",
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
        'Programming Language :: Python :: 3',
    ],
    keywords='networking multihoming ipfix tcp dns bcc ebpf instrumentation',
    license='GPLv2',
    install_requires=[
        'setuptools',
        'daemons',
        'ipfix>0.9.7',
        'bcc',
        'pyroute2',
        'py-radix',
    ],
    tests_require=['pytest'],
    setup_requires=['pytest-runner'],
    scripts=['bin/%s' % name for name in
             os.listdir(os.path.join(HERE, 'bin'))],
    data_files=[(UNIT_DIR, UNITS)],
)
