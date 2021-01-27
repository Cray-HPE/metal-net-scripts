# Copyright 2021 Hewlett Packard Enterprise Development LP
from setuptools import find_packages
from setuptools import setup


def readme() -> str:
    """
    Print the README file.
    :returns: Read README file.
    """
    with open('README.md') as file:
        return str(file.read())

def version() -> str:
    '''returns version'''
    with open('.version') as file:
        return str(file.read().rstrip())

setup(
    name='metal-net-scripts',
    version=version(),
    description='Network scripts for metal deployments.',
    long_description=readme(),
    author='',
    author_email='',
    maintainer='CSM/Metal Team',
    url='https://stash.us.cray.com/projects/MTL/repos/metal-net-scripts/browse',
    install_requires=[
        'pyyaml',
        'requests',
        'urllib3',
    ],
    extras_require={
        'ci': [
            'tox',
        ],
        'lint': [
            'pycodestyle',
        ],
        'unit': [
            'pytest',
            'pyfakefs',
            'pytest-mock',
        ],
        'docs': [
            'sphinx',
            'sphinx-click',
        ],
    },
    scripts=[
        'bin/aruba_set_bgp_peers.py',
        'bin/mellanox_set_bgp_peers.py',
    ],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)
