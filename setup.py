"""transferpy."""
from setuptools import setup

setup(
    name='transferpy',
    description='Fast tool for transferring files',
    version='1.2',
    url='https://doc.wikimedia.org/transferpy/',
    packages=(
        'transferpy',
        'transferpy.RemoteExecution',
        'transferpy.Firewall',
    ),
    install_requires=[
        'cumin',
    ],
    tests_require=[
        'flake8',
        'pytest',
        'coverage',
    ],
    extras_require={
        'sphinx': [
            'sphinx_rtd_theme>=0.4.3',
            'sphinx-argparse>=0.2.2',
            'Sphinx>=1.8.4',
        ]
    },
    entry_points={
        # TODO: Expand
        'console_scripts': [
            'transfer.py = transferpy.transfer:main',
        ],
    },
    test_suite='transferpy.test',
)
