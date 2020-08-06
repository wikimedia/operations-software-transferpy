"""transferpy."""
from setuptools import setup

setup(
    name='transferpy',
    description='Fast tool for transferring files',
    version='1.0',
    url='',
    packages=(
        'transferpy',
    ),
    install_requires=[
        'cumin',
        'wmfmariadbpy @ git+https://gerrit.wikimedia.org/r/operations/software/wmfmariadbpy@v0.4',
    ],
    tests_require=[
        'flake8',
        'nose',
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
