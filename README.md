transferpy is a Python 3 framework and command-line utility intended to efficiently move large files or directory trees between WMF production hosts, as well as to provide a low-level tool to backup and recover MySQL/MariaDB servers.

## Dependencies

Some dependencies are required in order to run the scripts and the tests. The easiest way to work is by using a virtualenv:

```
tox --no-test
tox -e venv -- <some command>
```

## Run tests

Tests are located under *transferpy/test*. They are split between unit and integration tests. To run unit tests:

```
tox -e unit
```

### Integration tests requirements

In order to be able to to run the tests you'll need to be able to run the script localy. You'll need to have:
* A remote machine with *passwordless ssh to root user*.
* Then assign the variable HOST\_NAME as the remote machine hostname in TestTransfer class of transferpy/test/integration/test\_trasfer.py file.

Then:
```
tox -e integration
```

### Tests coverage report

To run the unit and integration tests and generate a HTML coverage report under `cover/`

```
tox -e cover
```

### Documentation

The documentation has been written using Sphinx/rst. Sphinx uses three sources for document generation.

1. comments in the code.
2. `--help` option of the framework.
3. `rst` files in transferpy/doc

To generate the html documentation under transferpy/doc/.build

```
tox -e sphinx
```

## Code style compliance

To check the code style compliance:

```
tox -e flake8
```

## Execution

The easiest way to run it is via the virtualenv `venv`:
```
tox -e venv -- transferpy source_host:source_path destination_host:destination_path
```
