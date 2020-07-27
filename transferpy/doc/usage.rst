Usage
======

transfer.py is installed (via Puppet_) on PATH on WMF production infrastructure on cumin1001 and cumin1002,
and has to run as root (like cumin).

transfer.py --help
^^^^^^^^^^^^^^^^^^^

.. argparse::
   :module: transferpy.transfer
   :func: parse_arguments
   :prog: transfer.py
   :nodefault:


.. _Puppet: https://phabricator.wikimedia.org/source/operations-puppet/browse/production/modules/profile/manifests/mariadb/backup/transfer.pp
