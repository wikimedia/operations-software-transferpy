Installation
============

Dependencies
^^^^^^^^^^^^^^
transfer.py requires the following technologies

- Python 3, preferable 3.7 or later

  + cumin python class if chosen as the transfer system

- Transferpy development requires Python 3.7 or later.

- A remote execution system (ssh, paramiko, salt, etc.).
  If none are available, there is a LocalExecution class, but it will only allow to run commands locally (local transfers)

  + For cumin, transfer.py must be installed on a cumin* host to be able to execute remote commands

- Netcat (nc)
- pigz for compression
- tar for archiving before streaming
- openssl for encryption
- du, df to calculate used and available disk size
- bash to pipe the different unix commands
- wmf-mariadb package and an instance running for --type=xtrabackup
- xtrabackup (mariabackup) installed locally on the mariadb hosts for --type=xtrabackup
- mysql client if replication wants to be stopped
- iptables to manage the firewall hole during transfer

*Note*: transfer.py expect the user to have root privileges without the sudo prefix.
