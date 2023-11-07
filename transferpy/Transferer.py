#!/usr/bin/python3

"""
Transferer class: main class and entry point for the WMF transfer framework, and
what is used internally by the transfer.py command line utility.

For more details, see:
https://wikitech.wikimedia.org/wiki/Transfer.py
and
https://doc.wikimedia.org/transferpy/master/
"""

import base64
import os
import os.path
import re
import shlex
import time
import logging

from wmfmariadbpy.RemoteExecution.CuminExecution import CuminExecution as RemoteExecution
from transferpy.Firewall import Firewall
from transferpy.MariaDB import MariaDB
from transferpy.Exceptions import (TempDeletionError, TempCreationError, FirewallError, ChecksumError,
                                   FreeDiskSpaceError, MySQLError, NotFoundError, OverwriteError)


class Transferer:
    """
    Top class used to implement the tranference of files and databases between hosts, using
    some fast method- used primarily for cloning data for databases, backup and recoveries,
    and migrating swift data between hosts, and while it can be used as a general purpose
    transfer system, it was initially thougt mainly for massive transfer and data generated
    on the fly (e.g. xtrabackup dumps), and so it uses unix pipes. It is not suitable for
    transferences that can be paused and continued later.

    It can transfer at the moment files, directories (preserving its metadata) and
    xtrabackup outputs- while compressing and encrypting the data on the wire.

    Note: The right spelling of this class should be Tranferrer.
    """
    def __init__(self, source_host, source_path, target_hosts, target_paths, options={}):
        self.source_host = shlex.quote(source_host)
        self.source_path = shlex.quote(source_path)
        self.target_hosts = [shlex.quote(h) for h in target_hosts]
        self.target_paths = [shlex.quote(p) for p in target_paths]
        self.options = options
        if 'type' not in self.options:  # default transfer type is file/directory transfer
            self.options['type'] = 'file'
        if 'verbose' not in self.options:  # default to non-verbose output
            self.options['verbose'] = False
        if 'checksum' not in self.options:  # default to checksum
            self.options['checksum'] = True
        if 'parallel_checksum' not in self.options:  # default to non-parallel-checksum
            self.options['parallel_checksum'] = False

        self.logger = logging.getLogger(__name__)
        remote_execution_options = {'verbose': self.options['verbose']}
        self.remote_executor = RemoteExecution(remote_execution_options)
        self.mariadb = MariaDB(self.remote_executor)

        self.source_is_dir = False
        self.source_is_socket = False
        self.original_size = 0
        self.checksum = None
        self.parallel_checksum = None

        self.parent_tmp_dir = '/tmp'
        self.source_tmp_dir = None
        self.parallel_checksum_source_path = None
        self.parallel_checksum_target_path = None

        self._password = None
        self.cipher = 'chacha20'
        self.buffer_size = 8
        self.iterations = 310000

        self.logger.debug('Finished Transferer initialization')

    def run_command(self, host, command):
        """
        It redirects the remote execution of a given command for a given host to the right
        api executing that.
        """
        return self.remote_executor.run(host, command)

    @property
    def is_xtrabackup(self):
        """
        Returns true if the copy type is 'xtrabackup'- that means, it is running a database
        backup on the source host, otherwise it returns false.
        """
        return self.options['type'] == 'xtrabackup'

    @property
    def is_decompress(self):
        """
        Returns true if the execution involves xtrbackup on the source host, otherwise
        it returns false.
        """
        return self.options['type'] == 'decompress'

    def is_dir(self, host, path):
        """
        Returns true if the given path is a directory and exists on the given host, otherwise
        returns false.
        """
        command = ['/bin/bash', '-c', f'"[ -d "{path}" ]"']
        result = self.run_command(host, command)
        return not result.returncode

    def is_socket(self, host, path):
        """
        Returns true if the given path is a socket and exists on the given host, otherwise
        returns false.
        """
        command = ['/bin/bash', '-c', f'"[ -S "{path}" ]"']
        result = self.run_command(host, command)
        return not result.returncode

    def host_exists(self, host):
        """
        Checks the availability of given host by trying to run a noop on it.
        Returns true if the hosts exists and it is available for remote execution, otherwise
        returns false.

        :param host: host to be checked
        :return: remote execution run_command result
        """
        command = ['/bin/true']
        result = self.run_command(host, command)
        return result

    def file_exists(self, host, path):
        """
        Returns true if there is a file or a directory with such path on the remote
        host given.
        """
        command = ['/bin/bash', '-c', f'"[ -a "{path}" ]"']
        result = self.run_command(host, command)
        return not result.returncode

    def calculate_checksum_command(self, host, path):
        """
        Returns a list of strings with the command needed to run to check on the given
        trarget host that the file(s) created are the same as in the source host.
        """
        hash_executable = '/usr/bin/md5sum'
        parent_dir = os.path.normpath(os.path.join(path, '..'))
        basename = os.path.basename(os.path.normpath(path))
        if host == self.source_host and path == self.source_path:
            checksum_write_command = f' > "{self.parallel_checksum_source_path}"'
        else:
            checksum_write_command = ''
        if self.source_is_dir:
            command = [
                '/bin/bash',
                '-c',
                (
                    f'"cd {parent_dir} && '
                    f'/usr/bin/find {basename} -type f -exec {hash_executable} '
                    r'\{\} \; '
                    f'{checksum_write_command}"'
                )
            ]
        else:
            command = [
                '/bin/bash',
                '-c',
                f'"cd {parent_dir} && {hash_executable} {basename} {checksum_write_command}"'
            ]
        return command

    def calculate_checksum(self, host, path):
        """
        Returns the standard output of the result of calculating the checksum on
        the target host. If the checksums are different, it throws an exception. If
        the checkums match, it returns the standard output, if any.
        """
        self.logger.info('Started checksum calculation for %s:%s', host, path)
        command = self.calculate_checksum_command(host, path)
        result = self.run_command(host, command)
        if result.returncode != 0:
            raise ChecksumError('md5sum execution failed')
        self.logger.info('Finished checksum calculation for %s:%s', host, path)
        return result.stdout

    def read_checksum(self, host, path):
        """
        Returns a string with the checksum calculated of the given file path on the given host
        and then deletes the checksum file. It rises an exception if reading or deleting the file
        errors out.
        """
        command = ['/bin/bash', '-c', f'/bin/cat < {path} && /bin/rm {path}']
        result = self.run_command(host, command)
        if result.returncode != 0:
            raise ChecksumError(f'reading checksum failed for {host}:{path}')
        return result.stdout

    def has_available_disk_space(self, host, path, size):
        """
        Returns true if the disk space available at host on the given path location is larger
        than the provided size, otherwise returns false.
        """
        command = ['/bin/bash', '-c',
                   f'"df --block-size=1 --output=avail \"{path}\" | /usr/bin/tail -n 1"']
        result = self.run_command(host, command)
        if result.returncode != 0:
            raise FreeDiskSpaceError('df execution failed')
        return int(result.stdout) > size

    def disk_usage(self, host, path, is_xtrabackup=False):
        """
        Returns the size used on the filesystem by the file path on the given host,
        or the aggregated size of all the files inside path and its subdirectories
        """
        if is_xtrabackup:
            path = self.get_datadir_from_socket(path)
        # Sadly, our .tar.gz s, created with a pigz streaming pipe do not store
        # accurate file sizes, so a minimum number of the size of the tarball
        # will be used instead
        command = ['/usr/bin/du', '--bytes', '--summarize', f'{path}']
        result = self.run_command(host, command)
        if result.returncode != 0:
            raise FreeDiskSpaceError('du execution failed')
        return int(result.stdout.split()[0])

    def dir_is_empty(self, directory, host):
        """
        Returns true the given directory path is empty, false if it contains something
        (a file, a dir).
        If it is not a directory or does not exist, the result is undefined.
        """
        command = ['/bin/bash', '-c', f'"[ -z \\"$(/bin/ls -A {directory})\\" ]"']
        result = self.run_command(host, command)
        return result.returncode == 0

    @property
    def compress_command(self):
        """
        Returns a string with the command used for compression (gz-compatible) if
        compression is used and we are not running a decompression command.
        """
        if self.options['compress']:
            if self.source_is_dir or self.is_xtrabackup:
                compress_command = '| /usr/bin/pigz -c'
            elif self.is_decompress:
                compress_command = '/bin/cat'  # file is already compressed
            else:
                compress_command = '/usr/bin/pigz -c'
        else:
            if self.source_is_dir or self.source_is_socket:
                compress_command = ''
            else:
                compress_command = '/bin/cat'

        return compress_command

    @property
    def decompress_command(self):
        """
        Returns a string with the command used for decompression (gz-compatible) if
        compression is used.
        """
        if self.options['compress']:
            decompress_command = '| /usr/bin/pigz -c -d'
        else:
            decompress_command = ''

        return decompress_command

    @property
    def parallel_checksum_source_command(self):
        """
        Property: command to make source checksum parallel to the file transfer.

        :return: string with command to make the checksum
        """
        if self.options['parallel_checksum']:
            checksum_command = f'| tee >(md5sum > {self.parallel_checksum_source_path})'
        else:
            checksum_command = ''

        return checksum_command

    @property
    def parallel_checksum_target_command(self):
        """
        Property: command to make target checksum parallel to the file transfer.

        :return: string with command to make the checksum
        """
        if self.options['parallel_checksum']:
            checksum_command = f'| tee >(md5sum > {self.parallel_checksum_target_path})'
        else:
            checksum_command = ''

        return checksum_command

    def netcat_send_command(self, target_host, port):
        """
        Returns the netcat command used on the source host, including the target host and
        the target port.
        """
        netcat_send_command = f'| /bin/nc -q 0 -w 300 {target_host} {port}'

        return netcat_send_command

    def netcat_listen_command(self, port):
        """
        Returns the netcat command used to listen for dataon the target host, given
        the target port.
        """
        netcat_listen_command = f'/bin/nc -l -w 300 -p {port}'

        return netcat_listen_command

    @property
    def tar_command(self):
        """
        Returns the string command used for consolidating a directory into a single
        file/stream (using tar).
        """
        return '/bin/tar cf -'

    @property
    def untar_command(self):
        """
        Returns the string command used for reconstructing a directory back into
        several files from the incoming stream pipe (using tar).
        """
        if self.is_decompress:  # ignore subdir
            command = '| /bin/tar --strip-components=1 -xf -'
        else:
            command = '| /bin/tar xf -'
        return command

    def get_datadir_from_socket(self, socket):
        """
        Given a socket name, guess and return the data dir string following WMF
        conventions.
        """
        if socket.endswith('mysqld.sock'):
            datadir = '/srv/sqldata'
        else:
            result = re.match(r'.*mysqld\.(.+)\.sock', socket)
            if result:
                datadir = '/srv/sqldata.' + result.group(1)
            else:
                raise MySQLError(f'The socket "{socket}" does not have a known format.')
        return datadir

    @property
    def xtrabackup_command(self):
        """
        Returns a string with the command used to generate a backup of mysql/mariadb
        using xtrabackup on the local host- with the appropiate options as reflected
        on the transferrer properties.
        """
        user = 'root'
        threads = 16
        socket = self.source_path
        datadir = self.get_datadir_from_socket(socket)
        xtrabackup_command = ('xtrabackup --backup --target-dir /tmp '
                              f'--user {user} --socket={socket} --close-files --datadir={datadir} --parallel={threads} '
                              '--stream=xbstream --slave-info --skip-ssl'
                              )
        return xtrabackup_command

    @property
    def mbstream_command(self):
        """
        Returns a piped command to add at the end of the receiving stream in the target
        host to retrieve the files sent from the xtrabackup command on the source host.
        """
        return '| mbstream -x'

    @property
    def password(self):
        """
        Generate and return a random password sufficiently random and secure, in base 64.
        """
        if self._password is None:
            self._password = base64.b64encode(os.urandom(24)).decode('utf-8')

        return self._password

    @property
    def encrypt_command(self):
        """
        Returns a command string used to pipe data between the generation and the sending
        of data to encrypt a stream on the source host, using openssl.
        """
        if self.options['encrypt']:
            encrypt_command = (f'| /usr/bin/openssl enc -{self.cipher}'
                               f' -pass pass:{self.password}'
                               f' -bufsize {self.buffer_size}'
                               f' -iter {self.iterations}')
        else:
            encrypt_command = ''

        return encrypt_command

    @property
    def decrypt_command(self):
        """
        Returns a command string used to pipe data between the reception and the writing
        of data to decrypt a stream on the target host, using openssl.
        """
        if self.options['encrypt']:
            decrypt_command = (f'| /usr/bin/openssl enc -d -{self.cipher}'
                               f' -pass pass:{self.password}'
                               f' -bufsize {self.buffer_size}'
                               f' -iter {self.iterations}')
        else:
            decrypt_command = ''

        return decrypt_command

    def run_with_bash(self, command):
        """
        Given a bash command line string, return the full execution list, including the bash execution,
        to be able to run it on a local host.
        """
        return ['/bin/bash', '-c', '"' + command + '"']

    def copy_to(self, target_host, target_path, port):
        """
        Copies the source file or dir on the source host to 'target_host'.
        'target_path' is assumed to be a *directory* and the source file or
        directory will be copied inside.
        """
        if self.is_xtrabackup:
            src_command = (
                '"'
                f'{self.xtrabackup_command} '
                f'{self.compress_command} '
                f'{self.parallel_checksum_source_command} '
                f'{self.encrypt_command} '
                f'{self.netcat_send_command(target_host, port)}'
                '"'
            )

            dst_command = (
                '"'
                f'cd {target_path} && '
                f'{self.netcat_listen_command(port)} '
                f'{self.decrypt_command} '
                f'{self.parallel_checksum_target_command} '
                f'{self.decompress_command} '
                f'{self.mbstream_command}'
            )

        elif self.is_decompress:
            src_command = (
                f'{self.compress_command} < '
                f'{self.source_path} '
                f'{self.parallel_checksum_source_command} '
                f'{self.encrypt_command} '
                f'{self.netcat_send_command(target_host, port)}'
            )

            dst_command = (
                f'cd {target_path} && '
                f'{self.netcat_listen_command(port)} '
                f'{self.decrypt_command} '
                f'{self.parallel_checksum_target_command} '
                f'{self.decompress_command} '
                f'{self.untar_command}'
            )

        elif self.source_is_dir:
            source_parent_dir = os.path.normpath(os.path.join(self.source_path, '..'))
            source_basename = os.path.basename(os.path.normpath(self.source_path))
            src_command = (
                f'cd {source_parent_dir} && '
                f'{self.tar_command} {source_basename} '
                f'{self.compress_command} '
                f'{self.parallel_checksum_source_command} '
                f'{self.encrypt_command} '
                f'{self.netcat_send_command(target_host, port)}'
            )
            dst_command = (
                f'cd {target_path} && '
                f'{self.netcat_listen_command(port)} '
                f'{self.decrypt_command} '
                f'{self.parallel_checksum_target_command} '
                f'{self.decompress_command} '
                f'{self.untar_command}'
            )

        else:
            final_file = os.path.join(os.path.normpath(target_path),
                                      os.path.basename(self.source_path))
            src_command = (
                f'{self.compress_command} < {self.source_path} '
                f'{self.parallel_checksum_source_command} '
                f'{self.encrypt_command} '
                f'{self.netcat_send_command(target_host, port)}'
            )
            dst_command = (
                f'{self.netcat_listen_command(port)} '
                f'{self.decrypt_command} '
                f'{self.parallel_checksum_target_command} '
                f'{self.decompress_command} > {final_file}'
            )

        job = self.remote_executor.start_job(target_host, self.run_with_bash(dst_command))
        time.sleep(3)  # FIXME: Work on a better way to wait for nc to be listening
        result = self.run_command(self.source_host, self.run_with_bash(src_command))
        if result.returncode != 0:
            self.remote_executor.kill_job(target_host, job)
        else:
            self.remote_executor.wait_job(target_host, job)
        return result.returncode

    def sanity_checks(self):
        """
        Set of preflight checks for the transfer- raise an exception if
        they are not met.
        """
        # Does source host exist?
        result = self.host_exists(self.source_host)
        if result.returncode != 0:
            raise NotFoundError(f'The specified source host {self.source_host} does not exist or is unavailable.')
        # Does the source path (file or dir) exist?
        self.source_path = os.path.normpath(self.source_path)
        if not self.file_exists(self.source_host, self.source_path):
            raise NotFoundError(f'The specified source path {self.source_path} does not exist on {self.source_host}.')
        self.original_size = self.disk_usage(self.source_host, self.source_path,
                                             self.is_xtrabackup)

        for target_host, target_path in zip(self.target_hosts, self.target_paths):
            # Does the target host exist?
            result = self.host_exists(target_host)
            if result.returncode != 0:
                raise NotFoundError(f'The specified target host {target_host} does not exist or is unavailable.')
            # Does the target dir exist?
            if not self.file_exists(target_host, target_path):
                raise NotFoundError(f"The specified target path {target_path} doesn't exist on {target_host}.")
            # If it is a backup, is the target path emtpy
            if self.is_xtrabackup or self.is_decompress:
                if not self.dir_is_empty(target_path, target_host):
                    raise OverwriteError(f"The final target path {target_path} is not empty on {target_host}.")
            else:
                # Will the final path (target path + final dir or file) overwrite
                # an existing file or dir?
                target_final_path = os.path.join(os.path.normpath(target_path),
                                                 os.path.basename(self.source_path))
                if self.file_exists(target_host, target_final_path):
                    raise OverwriteError(f"The final target path {target_final_path} already exists on {target_host}.")
            # To the best of our knowledge, is there enough free space on target?
            if not self.has_available_disk_space(target_host, target_path,
                                                 self.original_size):
                raise FreeDiskSpaceError(f"{target_host} doesn't have enough space on {target_path}.")

        # For xtrabackup, is the source patch a socket?
        if self.is_xtrabackup:
            self.source_is_socket = self.is_socket(self.source_host, self.source_path)
            if not self.source_is_socket:
                raise NotFoundError(f"The specified source path {self.source_path} is not a valid socket")
        else:
            # If not xtrabackup, is the source a directory or a file?
            self.source_is_dir = self.is_dir(self.source_host, self.source_path)

    def after_transfer_checks(self, result, target_host, target_path):
        """
        Post-transfer checks: Was the transfer really successful. Yes- return 0; No-
        return 1 or more.
        """
        # Return code was not 0?
        if result != 0:
            self.logger.error('Copy from %s:%s to %s:%s failed',
                              self.source_host, self.source_path, target_host, target_path)
            return 1

        # if creating or restoring a backup, does it include an xtrabackup_info file,
        # otherwise, does the copied file or dir exists?
        if self.is_xtrabackup or self.is_decompress:
            target_final_path = os.path.normpath(target_path)
            check_path = os.path.join(os.path.normpath(target_path), 'xtrabackup_info')
        else:
            target_final_path = os.path.join(os.path.normpath(target_path),
                                             os.path.basename(self.source_path))
            check_path = target_final_path

        if not self.file_exists(target_host, check_path):
            self.logger.error('File was not found on the target path %s after transfer to %s',
                              check_path, target_host)
            return 2

        # Is original and final size the same? Otherwise throw a warning
        final_size = self.disk_usage(target_host, target_final_path)
        if self.original_size != final_size:
            self.logger.warning(('Original size on %s is %s bytes but transferred size is %s bytes '
                                 'after copy to %s.'),
                                self.source_host, self.original_size, final_size, target_host)

        # Was checksum requested, and does it match the original?
        if self.options['checksum']:
            target_checksum = self.calculate_checksum(target_host, target_final_path)
            if self.checksum != target_checksum:
                self.logger.error(('Original checksum %s on %s is different than checksum '
                                  '%s on %s'),
                                  self.checksum, self.source_host, target_checksum, target_host)
                return 3
            self.logger.info(('Checksum of all original files on %s and the transmitted ones'
                              ' on %s match.'),
                             self.source_host, target_host)

        if self.options['parallel_checksum']:
            self.parallel_checksum = self.read_checksum(self.source_host, self.parallel_checksum_source_path)
            target_checksum = self.read_checksum(target_host, self.parallel_checksum_target_path)
            if self.parallel_checksum != target_checksum:
                self.logger.error(('Original checksum %s on %s is different than checksum %s'
                                  ' on %s'),
                                  self.parallel_checksum, self.source_host, target_checksum, target_host)
                return 3
            self.logger.info(('Parallel checksum of source on %s and the transmitted ones'
                              ' on %s match.'),
                             self.source_host, target_host)
            self.remove_temp_paths()

        # All checks seem right, return success
        self.logger.info('%s bytes correctly transferred from %s to %s',
                         final_size, self.source_host, target_host)
        return 0

    def create_temp_paths(self, lock_dir):
        """
        Update checksum file paths, and create a temporary
        directory at the source machine.

        :param lock_dir: temporary lock directory at the target host
        :return: None if successful, else Exception
        """
        command = [f"/bin/mkdir {self.source_tmp_dir}"]
        result = self.run_command(self.source_host, command)
        self.parallel_checksum_source_path = os.path.join(self.source_tmp_dir, 'transferrer_source.md5sum')
        self.parallel_checksum_target_path = os.path.join(lock_dir, 'transferrer_target.md5sum')
        if result.returncode != 0:
            raise TempCreationError(f'Creation of temporary directory failed at source '
                                    f'{self.source_host}:{self.source_tmp_dir}')

    def remove_temp_paths(self):
        """
        Remove temporary directories.

        :return: None
        """
        tmp_dir = self.parallel_checksum_source_path.rsplit('/', 1)[0]
        command = [f"/bin/rmdir {tmp_dir}"]
        result = self.run_command(self.source_host, command)
        if result.returncode != 0:
            self.logger.warning('Deletion of temporary directory %s:%s failed.',
                                tmp_dir, self.source_host)

    def attempt_temp_deletion(self, host, path, file_type):
        """
        Delete directory/file if it exist.

        :param host: host in which path need to be deleted
        :param path: path need to be deleted
        :param file_type: type of the path ('file' or 'dir')
        """
        if self.file_exists(host, path):
            if file_type == 'dir':
                command = [f'/bin/rmdir {path}']
            elif file_type == 'file':
                command = [f'/bin/rm {path}']
            result = self.run_command(host, command)
            if result.returncode != 0:
                self.logger.error('Failed to delete temporary path %s:%s.', host, path)

    def clean_all_temps(self, target_host, target_tmp_dir):
        """
        Function to clean all the temporary paths if exists in case of any
        uncaught exception situations.

        :param target_host: last target host
        :param target_tmp_dir: temporary lock directory at the target
        :return:
        """
        self.logger.info("Cleaning up....")
        if self.source_tmp_dir:
            if self.options['parallel_checksum'] or self.options['checksum']:
                # Delete the checksum files if exist
                if self.parallel_checksum_source_path:
                    self.attempt_temp_deletion(self.source_host, self.parallel_checksum_source_path, 'file')
                if self.parallel_checksum_target_path and self.options['parallel_checksum']:
                    self.attempt_temp_deletion(target_host, self.parallel_checksum_target_path, 'file')
                # Delete the temp source directory if exist
                self.attempt_temp_deletion(self.source_host, self.source_tmp_dir, 'dir')
        if target_tmp_dir:
            self.attempt_temp_deletion(target_host, target_tmp_dir, 'dir')

    def run(self):
        """
        Starts the transference of the file (or the directory and all its contents) given on
        source_path from the source_target machine to all target_hosts hosts, as
        fast as possible. Returns an array of exit codes, one per target host,
        indicating if the transfer was successful (0) or not (<> 0).
        """
        # pre-execution sanity checks
        try:
            self.sanity_checks()
        except ValueError as ex:
            self.logger.error("%s", ex)
            return [-1]

        # stop slave if requested
        if self.options.get('stop_slave', False):
            result = self.mariadb.stop_replication(self.source_host, self.source_path)
            if result != 0:
                self.logger.error("Stop slave failed")
                return [-2]

        self.logger.info('About to transfer %s from %s to %s:%s (%s bytes).',
                         self.source_path, self.source_host,
                         self.target_hosts, self.target_paths,
                         self.original_size)

        transfer_sucessful = []
        wait_for_source_checksum = True
        # actual transfer process- this is done serially until we implement a
        # multicast-like process
        current_target_host = None
        current_target_tmp_dir = None
        try:
            for target_host, target_path in zip(self.target_hosts, self.target_paths):
                current_target_host = target_host
                firewall_handler = Firewall(target_host, self.remote_executor, self.parent_tmp_dir)
                try:
                    port = firewall_handler.open(self.source_host, self.options['port'])
                    current_target_tmp_dir = firewall_handler.reserve_port_dir_name
                    # Lets delete the lock suffix since the dir is not actually meant
                    # for locking (It also resolves the problem of trying to make
                    # the same dir twice in case of same source and target host).
                    if self.options['parallel_checksum'] or (self.options['checksum'] and wait_for_source_checksum):
                        self.source_tmp_dir = current_target_tmp_dir.rsplit('.', 1)[0]
                        self.create_temp_paths(current_target_tmp_dir)
                except (ValueError, FirewallError, TempDeletionError) as ex:
                    self.logger.error("%s", ex)
                    return [-1]

                if self.options['checksum'] and wait_for_source_checksum:
                    # Calculate the checksum in another process
                    command = self.calculate_checksum_command(self.source_host, self.source_path)
                    job = self.remote_executor.start_job(self.source_host, command)

                result = self.copy_to(target_host, target_path, port)

                if self.options['checksum'] and wait_for_source_checksum:
                    self.remote_executor.wait_job(self.source_host, job)
                    self.checksum = self.read_checksum(self.source_host, self.parallel_checksum_source_path)
                    self.remove_temp_paths()
                    wait_for_source_checksum = False
                transfer_sucessful.append(self.after_transfer_checks(result,
                                                                     target_host,
                                                                     target_path))
                if firewall_handler.close(self.source_host) != 0:
                    self.logger.warning('Firewall\'s temporary rule could not be deleted')
                del firewall_handler
        finally:
            self.clean_all_temps(current_target_host, current_target_tmp_dir)

        if self.options.get('stop_slave', False):
            result = self.mariadb.start_replication(self.source_host, self.source_path)
            if result != 0:
                self.logger.error("Start slave failed")
                return [-3]

        return transfer_sucessful
