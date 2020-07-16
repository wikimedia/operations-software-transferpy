#!/usr/bin/python3

import base64
import os
import os.path
import re
import time
import logging

from transferpy.RemoteExecution.CuminExecution import CuminExecution as RemoteExecution
from transferpy.Firewall import Firewall
from transferpy.MariaDB import MariaDB


class Transferer(object):
    def __init__(self, source_host, source_path, target_hosts, target_paths, options={}):
        self.source_host = source_host
        self.source_path = source_path
        self.target_hosts = target_hosts
        self.target_paths = target_paths
        self.options = options
        if 'type' not in self.options:  # default transfer type is file/directory transfer
            self.options['type'] = 'file'
        if 'verbose' not in self.options:  # default to non-verbose output
            self.options['verbose'] = False

        self.logger = logging.getLogger(__name__)
        remote_execution_options = {'verbose': self.options['verbose']}
        self.remote_executor = RemoteExecution(remote_execution_options)
        self.mariadb = MariaDB(self.remote_executor)

        self.source_is_dir = False
        self.source_is_socket = False
        self.original_size = 0
        self.checksum = None
        self.source_checksum_path = None

        self._password = None
        self.cipher = 'chacha20'
        self.buffer_size = 8

        self.logger.debug('Finished Transferer initialization')

    def run_command(self, host, command):
        return self.remote_executor.run(host, command)

    @property
    def is_xtrabackup(self):
        return self.options['type'] == 'xtrabackup'

    @property
    def is_decompress(self):
        return self.options['type'] == 'decompress'

    def is_dir(self, host, path):
        command = ['/bin/bash', '-c', r'"[ -d "{}" ]"'.format(path)]
        result = self.run_command(host, command)
        return not result.returncode

    def is_socket(self, host, path):
        command = ['/bin/bash', '-c', r'"[ -S "{}" ]"'.format(path)]
        result = self.run_command(host, command)
        return not result.returncode

    def host_exists(self, host):
        """
        Checks the availability of given host.

        :param host: host to be checked
        :return: remote execution run_command result
        """
        command = ['/bin/true']
        result = self.run_command(host, command)
        return result

    def file_exists(self, host, path):
        """
        Returns true if there is a file or a directory with such path on the remote
        host given
        """
        command = ['/bin/bash', '-c', r'"[ -a "{}" ]"'.format(path)]
        result = self.run_command(host, command)
        return not result.returncode

    def calculate_checksum_command(self, host, path):
        hash_executable = '/usr/bin/md5sum'
        parent_dir = os.path.normpath(os.path.join(path, '..'))
        basename = os.path.basename(os.path.normpath(path))
        if host == self.source_host and path == self.source_path:
            command = '/bin/mktemp'
            result = self.run_command(host, command)
            if result.returncode != 0:
                raise Exception('source checksum temporary file creation'
                                ' failed for {}'.format(host))
            self.source_checksum_path = result.stdout
            checksum_write_command = ' > {}'.format(self.source_checksum_path)
        else:
            checksum_write_command = ''
        if self.source_is_dir:
            command = ['/bin/bash', '-c',
                       r'"cd {} && /usr/bin/find {} -type f -exec {} {} {}"'
                       .format(parent_dir, basename, hash_executable, r'\{\} \;',
                               checksum_write_command)]
        else:
            command = ['/bin/bash', '-c', r'"cd {} && {} {} {}"'
                       .format(parent_dir, hash_executable, basename,
                               checksum_write_command)]
        return command

    def calculate_checksum(self, host, path):
        self.logger.info('Started checksum calculation for {}:{}'.format(host, path))
        command = self.calculate_checksum_command(host, path)
        result = self.run_command(host, command)
        if result.returncode != 0:
            raise Exception('md5sum execution failed')
        self.logger.info('Finished checksum calculation for {}:{}'.format(host, path))
        return result.stdout

    def read_checksum(self, host, path):
        command = ['/bin/bash', '-c', '/bin/cat < {} && /bin/rm {}'.format(path, path)]
        result = self.run_command(host, command)
        if result.returncode != 0:
            raise Exception('reading checksum failed for {}:{}'.format(host, path))
        return result.stdout

    def has_available_disk_space(self, host, path, size):
        command = ['/bin/bash', '-c',
                   r'"df --block-size=1 --output=avail {} | /usr/bin/tail -n 1"'.format(path)]
        result = self.run_command(host, command)
        if result.returncode != 0:
            raise Exception('df execution failed')
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
        command = ['/usr/bin/du', '--bytes', '--summarize', '{}'.format(path)]
        result = self.run_command(host, command)
        if result.returncode != 0:
            raise Exception('du execution failed')
        return int(result.stdout.split()[0])

    def dir_is_empty(self, directory, host):
        """
        Returns true the given directory path is empty, false if it contains something
        (a file, a dir).
        If it is not a directory or does not exist, the result is undefined.
        """
        command = ['/bin/bash', '-c', r'"[ -z \"$(/bin/ls -A {})\" ]"'.format(directory)]
        result = self.run_command(host, command)
        return result.returncode == 0

    @property
    def compress_command(self):
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
        if self.options['compress']:
            decompress_command = '| /usr/bin/pigz -c -d'
        else:
            decompress_command = ''

        return decompress_command

    def netcat_send_command(self, target_host):
        netcat_send_command = '| /bin/nc -q 0 -w 300 {} {}'.format(target_host, self.options['port'])

        return netcat_send_command

    @property
    def netcat_listen_command(self):
        netcat_listen_command = '/bin/nc -l -w 300 -p {}'.format(self.options['port'])

        return netcat_listen_command

    @property
    def tar_command(self):
        return '/bin/tar cf -'

    @property
    def untar_command(self):
        if self.is_decompress:  # ignore subdir
            return '| /bin/tar --strip-components=1 -xf -'
        else:
            return '| /bin/tar xf -'

    def get_datadir_from_socket(self, socket):
        if socket.endswith('mysqld.sock'):
            datadir = '/srv/sqldata'
        elif re.match(r'.*mysqld\.[smx]\d\.sock', socket):
            datadir = '/srv/sqldata.' + socket[-7:-5]
        else:
            raise Exception('the given socket does not have a known format')
        return datadir

    @property
    def xtrabackup_command(self):
        user = 'root'
        threads = 16
        socket = self.source_path
        datadir = self.get_datadir_from_socket(socket)
        xtrabackup_command = ('xtrabackup --backup --target-dir /tmp '
                              '--user {} --socket={} --close-files --datadir={} --parallel={} '
                              '--stream=xbstream --slave-info --skip-ssl'
                              ).format(user, socket, datadir, str(threads))
        return xtrabackup_command

    @property
    def mbstream_command(self):
        return '| mbstream -x'

    @property
    def password(self):
        if self._password is None:
            self._password = base64.b64encode(os.urandom(24)).decode('utf-8')

        return self._password

    @property
    def encrypt_command(self):
        if self.options['encrypt']:
            encrypt_command = ('| /usr/bin/openssl enc -{}'
                               ' -pass pass:{} -bufsize {}').format(self.cipher,
                                                                    self.password,
                                                                    self.buffer_size)
        else:
            encrypt_command = ''

        return encrypt_command

    @property
    def decrypt_command(self):
        if self.options['encrypt']:
            decrypt_command = ('| /usr/bin/openssl enc -d -{}'
                               ' -pass pass:{} -bufsize {}').format(self.cipher,
                                                                    self.password,
                                                                    self.buffer_size)
        else:
            decrypt_command = ''

        return decrypt_command

    def copy_to(self, target_host, target_path):
        """
        Copies the source file or dir on the source host to 'target_host'.
        'target_path' is assumed to be a *directory* and the source file or
        directory will be copied inside.
        """

        if self.is_xtrabackup:
            src_command = ['/bin/bash', '-c', r'"{} {} {} {}"'
                           .format(self.xtrabackup_command, self.compress_command,
                                   self.encrypt_command, self.netcat_send_command(target_host))]
            dst_command = ['/bin/bash', '-c', r'"cd {} && {} {} {} {}"'
                           .format(target_path, self.netcat_listen_command, self.decrypt_command,
                                   self.decompress_command, self.mbstream_command)]
        elif self.is_decompress:
            src_command = ['/bin/bash', '-c', r'"{} < {} {} {}"'
                           .format(self.compress_command, self.source_path, self.encrypt_command,
                                   self.netcat_send_command(target_host))]
            dst_command = ['/bin/bash', '-c', r'"cd {} && {} {} {} {}"'
                           .format(target_path, self.netcat_listen_command, self.decrypt_command,
                                   self.decompress_command, self.untar_command)]
        elif self.source_is_dir:
            source_parent_dir = os.path.normpath(os.path.join(self.source_path, '..'))
            source_basename = os.path.basename(os.path.normpath(self.source_path))
            src_command = ['/bin/bash', '-c', r'"cd {} && {} {} {} {} {}"'
                           .format(source_parent_dir, self.tar_command,
                                   source_basename, self.compress_command, self.encrypt_command,
                                   self.netcat_send_command(target_host))]

            dst_command = ['/bin/bash', '-c', r'"cd {} && {} {} {} {}"'
                           .format(target_path, self.netcat_listen_command, self.decrypt_command,
                                   self.decompress_command, self.untar_command)]
        else:
            src_command = ['/bin/bash', '-c', r'"{} < {} {} {}"'
                           .format(self.compress_command, self.source_path, self.encrypt_command,
                                   self.netcat_send_command(target_host))]

            final_file = os.path.join(os.path.normpath(target_path),
                                      os.path.basename(self.source_path))
            dst_command = ['/bin/bash', '-c', r'"{} {} {} > {}"'
                           .format(self.netcat_listen_command, self.decrypt_command,
                                   self.decompress_command, final_file)]

        job = self.remote_executor.start_job(target_host, dst_command)
        time.sleep(3)  # FIXME: Work on a better way to wait for nc to be listening
        result = self.run_command(self.source_host, src_command)
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
            raise ValueError("The specified source host {} does not exist or is unavailable."
                             .format(self.source_host))
        # Does the source path (file or dir) exist?
        self.source_path = os.path.normpath(self.source_path)
        if not self.file_exists(self.source_host, self.source_path):
            raise ValueError("The specified source path {} doesn't exist on {}"
                             .format(self.source_path, self.source_host))
        self.original_size = self.disk_usage(self.source_host, self.source_path,
                                             self.is_xtrabackup)

        for target_host, target_path in zip(self.target_hosts, self.target_paths):
            # Does the target host exist?
            result = self.host_exists(target_host)
            if result.returncode != 0:
                raise ValueError("The specified target host {} does not exist or is unavailable."
                                 .format(target_host))
            # Does the target dir exist?
            if not self.file_exists(target_host, target_path):
                raise ValueError("The specified target path {} doesn't exist on {}"
                                 .format(target_path, target_host))
            # If it is a backup, is the target path emtpy
            if self.is_xtrabackup or self.is_decompress:
                if not self.dir_is_empty(target_path, target_host):
                    raise ValueError("The final target path {} is not empty on {}."
                                     .format(target_path, target_host))
            else:
                # Will the final path (target path + final dir or file) overwrite
                # an existing file or dir?
                target_final_path = os.path.join(os.path.normpath(target_path),
                                                 os.path.basename(self.source_path))
                if self.file_exists(target_host, target_final_path):
                    raise ValueError("The final target path {} already exists on {}."
                                     .format(target_final_path, target_host))
            # To the best of our knowledge, is there enough free space on target?
            if not self.has_available_disk_space(target_host, target_path,
                                                 self.original_size):
                raise ValueError("{} doesn't have enough space on {}"
                                 .format(target_host, target_path))

        # For xtrabackup, is the source patch a socket?
        if self.is_xtrabackup:
            self.source_is_socket = self.is_socket(self.source_host, self.source_path)
            if not self.source_is_socket:
                raise ValueError("The specified source path {} is not a valid socket"
                                 .format(self.source_path))
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
            self.logger.error('Copy from {}:{} to {}:{} failed'
                              .format(self.source_host, self.source_path, target_host, target_path))
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
            self.logger.error(('file was not found on the target path {} after transfer'
                               ' to {}').format(check_path, target_host))
            return 2

        # Is original and final size the same? Otherwise throw a warning
        final_size = self.disk_usage(target_host, target_final_path)
        if self.original_size != final_size:
            self.logger.warning('Original size is {} but transferred size is {} '
                                'for copy to {}'.format(self.original_size, final_size, target_host))

        # Was checksum requested, and does it match the original?
        if self.options['checksum']:
            target_checksum = self.calculate_checksum(target_host, target_final_path)
            if self.checksum != target_checksum:
                self.logger.error('Original checksum {} on {} is different than checksum '
                                  '{} on {}'.format(self.checksum, self.source_host,
                                                    target_checksum, target_host))
                return 3
            else:
                self.logger.info(('Checksum of all original files on {} and the transmitted ones'
                                  ' on {} match.').format(self.source_host, target_host))

        # All checks seem right, return success
        self.logger.info('{} bytes correctly transferred from {} to {}'
                         .format(final_size, self.source_host, target_host))
        return 0

    def run(self):
        """
        Transfers the file (or the directory and all its contents) given on
        source_path from the source_target machine to all target_hosts hosts, as
        fast as possible. Returns an array of exit codes, one per target host,
        indicating if the transfer was successful (0) or not (<> 0).
        """
        # pre-execution sanity checks
        try:
            self.sanity_checks()
        except ValueError as e:
            self.logger.error("{}".format(str(e)))
            return [-1]

        # Calculate the checksum in another process
        if self.options['checksum']:
            command = self.calculate_checksum_command(self.source_host, self.source_path)
            job = self.remote_executor.start_job(self.source_host, command)

        # stop slave if requested
        if self.options.get('stop_slave', False):
            result = self.mariadb.stop_replication(self.source_host, self.source_path)
            if result != 0:
                self.logger.error("Stop slave failed")
                return [-2]

        self.logger.info('About to transfer {} from {} to {}:{} ({} bytes)'
                         .format(self.source_path, self.source_host,
                                 self.target_hosts, self.target_paths,
                                 self.original_size))

        transfer_sucessful = []
        wait_for_source_checksum = True
        # actual transfer process- this is done serially until we implement a
        # multicast-like process
        for target_host, target_path in zip(self.target_hosts, self.target_paths):
            firewall_handler = Firewall(target_host, self.remote_executor)
            self.options['port'] = firewall_handler.open(self.source_host, self.options['port'])
            result = self.copy_to(target_host, target_path)

            if firewall_handler.close(self.source_host, self.options['port']) != 0:
                self.logger.warning('Firewall\'s temporary rule could not be deleted')
            del firewall_handler
            if self.options['checksum'] and wait_for_source_checksum:
                self.remote_executor.wait_job(self.source_host, job)
                self.checksum = self.read_checksum(self.source_host, self.source_checksum_path)
                wait_for_source_checksum = False
            transfer_sucessful.append(self.after_transfer_checks(result,
                                                                 target_host,
                                                                 target_path))

        if self.options.get('stop_slave', False):
            result = self.mariadb.start_replication(self.source_host, self.source_path)
            if result != 0:
                self.logger.error("Start slave failed")
                return [-3]

        return transfer_sucessful
