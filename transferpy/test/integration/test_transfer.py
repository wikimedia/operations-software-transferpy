"""Integration tests for Transferer class.

WARNING: DON'T RUN THE INTEGRATION TESTS ON PRODUCTION
==========================================================
The following integration tests are DESTRUCTIVE in nature.
Some of the tests are designed to corrupt the testing data
(eg: test_parallel_checksum_*). Running these integration
tests on production could CORRUPT the important production
data.
"""
import unittest
import time
import os

from transferpy.Transferer import Transferer
from transferpy.Firewall import Firewall


class TestTransferer(unittest.TestCase):
    """Test cases for Transferer."""
    SRC_HOST = "source-host"
    DST_HOST = "target-host"
    SRC_PATH = "source-path"
    DEST_PATH = "target-path"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _use_ports(self, host, ports):
        """
        nc listen to the given ports on the give host.

        :param host: nc target host
        :param ports: nc target ports
        :return: list of references to nc listen jobs
        """
        jobs = []
        for port in ports:
            listen_command = ['/bin/bash', '-c', r'"{}"'.format(
                self.transferer.netcat_listen_command(port))]
            jobs.append(self.transferer.remote_executor.start_job(host, listen_command))
        time.sleep(3)
        return jobs

    def _kill_use_ports(self, host, jobs, ports):
        """
        Kill the jobs on the given host.

        :param host: host on which the jobs to be killed
        :param jobs: list of jobs to be killed
        :param ports: list of ports used
        """
        for job in jobs:
            self.transferer.remote_executor.kill_job(host, job)
        for p in ports:
            self.transferer.firewall_handler.kill_process(p)

    def _corrupt_data(self, transfer_type):
        if transfer_type == 'file' or transfer_type == 'decompress':
            command = ["/bin/bash", "-c", r'"echo corruption >> {}"'.format(self.transferer.source_path)]
        elif transfer_type == 'dir':
            target_file_path = os.path.join(os.path.normpath(self.transferer.source_path),
                                            'test_parallel_checksum')
            command = ["/bin/bash", "-c", r'"touch {}"'.format(target_file_path)]
        elif transfer_type == 'xtrabackup':
            data_dir = self.transferer.get_datadir_from_socket(self.transferer.source_path)
            command = ["/bin/bash", "-c",
                       r'"echo default-character-set=utf8 >> {}"'.format(
                           os.path.join(os.path.normpath(data_dir), 'performance_schema', 'db.opt'))]

        result = self.transferer.run_command(self.transferer.source_host, command)
        if result.returncode != 0:
            raise Exception('corrupt data execution failed on {}'.format(self.transferer.source_host))

    def _delete_target_data(self):
        for host, target_path in zip(self.transferer.target_hosts, self.transferer.target_paths):
            if self.transferer.options['type'] == 'file':
                path = os.path.join(os.path.normpath(target_path),
                                    os.path.basename(self.transferer.source_path))
            elif self.transferer.options['type'] == 'decompress':
                path = os.path.join(os.path.normpath(target_path), 'xtrabackup_info')
            elif self.transferer.options['type'] == 'xtrabackup':
                path = os.path.join(os.path.normpath(target_path), '*')

            command = ["/bin/bash", "-c", r'"/bin/rm -rf {}"'.format(path)]
            result = self.transferer.run_command(host, command)
            if result.returncode != 0:
                raise Exception('delete target data execution failed on {}'.format(host))

    def setUp(self):
        """Setup the tests."""
        self.options = {'port': 4000,
                        'type': 'file',
                        'compress': False,
                        'encrypt': False,
                        'checksum': False,
                        'parallel_checksum': False,
                        'stop_slave': False,
                        'verbose': False
                        }
        self.src_host = self.SRC_HOST
        self.dst_host = self.DST_HOST
        self.src_path = self.SRC_PATH
        self.dest_path = self.DEST_PATH
        self.transferer = Transferer(self.src_host, self.src_path,
                                     [self.dst_host], [self.dest_path],
                                     self.options)

    def test_find_available_port(self):
        """Test find available port."""
        use_ports = [4400, 4401]

        jobs = self._use_ports(self.dst_host, use_ports)
        self.options['port'] = 0
        self.transferer.firewall_handler = Firewall(self.src_host, self.transferer.remote_executor)
        self.options['port'] = self.transferer.firewall_handler.open(self.dst_host, self.options['port'])

        # Close ports
        self._kill_use_ports(self.dst_host, jobs, use_ports)
        if self.transferer.firewall_handler.close(self.dst_host, self.options['port']) != 0:
            print('WARNING: Firewall\'s temporary rule could not be deleted')

        # In the test running machine expect no other
        # process uses port between 4400 and 4499.
        # Since 4400 and 4401 are used by this test,
        # port opened for transfer should be 4402.
        self.assertEqual(self.options['port'], 4402)

    def test_parallel_checksum_file(self):
        """Test parallel checksum for single file transfer."""
        # Point the SRC_PATH to a correct file.
        transfer_type = 'file'
        self.transferer.options['parallel_checksum'] = True

        # Transfer data without any integrity issues
        result = self.transferer.run()
        self.assertEqual(max(result), 0)

        source_checksum = self.transferer.read_checksum(self.transferer.source_host,
                                                        self.transferer.parallel_checksum_source_path)
        for target_host in self.transferer.target_hosts:
            target_checksum = self.transferer.read_checksum(
                target_host, self.transferer.parallel_checksum_target_path)
            self.assertEqual(source_checksum, target_checksum)

        # Transfer data with some integrity issues
        self._corrupt_data(transfer_type)
        self._delete_target_data()

        result = self.transferer.run()
        self.assertEqual(max(result), 3)

        for target_host in self.transferer.target_hosts:
            target_checksum = self.transferer.read_checksum(target_host, self.transferer.parallel_checksum_target_path)
            self.assertNotEqual(source_checksum, target_checksum)

    def test_parallel_checksum_dir(self):
        """Test parallel checksum for a directory transfer."""
        # Point the SRC_PATH to a correct directory.
        transfer_type = 'dir'
        self.transferer.options['parallel_checksum'] = True

        # Transfer data without any integrity issues
        result = self.transferer.run()
        self.assertEqual(max(result), 0)

        source_checksum = self.transferer.read_checksum(self.transferer.source_host,
                                                        self.transferer.parallel_checksum_source_path)
        for target_host in self.transferer.target_hosts:
            target_checksum = self.transferer.read_checksum(
                target_host, self.transferer.parallel_checksum_target_path)
            self.assertEqual(source_checksum, target_checksum)

        # Transfer data with some integrity issues
        self._corrupt_data(transfer_type)
        self._delete_target_data()

        result = self.transferer.run()
        self.assertEqual(max(result), 3)

        for target_host in self.transferer.target_hosts:
            target_checksum = self.transferer.read_checksum(target_host, self.transferer.parallel_checksum_target_path)
            self.assertNotEqual(source_checksum, target_checksum)

    def test_parallel_checksum_decompress(self):
        """Test parallel checksum for a compressed transfer."""
        # Point the SRC_PATH to a correct tar.gz file.
        transfer_type = 'decompress'
        self.transferer.options['compress'] = True
        self.transferer.options['type'] = transfer_type
        self.transferer.options['parallel_checksum'] = True

        # Transfer data without any integrity issues
        result = self.transferer.run()
        self.assertEqual(max(result), 0)

        source_checksum = self.transferer.read_checksum(self.transferer.source_host,
                                                        self.transferer.parallel_checksum_source_path)
        for target_host in self.transferer.target_hosts:
            target_checksum = self.transferer.read_checksum(
                target_host, self.transferer.parallel_checksum_target_path)
            self.assertEqual(source_checksum, target_checksum)

        # Transfer data with some integrity issues
        self._corrupt_data(transfer_type)
        self._delete_target_data()

        result = self.transferer.run()
        self.assertEqual(max(result), 3)

        for target_host in self.transferer.target_hosts:
            target_checksum = self.transferer.read_checksum(target_host, self.transferer.parallel_checksum_target_path)
            self.assertNotEqual(source_checksum, target_checksum)

    def test_parallel_checksum_xtrabackup(self):
        """Test parallel checksum for xtrabackup transfer."""
        # Point the SRC_PATH to a socket.
        transfer_type = 'xtrabackup'
        self.transferer.options['type'] = transfer_type
        self.transferer.options['parallel_checksum'] = True

        # Transfer data without any integrity issues
        result = self.transferer.run()
        self.assertEqual(max(result), 0)

        source_checksum = self.transferer.read_checksum(self.transferer.source_host,
                                                        self.transferer.parallel_checksum_source_path)
        for target_host in self.transferer.target_hosts:
            target_checksum = self.transferer.read_checksum(
                target_host, self.transferer.parallel_checksum_target_path)
            self.assertEqual(source_checksum, target_checksum)

        # Transfer data with some integrity issues
        self._corrupt_data(transfer_type)
        self._delete_target_data()

        result = self.transferer.run()
        self.assertEqual(max(result), 3)

        for target_host in self.transferer.target_hosts:
            target_checksum = self.transferer.read_checksum(target_host, self.transferer.parallel_checksum_target_path)
            self.assertNotEqual(source_checksum, target_checksum)
