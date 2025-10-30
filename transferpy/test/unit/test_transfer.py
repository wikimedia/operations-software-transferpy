"""Tests for transfer.py class."""
import os
import sys
import logging
import unittest
from unittest.mock import patch, MagicMock

from transferpy.Transferer import Transferer
from transferpy.test.utils import hide_stderr
from transferpy.transfer import option_parse, \
    assign_default_options, configparser, parse_configurations, \
    split_target


class TestTransferer(unittest.TestCase):

    @patch('transferpy.Transferer.RemoteExecution')
    def setUp(self, executor_mock):
        self.executor = MagicMock()
        executor_mock.return_value = self.executor

        self.options = {'verbose': False}

        self.transferer = Transferer('source', 'path',
                                     ['target'], ['path'],
                                     self.options)

    def test_run_command(self):
        self.transferer.run_command('host', 'command')

        self.executor.run.assert_called_with('host', 'command')

    def test_remote_execution_injection(self):
        bad_transferer = Transferer('$PS1', '$(ls /)',  ['target `ls`'], ['~/path'], {})
        self.assertEqual(bad_transferer.source_host, "'$PS1'")
        self.assertEqual(bad_transferer.source_path, "'$(ls /)'")
        self.assertEqual(bad_transferer.target_hosts, ["'target `ls`'"])
        self.assertEqual(bad_transferer.target_paths, ["'~/path'"])

    def test_is_dir(self):
        path = 'path'
        self.transferer.is_dir('host', path)

        args = self.executor.run.call_args[0]
        self.assertEqual(['test', '-d', 'path'], args[1])

    def test_file_exists(self):
        file = 'path'
        self.transferer.file_exists('host', file)

        args = self.executor.run.call_args[0]
        self.assertEqual(['test', '-e', 'path'], args[1])

    def test_calculate_checksum_for_dir(self):
        self.transferer.source_is_dir = True
        self.executor.run.return_value = MagicMock()
        self.executor.run.return_value.returncode = 0

        self.transferer.calculate_checksum('host', 'path')

        args = self.executor.run.call_args[0]
        self.assertIn('find', args[1][-1])
        self.assertIn('md5sum', args[1][-1])

    def test_calculate_checksum_for_file(self):
        self.transferer.source_is_dir = False
        self.executor.run.return_value = MagicMock()
        self.executor.run.return_value.returncode = 0

        self.transferer.calculate_checksum('host', 'path')

        args = self.executor.run.call_args[0]
        self.assertNotIn('find', args[1][-1])
        self.assertIn('md5sum', args[1][-1])

    def test_has_available_disk_space(self):
        self.executor.run.return_value = MagicMock()
        self.executor.run.return_value.returncode = 0

        size = 100
        self.executor.run.return_value.stdout = str(size + 1)

        result = self.transferer.has_available_disk_space('host', 'path', size)

        self.assertTrue(result)

    def test_disk_usage(self):
        self.executor.run.return_value = MagicMock()
        self.executor.run.return_value.returncode = 0
        size = 1024
        self.executor.run.return_value.stdout = "{} path".format(size)

        result = self.transferer.disk_usage('host', 'path')

        self.assertEqual(size, result)

    def test_compress_command_compressing(self):
        self.options['compress'] = True

        command = self.transferer.compress_command
        self.assertIn('pigz -c', command)

    def test_compress_command_not_compressing(self):
        self.options['compress'] = False

        self.transferer.source_is_dir = True
        command = self.transferer.compress_command
        self.assertEqual('', command)

        self.transferer.source_is_dir = False
        command = self.transferer.compress_command
        self.assertIn('cat', command)

    def test_decompress_command_compressing(self):
        self.options['compress'] = True

        command = self.transferer.decompress_command
        self.assertIn('pigz -c -d', command)

    def test_decompress_command_not_compressing(self):
        self.options['compress'] = False

        command = self.transferer.decompress_command
        self.assertEqual('', command)

    def test_encrypt_command_encrypting(self):
        self.options['encrypt'] = True

        command = self.transferer.encrypt_command
        self.assertIn('openssl enc', command)

    def test_encrypt_command_not_encrypting(self):
        self.options['encrypt'] = False

        command = self.transferer.encrypt_command
        self.assertEqual('', command)

    def test_decrypt_command_encrypting(self):
        self.options['encrypt'] = True

        command = self.transferer.decrypt_command
        self.assertIn('openssl enc -d', command)

    def test_decrypt_command_not_encrypting(self):
        self.options['encrypt'] = False

        command = self.transferer.decrypt_command
        self.assertEqual('', command)

    def test_parallel_checksum_source_and_target_command(self):
        """Test to check the parallel_checksum command"""
        self.options['parallel_checksum'] = False
        src_command = self.transferer.parallel_checksum_source_command
        trgt_command = self.transferer.parallel_checksum_target_command
        self.assertEqual('', src_command)
        self.assertEqual('', trgt_command)

        self.options['parallel_checksum'] = True
        src_command = self.transferer.parallel_checksum_source_command
        trgt_command = self.transferer.parallel_checksum_target_command
        self.assertEqual('| tee >(md5sum > {})'.format(
            self.transferer.parallel_checksum_source_path), src_command)
        self.assertEqual('| tee >(md5sum > {})'.format(
            self.transferer.parallel_checksum_target_path), trgt_command)

    def test_run_sanity_checks_failing(self):
        """Test case for Transferer.run function which simulates sanity check failure."""
        with patch.object(Transferer, 'sanity_checks') as mocked_sanity_check:
            mocked_sanity_check.side_effect = ValueError('Test sanity_checks')
            command = self.transferer.run()
            self.assertTrue(isinstance(command, list))

    def test_run_stoping_slave(self):
        """Test case for Transferer.run function which provides stop_slave option"""
        with patch.object(Transferer, 'sanity_checks') as mocked_sanity_check, \
                patch('transferpy.Transferer.MariaDB.stop_replication') as mocked_stop_replication:
            self.options['stop_slave'] = True
            self.options['checksum'] = False
            #  Return value should be anything other than 0 for the if block to execute
            mocked_stop_replication.return_value = 1
            command = self.transferer.run()
            mocked_sanity_check.assert_called_once()
            self.assertTrue(isinstance(command, list))

    def test_run_successfully(self):
        """Test case for Transferer.run function starting transfer successfully"""
        with patch.object(Transferer, 'sanity_checks') as mocked_sanity_check, \
                patch.object(Transferer, 'copy_to') as mocked_copy_to, \
                patch.object(Transferer, 'after_transfer_checks') as mocked_after_transfer_checks, \
                patch('transferpy.Transferer.MariaDB.start_replication') as mocked_start_replication, \
                patch('transferpy.Transferer.get_firewall') as mocked_get_firewall:
            self.options['port'] = 4444
            self.options['checksum'] = False
            fw = MagicMock(spec=['open', 'close'])
            fw.open.return_value = 4444
            fw.close.return_value = 0
            fw.reserve_port_dir_name = '/tmp'
            mocked_get_firewall.return_value = fw
            mocked_copy_to.return_value = 0
            mocked_after_transfer_checks.return_value = 0
            mocked_start_replication.return_value = 0
            command = self.transferer.run()
            mocked_sanity_check.assert_called_once()
            self.assertTrue(isinstance(command, list))

    def test_run_start_slave(self):
        """Test case for Transferer.run function for when it runs the
           start_slave function with the stop_slave option
        """
        with patch('transferpy.Transferer.MariaDB.stop_replication') as mocked_stop_replication, \
                patch.object(Transferer, 'sanity_checks') as mocked_sanity_check, \
                patch.object(Transferer, 'copy_to') as mocked_copy_to, \
                patch.object(Transferer, 'after_transfer_checks') as mocked_after_transfer_checks, \
                patch('transferpy.Transferer.MariaDB.start_replication') as mocked_start_replication, \
                patch('transferpy.Transferer.get_firewall') as mocked_get_firewall:
            self.options['port'] = 4444
            self.options['checksum'] = False
            self.options['stop_slave'] = True
            fw = MagicMock(spec=['open', 'close'])
            fw.open.return_value = 4444
            fw.close.return_value = 0
            fw.reserve_port_dir_name = '/tmp'
            mocked_get_firewall.return_value = fw
            # We need to skip the first if statement
            # which checks the stop slave option
            mocked_stop_replication.return_value = 0
            mocked_copy_to.return_value = 0
            mocked_after_transfer_checks.return_value = 0
            # Return value should be anything other than 0
            # for this if block to execute
            command = self.transferer.run()
            mocked_start_replication.return_value = 1
            mocked_sanity_check.assert_called_once()
            self.assertTrue(isinstance(command, list))

    def test_copy_to_success(self):
        """Test case for the successful run of Transferer.copy_to function"""
        self.options['compress'] = False
        self.options['parallel_checksum'] = False
        self.options['encrypt'] = False
        port = 4400
        with patch('transferpy.Transferer.time'):
            target_host = 'target'
            target_path = 'target_path'
            self.executor.run.return_value.returncode = 0
            returncode = self.transferer.copy_to(target_host, target_path, port)
            self.executor.start_job.assert_called_once()
            # Successful run should call the wait_job function
            self.executor.wait_job.assert_called_once()
            self.executor.kill_job.assert_not_called()
            self.assertEqual(returncode, 0)

    def test_copy_to_failure(self):
        """Test case for the failed run of Transferer.copy_to function"""
        self.options['compress'] = False
        self.options['parallel_checksum'] = False
        self.options['encrypt'] = False
        port = 4400
        with patch('transferpy.Transferer.time'):
            target_host = 'target'
            target_path = 'target_path'
            self.executor.run.return_value.returncode = 1
            returncode = self.transferer.copy_to(target_host, target_path, port)
            self.executor.start_job.assert_called_once()
            # Failure should call the kill_job function
            self.executor.kill_job.assert_called_once()
            self.executor.wait_job.assert_not_called()
            self.assertEqual(returncode, 1)

    def test_is_socket(self):
        """Test is_socket"""
        path = 'path'
        command = ['test', '-S', 'path']
        self.transferer.is_socket('source', path)
        self.executor.run.assert_called_once_with('source', command)

    def test_host_exists(self):
        """Test host_exists"""
        command = ['/bin/true']
        self.transferer.host_exists('source')
        self.executor.run.assert_called_once_with('source', command)

    def test_dir_is_empty(self):
        """Test dir_is_empty"""
        directory = 'dir'
        command = ['/bin/bash', '-c', '"test -d dir && find dir -mindepth 1 -maxdepth 1 -exec false {} + 2>/dev/null"']
        self.transferer.dir_is_empty(directory, 'source')
        self.executor.run.assert_called_once_with('source', command)

    def test_parallel_checksum_source_command(self):
        """Test parallel_checksum_source_command"""
        self.options['parallel_checksum'] = True
        checksum_command = '| tee >(md5sum > {})'.format(self.transferer.parallel_checksum_source_path)
        self.assertEqual(checksum_command, self.transferer.parallel_checksum_source_command)
        # Make parallel_checksum False and try again
        self.options['parallel_checksum'] = False
        self.assertEqual('', self.transferer.parallel_checksum_source_command)

    def test_parallel_checksum_target_command(self):
        """Test parallel_checksum_target_command"""
        self.options['parallel_checksum'] = True
        checksum_command = '| tee >(md5sum > {})'.format(self.transferer.parallel_checksum_target_path)
        self.assertEqual(checksum_command, self.transferer.parallel_checksum_target_command)
        # Make parallel_checksum False and try again
        self.options['parallel_checksum'] = False
        self.assertEqual('', self.transferer.parallel_checksum_target_command)

    def test_read_checksum(self):
        """Test read_checksum"""
        path = 'path'
        command = ['/bin/bash', '-c', f'"/bin/cat < {path} && /bin/rm {path}"']
        self.executor.run.return_value.returncode = 0
        self.executor.run.return_value.stdout = "checksum - path"
        checksum = self.transferer.read_checksum('source', path)
        self.executor.run.assert_called_once_with('source', command)
        self.assertEqual(checksum, "checksum - path")

    def test_netcat_send_command(self):
        """Test netcat_send_command"""
        target_host = 'source'
        port = 4400
        expect_command = '| /bin/nc -4 -q 0 -w 300 {} {}'.format(target_host, port)
        actual_command = self.transferer.netcat_send_command(target_host, port)
        self.assertEqual(expect_command, actual_command)

    def test_netcat_listen_command(self):
        """Test netcat_listen_command"""
        port = 4400
        expect_command = '/bin/nc -4 -l -w 300 -p {}'.format(port)
        actual_command = self.transferer.netcat_listen_command(port)
        self.assertEqual(expect_command, actual_command)

    def test_tar_command(self):
        """Test tar_command"""
        expected_command = '/bin/tar cf -'
        actual_command = self.transferer.tar_command
        self.assertEqual(expected_command, actual_command)

    def test_untar_command(self):
        """Test untar_command"""
        expected_command_decompress = '| /bin/tar --strip-components=1 -xf -'
        expected_command_file = '| /bin/tar xf -'
        self.options['type'] = 'decompress'
        actual_command = self.transferer.untar_command
        self.assertEqual(actual_command, expected_command_decompress)
        self.options['type'] = 'file'
        actual_command = self.transferer.untar_command
        self.assertEqual(actual_command, expected_command_file)

    def test_get_datadir_from_socket(self):
        """Test get_datadir_from_socket"""
        socket = 'mysqld.sock'
        datadir = '/srv/sqldata'
        actual_dir = self.transferer.get_datadir_from_socket(socket)
        self.assertEqual(datadir, actual_dir)
        socket = '/var/run/mysqld/test.mysqld.s1.sock'
        datadir = '/srv/sqldata.s1'
        actual_dir = self.transferer.get_datadir_from_socket(socket)
        self.assertEqual(datadir, actual_dir)
        # Test analytics use case
        socket = '/run/mysqld/mysqld.analytics_meta.sock'
        datadir = '/srv/sqldata.analytics_meta'
        actual_dir = self.transferer.get_datadir_from_socket(socket)
        self.assertEqual(datadir, actual_dir)
        # Give wrong socket input
        socket = 'test.mysqld.skt'
        with self.assertRaises(Exception):
            self.transferer.get_datadir_from_socket(socket)

    def test_xtrabackup_command(self):
        """Test xtrabackup_command"""
        self.transferer.source_path = 'mysqld.sock'
        socket = self.transferer.source_path
        datadir = self.transferer.get_datadir_from_socket(socket)
        expected_command = 'xtrabackup --backup --target-dir /tmp ' \
                           '--user {} --socket={} --close-files --datadir={} --parallel={} ' \
                           '--stream=xbstream --slave-info --skip-ssl'.\
            format('root', socket, datadir, 16)
        actual_command = self.transferer.xtrabackup_command
        self.assertEqual(expected_command, actual_command)

    def test_mbstream_command(self):
        """Test mbstream_command"""
        expected_command = '| mbstream -x'
        actual_command = self.transferer.mbstream_command
        self.assertEqual(expected_command, actual_command)

    def test_password(self):
        """Test password function"""
        self.transferer._password = None
        password = self.transferer.password
        self.assertNotEqual(password, None)
        self.transferer._password = 'password'
        password = self.transferer.password
        self.assertEqual('password', password)

    def test_sanity_checks_file(self):
        """Test sanity_checks for file/dir"""
        with patch.object(Transferer, 'host_exists') as mocked_host_exists, \
                patch.object(Transferer, 'disk_usage') as mocked_disk_usage, \
                patch.object(Transferer, 'file_exists') as mocked_file_exists, \
                patch.object(Transferer, 'has_available_disk_space') as mocked_disk_space, \
                patch.object(Transferer, 'is_socket') as mocked_is_socket:
            self.transferer.target_hosts = ['target']
            self.transferer.target_paths = ['path']
            self.options['checksum'] = True
            self.options['type'] = 'file'
            mocked_disk_space.return_value = True
            mocked_is_socket.return_value = False
            mocked_file_exists.side_effect = [True, True, False]
            mocked_host_exists.return_value.returncode = 0
            self.transferer.sanity_checks()
            self.assertEqual(mocked_host_exists.call_count, 2)
            mocked_disk_space.assert_called_once()
            mocked_disk_usage.assert_called_once()
            self.assertEqual(mocked_file_exists.call_count, 3)

    def test_sanity_checks_xtrabackup(self):
        """Test sanity_checks for xtrabackup/decompress"""
        with patch.object(Transferer, 'host_exists') as mocked_host_exists, \
                patch.object(Transferer, 'disk_usage') as mocked_disk_usage, \
                patch.object(Transferer, 'file_exists') as mocked_file_exists, \
                patch.object(Transferer, 'dir_is_empty') as mocked_dir_is_empty, \
                patch.object(Transferer, 'has_available_disk_space') as mocked_disk_space, \
                patch.object(Transferer, 'is_socket') as mocked_is_socket:
            self.transferer.target_hosts = ['target']
            self.transferer.target_paths = ['path']
            self.options['checksum'] = True
            self.options['type'] = 'xtrabackup'
            mocked_dir_is_empty.return_value = True
            mocked_disk_space.return_value = True
            mocked_is_socket.return_value = True
            mocked_file_exists.return_value = True
            mocked_host_exists.return_value.returncode = 0
            self.transferer.sanity_checks()
            mocked_dir_is_empty.assert_called_once()
            self.assertEqual(mocked_host_exists.call_count, 2)
            mocked_disk_space.assert_called_once()
            mocked_disk_usage.assert_called_once()
            mocked_is_socket.assert_called_once()
            self.assertEqual(mocked_file_exists.call_count, 2)

    def test_after_transfer_checks(self):
        """Test after_transfer_checks"""
        with patch.object(Transferer, 'disk_usage') as mocked_disk_usage, \
                patch.object(Transferer, 'file_exists') as mocked_file_exists, \
                patch.object(Transferer, 'calculate_checksum') as mocked_calculate_checksum, \
                patch.object(Transferer, 'read_checksum') as mocked_read_checksum, \
                patch.object(Transferer, 'remove_temp_paths') as mocked_remove_temp_paths:
            target_host = 'target'
            target_path = 'path'
            self.options['checksum'] = True
            self.options['parallel_checksum'] = True
            self.options['type'] = 'file'
            self.transferer.checksum = 'checksum'
            mocked_calculate_checksum.return_value = 'checksum'
            mocked_file_exists.return_value = True
            result = self.transferer.after_transfer_checks(0, target_host, target_path)
            mocked_disk_usage.assert_called_once()
            mocked_calculate_checksum.assert_called_once()
            mocked_file_exists.assert_called_once()
            mocked_remove_temp_paths.assert_called_once()
            self.assertEqual(mocked_read_checksum.call_count, 2)
            self.assertEqual(result, 0)


class TestArgumentParsing(unittest.TestCase):
    """Test cases for the command line arguments parsing."""

    def option_parse(self, args):
        """Call parse_args patching the arguments."""
        with patch.object(sys, 'argv', args):
            return option_parse()

    def check_bad_args(self, args, expected_error=SystemExit):
        """Check arg parsing fails for the given args."""
        with self.assertRaises(expected_error) as exc:
            with hide_stderr():
                self.option_parse(args)

        if expected_error == SystemExit:
            self.assertEqual(exc.exception.code, 2)

    def test_missing_required_args(self):
        """Test errors with missing required args."""
        missing_required_args_list = [
            ['transfer'],
            ['transfer', 'src:path'],
            ['transfer', 'trg?:path'],
        ]
        for test_args in missing_required_args_list:
            self.check_bad_args(test_args)

    def test_bad_source(self):
        """Test errors with the source."""
        test_args = ['transfer', 'source', 'target:path']
        self.check_bad_args(test_args)

    def test_bad_target(self):
        """Test errors with the target."""
        test_args = ['transfer', 'source:path', 'target']
        self.check_bad_args(test_args)

    def test_just_source_and_targets(self):
        """Test call with just source and targets."""
        src = 'source'
        src_path = 'source_path'
        trg1 = 'target1'
        trg1_path = 'dst_path1'
        trg2 = 'target2'
        trg2_path = 'dst_path2'
        test_args = ['transfer',
                     '{}:{}'.format(src, src_path),
                     '{}:{}'.format(trg1, trg1_path),
                     '{}:{}'.format(trg2, trg2_path)]
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(test_args)

        self.assertEqual(src, source_host)
        self.assertEqual(src_path, source_path)
        self.assertEqual([trg1, trg2], target_hosts)
        self.assertEqual([trg1_path, trg2_path], target_paths)
        self.assertEqual(other_options['port'], 0)
        self.assertTrue(other_options['compress'])
        self.assertTrue(other_options['encrypt'])

    def test_port(self):
        """Test port param."""
        port = 12345
        test_args = ['transfer', 'source:path', 'target:path', '--port', str(port)]
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(test_args)
        self.assertEqual(other_options['port'], port)
        self.assertTrue(other_options['compress'])
        self.assertTrue(other_options['encrypt'])

    def test_compress(self):
        """Test compress params."""
        base_args = ['transfer', 'source:path', 'target:path']

        compress_test_args = base_args + ['--compress']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(compress_test_args)
        self.assertTrue(other_options['compress'])
        self.assertTrue(other_options['encrypt'])

        no_compress_test_args = base_args + ['--no-compress']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(no_compress_test_args)
        self.assertFalse(other_options['compress'])
        self.assertTrue(other_options['encrypt'])

    def test_encrypt(self):
        """Test encrypt params."""
        base_args = ['transfer', 'source:path', 'target:path']

        encrypt_test_args = base_args + ['--encrypt']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(encrypt_test_args)
        self.assertTrue(other_options['compress'])
        self.assertTrue(other_options['encrypt'])

        no_encrypt_test_args = base_args + ['--no-encrypt']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(no_encrypt_test_args)
        self.assertTrue(other_options['compress'])
        self.assertFalse(other_options['encrypt'])

    def test_split_target(self):
        """Test split_target function"""
        # Correct input with spaces
        target = 'host : path '
        host, path = split_target(target)
        self.assertEqual(host, 'host')
        self.assertEqual(path, 'path')

        # Input with no path but a space
        target = 'host: '
        with self.assertRaises(SystemExit) as se:
            split_target(target)
        self.assertEqual(se.exception.code, 2)

        # Input with no colon
        target = 'host path'
        with self.assertRaises(SystemExit) as se:
            split_target(target)
        self.assertEqual(se.exception.code, 2)

        # Input with just colon
        target = ':'
        with self.assertRaises(SystemExit) as se:
            split_target(target)
        self.assertEqual(se.exception.code, 2)

        # Input with more than one colon
        target = 'host:path:'
        with self.assertRaises(SystemExit) as se:
            split_target(target)
        self.assertEqual(se.exception.code, 2)

    def test_parallel_checksum(self):
        """Test parallel-checksum param."""
        base_args = ['transfer', 'source:path', 'target:path']

        # When normal checksum is enabled by the user,
        # parallel-checksum argument should be disabled.
        parallel_checksum_test_args = base_args + ['--parallel-checksum'] + ['--checksum']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(parallel_checksum_test_args)
        self.assertTrue(other_options['checksum'])
        self.assertFalse(other_options['parallel_checksum'])

        no_parallel_checksum_test_args = base_args + ['--no-parallel-checksum']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(no_parallel_checksum_test_args)
        self.assertTrue(other_options['checksum'])
        self.assertFalse(other_options['parallel_checksum'])

        # Now disable the normal checksum so that parallel-checksum can take effect
        base_args = ['transfer', 'source:path', 'target:path', '--no-checksum']
        # By default, normal checksum is enabled. So, irrespective of the
        # --parallel-checksum argument, this option is disabled.
        parallel_checksum_test_args = base_args + ['--parallel-checksum']
        (source_host, source_path, target_hosts, target_paths, other_options) \
            = self.option_parse(parallel_checksum_test_args)
        self.assertFalse(other_options['checksum'])
        self.assertTrue(other_options['parallel_checksum'])

        no_parallel_checksum_test_args = base_args + ['--no-parallel-checksum']
        (source_host, source_path, target_hosts, target_paths, other_options) \
            = self.option_parse(no_parallel_checksum_test_args)
        self.assertFalse(other_options['checksum'])
        self.assertFalse(other_options['parallel_checksum'])

    def test_verbose(self):
        """Test verbose param."""
        base_args = ['transfer', 'source:path', 'target:path']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(base_args)
        self.assertFalse(other_options['verbose'])

        verbose_test_args = base_args + ['--verbose']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(verbose_test_args)
        self.assertTrue(other_options['verbose'])

    def test_remote_execution_verbose(self):
        """Test the effect of verbose option on RemoteExecution"""
        base_args = ['transfer', 'source:path', 'target:path']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(base_args)
        t = Transferer(source_host, source_path, target_hosts, target_paths, other_options)
        self.assertEqual(t.remote_executor.options['verbose'], False)
        # Now enable verbose and check the effect on RemoteExecution
        verbose_test_args = base_args + ['--verbose']
        (source_host, source_path, target_hosts, target_paths, other_options)\
            = self.option_parse(verbose_test_args)
        t = Transferer(source_host, source_path, target_hosts, target_paths, other_options)
        self.assertEqual(t.remote_executor.options['verbose'], True)

    def test_setup_logger(self):
        """Test the logger's global availability and the impact
        of the verbose option on the logger level."""
        base_args = ['transfer', 'source:path', 'target:path']
        self.option_parse(base_args)
        # By default, verbose is false, so logging level
        # should be INFO
        logger = logging.getLogger('transferpy')
        self.assertEqual(logger.level, logging.INFO)
        # If verbose mentioned, level should be DEBUG
        verbose_test_args = base_args + ['--verbose']
        self.option_parse(verbose_test_args)
        logger = logging.getLogger('transferpy')
        self.assertEqual(logger.level, logging.DEBUG)

    def test_assign_default_options(self):
        """Test assign_default_options function"""
        default_options = assign_default_options({})
        self.assertEqual(default_options['port'], 0)
        self.assertEqual(default_options['transfer_type'], 'file')
        self.assertTrue(default_options['compress'])
        self.assertTrue(default_options['encrypt'])
        self.assertTrue(default_options['checksum'])
        self.assertFalse(default_options['verbose'])
        self.assertFalse(default_options['stop_slave'])
        # Check whether the values are getting accepted
        default_options = assign_default_options(
            {'port': 4444, 'transfer_type': 'xtrabackup',
             'compress': False, 'encrypt': False, 'checksum': False,
             'stop_slave': True, 'verbose': True
             })
        self.assertEqual(default_options['port'], 4444)
        self.assertEqual(default_options['transfer_type'], 'xtrabackup')
        self.assertFalse(default_options['compress'])
        self.assertFalse(default_options['encrypt'])
        self.assertFalse(default_options['checksum'])
        self.assertTrue(default_options['verbose'])
        self.assertTrue(default_options['stop_slave'])

    def test_parse_configurations(self):
        """test parse configuration file"""
        config_file = '/tmp/tmp_transferpy.conf'
        config = configparser.ConfigParser()
        config['DEFAULT'] = {'port': 4444, 'transfer_type': 'xtrabackup',
                             'compress': False, 'encrypt': False, 'checksum': False,
                             'stop_slave': True, 'verbose': True}
        # Write the config options to a file and use it as transferpy config file
        with open(config_file, 'w') as configfile:
            config.write(configfile)
        conf_args = dict(parse_configurations(config_file))
        os.remove(config_file)
        self.assertEqual(conf_args['port'], '4444')
        self.assertEqual(conf_args['transfer_type'], 'xtrabackup')
        self.assertEqual(conf_args['compress'], 'False')
        self.assertEqual(conf_args['encrypt'], 'False')
        self.assertEqual(conf_args['checksum'], 'False')
        self.assertEqual(conf_args['stop_slave'], 'True')
        self.assertEqual(conf_args['verbose'], 'True')

    def test_winner_among_cli_and_config(self):
        """Test the context of disagreement between command line arguments
        and configuration file arguments: command line arguments should get
        first preference."""
        config_file = '/tmp/tmp_transferpy.conf'
        config = configparser.ConfigParser()
        config['DEFAULT'] = {'port': 4444, 'transfer_type': 'file',
                             'compress': True, 'encrypt': True, 'checksum': True,
                             'stop_slave': False, 'verbose': False}
        # Write the config options to a file and use it as transferpy config file
        with open(config_file, 'w') as configfile:
            config.write(configfile)
        # Give command line arguments opposite to the config file
        args = ['transfer', 'source:path', 'target:path',
                '--port', 0, '--type', 'xtrabackup',
                '--no-compress', '--no-encrypt', '--no-checksum',
                '--stop-slave', '--verbose', '--config', config_file]
        (source_host, source_path, target_hosts, target_paths, other_options) = \
            self.option_parse(args)
        os.remove(config_file)
        # Command line arguments should get reflected
        self.assertEqual(other_options['port'], 0)
        self.assertEqual(other_options['type'], 'xtrabackup')
        self.assertFalse(other_options['compress'])
        self.assertFalse(other_options['encrypt'])
        self.assertFalse(other_options['checksum'])
        self.assertTrue(other_options['stop_slave'])
        self.assertTrue(other_options['verbose'])

    def test_missing_argument(self):
        """Test missing argument"""
        config_file = '/tmp/tmp_transferpy.conf'
        config = configparser.ConfigParser()
        config['DEFAULT'] = {'port': 4444, 'transfer_type': 'file',
                             'compress': True, 'encrypt': True, 'checksum': True,
                             'stop_slave': False}
        # Write the config options except verbose
        with open(config_file, 'w') as configfile:
            config.write(configfile)
        # Give command line arguments without --verbose option
        args = ['transfer', 'source:path', 'target:path',
                '--port', 0, '--type', 'xtrabackup',
                '--no-compress', '--no-encrypt', '--no-checksum',
                '--stop-slave', '--config', config_file]
        (source_host, source_path, target_hosts, target_paths, other_options) = \
            self.option_parse(args)
        os.remove(config_file)
        # The verbose is not mentioned anywhere, so default False should be taken
        self.assertFalse(other_options['verbose'])

    def test_parallel_checksum_and_checksum_true_in_config(self):
        """Test for config given True for both parallel-checksum and
        checksum, checksum should win"""
        config_file = '/tmp/tmp_transferpy.conf'
        config = configparser.ConfigParser()
        # The config file has checksum True
        config['DEFAULT'] = {'port': 4444, 'transfer_type': 'file',
                             'compress': True, 'encrypt': True, 'checksum': True,
                             'parallel_checksum': True, 'stop_slave': False}
        # Write the config options except verbose
        with open(config_file, 'w') as configfile:
            config.write(configfile)
        # But command line has no specification
        args = ['transfer', 'source:path', 'target:path',
                '--stop-slave', '--config', config_file]
        (source_host, source_path, target_hosts, target_paths, other_options) = \
            self.option_parse(args)
        os.remove(config_file)
        # The parallel-checksum should be True
        self.assertFalse(other_options['parallel_checksum'])
        self.assertTrue(other_options['checksum'])

    def test_parallel_checksum_arg_when_checksum_true_by_default(self):
        """Test for user given --parallel-checksum argument when the
        --no-checksum is not mentioned or in other words just the
        --parallel-checksum should enable parallel-checksum"""
        config_file = '/tmp/tmp_transferpy.conf'
        config = configparser.ConfigParser()
        # The config file has checksum True
        config['DEFAULT'] = {'port': 4444, 'transfer_type': 'file',
                             'compress': True, 'encrypt': True, 'checksum': True,
                             'parallel_checksum': False, 'stop_slave': False}
        # Write the config options except verbose
        with open(config_file, 'w') as configfile:
            config.write(configfile)
        # But command line has given with --parallel-checksum
        args = ['transfer', 'source:path', 'target:path',
                '--parallel-checksum', '--stop-slave',
                '--config', config_file]
        (source_host, source_path, target_hosts, target_paths, other_options) = \
            self.option_parse(args)
        os.remove(config_file)
        # The parallel-checksum should be True
        self.assertTrue(other_options['parallel_checksum'])
        self.assertFalse(other_options['checksum'])
