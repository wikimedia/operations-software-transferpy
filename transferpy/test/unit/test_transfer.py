"""Tests for transfer.py class."""
import sys
import logging
import unittest
from unittest.mock import patch, MagicMock

from transferpy.transfer import option_parse, split_target
from transferpy.Transferer import Transferer
from transferpy.Firewall import Firewall

from transferpy.test.utils import hide_stderr


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

    def test_is_dir(self):
        path = 'path'
        self.transferer.is_dir('host', path)

        args = self.executor.run.call_args[0]
        self.assertIn(r'"[ -d "{}" ]"'.format(path), args[1])

    def test_file_exists(self):
        file = 'path'
        self.transferer.file_exists('host', file)

        args = self.executor.run.call_args[0]
        self.assertIn(r'"[ -a "{}" ]"'.format(file), args[1])

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
            self.assertTrue(type(command) == list)

    def test_run_stoping_slave(self):
        """Test case for Transferer.run function which provides stop_slave option"""
        with patch.object(Transferer, 'sanity_checks') as mocked_sanity_check,\
                patch('transferpy.Transferer.MariaDB.stop_replication') as mocked_stop_replication:
            self.options['stop_slave'] = True
            self.options['checksum'] = False
            #  Return value should be anything other than 0 for the if block to execute
            mocked_stop_replication.return_value = 1
            mocked_sanity_check.called_once()
            command = self.transferer.run()
            self.assertTrue(type(command) == list)

    def test_run_successfully(self):
        """Test case for Transferer.run function starting transfer successfully"""
        with patch.object(Transferer, 'sanity_checks') as mocked_sanity_check,\
                patch('transferpy.Transferer.Firewall.open') as mocked_open_firewall,\
                patch.object(Transferer, 'copy_to') as mocked_copy_to,\
                patch('transferpy.Transferer.Firewall.close') as mocked_close_firewall,\
                patch.object(Transferer, 'after_transfer_checks') as mocked_after_transfer_checks,\
                patch('transferpy.Transferer.MariaDB.start_replication') as mocked_start_replication:
            self.options['port'] = 4444
            self.options['checksum'] = False
            mocked_copy_to.return_value = 0
            mocked_close_firewall.return_value = 0
            mocked_after_transfer_checks.return_value = 0
            mocked_start_replication.return_value = 0
            mocked_sanity_check.called_once()
            mocked_open_firewall.called_once()
            command = self.transferer.run()
            self.assertTrue(type(command) == list)

    def test_run_start_slave(self):
        """Test case for Transferer.run function for when it runs the
           start_slave function with the stop_slave option
        """
        with patch('transferpy.Transferer.MariaDB.stop_replication') as mocked_stop_replication,\
                patch.object(Transferer, 'sanity_checks') as mocked_sanity_check,\
                patch('transferpy.Transferer.Firewall.open') as mocked_open_firewall,\
                patch.object(Transferer, 'copy_to') as mocked_copy_to,\
                patch('transferpy.Transferer.Firewall.close') as mocked_close_firewall,\
                patch.object(Transferer, 'after_transfer_checks') as mocked_after_transfer_checks,\
                patch('transferpy.Transferer.MariaDB.start_replication') as mocked_start_replication:
            self.options['port'] = 4444
            self.options['checksum'] = False
            self.options['stop_slave'] = True
            # We need to skip the first if statement
            # which checks the stop slave option
            mocked_stop_replication.return_value = 0
            mocked_copy_to.return_value = 0
            mocked_close_firewall.return_value = 0
            mocked_after_transfer_checks.return_value = 0
            # Return value should be anything other than 0
            # for this if block to execute
            mocked_start_replication.return_value = 1
            mocked_sanity_check.called_once()
            mocked_open_firewall.called_once()
            command = self.transferer.run()
            self.assertTrue(type(command) == list)

    def test_close_gets_port_from_open(self):
        """Test case for Firewall.close function, close gets the port number from open function"""
        with patch.object(Transferer, 'sanity_checks') as mocked_sanity_check,\
                patch('transferpy.Transferer.Firewall.open') as mocked_open_firewall,\
                patch.object(Transferer, 'copy_to') as mocked_copy_to,\
                patch('transferpy.Transferer.Firewall.close') as mocked_close_firewall,\
                patch.object(Transferer, 'after_transfer_checks') as mocked_after_transfer_checks,\
                patch('transferpy.Transferer.MariaDB.start_replication') as mocked_start_replication:
            self.options['port'] = 0
            self.options['checksum'] = False
            mocked_sanity_check.return_value = 0
            mocked_copy_to.return_value = 0
            mocked_open_firewall.return_value = 4400
            mocked_close_firewall.return_value = 0
            mocked_after_transfer_checks.return_value = 0
            mocked_start_replication.return_value = 0
            command = self.transferer.run()
            mocked_open_firewall.assert_called_once_with('source', 0)
            mocked_close_firewall.assert_called_once_with('source', 4400)
            self.assertTrue(type(command) == list)


class TestFirewall(unittest.TestCase):
    """Test cases for Firewall module"""
    @patch('transferpy.Transferer.RemoteExecution')
    def setUp(self, executor_mock):
        self.executor = MagicMock()
        executor_mock.return_value = self.executor

        self.firewall_handler = Firewall('target', self.executor)

    def test_reserve_port(self):
        """Test for Firewall reserve_port function"""
        target_port = 4444
        command = ["/bin/mkdir {}".format(
            self.firewall_handler.reserve_port_dir_name.format(target_port))]
        self.firewall_handler.reserve_port(target_port)
        self.executor.run.assert_called_with('target', command)

    def test_unreserve_port(self):
        """Test for Firewall unreserve_port function"""
        target_port = 4444
        command = ["/bin/rmdir {}".format(
            self.firewall_handler.reserve_port_dir_name.format(target_port))]
        self.firewall_handler.unreserve_port(target_port)
        self.executor.run.assert_called_with('target', command)

    def test_find_available_port(self):
        """Test for find_available_port function"""
        self.executor.run.return_value.returncode = 0
        self.executor.run.return_value.stdout = "4400\n4401"
        with patch('transferpy.Firewall.Firewall.reserve_port') as mocked_reserve_port:
            mocked_reserve_port.return_value = 1
            target_port = self.firewall_handler.find_available_port()
            self.executor.run.assert_called_with('target', self.firewall_handler.find_used_ports_command)
            self.assertEqual(target_port, 4402)

    def test_no_available_port(self):
        """Test for find_available_port function when no ports are available"""
        self.executor.run.return_value.returncode = 0
        with patch('transferpy.Firewall.Firewall.reserve_port') as mocked_reserve_port:
            # reserve_port function failure lead to the idea of unavailability of the port
            mocked_reserve_port.return_value = 0
            with self.assertRaises(ValueError):
                self.firewall_handler.find_available_port()
            self.executor.run.assert_called_with('target', self.firewall_handler.find_used_ports_command)

    def test_open_with_auto_port_finding(self):
        """Test for open function with automatic port finding"""
        source_host = 'src_host'
        # When target_port is 0, Firewall automatically finds a free port
        target_port = 0
        expected_port = 4400
        self.executor.run.return_value.returncode = 0
        with patch('transferpy.Firewall.Firewall.find_available_port') as mocked_find_available_port:
            mocked_find_available_port.return_value = expected_port
            port = self.firewall_handler.open(source_host, target_port)
            command = ['/sbin/iptables', '-A', 'INPUT', '-p', 'tcp', '-s',
                       '{}'.format(source_host),
                       '--dport', '{}'.format(expected_port),
                       '-j', 'ACCEPT']
            self.executor.run.assert_called_with('target', command)
            self.assertEqual(port, expected_port)

    def test_open_with_given_port(self):
        """Test for open function with a given port"""
        source_host = 'src_host'
        target_port = 4400
        expected_port = 4400
        self.executor.run.return_value.returncode = 0
        with patch('transferpy.Firewall.Firewall.reserve_port') as mocked_reserve_port:
            mocked_reserve_port.return_value = 1
            port = self.firewall_handler.open(source_host, target_port)
            command = ['/sbin/iptables', '-A', 'INPUT', '-p', 'tcp', '-s',
                       '{}'.format(source_host),
                       '--dport', '{}'.format(expected_port),
                       '-j', 'ACCEPT']
            self.executor.run.assert_called_with('target', command)
            self.assertEqual(port, expected_port)

    def test_open_with_given_non_available_port(self):
        """Test for open function with a given port which is
        not available at the target host"""
        source_host = 'src_host'
        target_port = 4400
        self.executor.run.return_value.returncode = 0
        with patch('transferpy.Firewall.Firewall.reserve_port') as mocked_reserve_port:
            mocked_reserve_port.return_value = 0
            with self.assertRaises(ValueError):
                self.firewall_handler.open(source_host, target_port)

    def test_open_failure(self):
        """Test for open function failure"""
        source_host = 'src_host'
        target_port = 4400
        self.executor.run.return_value.returncode = 1
        with patch('transferpy.Firewall.Firewall.reserve_port') as mocked_reserve_port:
            mocked_reserve_port.return_value = 1
            with self.assertRaises(Exception):
                self.firewall_handler.open(source_host, target_port)

    def test_close(self):
        """Test for close function failure"""
        source_host = 'src_host'
        target_port = 4400
        self.executor.run.return_value.returncode = 1
        with patch('transferpy.Firewall.Firewall.unreserve_port') as mocked_unreserve_port:
            command = ['/sbin/iptables', '-D', 'INPUT', '-p', 'tcp', '-s',
                       '{}'.format(source_host),
                       '--dport', '{}'.format(target_port),
                       '-j', 'ACCEPT']
            mocked_unreserve_port.return_value = 1
            self.firewall_handler.close(source_host, target_port)
            self.executor.run.assert_called_once_with('target', command)
            mocked_unreserve_port.assert_called_once_with(target_port)

    def test_find_pid(self):
        """Test for find_pid"""
        target_port = 4400
        command = "/bin/fuser {}/tcp".format(target_port)
        self.executor.run.return_value.returncode = 0
        self.executor.run.return_value.stdout = 'port:123'
        pid = self.firewall_handler.find_pid(target_port)
        self.executor.run.assert_called_once_with('target', command)
        self.assertEqual(pid, 123)

    def test_kill_process(self):
        """Test for kill_process"""
        target_port = 4400
        command = "/bin/fuser -k {}/tcp || echo 0".format(target_port)
        self.executor.run.return_value.returncode = 0
        self.firewall_handler.kill_process(target_port)
        self.executor.run.assert_called_once_with('target', command)


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
            self.assertEquals(exc.exception.code, 2)

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
        # By default, normal checksum is enabled. So, irrespective of the
        # --parallel-checksum argument, this option is disabled.
        parallel_checksum_test_args = base_args + ['--parallel-checksum']
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
