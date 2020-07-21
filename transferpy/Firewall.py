#!/usr/bin/python3
import os

from transferpy.Exceptions import TempDeletionError, FirewallError


class Firewall(object):
    """Class for Transferer firewall related command execution"""
    def __init__(self, target_host, remote_execution, parent_tmp_dir='/tmp'):
        """
        Initialize the instance variables.

        :param target_host: host address for port open/close
        :param remote_execution: remote execution helper
        """
        self.target_host = target_host
        self.target_port = 0
        self.remote_executor = remote_execution
        self.search_start_port = 4400
        self.search_end_port = 4500
        self.parent_tmp_dir = parent_tmp_dir
        self.reserve_port_dir_name = None

    @property
    def find_used_ports_command(self):
        """
        Property: command to find used ports.

        :return: command to find used ports
        """
        # TODO: Make this command in terms of search_start_port and search_end_port
        command = ["/bin/netstat -altn | awk '{print $4}' | awk -F: '{print $NF}' | grep ^44[0-9][0-9]$ || echo 0"]
        return command

    def find_pid(self, target_port):
        """
        Finds pid of the process based on the port it is using.

        :param target_port: the port using by process
        """
        command = "/bin/fuser {}/tcp".format(target_port)
        result = self.run_command(command)
        if result.returncode != 0:
            raise Exception('failed to find PID based on the port {} on {}'
                            .format(target_port, self.target_host))
        else:
            try:
                pid = int(result.stdout.split(':')[1].strip())
            except Exception as e:
                raise Exception('failed to find PID based on the port {} on {}, {}'
                                .format(target_port, self.target_host, str(e)))
        return pid

    def kill_process(self, target_port):
        """
        Kill the process based on the port it is using.

        :param target_port: the port using by process
        :return: raises exception if not successful
        """
        command = "/bin/fuser -k {}/tcp || echo 0".format(target_port)
        result = self.run_command(command)
        if result.returncode != 0:
            raise Exception('failed to kill process based on the port {} on {}'
                            .format(target_port, self.target_host))

    def run_command(self, command):
        """
        Executes command on the target host.

        :param command: command to run
        :return: execution result (returncode, stdout, stderr)
        """
        return self.remote_executor.run(self.target_host, command)

    def open(self, source_host, target_port):
        """
        Opens target port on iptables of target host.

        :param source_host: sender host
        :param target_port: port to be opened
        :return: raises exception if not successful
        """
        # If target port is 0, find a free port automatically
        # else try to reserve the given port for the transfer
        if target_port == 0:
            target_port = self.find_available_port()
        elif not self.reserve_port(target_port):
            raise ValueError("ERROR: The given port {} is not available on {}"
                             .format(target_port, self.target_host))
        self.target_port = target_port

        command = ['/sbin/iptables', '-A', 'INPUT', '-p', 'tcp', '-s',
                   '{}'.format(source_host),
                   '--dport', '{}'.format(target_port),
                   '-j', 'ACCEPT']
        result = self.run_command(command)
        if result.returncode != 0:
            if not self.unreserve_port(target_port):
                raise TempDeletionError(
                    'iptables execution and temporary lock dir {} deletion failed'.format(
                        self.reserve_port_dir_name))
            raise FirewallError('iptables execution failed')
        return target_port

    def close(self, source_host):
        """
        Closes target port on iptables of target host.

        :param source_host: sender host
        :param target_port: port to be closed
        :return: remote run exit code, successful(0)
        """
        command = ['/sbin/iptables', '-D', 'INPUT', '-p', 'tcp', '-s',
                   '{}'.format(source_host),
                   '--dport', '{}'.format(self.target_port),
                   '-j', 'ACCEPT']
        result = self.run_command(command)
        if not self.unreserve_port(self.target_port):
            print('WARNING: {} temporary directory could not be deleted'
                  .format(self.reserve_port_dir_name))
        return result.returncode

    def reserve_port(self, target_port):
        """
        Reserves target port by creating a directory.

        :param target_port: port to be reserved
        :return: True if reservation is successful
        """
        reserve_port_dir_name = os.path.normpath(
                os.path.join(self.parent_tmp_dir, 'trnsfr_{}_{}.lock'.format(self.target_host, target_port)))
        command = ["/bin/mkdir {}".format(reserve_port_dir_name)]
        result = self.run_command(command)
        if result.returncode == 0:
            # The trnsfr_target_host_target_port will always be unique at an instance of time
            self.reserve_port_dir_name = reserve_port_dir_name
        return result.returncode == 0

    def unreserve_port(self, target_port):
        """
        Removes the reservation for target port by deleting a directory.

        :param target_port: port to be unreserved
        :return: True if port successfully unreserved
        """
        command = ["/bin/rmdir {}".format(self.reserve_port_dir_name)]
        result = self.run_command(command)
        return result.returncode == 0

    def find_available_port(self):
        """
        Checks port availability from a given range of ports on
        the target host and select one among them.

        :return: available port if successful, else raises ValueError
        """
        result = self.run_command(self.find_used_ports_command)
        num_of_searches = self.search_end_port - self.search_start_port
        if result.returncode != 0 or len(result.stdout.split('\n')) == num_of_searches:
            raise ValueError('failed to find an available port on {}'.format(self.target_host))

        try:
            used_ports = [int(i) for i in result.stdout.split('\n')]
        except Exception as e:
            raise ValueError("ERROR: Returned non integer value for used ports "
                             "on {}\n{}".format(self.target_host, str(e)))

        port = 0
        for p in range(self.search_start_port, self.search_end_port):
            if p not in used_ports:
                if self.reserve_port(p):
                    port = p
                    break
        if port == 0:
            raise ValueError("ERROR: Could not find a free port on {}".format(self.target_host))
        return port

    def __del__(self):
        """Destructor"""
        pass
