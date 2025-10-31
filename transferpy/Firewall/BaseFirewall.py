"""Base file which contains the common methods to handle the firewall"""
from __future__ import annotations

from transferpy.Exceptions import TempDeletionError, FirewallError
from transferpy.RemoteExecution.RemoteExecution import CommandReturn, RemoteExecution

from abc import ABC, abstractmethod
from typing import List
import os
import shlex


class BaseFirewall(ABC):
    """
    Abstract base for firewall implementations working against a remote host.
    Implementations must define open() and close() at minimum.
    """

    def __init__(self, target_host: str, remote_execution: RemoteExecution, parent_tmp_dir: str = "/tmp") -> None:
        """
        Constructor
        """
        self.target_host = target_host
        self.remote_executor = remote_execution
        self.parent_tmp_dir = parent_tmp_dir

        self.target_port = 0
        self.search_start_port = 4400
        self.search_end_port = 4500
        self.reserve_port_dir_name = None

    def run_command(self, command: List[str] | str) -> CommandReturn:
        """
        Executes command on the target host.

        :param command: command to run
        :return: execution result (returncode, stdout, stderr)
        """
        return self.remote_executor.run(self.target_host, command)

    @property
    def find_used_ports_command(self) -> List[str]:
        """
        Property: command to find used ports.

        :return: command to find used ports
        """
        # TODO: Make this command in terms of search_start_port and search_end_port
        command = ["/bin/netstat -altn | awk '{print $4}' | awk -F: '{print $NF}' | grep ^44[0-9][0-9]$ || echo 0"]
        return command

    def find_pid(self, target_port: int) -> int:
        """
        Finds pid of the process based on the port it is using.

        :param target_port: the port using by process
        :return: PID of the process ran
        :raises Exception: if process not found
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

    def kill_process(self, target_port: int) -> None:
        """
        Kill the process based on the port it is using.

        :param target_port: the port using by process
        :raises Exception: if the process killing did not return success error code
        """
        command = f"/bin/fuser -k {target_port}/tcp || echo 0"
        result = self.run_command(command)
        if result.returncode != 0:
            raise Exception('failed to kill process based on the port {} on {}'
                            .format(target_port, self.target_host))

    def get_available_port(self, target_port) -> int:
        """
        Given a target_port, validate it, check it is available and reserve it.
        Autofind it if 0.

        :param target_port: port to reserve, 0 to autofind it
        :return: Port reserved
        :raises ValueError: if an invalid port number was provided or it is unavailable
        """
        if not isinstance(target_port, int) or target_port < 0 or target_port > 65535:
            raise ValueError(f"target_port must be an int in [0, 65535]; got {target_port!r}")
        # If target port is 0, find a free port automatically
        # else try to reserve the given port for the transfer
        if target_port == 0:
            target_port = self.find_available_port_and_reserve()
        elif not self.reserve_port(target_port):
            raise ValueError(
                f"ERROR: The given port {target_port} is not available on {self.target_host}"
            )
        return target_port

    def reserve_port(self, target_port: int) -> bool:
        """
        Reserves target port by creating a directory.

        :param target_port: port to be reserved
        :return: 0 if reservation is successful, other error code if not
        """
        reserve_port_dir_name = os.path.normpath(
                os.path.join(self.parent_tmp_dir, 'trnsfr_{}_{}.lock'.format(self.target_host, target_port)))
        command = [f"/bin/mkdir {shlex.quote(reserve_port_dir_name)}"]
        result = self.run_command(command)
        if result.returncode == 0:
            # The trnsfr_target_host_target_port will always be unique at an instance of time
            self.reserve_port_dir_name = reserve_port_dir_name
        return result.returncode == 0

    def unreserve_port(self, target_port) -> bool:
        """
        Removes the reservation for target port by deleting a directory.

        :param target_port: port to be unreserved
        :return: True if port successfully unreserved
        """
        command = [f"/bin/rmdir {shlex.quote(self.reserve_port_dir_name)}"]
        result = self.run_command(command)
        return result.returncode == 0

    def find_available_port_and_reserve(self) -> int:
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

    def firewall_error(self, firewall_type="unknown") -> None:
        """Raises a firewall error, but tries to cleanup first"""
        # try to cleanup reservation before raising
        self.cleanup(firewall_type)
        raise FirewallError(f"ERROR: {firewall_type} firewall execution failed")

    def cleanup(self, firewall_type="unknown") -> None:
        """Cleanup temporary files"""
        if not self.unreserve_port(self.target_port):
            raise TempDeletionError(
                f"WARNING: {firewall_type} temporary lock dir {self.reserve_port_dir_name} deletion failed"
            )

    def __del__(self) -> None:
        """Destructor"""
        pass

    @abstractmethod
    def open(self, source_host: str, target_port: int) -> int:
        """
        Open traffic from source_host to target_port on target_host.
        If target_port == 0, choose and reserve an available port.
        Returns the opened port if succesful.
        Raise on failure.

        :param source_host: hostname, IP address or fqdn of the sending host
        :param target_port: Target port to open (0 for auto-select)
        :return: The port that was opened
        :raises FirewallError: If firewall operation fails
        :raises ValueError: If port is incorrect or unavailable
        """
        raise NotImplementedError

    @abstractmethod
    def close(self, source_host: str) -> int:
        """
        Close/undo whatever open() did.
        Return an integer exit code (0 on success, other, on failure).

        :param source_host: hostname, IP address or fqdn of the sending host
        :return: Exit code (0 on success)
        """
        raise NotImplementedError
