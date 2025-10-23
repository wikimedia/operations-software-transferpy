"""Handling of the firewall using IPTables"""
from .BaseFirewall import BaseFirewall


class IptablesFirewall(BaseFirewall):

    def open(self, source_host: str, target_port: int) -> int:
        """
        Opens target port on iptables of target host.

        If target_port is 0, finds an available port automatically.
        Otherwise, attempts to reserve the specified port.

        :param source_host: sender host
        :param target_port: port to be opened
        :return: the port that was opened, raises exception if not successful
        :raises ValueError: if the given port is not available or the source host is empty
        :raises FirewallError: if iptables command fails
        :raises TempDeletionError: if cleanp is unsuccesful after an error
        """
        if not source_host or not isinstance(source_host, str):
            raise ValueError("source_host must be a non-empty string")

        self.target_port = self.get_available_port(target_port)

        command = [
            '/sbin/iptables', '-A', 'INPUT', '-p', 'tcp',
            '-s', f'{source_host}',
            '--dport', f'{target_port}',
            '-j', 'ACCEPT'
        ]
        result = self.run_command(command)

        if result.returncode != 0:
            self.firewall_error("iptables")

        return self.target_port

    def close(self, source_host: str) -> int:
        """
        Closes target port on iptables of target host.

        :param source_host: sender host
        :return: remote run exit code, successful(0)
        :raises ValueError: If the requested port is not available.
        :raises TempDeletionError: if cleanup is unsuccesful after an error
        """
        command = [
            '/sbin/iptables', '-D', 'INPUT', '-p', 'tcp',
            '-s', f'{source_host}',
            '--dport', f'{self.target_port}',
            '-j', 'ACCEPT'
        ]
        result = self.run_command(command)

        self.cleanup("iptables")

        return result.returncode
