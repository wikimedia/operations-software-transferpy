"""Handling of the firewall using NFTables"""
from .BaseFirewall import BaseFirewall

import socket


class NftablesFirewall(BaseFirewall):
    """
    nftables implementation mirroring the public contract of the iptables Firewall.
    - open(): adds a rule allowing tcp from source_host to target_port
    - close(): removes that rule
    """

    # ---- nftables open/close ----
    def open(self, source_host: str, target_port: int) -> int:
        """
        Open a TCP port on the target host for traffic from `source_host`.

        If `target_port` is 0, a free port will be discovered and reserved.

        :param source_host: Source IP/hostname allowed to connect.
        :param target_port: Port to open (0 => auto-assign a free port).
        :return: The concrete opened port number.
        :raises ValueError: On invalid inputs.
        :raises FirewallError: If nft command fails.
        """
        if not source_host or not isinstance(source_host, str):
            raise ValueError("source_host must be a non-empty string")

        self.target_port = self.get_available_port(target_port)

        command = ['/usr/sbin/nft', 'add', 'rule', 'inet', 'base',
                   'input', 'ip', 'saddr', source_host,
                   'tcp', 'dport', f'{self.target_port}', 'accept']
        result = self.run_command(command)
        if result.returncode != 0:
            self.firewall_error("nftables")
        return self.target_port

    def close(self, source_host: str) -> int:
        """
        Close the previously opened TCP port rule for `source_host`.

        Relies on `self.target_port` being set by a prior `open()` call.
        If the rule does not exist, or the removal fails otherwise,
        returns >0.

        :param source_host: Source IP/hostname that was allowed.
        :return: Command run exit code (0 on success).
        :raises ValueError: If target_port or source_host was never set or
                it is a non-resolvable host.
        :raises TempDeletionError: if cleanup is unsuccesful after an error
        """
        try:
            host_ip = socket.gethostbyname(source_host)
        except Exception:
            raise ValueError("source_host must be a resolvable address")

        command = [
            'bash',
            '-c',
            f"\"/usr/sbin/nft -a list ruleset | grep {host_ip} | grep {self.target_port} | grep -o 'handle [0-9]*'\""
        ]
        result = self.run_command(command)

        if result.returncode != 0:
            self.cleanup("nftables")
            return result.returncode

        handle = result.stdout.strip().split(" ")[1]
        command = ['/usr/sbin/nft', 'delete', 'rule', 'inet', 'base', 'input', 'handle', handle]
        result = self.run_command(command)
        if result.returncode != 0:
            self.cleanup("nftables")
        return result.returncode
