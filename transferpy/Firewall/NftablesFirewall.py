"""Handling of the firewall using NFTables"""
from .BaseFirewall import BaseFirewall


class NftablesFirewall(BaseFirewall):
    """
    nftables implementation mirroring the public contract of the iptables Firewall.
    - open(): adds a rule allowing tcp from source_host to target_port
    - close(): removes that rule
    """

    # ---- nftables open/close ----
    def open(self, source_host, target_port):
        if target_port == 0:
            target_port = self.find_available_port()
        elif not self.reserve_port(target_port):
            raise ValueError(f"ERROR: The given port {target_port} is not available on {self.target_host}")
        self.target_port = str(target_port)

        command = ['/usr/sbin/nft', 'add', 'rule', 'inet', 'base',
                   'input', 'ip', 'saddr', source_host,
                   'tcp', 'dport', self.target_port, 'accept']
        result = self.run_command(command)
        if result.returncode != 0:
            self.firewall_error("nftables")
        return target_port

    def close(self, source_host):
        command = ['bash', '-c', f"\"/usr/sbin/nft -a list ruleset | grep $(dig +short {source_host}) | grep {self.target_port} | grep -o 'handle [0-9]*'\""]
        result = self.run_command(command)
        if result.returncode != 0:
            self.cleanup("nftables")
        handle = result.stdout.strip().split(" ")[1]
        command = ['/usr/sbin/nft', 'delete', 'rule', 'inet', 'base', 'input', 'handle', handle]
        result = self.run_command(command)
        if result.returncode != 0:
            self.cleanup("nftables")
        return result.returncode
