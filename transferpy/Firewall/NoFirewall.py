"""Firewall methods when no firewall is detected (no action is taken)"""
from .BaseFirewall import BaseFirewall


class NoFirewall(BaseFirewall):
    """
    No-op firewall: open() just "reserves" a port (directory lock) and returns it.
    close() removes the reservation. No packet filter changes.
    """

    def open(self, source_host, target_port):
        if target_port == 0:
            target_port = self.find_available_port()
        elif not self.reserve_port(target_port):
            raise ValueError(f"ERROR: The given port {target_port} is not available on {self.target_host}")
        self.target_port = target_port
        return target_port

    def close(self, source_host):
        return 0 if self.unreserve_port(self.target_port) else 1
