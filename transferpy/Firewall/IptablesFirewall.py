"""Handling of the firewall using IPTables"""
from .BaseFirewall import BaseFirewall


class IptablesFirewall(BaseFirewall):

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
            self.firewall_error("iptables")
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
        self.cleanup("iptables")
        return result.returncode
