"""Factory class to decide which method is to be used to handle the firewall"""

from .BaseFirewall import BaseFirewall
from .IptablesFirewall import IptablesFirewall
from .NftablesFirewall import NftablesFirewall
from .NoFirewall import NoFirewall


NFT_DETECTION = 'test -f /etc/nftables/100_base_puppet.nft'
IPTABLES_DETECTION = 'test -f /etc/ferm/conf.d/00_defs'


def _has_cmd(remote, host, cmd):
    """Return True if 'cmd' exists and runs on remote host."""
    res = remote.run(host, "bash -lc " + f"command -v {cmd} >/dev/null 2>&1")
    return res.returncode == 0


def _probe_nft(remote, host):
    """Check if nft is the prefered method to handle firewall on this host, through puppet"""
    if not _has_cmd(remote, host, "nft"):
        return False
    # Not only it is installed, it is configured through puppet
    res = remote.run(host, NFT_DETECTION)
    return res.returncode == 0


def _probe_iptables(remote, host):
    """Check if iptables is available on this host"""
    if not _has_cmd(remote, host, "iptables"):
        return False
    # Not only it is installed it is configured through puppet-ferm
    res = remote.run(host, IPTABLES_DETECTION)
    return res.returncode == 0


def get_firewall(target_host, remote_execution, parent_tmp_dir="/tmp", force_method=None) -> BaseFirewall:
    """
    Factory: detect and return the right firewall implementation for target_host.

    prefer: Optional[str] in {"nftables","iptables","nofirewall"} to force/override detection.
    """
    if force_method == "nftables":
        return NftablesFirewall(target_host, remote_execution, parent_tmp_dir)
    if force_method == "iptables":
        return IptablesFirewall(target_host, remote_execution, parent_tmp_dir)
    if force_method == "nofirewall":
        return NoFirewall(target_host, remote_execution, parent_tmp_dir)

    # Auto-detect: prefer nftables if present & working, otherwise iptables; else no firewall.
    try:
        if _probe_nft(remote_execution, target_host):
            return NftablesFirewall(target_host, remote_execution, parent_tmp_dir)
        if _probe_iptables(remote_execution, target_host):
            return IptablesFirewall(target_host, remote_execution, parent_tmp_dir)
    except Exception:
        # If probing fails (e.g., restricted shell), fall through to no-op
        pass

    return NoFirewall(target_host, remote_execution, parent_tmp_dir)
