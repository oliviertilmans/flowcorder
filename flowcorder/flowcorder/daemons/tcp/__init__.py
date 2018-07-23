"""
The tcp_flow_exporter instruments the host kernel TCP stack using kprobes.

It leverages eBPF hooks to gather statistics about on-going TCP flows, and
exports the events towards the collector.
"""
import os


def _supports_mptcp():
    return os.path.exists('/proc/net/mptcp_net')


HAS_MPTCP = _supports_mptcp()
