"""
This modules defines the instrumentation of the DNS stack.

We initiate a network tap such that all DNS traffic is sniffed.
A BPF shared map then contains the entries for such packets. This user-space
daemon then walks through the table and processes the intercepted messages.
"""
import bcc
import time
import os
import socket
import select
import logging
from enum import IntEnum
from hashlib import sha1

from .template import DNSTemplate
from .compute_timeout import get_timeout
from ..utils import ThreadedComponent
from ..transition import FLOW_STATES
from ...utils import embedded_ipv4, hash_seq_to_u64

LOG = logging.getLogger(__name__)


BPF_SRC_NAME = 'dnstap.c'


def int_in_range(v, default, name, minv=0, maxv=65535):
    """
    Assess that a given value is an integer within a range.

    :v: The integer to check
    :minv: The minimal value (included)
    :maxv: The maximal value (included)
    """
    try:
        val = int(v)
        if val < minv or val > maxv:
            LOG.warning('%s %d is not in the range [%d, %d], defaulting to %d'
                        % (name, val, minv, maxv, default))
            return default
    except (ValueError, TypeError) as e:
        LOG.warning('%d(%s) is not an integer: %s', val, name, e)
        return default
    return val


class DNSInstrumentation(ThreadedComponent):
    """Component instrumenting the DNS stack."""

    def __init__(self, Exporter=None, BPFManager=None,
                 dns_port=53, ipv6_depth=5, support_dot1q=False):
        """
        Initialize a new DNS stack instrumentation.

        :dns_port: The UDP destination port to match on to contact the DNS
                      server.
        :ipv6_depth: The maximal head chain depth to accept for IPv6 packets
        """
        super(DNSInstrumentation, self).__init__()
        self.dns_port = int_in_range(dns_port, 53, 'dns_port', minv=1)
        self.ipv6_depth = int_in_range(ipv6_depth, 5, 'ipv6_depth', maxv=10)
        self.connection_table = None
        self.ebpf = BPFManager
        self.ebpf.configure(BPF_SRC_NAME, DNS_DST_PORT=self.dns_port,
                            MAX_IPV6_DEPTH=self.ipv6_depth,
                            SUPPORT_DOT1Q='' if support_dot1q else None)
        self.exporter = Exporter
        self.exporter.configure(DNSTemplate)

    def start(self):
        """Start instrumenting DNS requests."""
        sk, poll = self._attach_filter()
        timeout = get_timeout() * 1e6  # in us
        super(DNSInstrumentation, self).start(
            timeout, poll=poll, sk=sk, timeout_ns=timeout)

    def _attach_filter(self):
        """
        Attach the BPF filter to a raw socket and prepare to poll it.

        :return: sock_fd, poll_object
        """
        func = self.ebpf.load_func('forward_dns', bcc.BPF.SOCKET_FILTER)
        bcc.BPF.attach_raw_socket(func, "")
        self.connection_table = self.ebpf["connection_map"]
        poll = select.epoll()
        poll.register(func.sock, select.EPOLLIN | select.POLLPRI)
        return func.sock, poll

    def do_work(self, timeout, poll=None, sk=None, timeout_ns=None):
        """Either wait for a new packet or for a query to expire."""
        events = poll.poll(timeout=float(timeout) / 1e6)
        if events:
            # Discard packet data
            os.read(sk, 1024)
        # Walk down connection table to find new connections, timeouts, ...
        return self._walk_bpf_table(timeout_ns)

    def _walk_bpf_table(self, timeout_val):
        """Walk down the BPF table to update flow stats."""
        now = _now_in_us()
        to_remove = []
        timeout = timeout_val
        for connection, info in self.connection_table.iteritems():
            if info.status == DNS_STATUS.STATUS_QUERY:
                tleft = timeout_val - (now - info.sent_ts)
                # Did the query time out ?
                if tleft <= 0:
                    self._export_event(connection, info,
                                       flow_state=FLOW_STATES.UNREACHABLE,
                                       rtt=info.sent_ts + int(timeout_val))
                    to_remove.append(connection)
                else:
                    # Update the max timeout value
                    timeout = min(timeout, tleft)
            else:
                self._export_event(connection, info,
                                   flow_state=DNS_STATUS_TO_FLOW[info.status],
                                   rtt=info.reply_ts - info.sent_ts)
                to_remove.append(connection)
        # Removal and export done in 2-phase to avoid ctype pointer corruption
        for k in to_remove:
            try:
                del self.connection_table[k]
            except KeyError:
                pass
        return timeout

    def _export_event(self, connection, info, flow_state, rtt):
        saddr, daddr = _extract_addr(connection,
                                     bool(info.version_retries & 0x8))
        self.exporter.export({
            'flowStartReason': FLOW_STATES.NEW,
            'flowEndReason': flow_state,
            'flowStartMicroseconds': info.first_ts,
            'flowEndMicroseconds': info.reply_ts,
            'saddr': saddr,
            'daddr': daddr,
            'selectorId': hash_seq_to_u64(connection.saddr,
                                          connection.daddr,
                                          connection.sport.to_bytes(16, 'big'),
                                          connection.id.to_bytes(16, 'big')),
            'applicationName': 'dnstap',
            'sourceTransportPort': connection.sport,
            'destinationTransportPort': self.dns_port,
            'transferredOctetTotalCount': info.query_size,
            'receivedOctetTotalCount': info.reply_size,
            'retransmittedPacketTotalCount': info.version_retries & 0x7F,
            'meanLatencyMilliseconds': int(rtt // 1e3)
        })


MAX_UINT64 = (2 ** 64) - 1


def _extract_addr(connection, is_ipv6):
    if is_ipv6:
        family = socket.AF_INET6
        extract = _mirror
    else:
        family = socket.AF_INET
        extract = embedded_ipv4
    return (socket.inet_ntop(family, extract(connection.saddr)),
            socket.inet_ntop(family, extract(connection.daddr)))


def _mirror(x):
    return x


CLK_RES = time.clock_getres(time.CLOCK_MONOTONIC) * 1e6  # in us


def _now_in_us():
    return time.clock_gettime(time.CLOCK_MONOTONIC) * CLK_RES


class DNS_STATUS(IntEnum):
    """The events that can be reported by the BPF filter."""

    STATUS_QUERY = 1
    STATUS_ANSWER = 2
    STATUS_FAIL = 3


DNS_STATUS_TO_FLOW = {
    DNS_STATUS.STATUS_QUERY: FLOW_STATES.NEW,
    DNS_STATUS.STATUS_ANSWER: FLOW_STATES.FINISHED,
    DNS_STATUS.STATUS_FAIL: FLOW_STATES.BROKEN,
}
