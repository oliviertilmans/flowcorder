"""The Exporter component exports events to the aggregator."""
import time
import sys
import socket
import pprint
from ipaddress import ip_address, IPv4Address, IPv6Address

from .utils import ConsumerComponent, DaemonComponent, CLIParam
from .pruning import NoPruning, PruningHelper
from .transition import CancelMessage

import logging
LOG = logging.getLogger(__name__)


class Exporter(ConsumerComponent):
    """
    Component that will export transitions.

    Either writing them to stdout for debbugging, or export them to an IPFIX
    collector if an address is provided.
    """

    def __init__(self, **kw):
        """Initialize the exporter to use stdout, or open an UNIX socket."""
        self.kw = kw
        super(Exporter, self).__init__()

    def configure(self, transition_type):
        """Configure the transition templates to use to export."""
        self.templ = transition_type
        super(Exporter, self).configure(Serializer.build)

    def start(self):
        """Start the exporter."""
        super(Exporter, self).start(template=self.templ, **self.kw)


class Serializer(object):
    """The consumer process that will receive transition and exports them."""

    def __init__(self, template=None, report_rate=0.1, collector_address=None,
                 collector_port=2055, prune=True, ignore_prefixes=[]):
        self.templ = None
        self.sk, self.write_func = (
            self._mk_sk(collector_address, collector_port, template)
            if collector_address else self._mk_stdout())
        self.rate = report_rate
        self.prune = PruningHelper(ignore_prefixes) if prune else NoPruning()

    @classmethod
    def build(cls, **kw):
        return cls(**kw).consume

    def consume(self, transition):
        pruned_transition = self.prune.keep_transition(transition)
        # Check if the transition is really needed
        if pruned_transition:
            if self.write_func(pruned_transition):
                # Backoff if we wrote anything
                self.backoff()

    def backoff(self):
        time.sleep(self.rate)

    def __del__(self):
        if self.sk is not None:
            self.sk.close()
            self.sk = None

    def _mk_sk(self, ip, port, template):
        sk = socket.socket(socket.AF_INET
                           if ip.version == 4 else socket.AF_INET6,
                           socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
        sk.connect((ip.compressed, port))
        LOG.debug('Connected exporter socket to: %s [%s]', ip.compressed, port)
        self.templ = template()
        return sk, self._write_sock

    def _write_sock(self, data):
        try:
            b_array = self.templ.encode(data)
        except CancelMessage as e:
            LOG.debug('Transition %s got canceled: %s', data, e)
            return False
        # is the message ready to be sent?
        if b_array is not None:
            try:
                self.sk.send(b_array)
            except (socket.error, OSError, IOError) as e:
                LOG.warning('Caught exception when exporting records: %s', e)
            return True
        return False

    def _mk_stdout(self):
        return sys.stdout, self._write_stdout

    def _write_stdout(self, data):
        pprint.pprint(data, self.sk, indent=2, width=80)
        self.sk.flush()
        # never backoff after writing to stdout
        return False


def _as_af(prefix):
    if prefix == 'v6' or prefix == 'ipv6':
        return socket.AF_INET6
    return socket.AF_INET


def host_address(addr):
    """Enforce that a parameter is an IP address (or resolves to)."""
    if not addr:
        return None
    try:
        return ip_address(addr)
    except ValueError:
        try:
            parts = addr.split('://')
            target_af, addr = ((_as_af(parts[0]), parts[1]) if len(parts) > 1
                               else (socket.AF_UNSPEC, addr))
            for (af, _, __, ___, sockaddr) in socket.getaddrinfo(
                    addr, None, family=target_af):
                try:
                    ip = (IPv4Address(sockaddr[0]) if af == socket.AF_INET else
                          IPv6Address(sockaddr[0]))
                    LOG.info('Resolved collector<%s> to %s',
                             addr, ip.compressed)
                    return ip
                except ValueError:
                    continue
            err = 'No valid address found'
        except socket.gaierror as e:
            err = str(e)
            raise ValueError('%s cannot be used to reach the collector: %s' %
                             (addr, err))


EXPORTER = DaemonComponent(Exporter, cli_params=[
            CLIParam('--report-rate', type=float, help='Minimal delay between'
                     ' two successive IPFIX messages (seconds)'),
            CLIParam('--collector-address', type=host_address,
                     help='The ip address to use to reach '
                     'the measurement collector(s). If using a domain name,'
                     ' you can prefix it by ipvX:// to force the use of IPvX'),
            CLIParam('--collector-port', type=int, help='The UDP port for the '
                     'collector'),
            CLIParam('--prune', action='store_true', help='Prune the number '
                     'of exported performance reports.'),
            CLIParam('--ignore-prefixes', nargs='*',
                     help='Ignore the following destination prefixes')])
