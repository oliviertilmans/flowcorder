"""
This module defines the expected FSM states and geenral utils.

In general, IPFIX templates should extend FlowTemplate.
The transition to export is then a dictionnary, whose keys are the various
fields of the IPFIX final template, or the ones used to dynamic construct
the final template, such as daddr or saddr.

See <template>.debug() for more information on either IPFIX IE names to provide
or their aliases (or run this file/module à-la
`python -m flowcorder.daemons.transition`
"""
import datetime
import ipaddress
import time
import logging
from enum import IntEnum

from ..ipfix import Template
from ..routing import RouteResolver, NoRoute, InternalFlow

LOG = logging.getLogger(__name__)

RRESOLVER = RouteResolver()

CLK_REZ = time.clock_getres(time.CLOCK_MONOTONIC)


class FLOW_STATES(IntEnum):
    """
    The lifecycle of an individual flow can have one of these state.

    :NEW: Connection initiation attempted
    :ESTABLISHED: The connection is established and exchanging data
    :FINISHED: The connection is over
    :BROKEN: The connection failed (e.g., protocol error)
    :UNREACHABLE: The connection end point can no longer be reached
                  (e.g., network error, time out)
    :DESYNC: The instrumetation stack lost track of this flow.
    """

    NEW = 1
    ESTABLISHED = 2
    UPDATE = 3
    FINISHED = 4
    BROKEN = 5
    UNREACHABLE = 6
    DESYNC = 7

    @staticmethod
    def is_terminal(state):
        """Return whether a state is terminal or not."""
        return state not in STATES_TRANSITIONS


"""This enumerates the possible state transitions for the flow lifecycle"""
STATES_TRANSITIONS = {  # [from] -> to_one_of[]
    FLOW_STATES.NEW: frozenset((FLOW_STATES.ESTABLISHED, FLOW_STATES.FINISHED,
                                FLOW_STATES.BROKEN, FLOW_STATES.UNREACHABLE,
                                FLOW_STATES.DESYNC, FLOW_STATES.UPDATE)),
    FLOW_STATES.ESTABLISHED: frozenset((
        FLOW_STATES.FINISHED, FLOW_STATES.BROKEN, FLOW_STATES.UNREACHABLE,
        FLOW_STATES.DESYNC, FLOW_STATES.ESTABLISHED, FLOW_STATES.UPDATE)),
    FLOW_STATES.UPDATE: frozenset((
        FLOW_STATES.FINISHED, FLOW_STATES.BROKEN, FLOW_STATES.UNREACHABLE,
        FLOW_STATES.DESYNC, FLOW_STATES.ESTABLISHED, FLOW_STATES.UPDATE)),
}


class BaseTemplate(Template):
    BASE_FIELDS = {
        'flowStartReason': 'FLOW_STATE value',
        'flowEndReason': 'FLOW_STATE value',
        'flowStartMicroseconds': 'MONOTONIC CLOCK value in us',
        'flowEndMicroseconds': 'MONOTONIC CLOCK value in us',
    }

    def __init__(self, tid, *fields, **kw):
        self.timebase = (0, 0)
        self.refresh_timebase()
        super(BaseTemplate, self).__init__(
            tid, self.BASE_FIELDS.keys(), *fields, **kw)

    def export(self, transition):
        self.scale_timestamp(transition, 'flowStartMicroseconds')
        self.scale_timestamp(transition, 'flowEndMicroseconds')
        return super(BaseTemplate, self).export(transition)

    def scale_timestamp(self, d, f):
        val = d[f]
        if isinstance(val, datetime.datetime):
            return val
        realtime, monotonic = self.timebase
        d[f] = datetime.datetime.fromtimestamp(
            (realtime + val - monotonic) / 1e6)

    def refresh_timebase(self):
        self.timebase = (
            time.time() * 1e6,
            time.clock_gettime(time.CLOCK_MONOTONIC) * CLK_REZ * 1e6)

    def need_export(self):
        need = super(BaseTemplate, self).need_export()
        if need:
            self.refresh_timebase()
        return need

    def debug(self):
        return self.BASE_FIELDS


class IPv4Template(BaseTemplate):

    IPVX_FIELDS = (
        'sourceIPv4Address',
        'destinationIPv4Address',
        'ipNextHopIPv4Address',
    )
    IPvX_MASK = ~((1 << 8) - 1)
    IPvX_CTOR = ipaddress.IPv4Address

    def __init__(self, tid, *fields, **kw):
        return super(IPv4Template, self).__init__(
            tid, self.IPVX_FIELDS, *fields, **kw)

    def export(self, transition):
        transition.update({
            self.IPVX_FIELDS[0]: self.anonymize_address(transition['saddr']),
            self.IPVX_FIELDS[1]: self.anonymize_address(transition['daddr']),
            self.IPVX_FIELDS[2]: transition['nh'],
        })
        return super(IPv4Template, self).export(transition)

    @classmethod
    def anonymize_address(cls, addr):
        """Override to mask address to its BGP min prefix length."""
        return cls.IPvX_CTOR(int(cls.IPvX_CTOR(addr)) & cls.IPvX_MASK)

    def debug(self):
        dbg = super(IPv4Template, self).debug()
        dbg.update({'saddr': 'Source IP address',
                    'daddr': 'Destination IP address'})
        return dbg


class IPv6Template(IPv4Template):

    IPVX_FIELDS = (
        'sourceIPv6Address',
        'destinationIPv6Address',
        'ipNextHopIPv6Address',
    )
    IPvX_MASK = ~((1 << 64) - 1)
    IPvX_CTOR = ipaddress.IPv6Address


class CancelMessage(ValueError):
    pass


class FlowTemplate(object):
    """Describe an IPv4 or IPv6 flow."""

    COMMON_FIELDS = (
        'selectorId',
        'interfaceName',
        'applicationName',
    )

    def __init__(self, tid, *fields, name_suffix='Flow'):
        """Will allocate both tid and tid+1 for IPv4/IPv6."""
        self._templ = self.make_template(name_suffix, tid, *fields)
        self.name = '%sTemplate' % name_suffix

    def encode(self, transition):
        try:
            provider = RRESOLVER.get_nh(transition['saddr'],
                                        transition['daddr'])
        except (NoRoute, InternalFlow) as e:
            raise CancelMessage('Cannot resolve the provider: %s' % e)
        transition['interfaceName'] = provider.intf
        transition['nh'] = ipaddress.ip_address(provider.nh)
        return self._templ[transition['nh'].version].export(transition)

    @classmethod
    def make_template(cls, name_suffix, tid, *fields):
        return {4: IPv4Template(tid, cls.COMMON_FIELDS, *fields,
                                name='IPv4%sTemplate' % name_suffix),
                6: IPv6Template(tid+1, cls.COMMON_FIELDS, *fields,
                                name='IPv6%sTemplate' % name_suffix)}

    def debug(self):
        dbg = self.inner.debug()  # Same for IPv4 and IPv6
        dbg.update({'selectorId': 'Connection UUID',
                    'applicationName': 'Application that created the flow'})
        return dbg

    @property
    def inner(self):
        return self._templ[4]

    @property
    def templ(self):
        return self.inner.templ


def debug_template(t):
    templ = t(12345)
    eqs = '=' * 30
    banner = '%s %s records %s' % (eqs, templ.name, eqs)
    print('\n%s' % banner)
    for i in templ.debug().items():
        print('%35s => %s' % i)
    print('=' * len(banner))


if __name__ == '__main__':
    debug_template(FlowTemplate)
