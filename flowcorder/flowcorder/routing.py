"""
This modules abstract lookups to figure out which provider/gateway is used.

It directly hooks into the kernel routing table, feeding it the IP source and
destination addresses.
"""
import pyroute2
import functools
import logging
from ipaddress import ip_address

log = logging.getLogger(__name__)


class NoRoute(ValueError):
    """No route has been found that can be used to reach a flow destination."""

    def __repr__(self):
        """Constant meaning regardless of the exception."""
        return 'No route to destination'
    __str__ = __repr__


class InternalFlow(ValueError):
    """The flow is destined to an internal host (loopback or LAN)."""

    def __init__(self, provider):
        """:provider: The provider denoting the target LAN."""
        self.oif = provider.intf
        self.saddr = provider.saddr

    def __repr__(self):
        """Log the output interface and source address used."""
        return 'Internal flow %s/%s' % (self.oif, self.saddr)
    __str__ = __repr__


@functools.total_ordering
class ProviderIdentifier(object):
    """
    Represent a given provider.

    A provider can be uniquely identified by the following 3-tuple:
    (output interface, source address, gateway).
    """

    LAN = {}

    @classmethod
    def get(cls, oif, gw, saddr):
        """
        Return a provider identifier for the given 3-tuple.

        :oif: The output interface name
        :gw: The gateway (nexthop) IP(v6) address
        :saddr: The used source address for the interface.
        :return: The associated provider instance.
        """
        try:
            provider = cls.LAN[(oif, gw, saddr)]
        except KeyError:
            provider = cls.LAN[(oif, gw, saddr)] = (
                ProviderIdentifier(oif, gw, saddr))
        return provider

    def __init__(self, interface, gw, saddr):
        """
        Provision a new Provider identifier.

        :interface: The output interface name,
        :gw: The gateway (nexthop) address
        :saddr: The source address used.
        """
        self.intf = interface
        self.saddr = saddr
        self.nh = gw if gw else ('::' if ip_address(saddr).version == 6 else 0)

    def __str__(self):
        """Log the provider 3-tuple."""
        return '<saddr:%s, oif: %s, nh: %s>' % self._tuple
    __repr__ = __str__

    def __eq__(self, other):
        """Two equal provider have equal 3-tuples."""
        try:
            return self is other or self._tuple == other._tuple
        except AttributeError:
            raise NotImplemented

    def __lt__(self, other):
        """Compare tuples as tie-breaker; needed to support total_ordering."""
        try:
            self._tuple < other._tuple
        except AttributeError:
            raise NotImplemented

    def __hash__(self):
        """Hash the provider based on its 3-tuple."""
        return hash(self._tuple)

    @property
    def _tuple(self):
        return (self.nh, self.intf, self.saddr)


class RouteResolver(object):
    """
    Wrapper around iproute to query the kernel routing table.

    This class is best used as a singleton.
    """

    def __init__(self):
        """Initialize the netlink channel to the kernel routing table."""
        self.ip = pyroute2.IPRoute()

    def get_nh(self, saddr, daddr):
        """
        Return the IP nexthop for the given flow.

        :flow: The flow entry to resolve
        :return: ProviderIdentifier
        :raise: NoRoute if there are no route for this flow
                InternalFlow if the flow does not exit the LAN
        """
        try:
            return self._ip_route_lookup(saddr=saddr, daddr=daddr)
        except pyroute2.netlink.exceptions.NetlinkError as e:
            raise NoRoute('Cannot resolve route %s->%s; NL error: %s' % (
                saddr, daddr, e))

    def _ip_route_lookup(self, saddr, daddr):
        """Perform a lookup in the IP routing table for the address pair."""
        resp = self.ip.route('get', dst=daddr, src=saddr)
        if not resp:
            raise NoRoute('No route results for the flow')
        r = resp[0]
        intf = self.ip.link('get', index=r.get_attr('RTA_OIF'))
        if not intf:
            raise NoRoute('Cannot find out the interface for the route')
        oif = intf[0].get_attr('IFLA_IFNAME')
        gw = r.get_attr('RTA_GATEWAY')
        provider = ProviderIdentifier.get(oif, gw, saddr)
        if not gw:
            raise InternalFlow(provider)
        return provider
