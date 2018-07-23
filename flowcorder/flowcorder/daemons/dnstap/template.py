
from ..transition import FlowTemplate, debug_template


class DNSTemplate(FlowTemplate):

    IESPECS = {
        'sourceTransportPort': 'Source port',
        'destinationTransportPort': 'Destination port',
        'transferredOctetTotalCount': 'Size of the DNS request',
        'receivedOctetTotalCount': 'Received bytes count',
        'retransmittedPacketTotalCount': 'Number of retries',
        'meanLatencyMilliseconds': 'Measured RTT',
    }

    def __init__(self, tid=47566, *extra_fields):
        super(DNSTemplate, self).__init__(
            tid, self.IESPECS.keys(), *extra_fields, name_suffix='DNS')

    def debug(self):
        dbg = super(DNSTemplate, self).debug()
        dbg.update(self.IESPECS)
        return dbg


if __name__ == '__main__':
    debug_template(DNSTemplate)
