import logging

from .import HAS_MPTCP
from ..transition import FlowTemplate, debug_template, BaseTemplate

LOG = logging.getLogger(__name__)


class TemplatePicker(object):
    def __init__(self):
        self.templ = {'tcp': TCPTemplate()}
        if HAS_MPTCP:
            self.templ.update({
                'mptcp': MPTCPTemplate(),
                'mptcp-meta': MPTCPMetaTemplate()
            })

    def encode(self, transition):
        try:
            cncttype = transition.pop('connection_type')
        except KeyError as e:
            LOG.exception(e)
            LOG.error('No connection_type present in the TCP transition'
                      ', defaulting to TCP')
            cncttype = 'tcp'
        try:
            templ = self.templ[cncttype]
        except KeyError as e:
            LOG.warning('Unkown TCP template for connection_type: %s,'
                        'defaulting to TCP', e)
            templ = self.templ['tcp']
        return templ.encode(transition)


class TCPTemplate(FlowTemplate):

    TID = 47561
    SUFFIX = 'TCP'
    IESPECS = {
        'sourceTransportPort': 'TCP source port',
        'destinationTransportPort': 'TCP destination port',
        'transferredOctetTotalCount': 'Bytes known as succesfully transferred',
        'receivedOctetTotalCount': 'Received bytes count',
        'retransmittedPacketTotalCount': 'Number of retransmitted segments',
        'droppedOctetTotalCount': 'Bytes sent inferred as lost',
        'meanLatencyMilliseconds': 'Smoothed TCP sender RTT',
        'rfc3550JitterMilliseconds': 'Jitter of the RTT',
        'duplicateOctetTotalCount': 'Received bytes that were already acked',
        'duplicatePacketTotalCount': 'Received segments already acked',
        'maximumIpTotalLength': 'Max MSS',
        'stallCount': 'Number of connection stalls (RTOs, ...)',
        'reorderingPacketCount': 'Number of out-of-order segments',
        'reorderingOctetCount': 'Number of out-of-order octets',
        'meanReorderingDistance': 'Mean out-of-order distance',
        'varReorderingDistance': 'Variance of out-of-order distance'
    }

    def __init__(self, tid=None, *extra_fields):
        if tid is None:
            tid = self.TID
        super(TCPTemplate, self).__init__(
            tid, self.IESPECS.keys(), *extra_fields, name_suffix=self.SUFFIX)

    def debug(self):
        dbg = super(TCPTemplate, self).debug()
        dbg.update(self.IESPECS)
        return dbg


if HAS_MPTCP:
    class MPTCPTemplate(TCPTemplate):
        IESPECS = TCPTemplate.IESPECS.copy()
        IESPECS.update({
                # 'reinjectionPacketIn': 'Segments reinjected in this flow',
                'reinjectionPacketOut': 'Segments reinjected in another flow',
                # 'reinjectionOctetIn': 'Octets reinjected in this flow',
                'reinjectionOctetOut': 'Octets reinjected in another flow',
                'pathIndex': 'The path id (subflow number)',
            })
        TID = 47564
        SUFFIX = 'MPTCP'

    class MPTCPMetaTemplate(BaseTemplate):
        IESPECS = {
            'stallCount': 'Head of line blocking occurence',
            'subflowCount': 'Number of subflows',
            'rcvBufOctetCount': 'Size of the receive buffer',
            'selectorId': 'UUID of the connection',
            'reinjectionOctetOut': 'Octets reinjected in another flow',
            'reinjectionPacketOut': 'Segments reinjected in another flow',
            'transferredOctetTotalCount':
            'Bytes known as succesfully transferred',
            'receivedOctetTotalCount': 'Received bytes count',
            'retransmittedPacketTotalCount':
            'Number of retransmitted segments',
            'droppedOctetTotalCount': 'Bytes sent inferred as lost',
            'reorderingPacketCount': 'Number of out-of-order segments',
            'reorderingOctetCount': 'Number of out-of-order octets',
            'meanReorderingDistance': 'Mean out-of-order distance',
            'varReorderingDistance': 'Variance of out-of-order distance'
        }

        def __init__(self, tid=47563, *extra_fields):
            self.name = 'MPTCPMetaTemplate'
            super(MPTCPMetaTemplate, self).__init__(
                tid, self.IESPECS.keys(), *extra_fields)

        def debug(self):
            dbg = super(MPTCPMetaTemplate, self).debug()
            dbg.update(self.IESPECS)
            return dbg

        def encode(self, t):
            return self.export(t)


if __name__ == '__main__':
    debug_template(TCPTemplate)
    if HAS_MPTCP:
        debug_template(MPTCPTemplate)
        debug_template(MPTCPMetaTemplate)
