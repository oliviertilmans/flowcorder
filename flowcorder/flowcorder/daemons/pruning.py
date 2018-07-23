"""
This module contains the pruning algorithms.

These enable to reduce the total number of generaed IPFIX messages.
"""
import logging
from ipaddress import ip_network

import radix

from .transition import FLOW_STATES


LOG = logging.getLogger(__name__)


# Terms in transition that should be exported as deltas
DELTA_TERMS = frozenset([
    'transferredOctetTotalCount',
    'receivedOctetTotalCount',
    'retransmittedPacketTotalCount',
    'droppedOctetTotalCount',
    'duplicateOctetTotalCount',
    'duplicatePacketTotalCount',
    'stallCount',
    'reorderingOctetCount',
    'reorderingPacketCount'
])


def _compute_transition_delta(transition, old):
    try:
        return {
            k: v if k not in DELTA_TERMS else v - old[k]
            for k, v in transition.items()
        }
    except TypeError:  # No previous transition for that flow
        return transition
    except KeyError as e:
        LOG.warning('Could not compute the transition delta for key %s, when '
                    'moving from %s -> %s', e, old, transition)
        return transition


def _transition_id(t):
    return (t['selectorId'], t.get('pathIndex', 0))


class BasicPruner(object):

    def __init__(self, *a, **kw):
        self.previous_transitions = {}

    def keep_transition(self, transition):
        new_t = _compute_transition_delta(
            transition, self.previous_transition(transition))
        if self.must_remove_transition(new_t):
            return None
        # Remember the last export point
        if not FLOW_STATES.is_terminal(transition['flowEndReason']):
            self.register_previous_transition(transition)
        else:
            self.forget_previous_transition(transition)
        return new_t

    def must_remove_transition(self, transition):
        raise NotImplementedError

    def previous_transition(self, t):
        return self.previous_transitions.get(_transition_id(t), None)

    def register_previous_transition(self, t):
        self.previous_transitions[_transition_id(t)] = t

    def forget_previous_transition(self, t):
        try:
            del self.previous_transitions[_transition_id(t)]
        except KeyError:
            pass


class NoPruning(BasicPruner):
    """This helper does not do any pruning of messages."""

    def must_remove_transition(self, transition):
        return False


class PruningHelper(BasicPruner):
    """Prune transitions towards a blacklist."""

    def __init__(self, *a, ignore_prefixes=[], **kw):
        super(PruningHelper, self).__init__(*a, **kw)
        self.ignore_list = radix.Radix()
        _fill_radix_tree(self.ignore_list, ignore_prefixes)

    def must_remove_transition(self, transition):
        if self.ignore_list.search_worst(
                transition['daddr'].compressed) is not None:
            return True
        # filter_looping transition
        endReason = transition['flowEndReason']
        if (endReason != FLOW_STATES.UPDATE and
                endReason == self.previous_transition['flowEndReason']):
            return True
        return False


def _fill_radix_tree(tree, plist):
    if not plist:
        plist = []
    elif isinstance(plist, str):
        plist = plist.split(' ')
    for prefix in plist:
        try:
            ip_network(prefix)
            tree.add(prefix)
            LOG.debug('Ignoring destination prefix: %s', prefix)
        except ValueError as e:
            LOG.warning('Cannot ignore destination prefix %s: %s', prefix, e)
