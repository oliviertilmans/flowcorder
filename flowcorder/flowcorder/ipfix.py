"""
This modules defines the IPFIX templates and primitives.

These enable to export our flow transitions.
"""
import time
import itertools
import logging
from pkg_resources import resource_string

import ipfix.ie as ie
import ipfix.template as template
import ipfix.message as message


LOG = logging.getLogger(__name__)

MAX_MTU = 1280


class Template(object):
    """Manage an IPFIX template export status."""

    EXPORT_INTERVAL = 300

    def __init__(self, tid, *fields, name=None):
        """Register a new template and IP-version specific field names."""
        self.name = name if name is not None else self.__class__.__name__
        self.last_export = 0
        # Ensure var-length IE are at the end of the field list
        all_fields = ie.InformationElementList(
            sorted((ie.for_spec(field)
                   for field in itertools.chain.from_iterable(fields)),
                   key=lambda f: f.length))
        self.templ = template.from_ielist(tid, all_fields)
        LOG.debug('Initialized a new template requiring %d bytes',
                  self.templ.enclength)
        self.msg = Message()
        self.add_self_to_message()

    def export(self, transition):
        """Export the given transition for this template."""
        return self._do_export(transition, has_recursed=False)

    def _do_export(self, transition, has_recursed):
        b_array = None
        try:
            self.add_self_to_message()
            self.msg.encode(transition, self.tid)
        except message.EndOfMessage as e:
            if has_recursed:
                LOG.exception(e)
                LOG.error('Cannot export %s as the transition is bigger than '
                          'the max MTU: %s', transition, e)
            else:
                b_array, cnt = self.msg.serialize()
                LOG.debug('New %s message, for %d bytes and %d records',
                          self.name, len(b_array), cnt)
                self._do_export(transition, has_recursed=True)
        return b_array

    def add_self_to_message(self):
        """Add a template to a message, optionally exporting it."""
        if self.need_export():
            LOG.debug('Exporting template %d', self.tid)
            self.msg.export_template(self.templ)
            self.last_export = time.time()

    def need_export(self):
        """Return whether the template should be exported or not."""
        return (time.time() - self.last_export > self.EXPORT_INTERVAL and
                self.msg.record_count == 0)  # otherwise race condition for MTU

    @property
    def tid(self):
        """Return the underlying template ID."""
        return self.templ.tid


class Message(object):
    """Manage the IPFIX MessageBuffer."""

    def __init__(self):
        """Initialize a MessageBuffer and set its MTU."""
        self.msg = message.MessageBuffer()
        self.msg.mtu = MAX_MTU
        self.record_count = 0
        self.begin_export()

    def encode(self, transition, tid):
        """Add the given transition to the message using the given template."""
        self.msg.export_ensure_set(tid)
        self.msg.export_namedict(transition)
        self.record_count += 1

    def serialize(self):
        """Serialize this message and reset the buffer."""
        b_array = self.msg.to_bytes()
        cnt = self.record_count
        self.begin_export()
        return b_array, cnt

    def begin_export(self):
        """Start a new message export process."""
        LOG.debug('Creating a new message buffer '
                  '(previous one contained %d records)' % self.record_count)
        self.msg.begin_export(56423)
        self.record_count = 0

    def export_template(self, templ):
        self.msg.add_template(templ, export=True)

    def __len__(self):
        """Return the record count for this message."""
        return self.record_count

    @classmethod
    def decode(cls, data):
        """Decode an IPFIX message."""
        msg = cls._INSTANCE
        msg.begin_export()
        msg.from_bytes(data)
        return msg.msg


def _load_res(name):
    return resource_string(__name__, 'iespec/%s' % name).decode('utf8')


def _init_ipfix():
    LOG.debug('Initializing IPFIX IEs')
    # Defaults
    ie.use_iana_default()
    ie.use_5103_default()
    # Load custom elems
    for line in _load_res('elements.iespec').split('\n'):
        if not line or "#" in line:
            continue
        nie = ie.for_spec(line)
        LOG.debug('Loaded IE: %s', nie)


_init_ipfix()
