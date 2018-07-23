"""Provide utilities to handle eBPF codes."""
import os
import time
import select
import subprocess as sp
import pkg_resources as res
import sys

import bcc
import flowcorder as lib
from .utils import DaemonComponent, CLIParam, Component, ThreadedComponent

import logging
LOG = logging.getLogger(__name__)


DEBUG_BPF_CODE = 'bpf_code'
DEBUG_BPF_LOG = 'bpf_log'
DEBUG_BPF_JIT = 'bpf_jit'


class BPFReset(Component):
    """Component that will trigger a reset of the BPF subsystem."""

    def __init__(self, reset_bpf):
        """Reset the bcc/bpf state if reset_bpf is true."""
        if reset_bpf:
            LOG.info('Resetting eBPF kernel state')
            sp.check_call(['/usr/share/bcc/tools/reset-trace', '-F'])
            time.sleep(2)
            LOG.debug('Re-enabling eBPF JIT')
            enable_bpf_jit()
            sys.exit(0)


BPF_RESET = DaemonComponent(BPFReset, cli_params=[
    CLIParam('--reset-bpf', help='Reset eBPG/tracing subsystems/bcc and exit',
             action='store_true')])


class DebuggableBPF(bcc.BPF):

    def attach_kprobe(self, event=b"", fn_name=b"", event_re=b""):
        try:
            return super(DebuggableBPF, self).attach_kprobe(event=event,
                                                            fn_name=fn_name,
                                                            event_re=event_re)
        except Exception as e:
            LOG.error('Could not attach kprobe %s/%s/%s: %s',
                      event, fn_name, event_re, e)
            sys.exit()


class BPFManager(ThreadedComponent):
    """Component that manages a BPF code's lifetime."""

    def __init__(self):
        """Initialize the manager."""
        super(BPFManager, self).__init__()
        self.defines = {'_DEBUG': '' if DEBUG_BPF_LOG in lib.DEBUG else None}
        self.bpf = None
        self.prog_name = None

    def configure(self, *prog_name, **defines):
        """
        Configure the BPF manager parameters.

        :prog_name: The BPF program names to load. These will be appended in
                    sequence.
        :defines: key-values that will be inserted as #define key (val).
                  None values will be skipped.
        """
        self.prog_name = prog_name
        self.defines.update(defines)
        self.code = '\n'.join(_load_code(n) for n in prog_name)

    def start(self):
        """Start instrumenting."""
        enable_bpf_jit()
        self.install()
        # Only start the underlying thread in debug mode.
        if DEBUG_BPF_LOG in lib.DEBUG:
            fd = self.bpf.trace_open(nonblocking=True)
            poll = select.epoll()
            poll.register(fd.fileno(), select.POLLIN | select.POLLPRI)
            super(BPFManager, self).start(fd=fd, poll=poll)

    def install(self):
        """Install the eBPF code in the kernel."""
        code = self.patch(self.code)
        dbg_flags = ((bcc.DEBUG_BPF | bcc.DEBUG_PREPROCESSOR |
                      bcc.DEBUG_SOURCE)
                     if DEBUG_BPF_CODE in lib.DEBUG else 0)
        tstart = -time.clock()
        self.bpf = DebuggableBPF(text=code, debug=dbg_flags)
        LOG.debug('Compiled BPF codes in %ssec', tstart + time.clock())

    def stop(self):
        """Stop instrumenting."""
        if self.bpf:
            self.bpf.cleanup()
        super(BPFManager, self).stop()

    def patch(self, text):
        """Patch the given input text."""
        text = self.patch_net_ns(text)
        return '%s\n%s' % ('\n'.join('#define %s (%s)' % (key, val)
                                     for key, val in self.defines.items()
                                     if val is not None),
                           text)

    @staticmethod
    def patch_net_ns(text):
        """Define the NETNS variable on the code."""
        ns = get_net_ns()
        if ns > 0:
            return ('#ifdef CONFIG_NET_NS\n'
                    '#define CURRENT_NET_NS (%d)\n'
                    '#endif\n%s' % (ns, text))
        return text

    def do_work(self, fd=None, poll=None):
        """Fetch debug events from the BPF probe."""
        events = poll.poll(1000)  # ms
        if events:
            msg = fd.readline(1024).strip()
            if msg:
                LOG.debug('%s: %s', self.prog_name, msg)

    def __repr__(self):
        """Debug using the managed program name."""
        return '<%s: %s>' % (self.__class__.__name__, self.prog_name)
    __str__ = __repr__

    # Proxy bcc.BPF calls

    def kprobe_poll(self):
        """Poll krpobes for events."""
        self.bpf.kprobe_poll()

    def __getitem__(self, map_name):
        """Retrieve an eBPF shared map."""
        return self.bpf[map_name]

    def load_func(self, *a, **kw):
        """Load a BPF function and return its handle."""
        return self.bpf.load_func(*a, **kw)


BPF_MANAGER = DaemonComponent(BPFManager, debug_keys=[DEBUG_BPF_CODE,
                                                      DEBUG_BPF_LOG,
                                                      DEBUG_BPF_JIT])


def get_net_ns():
    """
    Return the current network namespace inode number.

    :return: -1 if the kernel does not support network namespace.
    """
    try:
        return os.stat('/proc/self/ns/net').st_ino
    except FileNotFoundError:
        return -1


def uname_release():
    """Return the name of the running kernel."""
    return sp.check_output(['uname', '-r']).decode('utf8')


def get_kernel_release():
    """Return the kernel release string."""
    return uname_release()


def get_patch_level(kernel_release):
    """Return the running kernel version string."""
    # 4.13.6-1-ARCH
    return kernel_release.split('-')[0]


# The directory containing all eBPF codes relative to the package root
_BPF_CODE_LOC = 'bpf_codes'
# The directory containing fallback BPF codes (for any kernel version)
_BPF_FALLBACK_LOC = 'default'


def _load_code(prog):
    """
    Return the bpf code of the given name for the current kernel.

    :prog: The BPF code file
    """
    version = get_patch_level(get_kernel_release())
    fname = _bpf_path(version, prog)
    if res.resource_exists('flowcorder', fname):
        LOG.debug('%s: Loading eBPF code for kernel version %s', prog, version)
        return _read_bpf(fname)
    LOG.debug('%s: Loading default eBPF code', prog)
    return _read_bpf(_bpf_path(_BPF_FALLBACK_LOC, prog))


def _read_bpf(prog):
    """Read and return the BPF code string with the given access path."""
    return res.resource_string(__name__, prog).decode()


def _bpf_path(*scheme):
    """Return the access path to load a BPF code."""
    return os.path.join(_BPF_CODE_LOC, *scheme)


def enable_bpf_jit():
    """Enable the BPF in-kernel JIT."""
    try:
        with open('/proc/sys/net/core/bpf_jit_enable', 'w') as f:
            f.write('1' if DEBUG_BPF_JIT not in lib.DEBUG else '2')
    except Exception as e:
        LOG.warning('Failed to set net.core.bpf_jit_enable,'
                    ' the instrumentation overhead will be higher')
        LOG.debug(e)
