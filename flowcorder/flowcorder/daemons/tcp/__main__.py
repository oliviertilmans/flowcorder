"""Start the TCP instrumentation daemon."""

from ..utils import main, Daemon, DaemonComponent, CLIParam
from ..exporter import EXPORTER
from ..ebpf import BPF_RESET, BPF_MANAGER

from .instrumentation import TCPInstrumentation


DAEMON = Daemon(
    "Daemon that instruments the TCP stack to export statistics",
    BPF_RESET, DaemonComponent(
        TCPInstrumentation, components_deps=[EXPORTER, BPF_MANAGER],
        cli_params=[
            CLIParam('--enable-mptcp', type=bool,
                     help='Enable MPTCP support if available on the host '
                     'machine'),
            CLIParam('--naive', action='store_true',
                     help='Use a non-optimized, naive eBPF implementation')]))


if __name__ == '__main__':
    main(DAEMON)
