"""Start the DNS instrumentation daemon."""

from ..utils import main, Daemon, DaemonComponent, CLIParam
from ..exporter import EXPORTER
from ..ebpf import BPF_RESET, BPF_MANAGER

from .instrumentation import DNSInstrumentation


DAEMON = Daemon(
    "Daemon that instruments the DNS stack to export statistics",
    BPF_RESET,
    DaemonComponent(DNSInstrumentation,
                    components_deps=[EXPORTER, BPF_MANAGER],
                    cli_params=[
                        CLIParam('--ipv6-depth', type=int,
                                 help="Maximal IPv6 header chain depth"),
                        CLIParam('--dns-port', type=int,
                                 help="The UDP destination port to identify "
                                 "requests to DNS servers."),
                        CLIParam('--support-dot1q', action='store_true',
                                 help="Support encapsulated VLAN packets")]))


if __name__ == '__main__':
    main(DAEMON)
