"""Naive IPFIX collector to perform local tests."""
import argparse
import socket
import atexit
from ipaddress import ip_address

import flowcorder as lib
from .ipfix import Message

import logging
log = logging.getLogger(__name__)


def args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser('Naive IPFIX collector')
    parser.add_argument('--port', help="UDP port to bind on.",
                        type=int, default=2055)
    parser.add_argument('--address', help="IP address to bind on.",
                        type=ip_address, default=None)
    parser.add_argument('--rbuf', help="Receive buffer size.",
                        type=int, default=1500)
    return parser.parse_args()


def process_data(buf, peer):
    """Process received data."""
    msg = Message.decode(buf)
    log.info('Received %sb from %s\n%s\n', len(buf), peer,
             '\n'.join("\tRecord #%d:\n%s" % (cnt, '\n'.join(
                 '\t\t%s: %s' % (k, v) for k, v in rec.items()))
                 for cnt, rec in enumerate(msg.namedict_iterator())))


def main():
    """Entry point for the collector."""
    arguments = args()
    addr = arguments.address
    if addr is None:
        addr = ip_address(0)
    sfd = socket.socket(socket.AF_INET if addr.version == 4 else
                        socket.AF_INET6, socket.SOCK_DGRAM)
    sfd.bind((addr.compressed, arguments.port))
    atexit.register(sfd.close)
    buf_size = arguments.rbuf
    log.info('Waiting for records...')
    while lib.IS_RUNNING:
        try:
            buf, peer = sfd.recvfrom(buf_size)
            process_data(buf, peer)
        except (socket.error, IOError, KeyboardInterrupt):
            lib.IS_RUNNING = False
            log.warning('Exiting')


if __name__ == '__main__':
    main()
