"""This module attemps to infer the default DNS timeout values."""
import re
import logging


DEFAULT_TIMEOUT = 5
LOG = logging.getLogger(__name__)


def get_timeout():
    try:
        def_timeout = _parse_resolv_h(r'RES_TIMEOUT\s+(\d+)',
                                      DEFAULT_TIMEOUT)[0]
        timeout = int(_parse_resolv_conf(r'options\s+timeout:(\d+)',
                                         def_timeout)[0])
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    timeout *= 2
    LOG.debug('Using DNS request timeout: %s sec', timeout)
    return timeout * 2  # Twice the retry delay


def _parse_file(path, query, default):
    pattern = re.compile(query)
    try:
        with open(path, 'r') as f:
            match = re.search(pattern, f.read())
    except (FileNotFoundError, IOError):
        match = None
    return default if match is None else match.groups()


def _parse_resolv_h(q, d):
    return _parse_file('/usr/include/resolv.h', q, d)


def _parse_resolv_conf(q, d):
    return _parse_file('/etc/resolv.conf', q, d)


if __name__ == '__main__':
    print('Default libresolv timeout: %d sec' % get_timeout())
