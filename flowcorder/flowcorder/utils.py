"""Misc utils for daemons."""
import ctypes as ct
import threading
import math
import hashlib
import sys
from collections.abc import Sequence

import flowcorder as lib

import logging
LOG = logging.getLogger(__name__)


def embedded_ipv4(v):
    """
    Extract an IPv4 address at the start of a larger buffer.

    :return: 4-bytes long bytes()
    """
    return ct.cast(ct.byref(v), ct.POINTER(ct.c_uint32)).contents


class DaemonThread(threading.Thread):
    """
    A Thread that is always daemonized and will call target infinitly.

    The target function will be called with the provided args and kwargs,
    and then with the results of its previous call.
    """

    def __init__(self, **kw):
        """Forward all arguments to Thread."""
        self._loop_func = kw.pop('target')
        kw.update(daemon=True, target=self._loop_forever)
        super(DaemonThread, self).__init__(**kw)

    def _loop_forever(self, *args, **kw):
        func = self._loop_func
        while lib.IS_RUNNING:
            args = as_sequence(func(*args, **kw))


def is_sequence(x):
    """Return whether x is a 'true' sequence (iterable but not a string)."""
    return isinstance(x, Sequence) and not isinstance(x, str)


def as_sequence(x):
    """
    Return a sequence-compatible version of x.

    Either x itself if it is a 'real' sequence, except str (tuple, list, ...),
    or [x] if x is not None, or an empty tuple.
    """
    return (x if is_sequence(x) else ([x] if x is not None else []))


class IncrementalMeanVar(object):
    """
    Incrementally compute mean and variance.

    Implements the numerically stable method from B. P. Welford (1962).
    """

    def __init__(self):
        self._mean = 0
        self._var = 0
        self._count = 0
        self._mean_err = 0

    def update(self, v):
        """
        Update the statistics to take into account the new value.

        :v: the new value
        :return: (mean, variance)
        """
        # Calc new count
        old_count = self._count
        new_count = old_count + 1
        self._count = new_count
        # Update mean
        old_mean = self._mean
        delta = v - old_mean
        new_mean = old_mean + delta / new_count
        self._mean = new_mean
        # Update squared mean error
        new_delta = v - new_mean
        mean_err = self._mean_err + delta * new_delta
        self._mean_err = mean_err
        # Update variance
        try:
            new_var = mean_err / old_count
        except ZeroDivisionError:
            # We don't have enugh samples yet to get a variance
            new_var = 0
        self._var = new_var
        return new_mean, new_var

    @property
    def stats(self):
        return self._mean, self._var

    @property
    def mean(self):
        """Mean of all samples."""
        return self._mean

    @property
    def var(self):
        """Variance of all samples."""
        return self._var

    @property
    def stdev(self):
        """Standard deviation of all samples."""
        return math.sqrt(self._var)


# MAX_UINT64 = (2 ** 64) - 1
MAX_UINT64 = ((2 ** 63) - 1)  # bypass bug in logstash netflow codec


def hash_seq_to_u64(*seq):
    """Return a 64b UUID for a sequence."""
    h = hashlib.sha1()
    for s in seq:
        try:
            h.update(s)
        except TypeError as e:
            LOG.exception(e)
            LOG.error(s)
            sys.exit()
    return int.from_bytes(h.digest(), byteorder='big',
                          signed=False) % MAX_UINT64
