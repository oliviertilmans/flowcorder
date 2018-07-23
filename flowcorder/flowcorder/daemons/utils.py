"""
Classes to create and start a daemon process.

This module defines the following classes and compositions:
* Daemon: the base class to create a daemon.
  |
  | is made of
  v
* DaemonComponent: factories that will create the components of the daemon,
  see the Component class for an (empty) squeleton of a component class.
  |
  | is configured by
  v
* CLIParam: CLI parameter definitions.

Dependencies between DaemonComponent MUST BE LOOP FREE (this won't be checked)!

Creating and starting a daemon implies to:
- define the Component classes, and create the DaemonComponent instances that
  will manage them and their CLI parameter
- Create a Daemon instance
- call main() on the Daemon instance to start the daemon (possibly forking
  it in the background).
"""
import argparse
import atexit
import os
import itertools
import multiprocessing as mp
import time
from configparser import ConfigParser, Error as CFGError, NoSectionError
from pkg_resources import resource_string

from daemons.prefab import run as _daemons
import flowcorder as lib
from ..utils import DaemonThread

import logging
LOG = logging.getLogger(__name__)


def main(daemon):
    """Start a daemon."""
    parser = daemon.create_parser()
    args = parser.parse_args()
    cfg = _build_config_dict(args.cfg, args.name)
    # Daemonize or stay in foreground then start the actual daemon
    if args.daemonize:
        _daemonize(daemon.start_with_args, args, cfg)
    else:
        daemon.start_with_args(args, cfg)


def _build_config_dict(filename, names):
    cfg = _MConfigParser(allow_no_value=True)
    out = {}
    try:
        cfg.read_string(resource_string('flowcorder',
                                        'base_config.cfg').decode('utf8'),
                        'defaults')
        if filename is not None:
            LOG.debug('Using configuration file: %s', filename)
            cfg.read(filename, encoding='utf8')
        for k, v in cfg.items(section=cfg.default_section):
            out[k] = v
            LOG.debug('Registering default: %s -> %s', k, v)
        for section in itertools.chain(names):
            try:
                for key in cfg.options(section=section, exclude_default=True):
                    value = cfg.get(section, key)
                    out[key] = value
                    LOG.debug('[%s] Updated property %s -> %s', section,
                              key, value)
            except CFGError as e:
                LOG.warning('Cannot use section %s in the config file: %s',
                            section, e)
    except (CFGError, FileNotFoundError, IOError) as e:
        LOG.warning('Cannot read configuration file: %s', e)
    return out


class Daemon(object):
    """A Daemon that will run in the background."""

    def __init__(self, description, *components):
        """Instantiate this Daemon from the components list."""
        self.description = description
        self.components = _components_by_deps(components)
        LOG.debug('Components order by dependencies: %s',
                  '<-'.join(str(c) for c in self.components))
        self.instances = {}

    def start_with_args(self, args, cfg):
        """Start the daemon."""
        # Handle general arguments
        if args.debug:
            lib.DEBUG = set(args.debug)
        if args.log_config is not None:
            if os.path.isfile(args.log_config):
                logging.config.fileConfig(args.log_config)
            else:
                LOG.warning('Cannot load the logging configuration file at %s',
                            args.log_config)
        self._create_components(args, cfg)
        try:
            try:
                self._start_components()
                self._join_components()
            except KeyboardInterrupt:
                self._stop()
                self._join_components
        except Exception as e:
            LOG.exception(e)
            time.sleep(args.crash_hold_off)

    def create_parser(self):
        """Create and return a new CLI argument parser for this daemon."""
        # Create the parser and its global arguments
        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument('--log-config', type=str,
                            help='The logging configuration file to use')
        parser.add_argument('--debug', help='Turn debugging on, for '
                            'various components',
                            choices=list(lib.DEBUG_OPTIONS), nargs='*')
        # Daemon-specific arg group
        cfgparser = parser.add_argument_group('Config file properties')
        cfgparser.add_argument('--cfg', help='Configuration file path')
        cfgparser.add_argument('--name', help='Configuration file section '
                               'names to use other than the DEFAULT one '
                               'read in order (i.e., latest conflicting value '
                               'is the one used)', nargs='*', default=[])
        dparser = parser.add_argument_group('Daemon properties')
        dparser.add_argument('--daemonize', action='store_true',
                             help='Fork and detach this process to run in the '
                             'background')
        dparser.add_argument('--pid-file', help='The file in which this '
                             'process\' PID should be saved',
                             default='/var/run/flowcorder_daemon.pid')
        dparser.add_argument('--action', help='The action to perform when '
                             'daemonizing this process', default='start',
                             # Reload there to please systemd terminology
                             choices=['start', 'stop', 'restart', 'reload'])
        dparser.add_argument('--crash-hold-off', help='Wait X sec before '
                             'exiting when crashing', type=float, default=0.1)
        # Register all components arguments
        for c in self.components:
            c.complete_parser(parser)
        return parser

    def _create_components(self, args, cfg):
        for c in self.components:
            self.instances[c.name] = c.instantiate(args, cfg, self.instances)

    def _start_components(self):
        atexit.register(self._stop)
        for c in self.components:
            self.instances[c.name].start()

    def _join_components(self):
        for c in self.components:
            self.instances[c.name].join()

    def _stop(self):
        """Stop the daemon."""
        if lib.IS_RUNNING:
            atexit.unregister(self._stop)
        lib.IS_RUNNING = False
        for c in reversed(self.components):
            self.instances[c.name].stop()


class DaemonComponent(object):
    """Top-level object that needs to be instantiated to create the daemon."""

    def __init__(self, cls, cli_params=[], components_deps=[], debug_keys=[]):
        """
        Specify a new daemon component.

        :cls: The component class
        :cli_params: The list of parameter to parse from the CLI in order to
                     create this component. See CLIParam.
        :components_deps: Other needed component class that must be
                          instantiated prior to this one, and given as argument
                          when instantiating.
        :debug_keys: Keys that can be used as --debug flag
        """
        self.cls = cls
        self.cli_params = cli_params
        self.components_deps = components_deps
        lib.DEBUG_OPTIONS.update(debug_keys)

    def complete_parser(self, parser):
        """Complete a parser to add this component's arguments."""
        # Do not create a new group if the component has no CLI parameters
        if not self.cli_params:
            return
        grp = parser.add_argument_group(self.name, self.cls.__doc__)
        for param in self.cli_params:
            param.register(grp)

    def instantiate(self, args, cfg, components):
        """
        Instatiate this component.

        :args: The parsed CLI params.
        :cfg: The configuration dict.
        :components: A dict of already instantiated component instances,
                     keyed by their component name.
        """
        kwargs = {}
        for dep in self.components_deps:
            try:
                if isinstance(dep, DaemonComponent):
                    dep = dep.name
                kwargs[dep] = components[dep]
            except KeyError:
                raise RuntimeError('Could not create the component %s as it '
                                   'is missing its dependency %s' %
                                   (self.name, dep))
        try:
            kwargs.update({p.name: p.value(args, cfg)
                           for p in self.cli_params})
            LOG.debug('Arguments for %s: %s', self.name, kwargs)
        except (AttributeError, KeyError) as e:
            raise RuntimeError('Could not create the component %s as it as '
                               'an unspecified CLI param %s' % (self.name, e))
        return self.cls(**kwargs)

    @property
    def name(self):
        """Return the component name."""
        return self.cls.__name__

    def __str__(self):
        """Identify by component name."""
        return self.name
    __repr__ = __str__

    def __hash__(self):
        """Components are unique by name."""
        return hash(self.name)


class CLIParam(object):
    """A CLI parameter for a DaemonComponent."""

    def __init__(self, name, *args, **kwargs):
        """
        Register a new CLI parameter.

        See ArgumentParser.add_argument
        :name: paramter option string.
        """
        self.full_name = name
        self.name = name.replace('--', '').replace('-', '_')
        self.args = args
        self.kwargs = kwargs
        # We don't care if the default is None
        if kwargs.get('default', None) is not None:
            raise RuntimeError('default CLIParam values should only appear '
                               'in the base configuration file!\nkey:%s' %
                               self.full_name)

    def register(self, parser):
        """Register the parameter to an argument parser."""
        return parser.add_argument(self.full_name, *self.args, **self.kwargs)

    def value(self, args, cfg):
        """Extract this parameter value."""
        cli = getattr(args, self.name)
        if cli is not None:
            return cli
        # First try the in-code name
        arg = cfg.get(self.name, None)
        # Fallback on CLI name
        if args is None:
            arg = cfg.get(self.full_name, None)
        # Attempt CLI name without the leading --
        if args is None:
            arg = cfg.get(self.full_name[2:], None)
        # Convert to expected type, string by default
        cast_func = self.kwargs.get('type', str)
        LOG.debug('%s: Attempting to convert %s to %s', self.name,
                  arg, cast_func.__name__)
        # nargs indicates a list type
        if 'nargs' in self.kwargs:
            return list(map(cast_func, arg.split(' ')))
        return cast_func(arg)


DEFAULT_UNIX_SOCK_PARAM = CLIParam(
    '--ctrl-socket', help='The unix socket on which the daemon should listen'
    ' for the transport stacks flow exports')


class Component(object):
    """A Component that does nothing."""

    def start(self):
        """Start the component."""
        pass

    def stop(self):
        """Stop the component."""
        pass

    def join(self):
        """Return when this component halts."""


class ThreadedComponent(Component):
    """A Component that do its work in a separate thread."""

    def __init__(self):
        """Register the component thread variable."""
        self.evt_thread = None

    def start(self, *args, **kwargs):
        """
        Build and start the event thread.

        :args: The args array that will be passed to the step function initial
               call.
        :kwargs: The kwargs that will be passed to the step function.
        """
        self.evt_thread = DaemonThread(target=self.do_work,
                                       args=args, kwargs=kwargs)
        self.evt_thread.start()

    def join(self):
        """Wait for the event thread completion."""
        if self.evt_thread:
            self.evt_thread.join()

    def do_work(self):
        """Execute the work at each tick. See DaemonThread doc for args."""
        raise NotImplemented


class ConsumerComponent(Component):
    """
    A component that will spawn a new process to consume data.

    The configure function registers an initiamization function for the
    consumer, which should return a function that will be called for each
    newly received data.
    """

    def __init__(self):
        """Register the communication infrastructure for the component."""
        self.init_func = self.child = self.wq = self.halt_evt = None

    def configure(self, init_func=None):
        """Register the initialization function for the consumer."""
        self.init_func = init_func

    def start(self, **kw):
        """Start the consumer process."""
        rq, self.wq = mp.Pipe(False)
        self.halt_evt = mp.Event()
        self.child = mp.Process(target=_spawn_target,
                                args=(self.init_func, rq, self.halt_evt),
                                kwargs=kw,
                                daemon=True)
        self.child.start()

    def stop(self):
        if self.halt_evt:
            self.halt_evt.set()
        self.wq.close()

    def join(self):
        self.child.join()

    def export(self, data):
        self.wq.send(data)


def _spawn_target(init_func, rq, halt, **kw):
    consumer = init_func(**kw)
    while not halt.is_set():
        try:
            if rq.poll(1):
                d = rq.recv()
                consumer(d)
        except EOFError:
            break  # process needs to stop
    rq.close()
    LOG.debug('Stopping consumer subprocess')


def _daemonize(func, args, cfg):
    """Daemonize and call func with args."""
    class _Daemonizer(_daemons.RunDaemon):
        def run(self):
            func(args, cfg)
    daemon = _Daemonizer(pidfile=args.pid_file)
    action = args.action
    if action == 'start':
        daemon.start()
    elif action == 'stop':
        daemon.stop()
    elif action == 'restart' or action == 'reload':
        daemon.restart()
    else:
        LOG.error('Unsupported daemon action %s, aborting!', action)


def _components_by_deps(components):
    """
    Return a list of component names ordered by their dependencies.

    For two items at indexes i and j, such that i > j, all depencies of item
    at index i must be at indexes <= j.
    """
    class _Node(object):
        """A node in the dependcy tree."""

        def __init__(self, name):
            self.name = name
            self.parent = set()
            self.children = set()
            self.depth = 0

        def __lt__(self, other):
            """Order nodes based on their relative depth."""
            return self.depth < other.depth

        def __hash__(self):
            """Hash based on the node name."""
            return hash(self.name)

        def __repr__(self):
            """Represent by name and depth."""
            return '<%s: %d>' % (self.name, self.depth)

    dep_tree = {}

    def _lookup(name):
        """Find a node in the tree or insert a new one."""
        try:
            return dep_tree[name]
        except KeyError:
            n = _Node(name)
            dep_tree[name] = n
            return n

    c_dict = {c.name: c for c in components}
    # Create the dep. tree and link children/parents
    for c in components:
        node = _lookup(c.name)
        for child in c.components_deps:
            if isinstance(child, DaemonComponent):
                c_name = child.name
                c_dict[c_name] = child
                child = c_name
            n = _lookup(child)
            n.parent.add(c.name)
            node.children.add(child)
    # Perform a topological traversal, starting from the roots, such that
    # a node's depth is always smaller than any parent depth.
    # Tree roots have node parents, i.e. depends on everyone else
    stack = []
    for r in set(dep_tree.keys()).difference(
            name for name, node in dep_tree.items() if node.parent):
        stack.extend(dep_tree[r].children)
    while stack:
        elem = dep_tree[stack.pop(0)]
        stack.extend(elem.children)
        elem.depth = min(dep_tree[p].depth for p in elem.parent) - 1
    # Lowest depth is made of components that have no dependencies
    return [c_dict[n.name] for n in sorted(dep_tree.values())]


class _MConfigParser(ConfigParser):
    def options(self, section, exclude_default=True, **kwargs):
        if exclude_default:
            try:
                return list(self._sections[section].keys())
            except KeyError:
                raise NoSectionError(section)
        else:
            return super().options(section, **kwargs)
