#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Yanaunid - Yet ANother AUto NIce Daemon'''

import abc
import argparse
import dataclasses
import enum
import fnmatch
import logging
import numbers
import os
import os.path
import pathlib
import sys
import time
import unicodedata
from typing import Any, Dict, Generator, IO, Iterable, List, Mapping, \
    Optional, Sequence, Tuple, Union

import psutil
import yaml

__all__ = ('Settings', 'Rule', 'Yanaunid')

Rational = Union[int, float, numbers.Rational]
MYPY = False
if MYPY:
    # pylint: disable=unsubscriptable-object
    PathLike = Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]
else:
    PathLike = Union[str, bytes, os.PathLike]


def normalize(string: str) -> str:
    return unicodedata.normalize('NFKD', string)


class FormatError(Exception):
    pass


# pylint: disable=too-few-public-methods
@dataclasses.dataclass
class Settings():
    interval_ms: Rational = 60251
    slices: int = 293
    refresh_after: Rational = 25

    def load(self, stream: IO[str]) -> None:
        # TODO: implement
        pass


class IOClass(enum.IntEnum):
    NONE = 0
    REALTIME = 1
    BEST_EFFORT = 2
    IDLE = 3


class Scheduler(enum.IntEnum):
    NORMAL = 0
    OTHER = 0
    FIFO = 1
    RR = 2
    ROUND_ROBIN = 2
    BATCH = 3
    ISO = 4
    IDLE = 5
    DEADLINE = 6


# pylint: disable=too-many-instance-attributes
class Rule:
    class Matcher(abc.ABC):
        __slots__ = ()

        @abc.abstractmethod
        def matches(
                self,
                rule: 'Rule',
                process: psutil.Process
        ) -> bool:
            return False

    class NeverMatchingMatcher(Matcher):
        __slots__ = ()

        def matches(
                self,
                rule: 'Rule',
                process: psutil.Process
        ) -> bool:
            return False

    # pylint: disable=abstract-method
    class StringMatcher(Matcher):
        __slots__ = ('_normalize', '_case_insensitive')
        _normalize: bool
        _case_insensitive: bool

        @property
        def normalize(self) -> bool:
            return self._normalize

        @property
        def case_insensitive(self) -> bool:
            return self._case_insensitive

        def __init__(
                self,
                normalize: bool = True,  # pylint: disable=redefined-outer-name
                case_insensitive: bool = False
        ) -> None:
            self._normalize = normalize
            self._case_insensitive = case_insensitive

    class DefaultMatcher(StringMatcher):
        __slots__ = ('_name', '_name_norm')
        _name: str
        _name_norm: str

        def __init__(
                self,
                normalize: bool = True,  # pylint: disable=redefined-outer-name
                case_insensitive: bool = False
        ) -> None:
            super().__init__(normalize, case_insensitive)
            self._name = ''
            self._name_norm = ''

        def matches(
                self,
                rule: 'Rule',
                process: psutil.Process
        ) -> bool:
            if self._name != rule.name:
                self._name = rule.name
                self._name_norm = self._name
                if self.normalize:
                    self._name_norm = normalize(self._name_norm)
                if self.case_insensitive:
                    self._name_norm = self._name_norm.casefold()

            try:
                name: str = normalize(process.name())
                if self.case_insensitive:
                    name = name.casefold()
                if name == self._name_norm:
                    return True
            except psutil.AccessDenied:
                pass
            try:
                exe: str = normalize(process.exe())
                if self.case_insensitive:
                    exe = exe.casefold()
                if exe[1:3] == ':\\':
                    exe = pathlib.PureWindowsPath(exe).name
                else:
                    exe = pathlib.PurePath(exe).name
                if exe == self._name_norm:
                    return True
            except psutil.AccessDenied:
                pass
            return False

    __slots__ = (
        'name',
        '_matching_rules',
        '_base_resolved',
        '_null_fields',
        'base',
        'nice',
        'ioclass',
        'ionice',
        'sched',
        'sched_prio',
        'oom_score_adj',
        'cgroup'
    )
    name: str
    _matching_rules: Optional[Any]
    _base_resolved: bool
    _null_fields: List[str]

    base: Optional[str]

    nice: Optional[int]
    ioclass: Optional[IOClass]
    ionice: Optional[int]
    sched: Optional[Scheduler]
    sched_prio: Optional[int]
    oom_score_adj: Optional[int]
    cgroup: Optional[str]

    def __init__(self, name: str) -> None:
        self.name = name
        self._matching_rules = None
        self._base_resolved = True
        self._null_fields = []

        self.base = None

        self.nice = None
        self.ioclass = None
        self.ionice = None
        self.sched = None
        self.sched_prio = None
        self.oom_score_adj = None
        self.cgroup = None

    def matches(self, process: psutil.Process) -> bool:
        if not self._matching_rules:
            return Rule.DefaultMatcher().matches(self, process)
        if isinstance(self._matching_rules, Rule.Matcher):
            return self._matching_rules.matches(self, process)
        ret: bool = True
        for matching_rule in self._matching_rules:
            if isinstance(matching_rule, Rule.Matcher):
                ret &= matching_rule.matches(self, process)
        return ret

    # pylint: disable=too-many-branches
    def apply(self, process: psutil.Process) -> None:
        try:
            if self.nice is not None and process.nice() != self.nice:
                process.nice(self.nice)
        except psutil.AccessDenied:
            pass

        try:
            if (self.ioclass is not None
                    and process.ionice().ioclass != self.ioclass
                    or self.ionice is not None
                    and process.ionice().value != self.ionice):
                process.ionice(self.ioclass, self.ionice)
        except psutil.AccessDenied:
            pass

        if self.sched is not None:
            try:
                if os.sched_getscheduler(process.pid) != self.sched:
                    sched_prio: int = 0
                    if self.sched in (Scheduler.FIFO, Scheduler.RR):
                        assert self.sched_prio is not None
                        sched_prio = self.sched_prio
                    os.sched_setscheduler(
                        process.pid,
                        self.sched,
                        os.sched_param(sched_prio)  # type: ignore
                    )
            except PermissionError:
                pass
        elif self.sched_prio is not None:
            try:
                if (os.sched_getscheduler(process.pid)
                        in (Scheduler.FIFO, Scheduler.RR)):
                    os.sched_setparam(
                        process.pid,
                        os.sched_param(sched_prio)  # type: ignore
                    )
            except PermissionError:
                pass

        if self.oom_score_adj is not None:
            try:
                with open('/proc/%(pid)s/oom_score_adj'
                          % {'pid': process.pid}, 'r+') as file:
                    prev_oom_score_adj: int = int(file.read())
                    if prev_oom_score_adj != self.oom_score_adj:
                        file.write(str(self.oom_score_adj))
            except PermissionError:
                pass

        if self.cgroup is not None:
            # TODO: implement
            pass

    def resolve_base(self, rules: Dict[str, 'Rule']) -> None:
        if not self.base or self._base_resolved:
            return

        try:
            base_rule: Rule = rules[self.base]
        except KeyError as e:  # pylint: disable=invalid-name
            raise KeyError(
                'Base rule for rule %(name)s not found'
                % {'name': self.name}
            ) from e

        # pylint: disable=protected-access
        if not base_rule._base_resolved:
            base_rule.resolve_base(rules)

        if self.nice is None and 'nice' not in self._null_fields:
            self.nice = base_rule.nice
        if self.ioclass is None and 'ioclass' not in self._null_fields:
            self.ioclass = base_rule.ioclass
        if self.ionice is None and 'ionice' not in self._null_fields:
            self.ionice = base_rule.ionice
        if self.sched is None and 'sched' not in self._null_fields:
            self.sched = base_rule.sched
        if (self.oom_score_adj is None
                and 'oom_score_adj' not in self._null_fields):
            self.oom_score_adj = base_rule.oom_score_adj
        if self.cgroup is None and 'cgroup' not in self._null_fields:
            self.cgroup = base_rule.cgroup

        if self.sched_prio is not None:
            if (self.sched is not None
                    and self.sched not in (Scheduler.FIFO, Scheduler.RR)):
                raise FormatError('You can only set a scheduling priority for '
                                  'the FIFO and RR schedulers.')
        elif self.sched in (Scheduler.FIFO, Scheduler.RR):
            raise FormatError('You need to specify a scheduling priority with '
                              'the FIFO and RR schedulers.')

    # pylint: disable=too-many-branches,too-many-statements
    def load_from_dict(self, data: Mapping[str, Any]) -> None:
        for key, value in data.items():
            if key == 'match':
                if value is None:
                    self._matching_rules = Rule.NeverMatchingMatcher()
                else:
                    # TODO: implement
                    pass

            elif key == 'base':
                self.base = str(value)
                self._base_resolved = False

            elif key == 'nice':
                if value is None:
                    self._null_fields.append('nice')
                elif isinstance(value, int):
                    if value < -20 or value > 19:
                        raise ValueError(
                            'Niceness must be in the range [-20, 19]'
                        )
                    self.nice = value
                else:
                    raise FormatError('Niceness must be an integer')

            elif key == 'ioclass':
                if value is None:
                    self._null_fields.append('ioclass')
                elif isinstance(value, int):
                    self.ioclass = IOClass(value)
                else:
                    try:
                        self.ioclass = {
                            'none': IOClass.NONE,
                            'realtime': IOClass.REALTIME,
                            'best-effort': IOClass.BEST_EFFORT,
                            'idle': IOClass.IDLE,
                        }[str(value).casefold()]
                    except KeyError:
                        raise ValueError('I/O class %(ioclass)s not found'
                                         % {'ioclass': value})

            elif key == 'ionice':
                if value is None:
                    self._null_fields.append('ionice')
                elif isinstance(value, int):
                    if value < 0 or value > 7:
                        raise ValueError('I/O priority must be in the '
                                         'range [0, 7]')
                    self.ionice = value
                else:
                    raise FormatError('I/O priority must be an integer')

            elif key == 'sched':
                if value is None:
                    self._null_fields.append('sched')
                elif isinstance(value, int):
                    self.sched = Scheduler(value)
                else:
                    try:
                        self.sched = {
                            'normal': Scheduler.NORMAL,
                            'other': Scheduler.OTHER,
                            'fifo': Scheduler.FIFO,
                            'rr': Scheduler.RR,
                            'round-robin': Scheduler.ROUND_ROBIN,
                            'batch': Scheduler.BATCH,
                            'iso': Scheduler.ISO,
                            'idle': Scheduler.IDLE,
                            'deadline': Scheduler.DEADLINE,
                        }[str(value).casefold()]
                    except KeyError:
                        raise ValueError('Scheduler %(sched)s not found'
                                         % {'sched': value})

            elif key == 'sched_prio':
                if value is None:
                    self._null_fields.append('sched_prio')
                elif isinstance(value, int):
                    if value < 1 or value > 99:
                        raise ValueError('Scheduling priority must be in the '
                                         'range [1, 99]')
                    self.sched_prio = value
                else:
                    raise FormatError('Scheduling priority must be an integer')

            elif key == 'oom_score_adj':
                if value is None:
                    self._null_fields.append('oom_score_adj')
                elif isinstance(value, int):
                    if value < -1000 or value > 1000:
                        raise ValueError('OOM score adjustment must be in the '
                                         'range [-1000, 1000]')
                    self.oom_score_adj = value
                else:
                    raise FormatError(
                        'OOM score adjustment must be an integer'
                    )

            elif key == 'cgroup':
                if value is None:
                    self._null_fields.append('cgroup')
                else:
                    self.cgroup = str(value)
                    # TODO: verify cgroup exists

            else:
                raise FormatError(
                    'Unknown rule attribute "%(key)s"'
                    % {'key': key}
                )

    @staticmethod
    def load(
            stream: IO[str]
    ) -> Generator[Union['Rule', Exception], None, None]:
        def _normalize(
                data: Union[
                    Mapping[str, Mapping[str, Any]],
                    Iterable[Mapping[str, Mapping[str, Any]]]
                ]
        ) -> Generator[
            Union[Tuple[str, Mapping[str, Any]], Exception], None, None
        ]:
            if isinstance(data, Mapping):
                yield from data.items()  # type: ignore
                return

            for name in data:
                if isinstance(name, Mapping):
                    for _name, _data in name.items():
                        yield _name, _data
                else:
                    yield FormatError('Rule files must contain exactly one '
                                      'mapping or one list of mappings')

        for rule_data in _normalize(yaml.load(stream)):
            if isinstance(rule_data, Exception):
                yield rule_data
                continue
            try:
                rule: Rule = Rule(rule_data[0])
                rule.load_from_dict(rule_data[1])
                yield rule
            # pylint: disable=broad-except,invalid-name
            except Exception as e:
                try:
                    raise Exception(
                        'Exception while processing rule %(rule_name)s'
                        % {'rule_name': rule_data[0]}
                    ) from e
                # pylint: disable=broad-except,invalid-name
                except Exception as e:
                    yield e


class Yanaunid:
    _CONFIG_PATH: str = '/etc/yanaunid.d'
    _SETTINGS_PATH: str = _CONFIG_PATH + '/yanaunid.conf'
    _DEFAULT_RULES_PATH: str = _CONFIG_PATH

    __slots__ = ('logger', 'settings', 'rules', '_ignored_rules')
    logger: logging.Logger
    settings: Settings
    rules: Dict[str, Rule]

    _ignored_rules: Dict[psutil.Process, List[Rule]]

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        if logger is not None:
            self.logger = logger
        else:
            self.logger = logging.getLogger(__name__)
        self.settings = Settings()
        self.rules = {}
        self._ignored_rules = {}

    def load_settings(self) -> None:
        self.settings = Settings()
        try:
            with open(Yanaunid._SETTINGS_PATH, 'r') as file:
                self.settings.load(file)
        except FileNotFoundError:
            self.logger.warning(
                'Settings file not found (%(filename)s)',
                {'filename': Yanaunid._SETTINGS_PATH}
            )
        except OSError:
            self.logger.exception(
                'Could not open settings file (%(filename)s)',
                {'filename': Yanaunid._SETTINGS_PATH}
            )

    def load_rules(self) -> None:
        self.rules = {}
        for filepath in (
                os.path.join(dirpath, filename)
                for dirpath, _, filenames in os.walk(
                        Yanaunid._DEFAULT_RULES_PATH
                )
                for filename in filenames
                if fnmatch.fnmatch(filename, '*.rules')
        ):
            try:
                with open(filepath, 'r') as file:
                    for rule in Rule.load(file):
                        if isinstance(rule, Exception):
                            self.logger.error(
                                'Exception while processing rule '
                                '(in file %(filepath)s)',
                                {'filepath': filepath},
                                exc_info=rule
                            )
                        else:
                            self.rules[rule.name] = rule
            except Exception:  # pylint: disable=broad-except
                self.logger.exception(
                    'Exception while parsing rule file (%(filepath)s)',
                    {'filepath': filepath}
                )

            _rules_to_disable: List[str] = []
            for rule in self.rules.values():
                try:
                    rule.resolve_base(self.rules)
                except Exception:  # pylint: disable=broad-except
                    self.logger.exception(
                        'Exception while resolving rule %(name)s, '
                        'disabling rule.',
                        {'name': rule.name}
                    )
                    _rules_to_disable.append(rule.name)
            for rule_name in _rules_to_disable:
                del self.rules[rule_name]

    def _handle_processes(self, proc_ids: Iterable[int]) -> None:
        for pid in (x for x in proc_ids if x != 0):
            try:
                process: psutil.Process = psutil.Process(pid)

                _ignored_rules: List[Rule] = \
                    self._ignored_rules.get(process, [])

                with process.oneshot():
                    for rule in (
                            x
                            for x in self.rules.values()
                            if x not in _ignored_rules
                    ):
                        matches: bool

                        try:
                            matches = rule.matches(process)
                        except (ProcessLookupError, psutil.NoSuchProcess):
                            raise
                        except Exception:  # pylint: disable=broad-except
                            self.logger.exception(
                                'Exception while matching rule %(rule)s, '
                                'disabling rule for this process.',
                                {'rule': rule.name}
                            )
                            _ignored_rules.append(rule)
                            continue

                        if not matches:
                            continue

                        try:
                            rule.apply(process)
                        except (ProcessLookupError, psutil.NoSuchProcess):
                            raise
                        except Exception:  # pylint: disable=broad-except
                            self.logger.exception(
                                'Exception while applying rule %(rule)s, '
                                'disabling rule for this process.',
                                {'rule': rule.name}
                            )
                            _ignored_rules.append(rule)

                if _ignored_rules:
                    self._ignored_rules[process] = _ignored_rules
            except (ProcessLookupError, psutil.NoSuchProcess):
                pass

    def run(self) -> None:
        if not self.rules:
            raise Exception('No rules loaded')

        self._handle_processes(psutil.pids())

        proc_ids: Sequence[int] = psutil.pids()
        start: Rational = 0
        step: Rational = len(proc_ids) / self.settings.slices
        end: Rational = step
        sleep_time = self.settings.interval_ms / self.settings.slices / 1000
        refresh_countdown: Rational = self.settings.refresh_after
        while True:
            self._handle_processes(proc_ids[int(float(start)):int(float(end))])

            if float(end) > len(proc_ids):
                proc_ids = psutil.pids()
                start = 0
                step = len(proc_ids) / self.settings.slices
                end -= len(proc_ids)
            else:
                time.sleep(sleep_time)
                refresh_countdown -= 1
                if refresh_countdown <= 0:
                    refresh_countdown += self.settings.refresh_after
                    pid: int = proc_ids[int(float(end))]
                    proc_ids = psutil.pids()
                    index: int = next(
                        (i for i, v in enumerate(proc_ids) if v >= pid), 0
                    )
                    if int(float(start)) != index:
                        start = index
                    step = len(proc_ids) / self.settings.slices
                else:
                    start = end
                end = start + step


def main(args: Sequence[str]) -> None:
    argparser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='Yanaunid - Yet ANother AUto NIce Daemon'
    )
    argparser.parse_args(args)

    yanaunid: Yanaunid = Yanaunid()
    yanaunid.load_settings()
    yanaunid.load_rules()
    yanaunid.run()


if __name__ == '__main__':
    main(sys.argv)

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
