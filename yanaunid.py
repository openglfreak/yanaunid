#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Yanaunid - Yet ANother AUto NIce Daemon'''

# pylint: disable=too-many-lines

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
import re
import sys
import time
import unicodedata
from typing import Any, Dict, Generator, IO, Iterable, List, Mapping, \
                   Match, Optional, Sequence, Tuple, Union

import psutil
import yaml

__all__ = ('FormatError', 'Settings', 'IOClass', 'Scheduler', 'Matcher',
           'NeverMatchingMatcher', 'DefaultMatcher', 'PropertyMatcher', 'Rule',
           'Yanaunid')

RATIONAL_TYPES = (int, float, numbers.Rational)
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


class Matcher(abc.ABC):
    __slots__ = ()

    @abc.abstractmethod
    def matches(
            self,
            rule: 'Rule',
            process: psutil.Process,
            cache: Dict[str, Any]
    ) -> bool:
        return False


class NeverMatchingMatcher(Matcher):
    __slots__ = ()

    def matches(
            self,
            rule: 'Rule',
            process: psutil.Process,
            cache: Dict[str, Any]
    ) -> bool:
        return False


class DefaultMatcher(Matcher):
    __slots__ = ('_name', '_name_norm', '_name_norm_base', '_normalize',
                 '_case_insensitive')
    _name: Optional[str]
    _name_norm_base: Optional[str]
    _name_norm: str
    _normalize: bool
    _case_insensitive: bool

    @property
    def name(self) -> Optional[str]:
        return self._name

    @name.setter
    def name(self, value: Optional[str]) -> None:
        if self._name != value:
            self._name = value
            self._name_norm_base = ''
            if value is not None:
                self._name_norm = value
            else:
                self._name_norm = ''
                return
            if self._normalize:
                self._name_norm = normalize(self._name_norm)
            if self._case_insensitive:
                self._name_norm = self._name_norm.casefold()

    @property
    def normalize(self) -> bool:
        return self._normalize

    @normalize.setter
    def normalize(self, value: bool) -> None:
        if self._normalize != value:
            self._normalize = value
            if self._name is not None:
                self._name_norm = self._name
            elif self._name_norm_base is not None:
                self._name_norm = self._name_norm_base
            else:
                self._name_norm = ''
                return
            if value:
                self._name_norm = normalize(self._name_norm)
            if self._case_insensitive:
                self._name_norm = self._name_norm.casefold()

    @property
    def case_insensitive(self) -> bool:
        return self._case_insensitive

    @case_insensitive.setter
    def case_insensitive(self, value: bool) -> None:
        if self._case_insensitive != value:
            self._case_insensitive = value
            if self._name is not None:
                self._name_norm = self._name
            elif self._name_norm_base is not None:
                self._name_norm = self._name_norm_base
            else:
                self._name_norm = ''
                return
            if self._normalize:
                self._name_norm = normalize(self._name_norm)
            if value:
                self._name_norm = self._name_norm.casefold()

    def __init__(
            self,
            name: Optional[str] = None,
            normalize: bool = False,  # pylint: disable=redefined-outer-name
            case_insensitive: bool = False
    ) -> None:
        super().__init__()
        self._name = name
        self._normalize = normalize
        self._case_insensitive = case_insensitive

        # Moved to a seperate function to avoid the shadowed variable
        self._initial_norm()

    def _initial_norm(self) -> None:
        self._name_norm_base = ''
        if self.name is None:
            self._name_norm = ''
        else:
            self._name_norm = self.name
            if self.normalize:
                self._name_norm = normalize(self._name_norm)
            if self.case_insensitive:
                self._name_norm = self._name_norm.casefold()

    # pylint: disable=too-many-branches
    def matches(
            self,
            rule: 'Rule',
            process: psutil.Process,
            cache: Dict[str, Any]
    ) -> bool:
        if self._name is None and self._name_norm_base != rule.name:
            self._name_norm_base = rule.name
            self._name_norm = rule.name
            if self._normalize:
                self._name_norm = normalize(self._name_norm)
            if self._case_insensitive:
                self._name_norm = self._name_norm.casefold()

        if 'exe' not in cache:
            cache.update(process.as_dict(['exe']))

        exe: str = cache['exe']
        if exe is not None:
            if self._normalize:
                exe = normalize(exe)
            if self._case_insensitive:
                exe = exe.casefold()
            if exe[1:3] == ':\\':
                exe = pathlib.PureWindowsPath(exe).name
            else:
                exe = os.path.basename(exe)
            if exe == self._name_norm:
                return True

        return False


# pylint: disable=too-many-instance-attributes,too-many-statements
class PropertyMatcher(Matcher):
    class Operator(enum.Enum):
        EqualTo = enum.auto()
        GreaterThanOrEqualTo = enum.auto()
        LessThanOrEqualTo = enum.auto()
        StartsWith = enum.auto()
        EndsWith = enum.auto()
        MatchesGlob = enum.auto()
        MatchesRegex = enum.auto()
        Contains = enum.auto()

    OPERATOR_MAPPING = {
        '==': Operator.EqualTo,
        '>=': Operator.GreaterThanOrEqualTo,
        '<=': Operator.LessThanOrEqualTo,
        '^=': Operator.StartsWith,
        '$=': Operator.EndsWith,
        '*=': Operator.MatchesGlob,
        '~=': Operator.MatchesRegex,
        '%=': Operator.Contains,
    }

    ALLOWED_TYPES: Dict[Operator, Union[type, Tuple[type, ...]]] = {
        Operator.EqualTo: (str, *RATIONAL_TYPES),
        Operator.GreaterThanOrEqualTo: RATIONAL_TYPES,
        Operator.LessThanOrEqualTo: RATIONAL_TYPES,
        Operator.StartsWith: (str, Sequence),
        Operator.EndsWith: (str, Sequence),
        Operator.MatchesGlob: str,
        Operator.MatchesRegex: str,
        Operator.Contains: (str, Sequence, Dict),
    }

    PROPERTY_WHITELIST: Sequence[str] = ('children', 'cmdline', 'connections',
                                         'cpu_affinity', 'cpu_num',
                                         'cpu_percent', 'cpu_times',
                                         'create_time', 'cwd', 'environ',
                                         'exe', 'memory_percent', 'name',
                                         'nice', 'num_fds', 'num_threads',
                                         'open_files', 'parent', 'pid', 'ppid',
                                         'status', 'terminal', 'threads',
                                         'username')

    PARSE_PATTERN = re.compile(r'''^
        \s*
        (?P<length>\#)?
        (?P<name>[^[]+)
        (?:\[(?P<key>[^]]+)\])?
        \s*
        (?P<invert>!?)
        (?P<op>==|>=|<=|\^=|\$=|\*=|~=|%=)
        \s*
        (?P<value>.*?)
        \s*
    $''', re.VERBOSE)
    PARSE_PARTS_PATTERN_PROP = re.compile(r'''^
        \s*
        (?P<length>\#)?
        (?P<name>[^[]+)
        (?:\[(?P<key>[^]]+)\])?
        \s*
    $''', re.VERBOSE)
    PARSE_PARTS_PATTERN_EXPR = re.compile(r'''^
        \s*
        (?P<invert>!?)
        (?P<op>==|>=|<=|\^=|\$=|\*=|~=|%=)
        \s*
        (?P<value>.*?)
        \s*
    $''', re.VERBOSE)

    __slots__ = ('name', 'key', 'length', 'operation', 'inverted', 'value',
                 'normalize_strings', 'case_insensitive', '_cache')
    name: str
    key: Optional[Union[int, str]]
    length: bool
    operation: Operator
    inverted: bool
    value: Any
    normalize_strings: bool
    case_insensitive: bool
    _cache: Optional[Tuple[Operator, Any, Any]]

    # pylint: disable=too-many-arguments
    def __init__(
            self,
            name: str,
            operation: Operator,
            value: Any = None,
            key: Optional[Union[int, str]] = None,
            length: bool = False,
            inverted: bool = False
    ) -> None:
        self.name = name
        self.key = key
        self.length = length
        self.operation = operation
        self.inverted = inverted
        self.value = value
        self.normalize_strings = False
        self.case_insensitive = False
        self._cache = None

    # pylint: disable=too-many-branches
    def matches(
            self,
            rule: 'Rule',
            process: psutil.Process,
            cache: Dict[str, Any]
    ) -> bool:
        if self.name not in PropertyMatcher.PROPERTY_WHITELIST:
            raise PermissionError(
                'Property %(name)s not in whitelist'
                % {'name': self.name}
            )
        if not isinstance(
                self.value,
                PropertyMatcher.ALLOWED_TYPES[self.operation]
        ):
            raise TypeError(
                'Value of type %(type)s not supported for operation %(op)s'
                % {'type': self.value.__class__.__name__, 'op': self.operation}
            )

        if self.name not in cache:
            cache.update(process.as_dict([self.name]))

        value = cache[self.name]
        if self.key is not None:
            try:
                value = value[self.key]
            except KeyError:
                return self.inverted
        if self.length:
            try:
                value = len(value)
            except TypeError:
                return self.inverted

        if not isinstance(
                value,
                PropertyMatcher.ALLOWED_TYPES[self.operation]
        ):
            raise TypeError(
                'Operation %(op)s not supported on value of type %(type)s'
                % {'op': self.operation, 'type': value.__class__.__name__}
            )

        self_value: str = self.value

        if self.normalize_strings:
            if isinstance(value, str):
                value = normalize(value)
            if isinstance(self_value, str):
                self_value = normalize(self_value)
        if self.case_insensitive:
            if isinstance(value, str):
                value = value.casefold()
            if isinstance(self_value, str):
                self_value = self_value.casefold()

        result: bool

        if self.operation == PropertyMatcher.Operator.EqualTo:
            result = value == self_value
        elif self.operation == PropertyMatcher.Operator.GreaterThanOrEqualTo:
            result = value >= self_value
        elif self.operation == PropertyMatcher.Operator.LessThanOrEqualTo:
            result = value <= self_value
        elif self.operation == PropertyMatcher.Operator.StartsWith:
            if isinstance(value, Sequence):
                if isinstance(self_value, Sequence):
                    result = \
                        value[0:len(self_value)] == self_value[0:len(value)]
                else:
                    result = value[0] == self_value
            else:
                result = value.startswith(self_value)
        elif self.operation == PropertyMatcher.Operator.EndsWith:
            if isinstance(value, Sequence):
                if isinstance(self_value, Sequence):
                    result = \
                        value[-len(self_value):] == self_value[-len(value):]
                else:
                    result = value[-1] == self_value
            else:
                result = value.endswith(self_value)
        elif self.operation in (PropertyMatcher.Operator.MatchesGlob,
                                PropertyMatcher.Operator.MatchesRegex):
            if (self._cache is None
                    or self._cache[0] != self.operation
                    or self._cache[1] != self_value):
                _value: str = self_value
                if self.operation == PropertyMatcher.Operator.MatchesGlob:
                    _value = fnmatch.translate(_value)
                self._cache = (self.operation, self_value, re.compile(_value))
            result = self._cache[2].fullmatch(value) is not None
        elif self.operation == PropertyMatcher.Operator.Contains:
            result = self_value in value
        else:
            assert False

        return result if not self.inverted else not result

    @staticmethod
    def parse_value(inp: str) -> Any:
        return yaml.safe_load(inp)

    @staticmethod
    def parse_name(
            prop: str,
            start: int = 0,
            end: Optional[int] = None
    ) -> Tuple[Match[str], bool, str, Any]:
        prop_match: Optional[Match[str]]
        if end is None:
            prop_match = PropertyMatcher.PARSE_PARTS_PATTERN_PROP.fullmatch(
                prop,
                start
            )
        else:
            prop_match = PropertyMatcher.PARSE_PARTS_PATTERN_PROP.fullmatch(
                prop,
                start,
                end
            )
        if prop_match is None:
            raise FormatError('Could not parse matching rule property name')
        return (prop_match,
                bool(prop_match.group('length')),
                prop_match.group('name'),
                PropertyMatcher.parse_value(prop_match.group('key'))
                if prop_match.group('key') is not None
                else None)

    @staticmethod
    def parse_test(
            expr: str,
            start: int = 0,
            end: Optional[int] = None
    ) -> Tuple[Match[str], bool, 'PropertyMatcher.Operator', Any]:
        expr_match: Optional[Match[str]]
        if end is None:
            expr_match = PropertyMatcher.PARSE_PARTS_PATTERN_EXPR.fullmatch(
                expr,
                start
            )
        else:
            expr_match = PropertyMatcher.PARSE_PARTS_PATTERN_EXPR.fullmatch(
                expr,
                start,
                end
            )
        if expr_match is None:
            raise FormatError('Could not parse matching rule test expression')
        return (expr_match,
                bool(expr_match.group('invert')),
                PropertyMatcher.OPERATOR_MAPPING[expr_match.group('op')],
                PropertyMatcher.parse_value(expr_match.group('value')))

    @staticmethod
    def parse_parts(prop: str, expr: str) -> 'PropertyMatcher':
        length: bool
        name: str
        key: Any
        _, length, name, key = PropertyMatcher.parse_name(prop)

        invert: bool
        operation: PropertyMatcher.Operator
        value: Any
        _, invert, operation, value = PropertyMatcher.parse_test(expr)

        return PropertyMatcher(
            name,
            operation,
            value,
            key=key,
            length=length,
            inverted=invert
        )

    @staticmethod
    def parse(inp: str) -> 'PropertyMatcher':
        prop_match: Optional[Match[str]]
        length: bool
        name: str
        key: Any
        prop_match, length, name, key = \
            PropertyMatcher.parse_name(inp)

        invert: bool
        operation: PropertyMatcher.Operator
        value: Any
        _, invert, operation, value = \
            PropertyMatcher.parse_test(inp, prop_match.end())

        return PropertyMatcher(
            name,
            operation,
            value,
            key=key,
            length=length,
            inverted=invert
        )


# pylint: disable=too-many-instance-attributes
class Rule:
    __slots__ = ('name', '_matching_rules', '_base_resolved', '_null_fields',
                 'base', 'nice', 'ioclass', 'ionice', 'sched', 'sched_prio',
                 'oom_score_adj', 'cgroup')
    name: str
    _matching_rules: Optional[Union[Matcher, List[Matcher]]]
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

    def matches(self, process: psutil.Process, cache: Dict[str, Any]) -> bool:
        if self._matching_rules is None:
            return DefaultMatcher().matches(self, process, cache)
        if not self._matching_rules:
            return True
        if isinstance(self._matching_rules, Matcher):
            return self._matching_rules.matches(self, process, cache)
        if len(self._matching_rules) == 1:
            return self._matching_rules[0].matches(self, process, cache)
        ret: bool = True
        for matching_rule in self._matching_rules:
            if isinstance(matching_rule, Matcher):
                ret &= matching_rule.matches(self, process, cache)
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
        if self.sched_prio is None and 'sched_prio' not in self._null_fields:
            self.sched_prio = base_rule.sched_prio
        if (self.oom_score_adj is None
                and 'oom_score_adj' not in self._null_fields):
            self.oom_score_adj = base_rule.oom_score_adj
        if self.cgroup is None and 'cgroup' not in self._null_fields:
            self.cgroup = base_rule.cgroup

        if self.sched_prio is not None:
            if (self.sched is not None
                    and self.sched not in (Scheduler.FIFO, Scheduler.RR)):
                raise FormatError('You can only set a scheduling priority for '
                                  'the FIFO and RR schedulers')
        elif self.sched in (Scheduler.FIFO, Scheduler.RR):
            raise FormatError('You need to specify a scheduling priority with '
                              'the FIFO and RR schedulers')

        self._base_resolved = True

    # pylint: disable=too-many-locals,too-many-statements
    @staticmethod
    def load_matching_rule(data: Dict[str, Any]) -> Matcher:
        if len(data) == 1:
            item: Tuple[str, Any] = next(iter(data.items()))
            if not isinstance(item[0], str) or not isinstance(item[1], str):
                raise FormatError('Invalid matching rule format')
            return PropertyMatcher.parse_parts(item[0], item[1])

        name: Optional[str] = None
        _key: Any = None
        length: bool = False
        operation: Optional[PropertyMatcher.Operator] = None
        invert: bool = False
        _has_value: bool = False
        _value: Any = None
        # pylint: disable=redefined-outer-name
        normalize: bool = False
        case_insensitive: bool = False

        for key, value in data.items():
            if key == 'property':
                if isinstance(value, str):
                    name = value
                else:
                    raise FormatError('Property name must be a string')

            elif key == 'key':
                _key = value

            elif key == 'length':
                if isinstance(value, bool):
                    length = value
                else:
                    raise FormatError('"length" must be a boolean')

            elif key == 'operator':
                if isinstance(value, str):
                    try:
                        operation = PropertyMatcher.OPERATOR_MAPPING[value]
                    except KeyError as e:  # pylint: disable=invalid-name
                        raise FormatError(
                            '"%(op)s" is not a valid operator' % {'op': value}
                        ) from e
                else:
                    raise FormatError('Operator must be a string')

            elif key == 'invert':
                if isinstance(value, bool):
                    invert = value
                else:
                    raise FormatError('"invert" must be a boolean')

            elif key == 'value':
                _has_value = True
                _value = value

            elif key == 'test':
                if isinstance(value, str):
                    start: int = 0

                    if 'property' not in data:
                        prop_match: Match[str]
                        prop_match, length, name, _key = \
                            PropertyMatcher.parse_name(value)
                        # TODO: better error messages
                        if 'length' in data:
                            raise FormatError('Invalid attribute "length"')
                        if 'key' in data:
                            raise FormatError('Invalid attribute "key"')

                        start = prop_match.end()

                    _, invert, operation, _value = \
                        PropertyMatcher.parse_test(value, start)
                    _has_value = True
                    # TODO: better error messages
                    if invert and 'invert' in data:
                        raise FormatError('Invalid attribute "invert"')
                    if 'operator' in data:
                        raise FormatError('Invalid attribute "operator"')
                    if 'value' in data:
                        raise FormatError('Invalid attribute "value"')
                else:
                    raise FormatError('Test expression must be a string')

            elif key == 'normalize':
                if isinstance(value, bool):
                    normalize = value
                else:
                    raise FormatError('"normalize" must be a boolean')

            elif key == 'case_insensitive':
                if isinstance(value, bool):
                    case_insensitive = value
                else:
                    raise FormatError('"case_insensitive" must be a boolean')

        if name is None:
            raise FormatError('Matching rule has no property name attribute')
        if operation is None:
            raise FormatError('Matching rule has no operator attribute')
        if not _has_value:
            raise FormatError('Matching rule has no value attribute')

        prop_matcher = PropertyMatcher(
            name,
            operation,
            _value,
            key=_key,
            length=length,
            inverted=invert
        )
        prop_matcher.normalize_strings = normalize
        prop_matcher.case_insensitive = case_insensitive
        return prop_matcher

    # pylint: disable=too-many-branches,too-many-statements
    def load_from_dict(self, data: Mapping[str, Any]) -> None:
        for key, value in data.items():
            if key == 'match':
                if value is None:
                    self._matching_rules = NeverMatchingMatcher()
                elif isinstance(value, str):
                    try:
                        self._matching_rules = PropertyMatcher.parse(value)
                    except FormatError:
                        self._matching_rules = DefaultMatcher(value)
                elif isinstance(value, Sequence):
                    if len(value) == 1:
                        self._matching_rules = \
                            Rule.load_matching_rule(value[0])
                    else:
                        self._matching_rules = [
                            Rule.load_matching_rule(_value)
                            for _value in value
                        ]
                elif isinstance(value, Dict):
                    self._matching_rules = Rule.load_matching_rule(value)
                else:
                    # TODO: better error message
                    raise FormatError('Invalid "match" attribute')

            elif key == 'base':
                if value is None:
                    self._null_fields.append('base')
                elif isinstance(value, str):
                    self.base = value
                    self._base_resolved = False
                else:
                    raise FormatError('Base rule name must be a string')

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
                elif isinstance(value, str):
                    self.cgroup = str(value)
                    # TODO: verify cgroup exists
                else:
                    raise FormatError('Control group name must be a string')

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
                    Iterable[Mapping[str, Mapping[str, Any]]],
                    Iterable[Iterable[Mapping[str, Mapping[str, Any]]]]
                ]
        ) -> Generator[
            Union[Tuple[str, Mapping[str, Any]], Exception], None, None
        ]:
            if isinstance(data, Mapping):
                yield from data.items()  # type: ignore
            elif isinstance(data, Iterable):
                for item in data:
                    if isinstance(item, Mapping):
                        yield from item.items()
                    elif isinstance(item, Iterable):
                        for _item in item:
                            if isinstance(_item, Mapping):
                                yield from _item.items()
                            else:
                                yield FormatError('Rule files must contain '
                                                  'only mappings or lists of '
                                                  'mappings')
                    else:
                        yield FormatError('Rule files must contain only '
                                          'mappings or lists of mappings')
            else:
                yield FormatError('Rule files must contain only mappings or '
                                  'lists of mappings')

        for rule_data in _normalize(yaml.safe_load_all(stream)):
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
                        'disabling rule',
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
                    cache: Dict[str, Any] = {}

                    for rule in (
                            x
                            for x in self.rules.values()
                            if x not in _ignored_rules
                    ):
                        matches: bool

                        try:
                            matches = rule.matches(process, cache)
                        except (ProcessLookupError, psutil.NoSuchProcess):
                            raise
                        except Exception:  # pylint: disable=broad-except
                            self.logger.exception(
                                'Exception while matching rule %(rule)s, '
                                'disabling rule for this process',
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
                                'disabling rule for this process',
                                {'rule': rule.name}
                            )
                            _ignored_rules.append(rule)

                if _ignored_rules:
                    self._ignored_rules[process] = _ignored_rules
            except (ProcessLookupError, psutil.NoSuchProcess):
                pass

    def run(self) -> None:
        if not self.rules:
            self.logger.fatal('No rules loaded')
            return
        self.logger.info('%(n)s rules loaded', {'n': len(self.rules)})

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
                    if end < len(proc_ids):
                        pid: int = proc_ids[int(float(end))]
                        proc_ids = psutil.pids()
                        index: int = next(
                            (i for i, v in enumerate(proc_ids) if v >= pid), 0
                        )
                        if int(float(start)) != index:
                            start = index
                    else:
                        start = 0
                    step = len(proc_ids) / self.settings.slices
                else:
                    start = end
                end = start + step


def main(args: Sequence[str]) -> None:
    argparser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog=pathlib.PurePath(args[0]).name if args and args[0] else None,
        description='Yanaunid - Yet ANother AUto NIce Daemon'
    )
    argparser.parse_args(args[1:])

    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s'
    )

    yanaunid: Yanaunid = Yanaunid()
    yanaunid.load_settings()
    yanaunid.load_rules()
    yanaunid.run()


if __name__ == '__main__':
    main(sys.argv)

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
