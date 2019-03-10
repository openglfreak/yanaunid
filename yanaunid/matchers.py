# -*- coding: utf-8 -*-

import abc
import enum
import fnmatch
import re
from typing import Any, Dict, Match, Optional, Sequence, Tuple, Union

import psutil
import yaml

from .misc import FormatError, normalize, RATIONAL_TYPES

__all__ = ('Matcher', 'NeverMatchingMatcher', 'DefaultMatcher',
           'PropertyMatcher')


# pylint: disable=too-few-public-methods
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


# pylint: disable=too-few-public-methods
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

        exe: str
        try:
            exe = cache['exe']
        except KeyError:
            exe = next(iter(process.as_dict(['exe']).values()))
            cache['exe'] = exe

        if exe is not None:
            if self._normalize:
                exe = normalize(exe)
            if self._case_insensitive:
                exe = exe.casefold()
            if exe.endswith(self._name_norm):
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


# Has to be at the bottom because rule.py imports this module
# If Rule is not imported, mypy complains that it can't find that type
# pylint: disable=wrong-import-position,unused-import,cyclic-import
from .rule import Rule  # noqa: E402

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
