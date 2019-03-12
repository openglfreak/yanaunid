# -*- coding: utf-8 -*-
# Yanaunid - Yet ANother AUto NIce Daemon
# Copyright (C) 2019  Torge Matthies
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
from typing import Any, Dict, Generator, Iterable, List, Mapping, Match, \
                   Optional, Sequence, TextIO, Tuple, Union

import psutil
import yaml

from .matchers import DefaultMatcher, FormatError, Matcher, \
                      NeverMatchingMatcher, PropertyMatcher
from .misc import IOClass, Scheduler

__all__ = ('Rule',)

DefaultMatcherInstance: DefaultMatcher = DefaultMatcher()


# pylint: disable=too-many-instance-attributes
class Rule:
    __slots__ = ('name', '_matching_rules', '_bases_resolved', '_null_fields',
                 'base_rules', 'nice', 'ioclass', 'ionice', 'sched',
                 'sched_prio', 'oom_score_adj', 'cgroup')
    name: str
    _matching_rules: Optional[Union[Matcher, List[Matcher]]]
    _bases_resolved: bool
    _null_fields: List[str]

    base_rules: Optional[Union[str, List[str]]]

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
        self._bases_resolved = True
        self._null_fields = []

        self.base_rules = None

        self.nice = None
        self.ioclass = None
        self.ionice = None
        self.sched = None
        self.sched_prio = None
        self.oom_score_adj = None
        self.cgroup = None

    def matches(self, process: psutil.Process, cache: Dict[str, Any]) -> bool:
        if not self._matching_rules:
            if self._matching_rules is None:
                return DefaultMatcherInstance.matches(self, process, cache)
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

    def _resolve_base_rule(self, base: str, rules: Dict[str, 'Rule']) -> None:
        try:
            base_rule: Rule = rules[base]
        except KeyError as e:  # pylint: disable=invalid-name
            raise KeyError(
                'Base rule for rule %(name)s not found'
                % {'name': self.name}
            ) from e

        # pylint: disable=protected-access
        if not base_rule._bases_resolved:
            base_rule.resolve_base_rules(rules)

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

    def resolve_base_rules(self, rules: Dict[str, 'Rule']) -> None:
        if not self.base_rules or self._bases_resolved:
            return

        if isinstance(self.base_rules, str):
            self._resolve_base_rule(self.base_rules, rules)
        else:
            for base in self.base_rules:
                self._resolve_base_rule(base, rules)

        if self.sched_prio is not None:
            if (self.sched is not None
                    and self.sched not in (Scheduler.FIFO, Scheduler.RR)):
                raise FormatError('You can only set a scheduling priority for '
                                  'the FIFO and RR schedulers')
        elif self.sched in (Scheduler.FIFO, Scheduler.RR):
            raise FormatError('You need to specify a scheduling priority with '
                              'the FIFO and RR schedulers')

        self._bases_resolved = True

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
                    self.base_rules = value
                    self._bases_resolved = False
                elif (isinstance(value, list)
                      and all(isinstance(e, str) for e in value)):
                    self.base_rules = value
                    self._bases_resolved = False
                else:
                    raise FormatError(
                        'Base rule name must be a string or a list of strings'
                    )

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
            stream: TextIO
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
                        yield from item.items()  # type: ignore
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

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
