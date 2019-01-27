#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Yanaunid - Yet ANother AUto NIce Daemon'''

import dataclasses
import fnmatch
import logging
import numbers
import os
import os.path
import time
from typing import Dict, Generator, IO, Iterable, List, Optional, Sequence, \
    Union

import psutil

__all__ = ('Settings', 'Rule', 'Yanaunid')

Rational = Union[int, float, numbers.Rational]
MYPY = False
if MYPY:
    # pylint: disable=unsubscriptable-object
    PathLike = Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]
else:
    PathLike = Union[str, bytes, os.PathLike]


# pylint: disable=too-few-public-methods
@dataclasses.dataclass
class Settings():
    interval_ms: Rational = 60251
    slices: int = 293
    refresh_after: Rational = 25

    def load(self, stream: IO[str]) -> None:
        # TODO: implement
        pass


class Rule:
    __slots__ = ('name',)
    name: str

    # pylint: disable=unused-argument,no-self-use
    def matches(self, process: psutil.Process) -> bool:
        # TODO: implement
        return False

    def apply(self, process: psutil.Process) -> None:
        # TODO: implement
        pass

    # pylint: disable=unused-argument
    @staticmethod
    def load(
            stream: IO[str]
    ) -> Generator[Union['Rule', Exception], None, None]:
        # TODO: implement
        yield from []


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
        for dirpath, _, filenames in os.walk(Yanaunid._DEFAULT_RULES_PATH):
            for filename in filenames:
                if not fnmatch.fnmatch(filename, '*.rules'):
                    continue
                try:
                    with open(os.path.join(dirpath, filename), 'r') as file:
                        for rule in Rule.load(file):
                            if isinstance(rule, Exception):
                                self.logger.error(
                                    'Exception while processing rule '
                                    '(in file %(filename)s)',
                                    {'filename': filename},
                                    exc_info=rule
                                )
                            else:
                                self.rules[rule.name] = rule
                except Exception:  # pylint: disable=broad-except
                    self.logger.exception(
                        'Exception while parsing rule file (%(filename)s)',
                        {'filename': filename}
                    )

    def _handle_processes(self, proc_ids: Iterable[int]) -> None:
        for pid in proc_ids:
            if pid == 0:
                continue

            process: psutil.Process

            try:
                process = psutil.Process(pid)
            except psutil.NoSuchProcess:
                continue

            _ignored_rules: List[Rule] = self._ignored_rules.get(process, [])

            with process.oneshot():
                for rule in self.rules.values():
                    if rule in _ignored_rules:
                        continue

                    matches: bool

                    try:
                        matches = rule.matches(process)
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
                    except Exception:  # pylint: disable=broad-except
                        self.logger.exception(
                            'Exception while applying rule %(rule)s, '
                            'disabling rule for this process.',
                            {'rule': rule.name}
                        )
                        _ignored_rules.append(rule)

            if _ignored_rules:
                self._ignored_rules[process] = _ignored_rules

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
                    index: int = 0
                    for index, value in enumerate(proc_ids):
                        if value >= pid:
                            break
                    if int(float(start)) != index:
                        start = index
                    step = len(proc_ids) / self.settings.slices
                else:
                    start = end
                end = start + step


def main() -> None:
    yanaunid: Yanaunid = Yanaunid()
    yanaunid.load_settings()
    yanaunid.load_rules()
    yanaunid.run()


if __name__ == '__main__':
    main()

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
