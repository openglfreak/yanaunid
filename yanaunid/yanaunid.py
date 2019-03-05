# -*- coding: utf-8 -*-

import fnmatch
import logging
import os
import os.path
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence

import psutil

from .misc import Rational
from .rule import Rule
from .settings import Settings

__all__ = ('Yanaunid',)


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

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
