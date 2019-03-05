# -*- coding: utf-8 -*-

import enum
import numbers
import unicodedata
from typing import Union

__all__ = ('FormatError', 'IOClass', 'Scheduler')

RATIONAL_TYPES = (int, float, numbers.Rational)
Rational = Union[int, float, numbers.Rational]


class FormatError(Exception):
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


def normalize(string: str) -> str:
    return unicodedata.normalize('NFKD', string)

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
