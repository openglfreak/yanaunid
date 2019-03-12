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
