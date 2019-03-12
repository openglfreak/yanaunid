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

import dataclasses
from typing import TextIO

from .misc import Rational

__all__ = ('Settings',)


# pylint: disable=too-few-public-methods
@dataclasses.dataclass
class Settings():
    interval_ms: Rational = 15013
    slices: int = 15
    refresh_after: Rational = 5

    def load(self, stream: TextIO) -> None:
        # TODO: implement
        pass

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
