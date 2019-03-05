# -*- coding: utf-8 -*-

import dataclasses
from typing import TextIO

from .misc import Rational

__all__ = ('Settings',)


# pylint: disable=too-few-public-methods
@dataclasses.dataclass
class Settings():
    interval_ms: Rational = 15013
    slices: int = 1
    refresh_after: Rational = 1

    def load(self, stream: TextIO) -> None:
        # TODO: implement
        pass

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
