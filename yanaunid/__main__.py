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

import argparse
import logging
import os.path
import sys
from typing import Optional, Sequence

from yanaunid import Yanaunid

__all__ = ('main',)


def main(exe_name: Optional[str], args: Sequence[str]) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s'
    )

    argparser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog=exe_name,
        description='Yanaunid - Yet ANother AUto NIce Daemon'
    )
    argparser.parse_args(args)

    yanaunid: Yanaunid = Yanaunid()
    yanaunid.load_settings()
    yanaunid.load_rules()
    yanaunid.run()


if __name__ == '__main__':
    main(os.path.basename(sys.argv[0]), sys.argv[1:])

# vim: ai ts=4 sts=4 et sw=4 tw=79 ft=python
