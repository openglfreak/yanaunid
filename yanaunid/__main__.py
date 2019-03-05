# -*- coding: utf-8 -*-

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
