# Yanaunid
This program is currently in an alpha state and not production-ready.
There are still missing features.

## Description
Yanaunid (Yet ANother AUto NIce Daemon) is a python daemon created to manage
parameters of running processes, such as the
[CPU](http://linux.die.net/man/1/nice) and
[I/O](http://linux.die.net/man/1/ionice) priorities.

This program is a rewrite of [Ananicy](https://github.com/Nefelim4ag/Ananicy)
using [PyYAML](https://pyyaml.org/wiki/PyYAML) and
[psutil](https://github.com/giampaolo/psutil).

## Versions
See [PEP 386](https://www.python.org/dev/peps/pep-0386) (Under "The new
versioning algorithm").

## Running
To run Yanaunid, execute the command `python -OO -m yanaunid` in the root of
the cloned repository.
