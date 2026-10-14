"""Runtime state for the firewall (Person 2 owns). STUB for now.

Real version also tracks rolling daily spend and recent action times.
"""

_KILL_SWITCH = False


def set_kill_switch(on: bool) -> None:
    global _KILL_SWITCH
    _KILL_SWITCH = bool(on)


def kill_switch_on() -> bool:
    return _KILL_SWITCH
