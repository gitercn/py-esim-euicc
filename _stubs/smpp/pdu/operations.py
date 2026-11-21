"""Stub of smpp.pdu.operations -- see pdu_types.py in this directory."""
from .pdu_types import _Unavailable


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    return _Unavailable
