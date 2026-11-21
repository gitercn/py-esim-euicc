"""Stub of smpp.pdu.pdu_types.

Only the names pySim touches are reachable: `DataCoding`, `PDU`, `CommandId`
and the enums appear in *annotations*, which Python evaluates at function
definition time, so they must exist as objects.  Using one is an error.
"""


class _Unavailable:
    """Placeholder for any smpp.pdu.pdu_types name."""

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "smpp.pdu.pdu_types is a stub (see _stubs/smpp/__init__.py); "
            "SMS PDU <-> SMPP translation is not available in this checkout")

    def __getattr__(self, name):
        raise NotImplementedError(
            f"smpp.pdu.pdu_types stub has no member {name!r}")


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    return _Unavailable
