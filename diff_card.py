#!/usr/bin/env python3
"""Compare a profile DER against the card in the reader, field by field.

The point is to see *what still differs* after a profile has been built to
imitate a working SIM, without hand-reading two dumps.

    python diff_card.py cmcc_ff03.der [COM4]

Read-only on the card. Files are compared after stripping trailing 0xFF, so a
250-byte SAIP file and a 15-byte on-card file with the same content count as
equal -- the padding is not a difference anyone cares about.
"""
import sys

from euicc_lpa import Phoenix

# (label, FID, structure, record size for LF)
# The record sizes here are only a *first guess*: a card answers 6700 (wrong
# length) for any Le that is not exactly the record length, so read_card()
# falls back to REC_LENS and keeps whichever one the card accepts.
FIELDS = [
    ("EF.IMSI",     "6F07", "tr", 0),
    ("EF.ACC",      "6F78", "tr", 0),
    ("EF.AD",       "6FAD", "tr", 0),
    ("EF.SPN",      "6F46", "tr", 0),
    ("EF.FPLMN",    "6F7B", "tr", 0),
    ("EF.PLMNwAcT", "6F60", "tr", 0),
    ("EF.OPLMNwAcT", "6F61", "tr", 0),
    ("EF.HPLMNwAcT", "6F62", "tr", 0),
    ("EF.UST",      "6F38", "tr", 0),
    ("EF.HPPLMN",   "6F31", "tr", 0),
    ("EF.MSISDN",   "6F40", "lf", 0x22),
    ("EF.SMSP",     "6F42", "lf", 0x28),
]

# READ RECORD only succeeds when Le is exactly the record length, and this card
# does not return an FCP to read it from, so try the sizes seen in the wild.
REC_LENS = (0x1C, 0x2A, 0x22, 0x28, 0x0C, 0x10, 0x14, 0x18,
            0x1E, 0x20, 0x24, 0x26, 0x2C, 0x30, 0x40, 0x50)


# The subscription lives in a different DF depending on the card: a USIM keeps
# it in ADF.USIM (7FD0), a 2G SIM in DF.GSM (7F20), some cards in 7FFF. Reading
# only one of them is how sim_dump.py used to print ICCID and nothing else.
ROOTS = ("7FD0", "7FFF", "7F20")
# Files a 2G card keeps in DF.TELECOM instead.
TELECOM = "7F10"

DER_NAME = {  # label -> pysim decoded key
    "EF.IMSI": "ef-imsi", "EF.ACC": "ef-acc", "EF.AD": "ef-ad",
    "EF.SPN": "ef-spn", "EF.FPLMN": "ef-fplmn",
    "EF.PLMNwAcT": "ef-plmnwact", "EF.OPLMNwAcT": "ef-oplmnwact",
    "EF.HPLMNwAcT": "ef-hplmnwact", "EF.UST": "ef-ust",
    "EF.HPPLMN": "ef-hpplmn", "EF.MSISDN": "ef-msisdn", "EF.SMSP": "ef-smsp",
}


def read_card(port):
    ph = Phoenix(port)
    atr = ph.reset()
    if not atr:
        raise SystemExit("no ATR -- reseat the reader")
    print(f"card ATR: {atr.hex(' ').upper()}")

    def apdu(cla, ins, p1, p2, data=b"", le=0):
        raw = (bytes([cla, ins, p1, p2, len(data)]) + data + bytes([le])
               if data else bytes([cla, ins, p1, p2, le]))
        d, sw = ph.transceive(raw)
        return d, sw.hex().upper()

    def sel(fid):
        _d, sw = apdu(0x00, 0xA4, 0x00, 0x0C, bytes.fromhex(fid))
        return sw.startswith("9")

    root = None
    for fid in ROOTS:
        sel("3F00")
        if sel(fid):
            root = fid
            break
    print(f"subscription root: {root or '(none)'}")

    out = {}
    for label, fid, struct, rec in FIELDS:
        out[label] = None
        # try the subscription root first, then DF.TELECOM (2G layout)
        for df in [root, TELECOM]:
            if not df:
                continue
            sel("3F00")
            if not sel(df) or not sel(fid):
                continue
            if struct == "tr":
                d, sw = apdu(0x00, 0xB0, 0x00, 0x00, le=0xFA)
                out[label] = d if sw.startswith("9") else None
            else:
                out[label] = None
                for le in dict.fromkeys((rec,) + REC_LENS):
                    d, sw = apdu(0x00, 0xB2, 1, 0x04, le=le)
                    if sw.startswith("9"):
                        out[label] = d
                        break
            break
    ph.close()
    return out


def read_der(path):
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(here, "pysim"))
    # pySim imports `smpp` on the way to its SAIP code; upstream smpplib no
    # longer ships it.  The stub only satisfies annotations.
    sys.path.insert(0, os.path.join(here, "_stubs"))
    from pySim.esim.saip import ProfileElement

    der = open(path, "rb").read()

    def split(buf, off=0):
        t = buf[off]
        off += 1
        if t & 0x1F == 0x1F:
            t = (t << 8) | buf[off]
            off += 1
        ln = buf[off]
        off += 1
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(buf[off:off + k], "big")
            off += k
        return t, buf[off:off + ln], off + ln

    out = {}
    off = 0
    while off < len(der):
        start = off
        tag, _v, off = split(der, off)
        if tag not in (0xB3, 0xB4):
            continue
        pe = ProfileElement.from_der(der[start:off], pe_sequence=None)
        for label, key in DER_NAME.items():
            f = pe.files.get(key)
            if f is not None and label not in out:
                out[label] = f._body or b""
    return out


TRIM_ACT = {"EF.PLMNwAcT", "EF.OPLMNwAcT", "EF.HPLMNwAcT"}
TRIM_LIST = {"EF.FPLMN"}


def strip_ff(b):
    return b.rstrip(b"\xff") if b else b


def norm(label, b):
    """Drop trailing 'nothing here' entries so sizes are not a difference.

    A PLMNwAcT file padded to 250 bytes and one padded to 170 are the same
    statement -- "no preferred PLMN" -- as long as every trailing slot is the
    empty entry. Comparing raw bytes would call that a mismatch.
    """
    if not b:
        return b
    if label in TRIM_ACT:
        while len(b) >= 5 and b[-5:] == b"\xff\xff\xff\x00\x00":
            b = b[:-5]
        return b
    if label in TRIM_LIST:
        while len(b) >= 3 and b[-3:] == b"\xff\xff\xff":
            b = b[:-3]
        return b
    return b.rstrip(b"\xff")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    der_path = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else "COM4"

    card = read_card(port)
    prof = read_der(der_path)
    print(f"profile: {der_path}\n")
    print(f"  {'field':<13} {'card':<34} {'profile':<34} ")
    print(f"  {'-'*13} {'-'*34} {'-'*34} ")
    same = diff = 0
    for label, _fid, _s, _r in FIELDS:
        c, p = card.get(label), prof.get(label)
        cs = "(absent)" if c is None else strip_ff(c).hex().upper()
        ps = "(absent)" if p is None else strip_ff(p).hex().upper()
        eq = (norm(label, c or b"") == norm(label, p or b""))
        same += eq
        diff += not eq
        print(f"  {label:<13} {cs[:32]:<34} {ps[:32]:<34} "
              f"{'same' if eq else 'DIFF'}")
    print(f"\n{same} same, {diff} different")
    for label, _fid, _s, _r in FIELDS:
        c, p = card.get(label), prof.get(label)
        if c is not None and p is not None and len(c) != len(p):
            print(f"  note: {label} is {len(c)}B on the card, {len(p)}B in the "
                  f"profile (padding only, see norm())")
    return 0


if __name__ == "__main__":
    sys.exit(main())
