#!/usr/bin/env python3
"""Dump the public / user-visible fields of a GSM/USIM card.

Works on a plain SIM as well as on a USIM: it only reads the files every card
has. Secrets (EF_Kc, EF_BCCH key material, OPc/Ki containers) are deliberately
not read.

    python sim_dump.py [COM4] [19200]

The transport (T=0 framing, NULL bytes, Le=0 handling) lives in euicc_lpa.py so
there is exactly one implementation of it.
"""
import sys

from euicc_lpa import Phoenix

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"
BAUD = int(sys.argv[2]) if len(sys.argv) > 2 else 19200


class Sim:
    """Thin SIM/USIM helpers on top of the shared Phoenix transport."""

    def __init__(self, ph):
        self.ph = ph

    def apdu(self, cla, ins, p1, p2, data=b"", le=0):
        if data:
            apdu = bytes([cla, ins, p1, p2, len(data)]) + data
        else:
            apdu = bytes([cla, ins, p1, p2, le])
        payload, sw = self.ph.transceive(apdu)
        return payload, sw.hex().upper()

    def select(self, fid, tries=3):
        for _ in range(tries):
            if self.apdu(0x00, 0xA4, 0x00, 0x0C, bytes.fromhex(fid))[1].startswith("9"):
                return True
        return False

    def read_bin(self, fid, n, tries=3):
        for _ in range(tries):
            if self.select(fid):
                d, sw = self.apdu(0x00, 0xB0, 0x00, 0x00, le=n)
                if sw.startswith("9"):
                    return d
        return b""

    def read_rec(self, fid, rec, n, tries=3):
        for _ in range(tries):
            if self.select(fid):
                d, sw = self.apdu(0x00, 0xB2, rec, 0x04, le=n)
                if sw.startswith("9"):
                    return d
        return b""


def bcd(raw):
    return "".join("%X%X" % (b & 0x0F, b >> 4) for b in raw)


def swap_imsi(raw):
    s = bcd(raw)
    if len(s) == 16 and s[0] == "9":
        s = s[1:]
    return s


def decode_smsp(rec):
    """Tolerant: some cards store alpha as raw ASCII with no length prefix."""
    if not rec:
        return None
    alpha = ""
    al = rec[0]
    if 0 < al < len(rec) - 2 and all(0x20 <= b < 0x7F for b in rec[1:1 + al]):
        alpha = rec[1:1 + al].decode("latin-1")
    else:
        head = rec[:24].split(b"\xff")[0]
        head = bytes(b for b in head if 0x20 <= b < 0x7F)
        alpha = head.decode("latin-1")
    for i in range(len(rec) - 1):
        if rec[i] in (0x91, 0x81):
            j = i + 1
            while j < len(rec) and rec[j] != 0xFF:
                j += 1
            digits = bcd(rec[i + 1:j]).rstrip("F")
            if len(digits) >= 6 and digits.isdigit():
                prefix = "+" if (rec[i] & 0x70) == 0x10 else ""
                return {"alpha": alpha, "ton_npi": rec[i], "digits": len(digits),
                        "smsc": prefix + digits, "tp_pid": 0}
    return None


def main():
    ph = Phoenix(PORT, BAUD)
    atr = ph.reset()
    print("ATR   :", atr.hex(" ").upper() if atr else "(none)")
    if not atr:
        print("       卡无响应：拔插读卡器，确认开关在 19200 一侧")
        ph.close()
        return 1

    sim = Sim(ph)
    sim.select("3F00")
    print("ICCID :", bcd(sim.read_bin("2FE2", 10)).rstrip("F"))

    sim.select("7F20")
    d = sim.read_bin("6F07", 9)
    if d:
        print("IMSI  :", swap_imsi(d[1:1 + d[0]]))

    d = sim.read_bin("6F78", 2)
    if d:
        print("ACC   :", d.hex().upper())

    d = sim.read_bin("6FAD", 4)
    if d:
        print("EF_AD :", d.hex(" ").upper(),
              f"(MNC len={d[0] & 0x0F}, OPLMN={d[1:4].hex().upper()})")

    d = sim.read_bin("6F46", 17)
    if d:
        raw = d[1:].rstrip(b"\xFF")
        while raw and raw[0] < 0x20:
            raw = raw[1:]
        print("SPN   :", raw.decode("latin-1", "replace"))

    d = sim.read_bin("6F7B", 12)
    if d:
        print("FPLMN :", " ".join(
            d[i:i + 3].hex().upper()
            for i in range(0, len(d), 3)
            if d[i:i + 3] != b"\xff\xff\xff"))

    smsp = None
    for df in ("7F10", "7F20"):
        if sim.select(df):
            smsp = decode_smsp(sim.read_rec("6F42", 1, 0x24))
            if smsp:
                break
    if smsp:
        print(f"SMSP  : {smsp['smsc']}  (alpha='{smsp['alpha']}' "
              f"TON/NPI={smsp['ton_npi']:#04x} digits={smsp['digits']} "
              f"TP-PID={smsp['tp_pid']:#04x})")
    else:
        print("SMSP  : (EF 6F42 not present on this card)")

    d = sim.read_rec("6F40", 1, 0x22)
    if d:
        al = d[0]
        num = bcd(d[2 + al:]).rstrip("F")
        print("MSISDN:", num or "(empty)")

    if ph.echo_errors:
        print(f"        (echo errors: {ph.echo_errors})")
    ph.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
