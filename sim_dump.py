#!/usr/bin/env python3
"""Dump the public / user-visible fields of a GSM/USIM card.

Works on a plain SIM as well as on a USIM. The USIM application lives in
ADF.USIM (FID 7FD0), while a 2G-only SIM keeps EF.IMSI in DF.GSM (7F20) --
reading only 7F20 is why a USIM looks empty. This tries both, plus AID select.

Secrets (Ki/OPc/Kc) are deliberately not read: they are not reachable through
READ BINARY at all. --auth runs one GSM algorithm round trip, which only shows
that the USIM applet is alive and has *a* key, not that the key is right.

    python sim_dump.py [COM4] [19200] [--auth]

The transport (T=0 framing, NULL bytes, Le=0 handling) lives in euicc_lpa.py so
there is exactly one implementation of it.
"""
import sys

from euicc_lpa import (EF, ROOTS, ROOTS_WITH_TELECOM, USIM_AIDS, Phoenix)

PORT = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].upper().startswith("COM") else "COM4"
BAUD = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 19200
DO_AUTH = "--auth" in sys.argv


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

    def select(self, fid, tries=2):
        for _ in range(tries):
            if self.apdu(0x00, 0xA4, 0x00, 0x0C, bytes.fromhex(fid))[1].startswith("9"):
                return True
        return False

    def select_aid(self, aid):
        _d, sw = self.apdu(0x00, 0xA4, 0x04, 0x00, bytes.fromhex(aid))
        return sw.startswith("9"), sw

    def read_bin(self, fid, n, tries=2):
        for _ in range(tries):
            if self.select(fid):
                d, sw = self.apdu(0x00, 0xB0, 0x00, 0x00, le=n)
                if sw.startswith("9"):
                    return d
        return b""

    def read_rec(self, fid, rec, n, tries=2):
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


def dec_plmn(b3):
    """3-byte PLMN -> '46000', or None for FFFFFF."""
    if len(b3) < 3 or b3 == b"\xff\xff\xff":
        return None
    mcc1, mcc2 = b3[0] & 0x0F, b3[0] >> 4
    mcc3, mnc3 = b3[1] & 0x0F, b3[1] >> 4
    mnc1, mnc2 = b3[2] & 0x0F, b3[2] >> 4
    mcc = f"{mcc1}{mcc2}{mcc3}"
    mnc = f"{mnc1}{mnc2}" if mnc3 == 0x0F else f"{mnc3}{mnc1}{mnc2}"
    return mcc + mnc


def plmn_list(raw, step=5, with_act=False):
    out = []
    for i in range(0, len(raw) - step + 1, step):
        p = dec_plmn(raw[i:i + 3])
        if p:
            out.append(p + (f"/{raw[i + 3:i + 5].hex().upper()}" if with_act else ""))
    return out


def decode_smsp(rec):
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
                return {"alpha": alpha, "ton_npi": rec[i],
                        "digits": len(digits), "smsc": prefix + digits}
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
    print("ICCID :", bcd(sim.read_bin(EF.ICCID, 10)).rstrip("F"))

    # Which application root holds the subscription? USIM -> 7FD0,
    # 2G SIM -> 7F20, some cards -> 7FFF.
    root, imsi = None, ""
    for fid in ROOTS:
        sim.select("3F00")
        if not sim.select(fid):
            continue
        d = sim.read_bin(EF.IMSI, 9)
        if d and len(d) >= 9:
            root, imsi = fid, swap_imsi(d[1:1 + d[0]])
            break
    print(f"USIM  : {'ADF at ' + root if root else 'not reachable by FID'}   IMSI: {imsi or '-'}")

    if not root:
        for aid in USIM_AIDS:
            ok, sw = sim.select_aid(aid)
            print(f"        AID {aid}: {sw}")
            if ok:
                break
    else:
        # confirm what the AID route says, it matters for a phone
        res = []
        for aid in USIM_AIDS:
            ok, sw = sim.select_aid(aid)
            res.append(f"{aid[-6:]}={sw}")
            if ok:
                break
        print("        AID select:", "  ".join(res))

    if not root:
        print("        USIM/GSM application 都选不上 —— 卡不会给手机提供服务")
        ph.close()
        return 1

    sim.select("3F00")
    sim.select(root)

    d = sim.read_bin(EF.ACC, 2)
    if d:
        print("ACC   :", d.hex().upper())
    d = sim.read_bin(EF.AD, 4)
    if d:
        print("EF_AD :", d.hex(" ").upper(),
              f"(MNC len={d[0] & 0x0F}, OPLMN={d[1:4].hex().upper()})")
    d = sim.read_bin(EF.SPN, 17)
    if d:
        raw = d[1:].rstrip(b"\xFF")
        while raw and raw[0] < 0x20:
            raw = raw[1:]
        print("SPN   :", raw.decode("latin-1", "replace"))
    d = sim.read_bin(EF.FPLMN, 12)
    if d:
        print("FPLMN :", " ".join(plmn_list(d, 3)) or "(none)")
    d = sim.read_bin(EF.PLMNwAcT, 170)
    if d:
        print("PLMNSEL:", " ".join(plmn_list(d)) or "(none)")
    d = sim.read_bin(EF.HPLMNwAcT, 250)
    if d:
        print("HPLMN :", " ".join(plmn_list(d)) or "(none)")
    d = sim.read_bin(EF.UST, 15)
    if d:
        print("UST   :", d.hex().upper())
    d = sim.read_bin(EF.KEYS, 33)
    if d:
        # EF.KEYS is 33 bytes: key-set version + K + OPc in the SAIP layout, but
        # in a downloaded profile it is left as 07 FF*32 -- the eUICC's
        # personalisation agent takes the real keys from the A4 akaParameter
        # element and keeps them in the applet, never in this file. So an
        # all-FF tail here is normal and says nothing about whether the keys work.
        tail = d[1:].rstrip(b"\xff")
        print("KEYS  :", d.hex().upper(),
              "  (07 FF*32 = 未个人化，正常)" if not tail else "")

    sim.select("3F00")
    d = sim.read_bin(EF.FF03, 5)
    if d:
        print("R1-R5 :", d.hex().upper())

    smsp = None
    for df in ROOTS_WITH_TELECOM:
        sim.select("3F00")
        if sim.select(df):
            smsp = decode_smsp(sim.read_rec(EF.SMSP, 1, 0x24))
            if smsp:
                break
    if smsp:
        print(f"SMSP  : {smsp['smsc']}  (alpha='{smsp['alpha']}')")

    sim.select("3F00")
    sim.select(root)
    d = sim.read_rec(EF.MSISDN, 1, 0x22)
    if d:
        al = d[0]
        print("MSISDN:", bcd(d[2 + al:]).rstrip("F") or "(empty)")

    if DO_AUTH:
        sim.select("3F00")
        sim.select(root)
        rand = bytes(range(16))
        # case 4: Lc=16 RAND, Le=12 (SRES 4 + Kc 8)
        apdu = bytes([0xA0, 0x88, 0x00, 0x00, 0x10]) + rand + bytes([12])
        payload, sw = ph.transceive(apdu)
        print(f"AUTH  : {sw.hex().upper()}  {payload.hex().upper() or '(empty)'}"
              f"   <- SRES(4)+Kc(8); 有返回只说明 applet 活着且有一把密钥，"
              f"不说明这把密钥是对的")

    if ph.echo_errors:
        print(f"        (echo errors: {ph.echo_errors})")
    ph.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
