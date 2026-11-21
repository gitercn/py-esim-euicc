#!/usr/bin/env python3
"""Minimal LPA (ES10a/b/c) over a Phoenix serial reader.

This is the Python prototype of what NekokoLPA's Phoenix adapter has to do.
If this works, the same byte sequence is what the Flutter app must produce.

    python euicc_lpa.py [COM4] [19200]
    python euicc_lpa.py COM4 19200 --reset-only
"""
import sys
import time
from types import SimpleNamespace

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].upper().startswith("COM") else "COM4"
try:
    BAUD = int(sys.argv[2]) if len(sys.argv) > 2 else 19200
except ValueError:
    BAUD = 19200

# SGP.22 ISD-R. First one is the spec value, the other two are the AIDs
# NekokoLPA tries.
ISDR_AIDS = [
    "A0000005591010FFFFFFFF8900000100",
    "A0000005591010FFFFFFFF8900050500",
    "A0000005591010000000008900000300",
]


# ---------------------------------------------------------------- TLV helpers
def tlv(tag, value=b""):
    if tag > 0xFF:
        head = bytes([(tag >> 8) & 0xFF, tag & 0xFF])
    else:
        head = bytes([tag])
    n = len(value)
    if n < 0x80:
        return head + bytes([n]) + value
    if n < 0x100:
        return head + bytes([0x81, n]) + value
    return head + bytes([0x82, (n >> 8) & 0xFF, n & 0xFF]) + value


def parse_tlv(data, depth=0):
    """Yield (tag, value, children_or_None) recursively, best effort."""
    i = 0
    while i < len(data):
        b0 = data[i]
        i += 1
        if b0 & 0x1F == 0x1F:  # two-byte tag
            if i >= len(data):
                return
            b1 = data[i]
            i += 1
            tag = (b0 << 8) | b1
        else:
            tag = b0
        if i >= len(data):
            return
        ln = data[i]
        i += 1
        if ln == 0x81:
            ln = data[i]
            i += 1
        elif ln == 0x82:
            ln = (data[i] << 8) | data[i + 1]
            i += 2
        elif ln == 0x83:
            ln = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
            i += 3
        value = data[i:i + ln]
        i += ln
        constructed = bool(tag & 0x20) or (tag & 0xFF00) in (0xBF00, 0xBF00)
        yield tag, value, constructed


def dump(data, indent=0):
    pad = "  " * indent
    try:
        items = list(parse_tlv(data))
    except Exception:
        print(f"{pad}{data.hex().upper()}")
        return
    for tag, value, _ in items:
        name = f"{tag:04X}" if tag > 0xFF else f"{tag:02X}"
        inner = None
        if len(value) > 1:
            try:
                inner = list(parse_tlv(value))
            except Exception:
                inner = None
        if inner and (tag & 0x20 or tag >= 0xBF00):
            print(f"{pad}{name} ({len(value)}B)")
            dump(value, indent + 1)
        else:
            printable = all(0x20 <= c < 0x7F for c in value) and value
            extra = f' "{value.decode()}"' if printable else ""
            print(f"{pad}{name} = {value.hex().upper()}{extra}")


# ------------------------------------------------------------------ transport
class Phoenix:
    def __init__(self, port=PORT, baud=BAUD):
        self.port = port
        self.baud = baud
        self.s = self._open()
        self.echo_errors = 0

    def _open(self):
        return serial.Serial(
            self.port, self.baud, bytesize=8, parity=serial.PARITY_EVEN,
            stopbits=2, timeout=0.05, xonxoff=0, rtscts=0,
        )

    def close(self):
        self.s.close()

    def _pulse(self, low, hold):
        """One reset cycle. RTS low = reset asserted, high = card running."""
        self.s.rts = False
        self.s.dtr = False
        time.sleep(low)
        self.s.reset_input_buffer()
        self.s.rts = True
        time.sleep(hold)
        self.s.reset_input_buffer()
        self.s.rts = False

        atr, quiet = b"", 0
        end = time.time() + 3.0
        while time.time() < end:
            chunk = self.s.read(64)
            if chunk:
                atr += chunk
                quiet = 0
            else:
                quiet += 1
                if atr and quiet > 15:
                    break
        return atr

    def reset(self, hold=0.30, pulses=4):
        """Power-cycle the card and read its ATR.

        This PL2303 reader is marginal at 19200 8E2: a fresh open sometimes
        leaves the line idle-low and the read comes back as a run of 0x00,
        and repeating the pulse on the same handle does not clear it. Closing
        and reopening the port does. Retry until the answer looks like an ATR
        (TS byte 0x3B/0x3F, not a run of zeros).
        """
        atr = b""
        for i in range(pulses):
            if i:
                self.s.close()
                time.sleep(0.40)
                self.s = self._open()
            atr = self._pulse(0.30 if i == 0 else 0.60, hold)
            if len(atr) >= 2 and atr[0] in (0x3B, 0x3F) and atr.count(0) < len(atr):
                return atr
        return atr

    def _tx(self, data):
        for b in data:
            self.s.write(bytes([b]))
            echo = self.s.read(1)
            if echo != bytes([b]):
                self.echo_errors += 1

    def _rx(self, n, timeout):
        buf = b""
        end = time.time() + timeout
        while len(buf) < n and time.time() < end:
            chunk = self.s.read(n - len(buf))
            if chunk:
                buf += chunk
        return buf

    def _first_byte(self, timeout=1.5):
        b = self._rx(1, timeout)
        while b and b[0] == 0x60:
            b = self._rx(1, timeout)
        return b[0] if b else None

    def _read_sw(self, timeout=8.0):
        """SW1SW2, skipping the T=0 NULL bytes (0x60) a busy card emits.

        A chunked STORE DATA takes a while per block; treating NULLs as a
        status word aborts a transaction the card is still finishing, and the
        link then stays desynchronised until the reader is replugged.
        """
        sw1 = None
        end = time.time() + timeout
        while time.time() < end:
            b = self._rx(1, 0.4)
            if not b:
                continue
            if sw1 is None:
                if b[0] == 0x60:
                    continue
                sw1 = b[0]
            else:
                return bytes([sw1, b[0]])
        return bytes([sw1]) if sw1 is not None else b""

    def _read_body(self, le):
        """After a case-4 data field: either Le bytes + SW, or a bare SW."""
        first = self._rx(1, 6.0)
        if not first:
            return b"", b""
        b = first[0]
        if b == 0x61 or (b & 0xF0) in (0x60, 0x90, 0x62, 0x63,
                                       0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F):
            return b"", first + self._rx(1, 1.5)
        return first + self._rx(le - 1, 6.0), self._rx(2, 3.0)

    def transceive_ext(self, apdu, sw_timeout=60.0):
        """T=0 mapping of an extended case-3 APDU: 00 LcHi LcLo <data>.

        The 5-byte header carries Lc=00; the two length bytes and the data go
        in the data phase, after the procedure byte. This is the only way to
        hand the card more than 255 bytes in a single command.
        """
        ins = apdu[1]
        lc = (apdu[5] << 8) | apdu[6]
        body = len(apdu) - 7
        if body != lc:
            raise ValueError(
                f"malformed extended APDU: Lc={lc} but {body} data bytes")
        self._tx(apdu[:5])
        pb = self._first_byte(2.0)
        if pb is None:
            raise IOError(f"no procedure byte (echoErrors={self.echo_errors})")
        if pb != ins:
            # Card refused the header outright (usually 67xx / 6E00):
            # do NOT push the payload, it would desynchronise the link.
            sw2 = self._rx(1, 1.5)
            return b"", bytes([pb]) + sw2
        self._tx(apdu[5:])
        return b"", self._read_sw(sw_timeout)

    def transceive(self, apdu, _retry_6c=True):
        """T=0, case 1/2/3/4. Returns (data, sw)."""
        if len(apdu) >= 7 and apdu[4] == 0x00:
            return self.transceive_ext(apdu)
        ins, p3 = apdu[1], apdu[4]
        # GET RESPONSE with Le=0 means 256 bytes (ISO 7816-4).
        if ins == 0xC0 and p3 == 0:
            p3 = 256
        body = len(apdu) - 5
        # A case-4 APDU may carry a trailing Le byte after Lc data bytes.
        # T=0 conveys Le in the header, so it must NOT be transmitted: sending
        # it makes the card read one byte too many and desynchronise.
        # Refuse malformed case-3/4 APDUs: the card would read past Lc and
        # go silent until it is physically power-cycled.
        if body > 0 and body != p3 and body != p3 + 1:
            raise ValueError(
                f"malformed APDU: Lc={p3} but {body} data bytes (refusing to send)")
        lc = p3 if p3 <= body else body
        has_data = lc > 0
        le = apdu[5 + p3] if body > p3 else 0
        self._tx(apdu[:5])

        pb = self._first_byte()
        if pb is None:
            raise IOError(f"no procedure byte (echoErrors={self.echo_errors})")

        # 6Cxx = "wrong Le, use xx". T=0 has no other way to say it, and the
        # card sends no data with it. Treating 6C as SW1 and then reading
        # p3-1 bytes as payload desynchronises the link -- which is why every
        # READ BINARY whose Le did not match the file size used to come back
        # empty and get skipped.
        if not has_data and pb == 0x6C:
            sw2 = self._rx(1, 1.5)
            if not sw2:
                return b"", b"\x6c\x00"
            new_le = sw2[0]
            if _retry_6c and new_le != apdu[4]:
                return self.transceive(apdu[:4] + bytes([new_le]), _retry_6c=False)
            return b"", b"\x6c" + sw2

        if has_data:
            if pb != ins:
                sw2 = self._rx(1, 1.0)
                return b"", bytes([pb]) + sw2
            self._tx(apdu[5:5 + lc])
            if le:
                return self._read_body(le)
            return b"", self._read_sw()

        if pb == ins:
            body = self._rx(p3, 6.0)
            return body, self._read_sw()
        # pb is SW1, so the card answered with a status word and no data at all
        # (6700 wrong length, 6A82 file not found, 6981 wrong structure, ...).
        # Reading p3-1 bytes here would eat the next command's bytes and leave
        # the link desynchronised -- that is how a READ RECORD with a slightly
        # wrong Le turned into "2B6700" and a dead session.
        sw2 = self._rx(1, 1.5)
        return b"", bytes([pb]) + sw2

    def send(self, apdu_hex):
        data, sw = self.transceive(bytes.fromhex(apdu_hex))
        # 61xx: more data waiting
        # GET RESPONSE must use the logical channel of the command.
        gr_cla = bytes.fromhex(apdu_hex)[0] & 0x03
        while len(sw) == 2 and sw[0] == 0x61:
            more, sw = self.transceive(bytes([gr_cla, 0xC0, 0x00, 0x00, sw[1]]))
            data += more
        return data, sw.hex().upper()


def store_data(ph, payload_hex, label=""):
    """ES10x entry point: STORE DATA, then drain 61xx."""
    p = bytes.fromhex(payload_hex)
    apdu = bytes([0x80, 0xE2, 0x91, 0x00, len(p)]) + p
    data, sw = ph.transceive(apdu)
    gr_cla = apdu[0] & 0x03
    while len(sw) == 2 and sw[0] == 0x61:
        more, sw = ph.transceive(bytes([gr_cla, 0xC0, 0x00, 0x00, sw[1]]))
        data += more
    return data, sw.hex().upper()


# ------------------------------------------------------- USIM filesystem side
# After a profile is enabled the eUICC runs a REFRESH, which in a Phoenix reader
# is just an RTS toggle. Only then does ADF.USIM exist on the contact interface.
# ---------------------------------------------------------------- AID table
# Every AID that appears anywhere in this repo. The per-script lists below
# compose from these, so the hex string itself lives in exactly one place.
AID = {
    "stock":  "A0000000871002FF49FF0589",           # 12B, SGP.26 test UPP
    "usim":   "A0000000871002FF33FFFF8900000100",   # standard USIM, 16B
    "usim15": "A0000000871002FF33FFFF89000001",     # the 15B form some cards use
    "cmcc":   "A0000000871002FF86FFFF8900000100",   # CMCC variant
    "cmcc2g": "A0000000871002FF86FFFF89FFFFFFFF",   # the 2G working card's AID
    "isim":   "A0000000871004FF33FFFF8900000100",
    "csim":   "A0000000871006FF33FFFF8900000100",
}

USIM_AIDS = [
    # 必须排第一。这张 eUICC 的 EF.DIR 里登记的还是标准 16B AID，但真正能
    # SELECT 成功的只有 stock 这条 12B AID（实测 9000，其他全是 6A82）。
    # 少了它，sim_dump 会打出一行「AID select 全 6A82」，看着像卡废了。
    AID["stock"],
    AID["usim"],
    AID["usim15"],
    AID["cmcc"],
    AID["cmcc2g"],
]
MF = "3F00"
DF_7FF0 = "7FF0"
EF_FF03 = "FF03"

# What probe_after_install.py reports on, in the order it prints them. A
# superset of USIM_AIDS: it also covers what a phone might ask for (ISIM/CSIM)
# and what the stock test UPP registers.
PROBE_AIDS = [AID["stock"], AID["usim"], AID["usim15"], AID["cmcc"],
              AID["cmcc2g"], AID["isim"], AID["csim"]]


# ---------------------------------------------------------------- EF table
# One table, one truth. Every script that names a file by FID reads it from
# here instead of hard-coding the hex, so a wrong FID gets fixed once.
#   fid -> (name, structure, record length hint)
#   "tr" = transparent (READ BINARY), "lf" = linear fixed (READ RECORD)
EFS = {
    "2FE2": ("EF.ICCID",     "tr", 0),
    "6F07": ("EF.IMSI",      "tr", 0),
    "6F78": ("EF.ACC",       "tr", 0),
    "6FAD": ("EF.AD",        "tr", 0),
    "6F46": ("EF.SPN",       "tr", 0),
    "6F7B": ("EF.FPLMN",     "tr", 0),
    "6F60": ("EF.PLMNwAcT",  "tr", 0),
    "6F61": ("EF.OPLMNwAcT", "tr", 0),
    "6F62": ("EF.HPLMNwAcT", "tr", 0),
    "6F38": ("EF.UST",       "tr", 0),
    "6F31": ("EF.HPPLMN",    "tr", 0),
    "6F08": ("EF.KEYS",      "tr", 0),
    "6F40": ("EF.MSISDN",    "lf", 0x22),
    "6F42": ("EF.SMSP",      "lf", 0x28),
    "2F00": ("EF.DIR",       "lf", 0x21),
    "FF03": ("EF.FF03",      "tr", 0),
}

# Name -> FID as attributes, so call sites read EF.IMSI instead of "6F07".
EF = SimpleNamespace(**{name[3:]: fid for fid, (name, _s, _r) in EFS.items()})

# The subscription lives in a different DF depending on the card: a USIM keeps
# it in ADF.USIM (7FD0), a 2G SIM in DF.GSM (7F20), some in DF.TELECOM (7FFF).
# Reading only one of them is how a USIM ends up looking empty.
ROOTS = ("7FD0", "7FFF", "7F20")
TELECOM = "7F10"
# Some 2G cards keep EF.SMSP in DF.TELECOM instead of the subscription root, so
# the lookup order puts it between the two GSM roots.
ROOTS_WITH_TELECOM = (ROOTS[0], TELECOM, ROOTS[2])

# READ RECORD only succeeds when Le is exactly the record length, and these
# cards return no FCP to read it from, so try the sizes seen in the wild.
REC_LENS = (0x1C, 0x2A, 0x22, 0x28, 0x0C, 0x10, 0x14, 0x18,
            0x1E, 0x20, 0x24, 0x26, 0x2C, 0x30, 0x40, 0x50)


def select_fid(ph, fid):
    """SELECT by FID. P2=0C first (no FCI), fall back to P2=00 + Le."""
    sw = "0000"
    for apdu in (f"00A4000C02{fid}", f"00A4000002{fid}00"):
        _d, sw = ph.send(apdu)
        if sw.startswith("90") or sw.startswith("61"):
            return True
    print(f"  SELECT {fid}: {sw}")
    return False


def select_usim(ph, aid=None):
    """SELECT ADF.USIM. Returns the AID that worked, or None."""
    for candidate in ([aid] if aid else USIM_AIDS):
        _d, sw = ph.send(f"00A40400{len(candidate)//2:02X}{candidate}")
        print(f"  SELECT ADF.USIM {candidate}: {sw}")
        if sw.startswith("90") or sw.startswith("61"):
            return candidate
    return None


def read_ff03(ph, length=5):
    """Walk MF/FF03 then MF/7FF0/FF03 and return the file body, or None.

    The card must already be reset with a profile enabled; this does not touch
    ISD-R at all.
    """
    for path, steps in ((("3F00", "FF03"), [EF_FF03]),
                        (("3F00", "7FF0", "FF03"), [DF_7FF0, EF_FF03])):
        print(f"  [{'/'.join(path)}]")
        if not select_fid(ph, MF):
            continue
        if not all(select_fid(ph, f) for f in steps):
            continue
        data, sw = ph.send(f"00B00000{length:02X}")
        print(f"    READ {length}B: {sw}  {data.hex().upper()}")
        if sw == "9000" and len(data) >= length:
            return data
    return None


# ----------------------------------------------------------------------- main
def main():
    reset_only = "--reset-only" in sys.argv
    ph = Phoenix()
    atr = ph.reset()
    print(f"ATR : {atr.hex(' ').upper() or '(nothing)'}  ({len(atr)} bytes)")
    if not atr:
        print("\n卡没有响应，先拔插一次读卡器再试。")
        ph.close()
        return 1
    if reset_only:
        ph.close()
        return 0

    time.sleep(0.2)

    # 1) Select ISD-R
    selected = None
    for aid in ISDR_AIDS:
        for p2 in ("04", "0C"):
            apdu = f"00A4{p2}00{len(aid)//2:02X}{aid}"
            try:
                data, sw = ph.send(apdu)
            except IOError as e:
                print(f"SELECT {aid} p2={p2}: {e}")
                continue
            print(f"SELECT {aid} p2={p2}: sw={sw} data={data.hex().upper()}")
            if sw.startswith("90") or sw.startswith("61"):
                selected = aid
                break
        if selected:
            break
    if not selected:
        print("\n选不到 ISD-R —— 卡在 APDU 层没有应答。")
        ph.close()
        return 1

    # 2) ES10c GetEuiccData -> EID  (BF3E { 5C 01 5A })
    print("\n--- GetEID (BF3E / tag list 5C->5A) ---")
    try:
        data, sw = store_data(ph, tlv(0xBF3E, tlv(0x5C, b"\x5A")).hex())
        print(f"sw={sw} len={len(data)}")
        dump(data)
        # EID is the 5A inside
        for tag, value, _ in parse_tlv(data):
            if tag == 0x5A:
                print("EID =", value.hex().upper())
    except IOError as e:
        print("failed:", e)

    # 3) ES10b GetEUICCInfo2
    print("\n--- GetEUICCInfo2 (BF22) ---")
    try:
        data, sw = store_data(ph, "BF2200")
        print(f"sw={sw} len={len(data)}")
        dump(data)
    except IOError as e:
        print("failed:", e)

    # 4) ES10c GetProfilesInfo
    print("\n--- GetProfilesInfo (BF2D) ---")
    try:
        data, sw = store_data(ph, "BF2D00")
        print(f"sw={sw} len={len(data)}")
        dump(data)
    except IOError as e:
        print("failed:", e)

    # 5) ES10a GetEuiccConfiguredAddresses (default SM-DP+ / root DS)
    print("\n--- GetEuiccConfiguredAddresses (BF3C) ---")
    try:
        data, sw = store_data(ph, "BF3C00")
        print(f"sw={sw} len={len(data)}")
        dump(data)
    except IOError as e:
        print("failed:", e)

    # 6) ES10b GetEUICCChallenge -- first step of the RSP handshake
    print("\n--- GetEUICCChallenge (BF2E) ---")
    try:
        data, sw = store_data(ph, "BF2E00")
        print(f"sw={sw} len={len(data)}")
        dump(data)
    except IOError as e:
        print("failed:", e)

    # 7) ES10b ListNotification
    print("\n--- ListNotification (BF28) ---")
    try:
        data, sw = store_data(ph, "BF2800")
        print(f"sw={sw} len={len(data)}")
        dump(data)
    except IOError as e:
        print("failed:", e)

    print(f"\nechoErrors={ph.echo_errors}")
    ph.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
