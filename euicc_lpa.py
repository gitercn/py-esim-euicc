#!/usr/bin/env python3
"""Minimal LPA (ES10a/b/c) over a Phoenix serial reader.

This is the Python prototype of what NekokoLPA's Phoenix adapter has to do.
If this works, the same byte sequence is what the Flutter app must produce.

    python euicc_lpa.py [COM4] [19200]
    python euicc_lpa.py COM4 19200 --reset-only
"""
import sys
import time

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
        self.s = serial.Serial(
            port, baud, bytesize=8, parity=serial.PARITY_EVEN, stopbits=2,
            timeout=0.05, xonxoff=0, rtscts=0,
        )
        self.echo_errors = 0

    def close(self):
        self.s.close()

    def reset(self, hold=0.30):
        self.s.rts = False
        self.s.dtr = False
        time.sleep(0.30)
        self.s.reset_input_buffer()
        self.s.rts = True
        time.sleep(hold)
        self.s.reset_input_buffer()
        self.s.rts = False

        atr = b""
        quiet = 0
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

    def transceive(self, apdu):
        """T=0, case 1/2/3/4. Returns (data, sw)."""
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
        # pb is already SW1
        if p3 == 0:
            return b"", bytes([pb]) + self._rx(1, 1.5)
        body = bytes([pb]) + self._rx(p3 - 1, 6.0)
        return body, self._read_sw()

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
