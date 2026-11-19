#!/usr/bin/env python3
"""Python LPA prototype: ES9+ / ES10b profile download over the Phoenix reader.

Speaks ES9+ over plain HTTPS and builds the ES10b TLVs by hand, the same way
the Dart app and lpac do. Keeping the bytes under our control matters: asn1tools
re-encoding does not produce what this card accepts.

    python euicc_download.py "LPA:1$smdp.example.com$MATCHING-ID" [COM4]
"""
import base64
import json
import sys
import time

import requests

from euicc_lpa import Phoenix

requests.packages.urllib3.disable_warnings()

ISDR_AID = "A0000005591010FFFFFFFF8900000100"


# ------------------------------------------------------------------- helpers
def parse_activation_code(code: str):
    code = code.strip()
    if code.startswith("LPA:"):
        code = code[4:]
    parts = code.split("$")
    if len(parts) < 3:
        raise ValueError(f"bad activation code: {code}")
    return parts[1], parts[2], (parts[3] if len(parts) > 3 else None)


def read_tlv(data: bytes, off: int = 0):
    """One DER TLV -> (tag, content, next_offset). Only what RSP needs."""
    tag = data[off]
    off += 1
    if tag & 0x1F == 0x1F:
        tag = (tag << 8) | data[off]
        off += 1
    ln = data[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[off:off + n], "big")
        off += n
    return tag, data[off:off + ln], off + ln


def decode_choice_response(resp: bytes, outer: int):
    """Decode the BF38 / BF21 CHOICE replies without pulling in an ASN.1 stack.

    Returns ("ok", None) or ("error", <code>). Both messages are a SEQUENCE
    whose single child is either [0] (ok) or [1] (error); the error payload
    carries an INTEGER error code.
    """
    tag, body, _ = read_tlv(resp)
    if tag != outer:
        return "unknown", None
    alt, content, _ = read_tlv(body)
    if alt == 0xA0:
        return "ok", None
    off, code = 0, None
    while off < len(content):
        child, value, off = read_tlv(content, off)
        if child == 0x02:
            code = int.from_bytes(value, "big")
    return "error", code


def tlv(tag: bytes, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return tag + bytes([n]) + content
    if n < 0x100:
        return tag + b"\x81" + bytes([n]) + content
    return tag + b"\x82" + n.to_bytes(2, "big") + content


# ---------------------------------------------------------------------- card
class EuiccCard:
    """ISD-R on a logical channel, STORE DATA block chaining on top of Phoenix."""

    def __init__(self, ph: Phoenix):
        self.ph = ph
        self.channel = 0

    @property
    def cla(self):
        return 0x00 | self.channel

    def select_isdr(self, aid=ISDR_AID):
        d, sw = self.ph.send("0070000001")
        if sw != "9000":
            raise IOError(f"MANAGE CHANNEL failed: {sw}")
        self.channel = d[0]
        d, sw = self.ph.send(f"{self.cla:02X}A40400{len(aid)//2:02X}{aid}")
        if sw != "9000":
            raise IOError(f"SELECT ISD-R failed: {sw}")
        return d

    def _store_data(self, payload: bytes, label="", chunk=120):
        cla = 0x80 | self.channel
        blocks = [payload[i:i + chunk] for i in range(0, len(payload), chunk)]
        data, sw = b"", b"\x90\x00"
        for idx, blk in enumerate(blocks):
            last = idx == len(blocks) - 1
            p1 = 0x91 if last else 0x11
            apdu = bytes([cla, 0xE2, p1, idx & 0xFF, len(blk)]) + blk
            d, sw = self.ph.transceive(apdu)
            if not last:
                if sw != b"\x90\x00":
                    raise IOError(f"{label} block {idx} failed: {sw.hex().upper()}")
                continue
            data = d
        # The card answers 61xx when a response is waiting (61 00 = 256 bytes).
        while len(sw) == 2 and sw[0] == 0x61:
            more, sw = self.ph.transceive(
                bytes([self.cla, 0xC0, 0x00, 0x00, sw[1]]))
            data += more
        if sw != b"\x90\x00":
            raise IOError(f"{label} failed: {sw.hex().upper()}")
        return data

    def get_euicc_info1(self):
        return self._store_data(bytes.fromhex("BF2000"), "GetEUICCInfo1")

    def get_euicc_challenge(self):
        return self._store_data(bytes.fromhex("BF2E00"), "GetEUICCChallenge")[-16:]

    def authenticate_server(self, req: bytes):
        return self._store_data(tlv(b"\xbf\x38", req), "AuthenticateServer")

    def prepare_download(self, body: bytes):
        """ES10b.PrepareDownload (BF21): smdpSigned2 + smdpSignature2 + smdpCertificate."""
        return self._store_data(tlv(b"\xbf\x21", body), "PrepareDownload")


# ----------------------------------------------------------------------- es9
def es9_post(smdp: str, fn: str, body: dict) -> dict:
    url = f"https://{smdp}/gsma/rsp2/es9plus/{fn}"
    r = requests.post(
        url, json=body, verify=False, timeout=30,
        headers={
            "User-Agent": "gsma-rsp-lpad",
            "X-Admin-Protocol": "gsma/rsp/v2.2.0",
            "Content-Type": "application/json",
        },
    )
    try:
        return r.json()
    except ValueError:
        raise RuntimeError(f"{fn}: HTTP {r.status_code} {r.text[:200]}")


def check_status(resp: dict, fn: str):
    st = resp.get("header", {}).get("functionExecutionStatus", {})
    if st.get("status") != "Executed-Success":
        raise RuntimeError(f"{fn} failed: {json.dumps(st, indent=2)}")
    return resp


def build_auth_server_request(init_resp: dict, matching_id: str, tac: bytes):
    """Hand-rolled AuthenticateServerRequest content, byte-compatible with the app."""
    signed1 = base64.b64decode(init_resp["serverSigned1"])
    sig1 = base64.b64decode(init_resp["serverSignature1"])
    ci_id = base64.b64decode(init_resp["euiccCiPKIdToBeUsed"])
    cert = base64.b64decode(init_resp["serverCertificate"])

    print(f"  signed1[{len(signed1)}]: {signed1[:6].hex().upper()}")
    print(f"  sig1   [{len(sig1)}]: {sig1[:6].hex().upper()}")
    print(f"  ci_id  [{len(ci_id)}]: {ci_id.hex().upper()}")
    print(f"  cert   [{len(cert)}]: {cert[:6].hex().upper()}")

    device_info = tlv(b"\xa1", tlv(b"\x80", tac) + tlv(b"\xa1", b""))
    ctx = tlv(b"\xa0", tlv(b"\x80", matching_id.encode()) + device_info)

    # signed1 / sig1 / ci_id / cert already carry their own tag+length.
    return signed1 + sig1 + ci_id + cert + ctx


def split_tlvs(data: bytes):
    """Split a buffer into consecutive raw TLVs (tag+len+value)."""
    out, i = [], 0
    while i < len(data):
        start = i
        b = data[i]; i += 1
        if b & 0x1F == 0x1F:      # two-byte tag
            i += 1
        ln = data[i]; i += 1
        if ln == 0x81:
            ln = data[i]; i += 1
        elif ln == 0x82:
            ln = int.from_bytes(data[i:i + 2], "big"); i += 2
        elif ln == 0x83:
            ln = int.from_bytes(data[i:i + 3], "big"); i += 3
        i += ln
        out.append(data[start:i])
    return out


def load_bpp(card, bpp: bytes):
    """Send the bound profile package element by element (SGP.22 2.5.5)."""
    if bpp[:2] != b"\xbf\x36":
        raise ValueError(f"unexpected BPP tag: {bpp[:2].hex()}")
    # strip the outer BF36 header
    i = 2
    ln = bpp[i]; i += 1
    if ln == 0x81:
        ln = bpp[i]; i += 1
    elif ln == 0x82:
        ln = int.from_bytes(bpp[i:i + 2], "big"); i += 2
    elif ln == 0x83:
        ln = int.from_bytes(bpp[i:i + 3], "big"); i += 3
    body = bpp[i:i + ln]

    elements = split_tlvs(body)
    print(f"  {len(elements)} elements, total {len(body)}B")
    for idx, el in enumerate(elements):
        tag = el[:2].hex().upper() if el[0] & 0x1F == 0x1F else el[:1].hex().upper()
        t0 = time.time()
        try:
            data = card._store_data(el, f"BPP element {idx} ({tag})")
        except Exception as e:
            print(f"  element {idx} ({tag}, {len(el)}B) FAILED: {e}")
            return False
        print(f"  element {idx} ({tag}, {len(el):6d}B) ok "
              f"{len(data)}B rsp, {(time.time()-t0)*1000:6.0f} ms")
    return True


# ---------------------------------------------------------------------- main
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    smdp, matching_id, _cc = parse_activation_code(sys.argv[1])
    port = "COM4"
    stop_at = "bpp"          # authclient | bpp | load
    for a in sys.argv[2:]:
        if a.startswith("COM"):
            port = a
        elif a == "--load":
            stop_at = "load"
        elif a.startswith("--stop="):
            stop_at = a.split("=", 1)[1]
    print(f"SM-DP+     : {smdp}")
    print(f"Matching ID: {matching_id}")

    ph = Phoenix(port, 19200)
    atr = ph.reset()
    print(f"ATR        : {atr.hex(' ').upper() or '(nothing)'}")
    if not atr:
        print("卡无响应，先拔插读卡器")
        ph.close()
        return 1
    time.sleep(0.2)

    card = EuiccCard(ph)
    card.select_isdr()
    print(f"ISD-R      : selected on channel {card.channel}")

    info1 = card.get_euicc_info1()
    challenge = card.get_euicc_challenge()
    print(f"Info1      : {len(info1)}B   Challenge: {challenge.hex().upper()}")

    init = es9_post(smdp, "initiateAuthentication", {
        "euiccChallenge": base64.b64encode(challenge).decode(),
        "euiccInfo1": base64.b64encode(info1).decode(),
        "smdpAddress": smdp,
    })
    check_status(init, "initiateAuthentication")
    print(f"transactionId = {init['transactionId']}")

    # Same 4-byte TAC the Dart app sends.
    req = build_auth_server_request(init, matching_id, b"\x35\x38\x37\x41")
    print(f"\n--- AuthenticateServer: {len(req)} bytes ---")
    print(f"  head: {req[:24].hex().upper()}")
    print(f"  tail: {req[-30:].hex().upper()}")

    t0 = time.time()
    resp = card.authenticate_server(req)
    print(f"  response: {len(resp)}B in {(time.time()-t0)*1000:.0f} ms")
    print(f"  {resp.hex().upper()[:100]}")

    choice, code = decode_choice_response(resp, 0xBF38)
    print(f"  choice: {choice}" + (f" (code {code})" if code is not None else ""))
    if choice != "ok":
        ph.close()
        return 1

    print("\n[OK] AuthenticateServer passed.")
    as_resp = resp

    # ---- ES9+ AuthenticateClient -------------------------------------------
    ac = es9_post(smdp, "authenticateClient", {
        "transactionId": init["transactionId"],
        "authenticateServerResponse": base64.b64encode(as_resp).decode(),
    })
    check_status(ac, "authenticateClient")
    tid = bytes.fromhex(init["transactionId"])
    signed2 = base64.b64decode(ac["smdpSigned2"])
    sig2 = base64.b64decode(ac["smdpSignature2"])
    cert2 = base64.b64decode(ac["smdpCertificate"])

    print(f"\n--- PrepareDownload ({len(signed2)+len(sig2)+len(cert2)}B) ---")
    t0 = time.time()
    ac_resp = card.prepare_download(signed2 + sig2 + cert2)
    print(f"  response: {len(ac_resp)}B in {(time.time()-t0)*1000:.0f} ms")
    print(f"  {ac_resp.hex().upper()[:80]}")
    choice, code = decode_choice_response(ac_resp, 0xBF21)
    print(f"  choice: {choice}" + (f" (code {code})" if code is not None else ""))

    if stop_at == "authclient":
        print("\n[STOP] after AuthenticateClient -- card NOT modified.")
        ph.close()
        return 0

    # ---- ES9+ GetBoundProfilePackage ---------------------------------------
    gb = es9_post(smdp, "getBoundProfilePackage", {
        "transactionId": init["transactionId"],
        "prepareDownloadResponse": base64.b64encode(ac_resp).decode(),
    })
    check_status(gb, "getBoundProfilePackage")
    bpp = base64.b64decode(gb["boundProfilePackage"])
    import hashlib
    print(f"\nboundProfilePackage: {len(bpp)}B  sha256={hashlib.sha256(bpp).hexdigest()[:32]}")
    print(f"  head: {bpp[:16].hex().upper()}")

    if stop_at == "bpp":
        print("\n[STOP] after GetBoundProfilePackage -- card NOT modified.")
        print("       Compare this sha256 with the app's log.")
        ph.close()
        return 0

    # ---- ES10b LoadBoundProfilePackage -------------------------------------
    print("\n--- LoadBoundProfilePackage ---")
    ok = load_bpp(card, bpp)
    print(f"\n[{'OK' if ok else 'FAILED'}] LoadBoundProfilePackage")
    ph.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
