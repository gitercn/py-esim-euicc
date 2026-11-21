#!/usr/bin/env python3
"""Python LPA prototype: ES9+ / ES10b profile download over the Phoenix reader.

Speaks ES9+ over plain HTTPS and builds the ES10b TLVs by hand, the same way
the Dart app and lpac do. Keeping the bytes under our control matters: asn1tools
re-encoding does not produce what this card accepts.

    python euicc_download.py 'LPA:1$smdp.example.com$MATCHING-ID' [COM4]

Note: use SINGLE quotes. PowerShell expands $rsp / $XXXXX inside double
quotes and silently strips them, leaving "LPA:1.example.com-...".

Options:
    --stop=authclient|bpp   stop before touching the card
    --load                  go all the way to LoadBoundProfilePackage
    --save-bpp=FILE         write the raw BPP to FILE for offline analysis
    --bpp=FILE              skip ES9+ and load a saved BPP directly
    --enable                ES10c EnableProfile after load (refreshFlag=TRUE,
                            retried with explicit FALSE if the card refuses)
    --iccid=ICCID           which profile to enable (default: last disabled one)
    --verify-ff03           reset, then read EF_FF03 (R1-R5) back off the card
    --chunk=N               STORE DATA block size (default 255, i.e. no chaining
                            for short commands; use 120 if a card mishandles 255)
    --segment=N             only used by --mode=stream: cut the raw BPP every N
                            bytes. Cutting mid-TLV breaks DER, so this is not
                            the default any more.
    --mode=tlv|stream|elements  tlv (default): split at TLV boundaries, one
                        complete DER fragment per command -- required by cards
                        that parse each command independently.
                        stream: send BF36 + body as one chained
                            command, as SGP.22 means by "transferred in
                            segments". elements: strip BF36 and send each
                            top-level TLV separately (older ISD-Rs).
    --trace                 dump every APDU and its SW
"""
import base64
import json
import sys
import time

import requests

from euicc_lpa import Phoenix, parse_tlv, read_ff03, select_usim

requests.packages.urllib3.disable_warnings()

ISDR_AID = "A0000005591010FFFFFFFF8900000100"


# ------------------------------------------------------------------- helpers
def parse_activation_code(code: str):
    raw = code.strip()
    code = raw[4:] if raw.upper().startswith("LPA:") else raw
    parts = code.split("$")
    if len(parts) < 3:
        # PowerShell expands $rsp / $XXXXX inside double quotes and eats them,
        # which is by far the most common way this fails on Windows.
        hint = ""
        if raw.upper().startswith("LPA:") and "$" not in raw:
            hint = ("\n  PowerShell 把双引号里的 $rsp / $XXXXX 当变量展开了，"
                    "原样重贴一遍，改用单引号：\n"
                    "    python euicc_download.py 'LPA:1$rsp.example.com$XXXXX-...' COM4\n"
                    "  （cmd.exe / bash 里双引号没问题，但单引号两边都安全）")
        raise ValueError(f"bad activation code: {raw}{hint}")

    host, mid = parts[1].strip(), parts[2].strip()
    if "\\" in host or "/" in host or " " in host:
        # 'LPA:1\$host\$mid' -- single quotes are literal, the backslash stays.
        cleaned = host.replace("\\", "").replace("/", "").replace(" ", "")
        print(f"[警告] SM-DP+ 地址里有多余的转义符 {host!r}，按 {cleaned!r} 处理。\n"
              "       单引号里不需要转义 $，下次直接写 "
              "'LPA:1$host$MATCHING-ID'", file=sys.stderr)
        host = cleaned
    if not host or "." not in host:
        raise ValueError(f"SM-DP+ 地址看起来不对: {host!r}（应该像 rsp.example.com）")
    if not mid:
        raise ValueError("matchingId 是空的，激活码不完整")
    return host, mid, (parts[3].strip() if len(parts) > 3 else None)


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


def iccid_to_bin(s: str) -> bytes:
    """Accept 19/20 decimal digits, or 20 hex chars of already-packed BCD.

    ICCID is packed low-nibble-first (GSM 11.11 / ETSI TS 102 221): the first
    digit goes into the low nibble of the first byte, so "89..." -> 0x98.
    """
    s = s.strip().replace(" ", "")
    if s.lower().startswith("0x"):
        return bytes.fromhex(s[2:])
    if s.isdigit():
        if len(s) == 19:
            s += "F"
        if len(s) != 20:
            raise ValueError(f"ICCID must be 19/20 digits: {s}")
        s = "".join(s[i + 1] + s[i] for i in range(0, 20, 2))
    b = bytes.fromhex(s)
    if len(b) != 10:
        raise ValueError(f"ICCID must be 10 bytes: {s}")
    return b


def iccid_to_str(b: bytes) -> str:
    """Packed BCD -> decimal digits (undo the nibble swap, drop the F filler)."""
    h = b.hex().upper()
    return "".join(h[i + 1] + h[i] for i in range(0, len(h), 2)).rstrip("F")


# ---------------------------------------------------------------------- card
TRACE = False          # --trace: dump every APDU + SW


class EuiccCard:
    """ISD-R on a logical channel, STORE DATA block chaining on top of Phoenix."""

    def __init__(self, ph: Phoenix, chunk: int = 255):
        self.ph = ph
        self.channel = 0
        # 255 keeps every short command in a single STORE DATA; only the big
        # sequenceOf86 blocks get chained. Some ISD-Rs mishandle chaining.
        self.chunk = max(16, min(255, chunk))

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

    def _store_data(self, payload: bytes, label="", chunk=None):
        chunk = chunk or self.chunk
        cla = 0x80 | self.channel
        blocks = [payload[i:i + chunk] for i in range(0, len(payload), chunk)]
        data, sw = b"", b"\x90\x00"
        for idx, blk in enumerate(blocks):
            last = idx == len(blocks) - 1
            p1 = 0x91 if last else 0x11
            apdu = bytes([cla, 0xE2, p1, idx & 0xFF, len(blk)]) + blk
            if TRACE:
                print(f"    > {apdu[:8].hex(' ').upper()} ... "
                      f"({len(apdu)}B, P1={p1:02X} P2={idx & 0xFF:02X})")
            d, sw = self.ph.transceive(apdu)
            if TRACE:
                print(f"    < {sw.hex().upper()}  {len(d)}B")
            if not last:
                if sw != b"\x90\x00":
                    raise IOError(f"{label} block {idx}/{len(blocks)-1} failed: "
                                  f"{sw.hex().upper()}")
                continue
            data = d
        # The card answers 61xx when a response is waiting (61 00 = 256 bytes).
        while len(sw) == 2 and sw[0] == 0x61:
            more, sw = self.ph.transceive(
                bytes([self.cla, 0xC0, 0x00, 0x00, sw[1]]))
            data += more
        if sw != b"\x90\x00":
            raise IOError(f"{label} failed: {sw.hex().upper()} "
                          f"({len(blocks)} block(s) of {chunk}B)")
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

    # ---- ES10c -----------------------------------------------------------
    def get_profiles_info(self):
        """ES10c GetProfilesInfo (BF2D) -> [(iccid_bin, state)] with 0=disabled."""
        resp = self._store_data(bytes.fromhex("BF2D00"), "GetProfilesInfo")
        tag, body, _ = read_tlv(resp)
        if tag != 0xBF2D:
            raise IOError(f"GetProfilesInfo: unexpected tag {tag:04X}")
        alt, content, _ = read_tlv(body)
        if alt != 0xA0:
            raise IOError("GetProfilesInfo returned profileInfoListError")
        out = []
        for el in split_tlvs(content):          # each ProfileInfo (E3)
            _t, info, _ = read_tlv(el)
            iccid = state = None
            for ctag, cval, _c in parse_tlv(info):
                if ctag == 0x5A:
                    iccid = cval
                elif ctag == 0x9F70:
                    state = int.from_bytes(cval, "big")
            out.append((iccid, state))
        return out

    def enable_profile(self, iccid_bin: bytes, refresh: bool = True):
        """ES10c EnableProfile (BF31).

        Encoding matches SGP.22 ASN.1 with automatic tags:
        BF31 { A0 { 5A 0A <iccid> } 81 01 FF }     -- refreshFlag=TRUE

        refreshFlag is sent explicitly even for FALSE: strict DER would omit a
        DEFAULT value, and this card answers 127 (undefinedError) when absent.

        Some cards (this test eUICC included) refuse to run the REFRESH
        themselves and answer enableResult=7 for refreshFlag=TRUE. Retrying
        with refreshFlag=FALSE succeeds because the LPA then resets the card
        itself -- which is what finish() does anyway.
        """
        body = tlv(b"\xa0", tlv(b"\x5a", iccid_bin))
        # refreshFlag has DEFAULT FALSE, so strict DER would omit it -- and this
        # card answers 127 (undefinedError) when it is absent. Send it
        # explicitly: FF for true, 00 for false.
        body += tlv(b"\x81", b"\xff" if refresh else b"\x00")
        resp = self._store_data(tlv(b"\xbf\x31", body), "EnableProfile")
        tag, content, _ = read_tlv(resp)
        if tag != 0xBF31:
            raise IOError(f"EnableProfile: unexpected tag {tag:04X}")
        code = None
        for ctag, cval, _c in parse_tlv(content):
            # enableResult is [0] under automatic tagging, plain INTEGER otherwise
            if ctag in (0x80, 0x02):
                code = int.from_bytes(cval, "big")
        names = {0: "ok", 1: "iccidOrAidNotFound", 2: "profileNotInDisabledState",
                 3: "disallowedByPolicy", 4: "wrongProfileReenabling",
                 5: "catBusy", 127: "undefinedError"}
        print(f"  enableResult: {code} ({names.get(code, 'vendor-specific')})"
              f"  refreshFlag={refresh}")
        if refresh and code not in (0, 2):
            print(f"  [vendor] 这张卡拒绝 refreshFlag=TRUE (enableResult={code})，"
                  f"改 refreshFlag=FALSE 重试，REFRESH 由我们自己复位来做")
            return self.enable_profile(iccid_bin, refresh=False)
        return code


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


def _tlv_at(buf, off):
    """(tag, header_len, value_len, total_len) for the TLV starting at off."""
    b0 = buf[off]
    if b0 & 0x1F == 0x1F:
        tag = (b0 << 8) | buf[off + 1]
        i = off + 2
    else:
        tag = b0
        i = off + 1
    ln = buf[i]; i += 1
    if ln < 0x80:
        vlen = ln
    elif ln == 0x81:
        vlen = buf[i]; i += 1
    elif ln == 0x82:
        vlen = int.from_bytes(buf[i:i + 2], "big"); i += 2
    elif ln == 0x83:
        vlen = int.from_bytes(buf[i:i + 3], "big"); i += 3
    elif ln == 0x84:
        vlen = int.from_bytes(buf[i:i + 4], "big"); i += 4
    else:
        raise ValueError(f"bad length byte 0x{ln:02X} at {off}")
    return tag, i - off, vlen, (i - off) + vlen


def _children(buf, start, end):
    """[(tag, start, value_start, end)] for every TLV in buf[start:end]."""
    out, o = [], start
    while o < end:
        tag, hlen, _vlen, tlen = _tlv_at(buf, o)
        if tlen <= 0:
            break
        out.append((tag, o, o + hlen, o + tlen))
        o += tlen
    return out


def decompose_bpp(bpp: bytes):
    """Split a BF36 BPP into segments the eUICC can accept one command at a time.

    This is the part that makes a 12 KB package fit through a 4 KB command
    window. An eUICC parses each ES10b command on its own, so a segment has to
    be a complete DER fragment, never a byte range. The layout that works
    (mirrors NekokoLPA's `_decomposeBpp`, itself following lpac):

      seg 0 : BF36 header (tag+length) + the BF23 InitialiseSecureChannelRequest
      A0/A2 : the sequence header + its FIRST element, then one segment per
              remaining element
      A1/A3 : the sequence header alone, then one segment per element
      other : the element as-is

    The BF36 header in segment 0 carries the full package length, which is how
    the card knows how much more to expect.
    """
    tag, hlen, vlen, _tlen = _tlv_at(bpp, 0)
    if tag != 0xBF36:
        raise ValueError(f"BPP does not start with BF36: {bpp[:2].hex().upper()}")
    root_tl = bpp[:hlen]
    kids = _children(bpp, hlen, hlen + vlen)

    segs = []
    if kids and kids[0][0] == 0xBF23:
        segs.append(root_tl + bpp[kids[0][1]:kids[0][3]])
        rest = kids[1:]
    else:
        segs.append(root_tl)
        rest = kids

    for tag, s, vs, e in rest:
        if tag in (0xA0, 0xA1, 0xA2, 0xA3):
            seq_tl = bpp[s:vs]
            elems = _children(bpp, vs, e)
            if not elems:
                segs.append(bpp[s:e])
                continue
            if tag in (0xA0, 0xA2):
                segs.append(seq_tl + bpp[elems[0][1]:elems[0][3]])
                segs.extend(bpp[x[1]:x[3]] for x in elems[1:])
            else:
                segs.append(seq_tl)
                segs.extend(bpp[x[1]:x[3]] for x in elems)
        else:
            segs.append(bpp[s:e])
    return segs


BPP_CMD_NAMES = {
    0: "initialiseSecureChannel", 1: "configureISDP", 2: "storeMetadata",
    3: "storeMetadata2", 4: "replaceSessionKeys", 5: "loadProfileElements",
}
ERR_REASON_NAMES = {
    1: "incorrectInputValues", 2: "invalidSignature", 3: "invalidTransactionId",
    4: "unsupportedCrtValues", 5: "unsupportedRemoteOperationType",
    6: "unsupportedProfileClass", 7: "bspStructureError",
    8: "bspSecurityError", 9: "installFailedDueToIccidAlreadyExistsOnEuicc",
    10: "installFailedDueToInsufficientMemoryForProfile",
    11: "installFailedDueToInterruption",
    12: "installFailedDueToPEProcessingError",
    13: "installFailedDueToDataMismatch",
    14: "testProfileInstallFailedDueToInvalidNaaKey", 15: "pprNotAllowed",
    17: "enterpriseProfilesNotSupported", 18: "enterpriseRulesNotAllowed",
    19: "enterpriseProfileNotAllowed", 20: "enterpriseOidMismatch",
    21: "enterpriseRulesError", 22: "enterpriseProfilesOnly",
    23: "lprNotSupported", 26: "unknownTlvInMetadata",
    127: "installFailedDueToUnknownError",
}


def _tlv_children(buf):
    out, o = [], 0
    while o < len(buf):
        try:
            tag, hlen, _vlen, tlen = _tlv_at(buf, o)
        except Exception:
            return out
        if tlen <= 0 or o + tlen > len(buf):
            return out
        out.append((tag, buf[o + hlen:o + tlen]))
        o += tlen
    return out


def _first_child(buf, *tags):
    for t, v in _tlv_children(buf):
        if t in tags:
            return v
    return None


def decode_install_result(data: bytes, save_to: str = None):
    """Decode a ProfileInstallationResult (BF37) returned by a BPP segment.

    A failed LoadBoundProfilePackage does not always leave a notification: the
    card hands the result back inline in the segment response. Dropping that
    response is why an aborted load looked like an unexplained 6985 afterwards.

    Layout this card actually emits (captured, 2026-11-20):
      BF37 { BF27 { 80 transactionId, BF2F notificationMetadata,
                    06 smdpOid, A2 { A1 { 80 bppCommandId, 81 errorReason,
                                        82 identification } } },
             5F37 euiccSignPIR }
    Note BF27 for the data and A2 for finalResult -- not A0/A3 as the
    spec text suggests, so accept both.
    """
    if data[:2] == b"\xbf\x37":
        _t, hlen, _vlen, _tlen = _tlv_at(data, 0)
        pir = data[hlen:]          # strip BF37, keep its value
    else:
        pir = _first_child(data, 0xBF37)
    if pir is None:
        return False
    if save_to:
        with open(save_to, "wb") as f:
            f.write(data)
        print(f"  [result] saved raw response: {save_to}")
    body = _first_child(pir, 0xBF27, 0xA0)
    if body is None:
        return False
    tx = _first_child(body, 0x80)
    final = _first_child(body, 0xA3, 0xA2)
    if final is None:
        return False
    if _first_child(final, 0xA0) is not None:
        print(f"  [result] ProfileInstallationResult: SUCCESS"
              f"{'  tx=' + tx.hex().upper() if tx else ''}")
        return True
    err = _first_child(final, 0xA1)
    if err is None:
        return False
    c = _first_child(err, 0x80)
    r = _first_child(err, 0x81)
    cmd = int.from_bytes(c, "big") if c else None
    rsn = int.from_bytes(r, "big") if r else None
    print(f"  [result] ProfileInstallationResult: ERROR")
    if tx:
        print(f"  [result]   transactionId = {tx.hex().upper()}")
    print(f"  [result]   bppCommandId  = {cmd} ({BPP_CMD_NAMES.get(cmd, '?')})")
    print(f"  [result]   errorReason   = {rsn} ({ERR_REASON_NAMES.get(rsn, '?')})")
    meta = _first_child(body, 0xBF2F)
    if meta is not None:
        iccid = _first_child(meta, 0x5A)
        if iccid:
            print(f"  [result]   storeMetadata ICCID = {iccid.hex().upper()}")
    return True


def load_bpp(card, bpp: bytes, mode: str = "tlv", segment: int = 3800):
    """Load the Bound Profile Package (SGP.22 2.5.5).

    mode="tlv"      -- split at TLV boundaries. This is the correct form and the
                       only one this card accepts: it parses every ES10b command
                       on its own, so each command must be a complete DER
                       fragment. See decompose_bpp().

    mode="stream"   -- the whole BF36 + body as one chained command, optionally
                       cut every `segment` bytes. Only works on a card whose
                       command window holds the entire package; cutting at a
                       raw byte offset breaks DER and the card answers 6A88.

    mode="elements" -- BF36 header stripped, each top-level TLV its own command.
                       Some old ISD-Rs want this.
    """
    if bpp[:2] != b"\xbf\x36":
        raise ValueError(f"unexpected BPP tag: {bpp[:2].hex().upper()}")

    if mode == "tlv":
        segs = decompose_bpp(bpp)
        biggest = max(len(s) for s in segs)
        print(f"  BF36 {len(bpp)}B -> {len(segs)} segment(s), largest {biggest}B, "
              f"{card.chunk}B per STORE DATA block")
        if biggest > 4096:
            print(f"  [警告] 最大段 {biggest}B 超过这张卡的 4096B 单命令窗口，"
                  f"那一段会被 6A84 拒掉。")
        for n, s in enumerate(segs):
            tag = s[:2].hex().upper() if s[0] & 0x1F == 0x1F else s[:1].hex().upper()
            t0 = time.time()
            data = card._store_data(s, f"BPP segment {n} ({tag})")
            print(f"  seg {n:2d}/{len(segs)-1} {tag:>4} {len(s):5d}B ok "
                  f"{len(data):4d}B rsp {(time.time()-t0)*1000:6.0f} ms")
            if data and decode_install_result(data, "load_result.bin"):
                if n < len(segs) - 1:
                    print(f"  [abort] 卡在第 {n} 段就下了安装结论，"
                          f"剩下的段它不会再收（继续发只会得到 6985）。")
                    return False
        return True

    if mode == "stream":
        seg = segment if segment and segment > 0 else len(bpp)
        parts = [bpp[o:o + seg] for o in range(0, len(bpp), seg)]
        print(f"  stream BF36: {len(bpp)}B in {len(parts)} segment(s) "
              f"of <={seg}B, {card.chunk}B per STORE DATA block")
        for n, part in enumerate(parts):
            t0 = time.time()
            card._store_data(part, f"BPP segment {n}")   # raises on failure
            print(f"  segment {n}/{len(parts)-1} @{n*seg:5d} "
                  f"({len(part):5d}B) ok {(time.time()-t0)*1000:6.0f} ms")
        return True

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
            print_sw_hint(str(e))
            return False
        print(f"  element {idx} ({tag}, {len(el):6d}B) ok "
              f"{len(data)}B rsp, {(time.time()-t0)*1000:6.0f} ms")
    return True


def do_load(card, bpp, mode="tlv", segment=3800):
    """load_bpp with a safe fallback: if the first command is rejected nothing
    has been consumed yet, so another framing can still be tried."""
    try:
        return load_bpp(card, bpp, mode, segment)
    except IOError as e:
        msg = str(e)
        print(f"  FAILED: {msg}")
        print_sw_hint(msg)
        if mode == "tlv" and "segment 0" in msg:
            print("\n  [退回] 第一段就被拒 -> 改试整包 stream 模式"
                  "（同一次 PrepareDownload 内，还没写进任何东西）")
            try:
                return load_bpp(card, bpp, "stream", segment)
            except IOError as e2:
                print(f"  FAILED: {e2}")
                print_sw_hint(str(e2))
        if "6A84" in msg.upper():
            print("\n  [提示] 6A84 出现在固定偏移处 = 单条命令的缓冲上限。\n"
                  "         看最后一个成功的 segment/block 偏移，用它附近的值设 --segment\n"
                  "         （例如 4080 失败 -> --segment=4000）")
        return False


SW_HINTS = {
    "6A88": "Referenced data not found —— 卡没找到它期望的 tag/数据。\n"
            "    最常见：BPP 被按字节偏移切开，某一段从 TLV 中间开始，\n"
            "    卡单独解析这一条命令就崩了。用默认 --mode=tlv（按 TLV 边界切）。\n"
            "    其次：卡里已有半装完的 profile，或 PrepareDownload 之后被复位过。",
    "6A80": "Incorrect data —— 字段内容被拒，通常是签名/证书链校验不过。",
    "6985": "Conditions of use not satisfied —— 卡不允许现在做这个操作"
            "（状态机不对，先拔插读卡器重来）。",
    "6A84": "Not enough memory —— 这里几乎都不是真的空间不够。\n"
            "    如果它出现在**固定偏移**（例如 16×255=4080 之后），那是单条\n"
            "    STORE DATA 的缓冲/块数上限（4 KB 或 16 块）。用 --segment 把\n"
            "    整包拆成多条命令（默认 3800B = 15 块）。\n"
            "    只有出现在 BPP 末尾附近、且 GetEUICCInfo2 的 freeNV 很小时，\n"
            "    才是真的存储不足。",
    "6A82": "File or application not found —— ISD-R 没选上，或者卡不是 eUICC。",
    "6982": "Security status not satisfied —— 需要先做安全通道。",
    "6D00": "INS not supported —— 这个 applet 在当前状态不认 STORE DATA。\n"
            "    注意：LoadBoundProfilePackage 只能在 PrepareDownload 之后调用，"
            "所以 --bpp= 离线重放在这张卡上行不通。",
}


def print_sw_hint(msg: str):
    for sw, hint in SW_HINTS.items():
        if sw in msg.upper():
            print(f"    {sw}: {hint}")
            return


# ---------------------------------------------------------------------- main
def finish(card, ph, loaded_ok, do_enable, iccid_arg, do_verify):
    """Common tail: enable, refresh, then read EF_FF03 back off the card."""
    if not loaded_ok:
        print("\n[FAILED] LoadBoundProfilePackage -- 卡没动过")
        ph.close()
        return 1

    if do_enable:
        print("\n--- GetProfilesInfo ---")
        profiles = card.get_profiles_info()
        for iccid, state in profiles:
            print(f"  {iccid_to_str(iccid) if iccid else '?'}  "
                  f"state={state} ({'enabled' if state == 1 else 'disabled'})")

        target = None
        if iccid_arg:
            want = iccid_to_bin(iccid_arg)
            target = next((i for i, _s in profiles if i == want), None)
            if target is None:
                print(f"  {iccid_arg} 不在这张卡里")
                ph.close()
                return 1
        else:
            disabled = [i for i, s in profiles if i and s == 0]
            if not disabled:
                print("  没有 disabled 状态的 profile 可启用")
                ph.close()
                return 1
            target = disabled[-1]
        print(f"\n--- EnableProfile {iccid_to_str(target)} ---")
        code = card.enable_profile(target)
        if code not in (0, 2):
            print(f"  [FAILED] EnableProfile 返回 {code}，profile 没切过去")
            ph.close()
            return 1
        print("  已切换（REFRESH 若被卡拒绝，下面用 RTS 复位自己完成）")

    if do_verify:
        print("\n--- reset (RTS) + read EF_FF03 ---")
        atr = ph.reset()
        print(f"  ATR: {atr.hex(' ').upper() or '(nothing)'}")
        if not atr:
            print("  复位后卡无响应，拔插读卡器再跑 read_ff03.py")
            ph.close()
            return 1
        time.sleep(0.3)
        select_usim(ph)
        data = read_ff03(ph)
        ph.close()
        if data is None:
            print("\n[FF03 NOT FOUND] profile 装上了，但读不到 FF03 —— "
                  "检查 ARR 是否允许读，或者换 --iccid 再试")
            return 1
        value = data[:5].hex().upper()
        print(f"\n[R1-R5] {value}"
              f"{'   (与工作卡一致)' if value == '20132F495B' else ''}")
        return 0

    ph.close()
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    # Offline: decode a saved ProfileInstallationResult, no card, no code.
    for a in sys.argv[1:]:
        if a.startswith("--decode-result="):
            path = a.split("=", 1)[1]
            data = open(path, "rb").read()
            print(f"[--decode-result] {path}: {len(data)}B")
            if not decode_install_result(data):
                print("  不是 ProfileInstallationResult (BF37)，前 32 字节：")
                print(f"  {data[:32].hex(' ').upper()}")
            return 0
    try:
        smdp, matching_id, _cc = parse_activation_code(sys.argv[1])
    except ValueError as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 2
    port = "COM4"
    stop_at = "bpp"          # authclient | bpp | load
    save_bpp = None          # write the raw BPP here for offline analysis
    load_file = None         # skip ES9+ entirely, load a saved BPP
    do_enable = False
    do_verify = False
    iccid_arg = None
    chunk = 255
    segment = 3800
    mode = "tlv"
    global TRACE
    for a in sys.argv[2:]:
        if a.startswith("COM"):
            port = a
        elif a == "--load":
            stop_at = "load"
        elif a.startswith("--stop="):
            stop_at = a.split("=", 1)[1]
        elif a.startswith("--save-bpp="):
            save_bpp = a.split("=", 1)[1]
        elif a.startswith("--bpp="):
            load_file = a.split("=", 1)[1]
            stop_at = "load"
        elif a == "--enable":
            do_enable = True
        elif a == "--verify-ff03":
            do_verify = True
        elif a.startswith("--iccid="):
            iccid_arg = a.split("=", 1)[1]
        elif a.startswith("--chunk="):
            chunk = int(a.split("=", 1)[1])
        elif a.startswith("--segment="):
            segment = int(a.split("=", 1)[1])
        elif a.startswith("--mode="):
            mode = a.split("=", 1)[1].strip().lower()
            if mode not in ("tlv", "stream", "elements"):
                print(f"[错误] --mode 只能是 tlv / stream / elements，收到 {mode!r}",
                      file=sys.stderr)
                return 2
        elif a == "--trace":
            TRACE = True
        elif a.startswith("--decode-result="):
            path = a.split("=", 1)[1]
            data = open(path, "rb").read()
            print(f"[--decode-result] {path}: {len(data)}B")
            if not decode_install_result(data):
                print("  不是 ProfileInstallationResult (BF37)，前 32 字节：")
                print(f"  {data[:32].hex(' ').upper()}")
            return 0
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

    card = EuiccCard(ph, chunk=chunk)
    card.select_isdr()
    print(f"ISD-R      : selected on channel {card.channel}")

    if load_file:
        # Offline replay: the BPP is self-contained (BF23 carries the
        # transactionId and the BSP keys derive from the eUICC OTPK), so no
        # ES9+ round trip is needed. Some eUICCs insist on a live
        # PrepareDownload in the same power cycle; if this fails, redo the
        # full flow with --save-bpp= instead.
        bpp = open(load_file, "rb").read()
        print(f"[--bpp] {load_file}: {len(bpp)}B, ES9+ skipped")
        print("\n--- LoadBoundProfilePackage ---")
        ok = do_load(card, bpp, mode, segment)
        print(f"\n[{'OK' if ok else 'FAILED'}] LoadBoundProfilePackage")
        return finish(card, ph, ok, do_enable, iccid_arg, do_verify)

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
    if save_bpp:
        with open(save_bpp, "wb") as f:
            f.write(bpp)
        print(f"  saved: {save_bpp}")

    if stop_at == "bpp":
        print("\n[STOP] after GetBoundProfilePackage -- card NOT modified.")
        print("       Compare this sha256 with the app's log.")
        ph.close()
        return 0

    # ---- ES10b LoadBoundProfilePackage -------------------------------------
    print("\n--- LoadBoundProfilePackage ---")
    ok = do_load(card, bpp, mode, segment)
    print(f"\n[{'OK' if ok else 'FAILED'}] LoadBoundProfilePackage")
    return finish(card, ph, ok, do_enable, iccid_arg, do_verify)


if __name__ == "__main__":
    sys.exit(main())
