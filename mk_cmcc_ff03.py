#!/usr/bin/env python3
"""Build a China-Mobile-shaped SAIP profile that also carries EF_FF03 (R1-R5).

Base: the GSMA TS48v1 test UPP (the only profile source on disk).
Patched:
  PE-Header.iccid   -> --iccid     (must equal what the DP announces)
  EF.ICCID (2FE2)   -> --iccid     (must equal the header)
  EF.DIR   (2F00)   -> --dir-aid   (record 1 = the AID the eUICC exposes)
  EF.IMSI  (6F07)   -> --imsi
  EF.SPN   (6F46)   -> --spn        (padded to 17 B with FF, flags 0x01)
  EF.FF03  (vendor) -> R1-R5, appended to PE-GenericFileManagement (A1)
  A4 akaParameter   -> --ki/--opc  (the Milenage K and OPc, see below)

Three of these decide whether the card works in a phone, and all three fail
silently:

  * EF.DIR -- the eUICC registers the AIDs listed there. The stock test UPP
    lists A0000000871002FF49FF0589 (12 bytes); no phone asks for that, so
    SELECT ADF.USIM answers 6A82 and the card looks empty. Fixed to the
    standard A0000000871002FF33FFFF8900000100.

  * EF.IMSI -- a placeholder IMSI installs and reads back perfectly, then
    never registers. Always pass the real one.

  * A4 akaParameter -- this is where Ki/OPc actually live. The test UPP ships
    K=000102...0F / OPc=00...00, and those are the values the SM-DP+ echoes
    back from /validate-der-file. A profile carrying them installs fine and
    then fails authentication on the network. Pass --ki/--opc to replace them.

EF.KEYS (6F08) is *not* where the keys are: it ships as 07 FF*32 and the
eUICC's personalisation agent fills it from A4 while loading. So patching
EF.KEYS does nothing; patching A4 does.

Encoding is done by pysim (enc_imsi / enc_iccid / ProfileElement.to_der), so
the result re-decodes; hand-rolled DER breaks on `lcsi` (DEFAULT '05'H).

    python mk_cmcc_ff03.py --imsi=460009876543210 --iccid=89860012345678901234
                           [--spn="CMCC"] [--spn-flag=00] [--dir-aid=A000...]
                           [--ki=<32 hex>] [--opc=<32 hex>]
                           [--acc=0080] [--ad=00000002] [--hpplmn=50]
                           [--fplmn=45008,45012] [--oplmn=46000:4000,...]
                           [--hplmn=46000:4000,...] [--plmn=...]
                           [--in=SRC.der] [--out=DST.der]

The alignment options exist so the profile can be made to match a reference
card field by field. Values measured off a real China Mobile SIM:

    --acc=0080 --ad=00000002 --hpplmn=50 --spn="CMCC" --spn-flag=00
    --oplmn=46000:4000,46000:8000,46000:0080
    --hplmn=46000:4000,46000:8000,46000:0080

`--ad=00000002` matters more than it looks: the test UPP ships 80000002, whose
first byte is ms_operation_mode = type_approval, not normal.

--in defaults to the pristine GSMA test UPP. Always rebuild from it: feeding a
previous output back in appends a second EF_FF03 (+32 B) and the card then
carries two vendor files.
"""
import os
import sys

PYSIM = os.environ.get("PYSIM", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "pysim"))
sys.path.insert(0, os.path.abspath(PYSIM))
# pySim imports `smpp` on its way to the SAIP code and upstream smpplib no
# longer ships that module; the stub only satisfies the type annotations.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "_stubs"))

SRC = os.path.join(PYSIM, "smdpp-data", "upp", "TS48V1-A-UNIQUE.der")
DST = "cmcc_ff03.der"
FID_FF03 = bytes.fromhex("FF03")


def split_tlv(buf, off=0):
    tag = buf[off]; off += 1
    if tag & 0x1F == 0x1F:
        tag = (tag << 8) | buf[off]; off += 1
    ln = buf[off]; off += 1
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(buf[off:off + k], "big"); off += k
    return tag, buf[off:off + ln], off + ln


def set_content(pe, name, content):
    """Replace a file's content, keeping the FCP fillPattern in sync.

    pysim rebuilds `fillFileContent` by repeating `fillPattern` up to
    `efFileSize`. So the pattern has to be the *exact* content: a shorter
    pattern gets its last byte repeated into the tail, which is how
    "China Mobile" turned into "China Mobileeeee" (0x65 = 'e').

    A file that ships as pure padding (EF.FPLMN, EF.SMSP in the test UPP) has
    no `fillFileContent` entry at all, only a size. Setting one there used to
    do nothing at all -- silently. Add the entry instead, in front of the
    trailing fillFileOffset so the SEQUENCE stays ordered.
    """
    entry = pe.decoded.get(name)
    if entry is None:
        raise SystemExit(f"{name} not in {pe.type}")
    hit = False
    for i, (tag, val) in enumerate(entry):
        if tag == "fillFileContent":
            entry[i] = ("fillFileContent", content)
            hit = True
    if not hit:
        pos = next((i for i, (t, _v) in enumerate(entry)
                    if t == "fillFileOffset"), len(entry))
        entry.insert(pos, ("fillFileContent", content))
    for tag, val in entry:
        if tag != "fileDescriptor":
            continue
        pei = val.get("proprietaryEFInfo")
        if isinstance(pei, dict) and "fillPattern" in pei:
            pei["fillPattern"] = content
        if "efFileSize" in val:
            val["efFileSize"] = (bytes([len(content)]) if len(content) < 256
                                 else len(content).to_bytes(2, "big"))
    return pe


def file_sizes(pe, name):
    """(efFileSize, recordLength) from the FCP, 0 when not encoded."""
    size = rec = 0
    for tag, val in pe.decoded.get(name, []):
        if tag != "fileDescriptor":
            continue
        if "efFileSize" in val:
            size = int.from_bytes(val["efFileSize"], "big")
        fd = val.get("fileDescriptor") or b""
        # ISO 7816-4 byte 1 bits 3-1: 1 transparent, 2 linear fixed, 6 cyclic.
        if len(fd) >= 4 and fd[0] & 0x07 == 0x02:
            rec = int.from_bytes(fd[2:4], "big")
    return size, rec


def build_smsp(number, rec_len, n_rec):
    """EF.SMSP: alpha(12) + parameter indicators + TP-DA(12) + SC address.

    Offsets verified against a real China Mobile card: the SMSC TLV starts at
    byte 25, TP-PID/DCS/VP are the three bytes after it and are left 0xFF
    ("not set"), which is what the card does.
    """
    digits = number.strip().lstrip("+")
    if not digits.isdigit():
        raise SystemExit(f"bad SMSC {number!r}: digits and an optional + only")
    if len(digits) % 2:
        digits += "F"
    bcd = bytes.fromhex("".join(digits[i + 1] + digits[i]
                                for i in range(0, len(digits), 2)))
    sc = bytes([len(bcd) + 1, 0x91]) + bcd
    rec = b"\xff" * 12 + b"\xfd" + b"\xff" * 12 + sc + b"\xff" * 3
    if len(rec) > rec_len:
        raise SystemExit(f"SMSC {number} does not fit a {rec_len}B record")
    rec = rec.ljust(rec_len, b"\xff")
    return rec + b"\xff" * rec_len * (n_rec - 1)


def build_app_template(aid_hex, label=b"USIM"):
    """One EF.DIR record body: 61 { 4F <AID> 50 <label> } (no padding)."""
    aid = bytes.fromhex(aid_hex)
    tpl = b"\x4f" + bytes([len(aid)]) + aid
    tpl += b"\x50" + bytes([len(label)]) + label
    return b"\x61" + bytes([len(tpl)]) + tpl


def build_spn(text, flag=0x01):
    """EF.SPN: display-condition byte + up to 16 chars, FF padded to 17.

    The flag byte decides whether the ME shows the SPN at all: the reference
    China Mobile card ships 0x00 with "CMCC", i.e. "do not display", so the
    phone keeps showing the network name instead.
    """
    body = bytes([flag]) + text.encode("ascii")
    if len(body) > 17:
        raise SystemExit(f'SPN "{text}" is {len(body) - 1} chars, max 16')
    return body.ljust(17, b"\xff")


def enc_plmn(spec):
    """'46000' or '460/00' -> 3 bytes, TS 24.008 BCD (MNC 2 or 3 digits)."""
    s = spec.strip().replace("/", "").replace("-", "").replace(" ", "")
    if len(s) not in (5, 6):
        raise SystemExit(f"bad PLMN {spec!r}: use 46000 or 460/00")
    d = [int(c, 16) for c in s]
    mcc, mnc = d[:3], d[3:]
    mnc3 = 0xF if len(mnc) == 2 else mnc[2]
    return bytes([mcc[0] | (mcc[1] << 4),
                  mcc[2] | (mnc3 << 4),
                  mnc[0] | (mnc[1] << 4)])


def enc_plmn_list(spec, size):
    """'45008,45012' -> 3-byte entries, FF padded to the file size."""
    out = b"".join(enc_plmn(x) for x in spec.split(",") if x.strip())
    if len(out) > size:
        raise SystemExit(f"too many PLMNs ({len(out)}B > {size}B)")
    return out.ljust(size, b"\xff")


def enc_plmn_act(spec, size):
    """'46000:4000,46000:8000' -> 5-byte (PLMN + AcT) entries.

    AcT is a 16-bit field (TS 31.102 4.2.5): 0x8000 UTRAN, 0x4000 E-UTRAN,
    0x0080 GSM. E-UTRAN lives in bits 14-12: 0x4000 = WB-S1 + NB-S1, 0x6000 =
    WB-S1 only, 0x5000 = NB-S1 only. The reference card lists 46000 three
    times, once per access technology.

    Unused slots are padded with FFFFFF0000, not FF: that is the "no PLMN,
    no access technology" entry the SAIP templates use, so a padded file
    reads as N empty entries rather than as garbage.
    """
    out = b""
    for item in [x for x in spec.split(",") if x.strip()]:
        if ":" not in item:
            raise SystemExit(
                f"bad entry {item!r}: a PLMN on its own is ambiguous, it needs "
                f"an access technology -- write {item}:4000\n"
                f"  AcT: 8000 UTRAN, 4000 E-UTRAN, 0080 GSM\n"
                f"  e.g. --oplmn=46000:4000,46000:8000,46000:0080")
        plmn, act = item.split(":", 1)
        actb = bytes.fromhex(act)
        if len(actb) != 2:
            raise SystemExit(f"bad AcT {act!r} in {item!r}: need 2 bytes")
        out += enc_plmn(plmn) + actb
    if len(out) > size:
        raise SystemExit(f"too many PLMN/AcT entries ({len(out)}B > {size}B)")
    empty = b"\xff\xff\xff\x00\x00"
    while len(out) < size:
        out += empty
    return out[:size]


def main():
    from pySim.esim.saip import ProfileElement
    from pySim.utils import enc_iccid, enc_imsi

    opts = {"imsi": None, "spn": "China Mobile", "spn-flag": "01", "iccid": None,
            "r1r5": "20132F495B",
            "ki": None, "opc": None,
            # keep = 照抄源 UPP；milenage(1) / usim-test(3) / tuak(2) 可显式指定。
            # 想要在真网注册必须用 milenage(1)：运营商 AuC 用的是 Milenage，
            # usim-test(3) 是 TS 31.102 Annex F 的公开测试算法，而且忽略 OPc。
            "algo": "keep",
            # alignment with a reference card (all optional; unset = keep UPP)
            "acc": None, "ad": None, "hpplmn": None, "smsc": None,
            "fplmn": None, "plmn": None, "oplmn": None, "hplmn": None,
            "in": SRC, "out": DST,
            "dir-aid": "A0000000871002FF33FFFF8900000100"}
    pos = []
    for a in sys.argv[1:]:
        if a.startswith("--") and "=" in a:
            k, v = a[2:].split("=", 1)
            if k not in opts:
                raise SystemExit(f"unknown option --{k}")
            opts[k] = v
        else:
            pos.append(a)
    if pos:
        raise SystemExit("positional arguments are gone (that is how a previous "
                         "output got fed back in and double-appended EF_FF03)\n"
                         "  use --in=SRC.der / --out=DST.der")
    # No placeholder defaults: a silently wrong IMSI produces a profile that
    # installs fine, reads back fine, and then never registers on the network.
    missing = [k for k in ("imsi", "iccid") if not opts[k]]
    if missing:
        raise SystemExit(
            "missing " + ", ".join(f"--{k}=" for k in missing) + "\n"
            "  这两项必须显式给出，不能用默认值：IMSI 决定注不上网，"
            "ICCID 必须和 DP 声明的一致（否则 dataMismatch）。")
    src = opts["in"]
    dst = opts["out"]
    r1r5 = bytes.fromhex(opts["r1r5"])
    if len(r1r5) != 5:
        raise SystemExit("--r1r5 must be 5 bytes (10 hex chars)")

    if bool(opts["ki"]) != bool(opts["opc"]):
        raise SystemExit("--ki= and --opc= must be given together "
                         "(a K without an OPc is not a usable Milenage set)")
    ki = opc = None
    if opts["ki"]:
        ki, opc = bytes.fromhex(opts["ki"]), bytes.fromhex(opts["opc"])
        if len(ki) != 16 or len(opc) != 16:
            raise SystemExit("--ki= and --opc= must each be 16 bytes (32 hex)")
    algo = opts["algo"]
    algo_id = {"keep": None, "milenage": 1, "tuak": 2, "usim-test": 3}.get(algo)
    if algo_id is None and algo != "keep":
        raise SystemExit("--algo must be keep / milenage / tuak / usim-test")
    if algo_id is not None and not ki:
        raise SystemExit("--algo requires --ki= and --opc= (A4 只在这条路径里改)")

    der = open(src, "rb").read()
    elements, off = [], 0
    while off < len(der):
        start = off
        _t, _v, off = split_tlv(der, off)
        elements.append(der[start:off])
    print(f"source {src}: {len(der)}B, {len(elements)} top-level elements")

    want = {0xB0: "mf", 0xB3: "usim", 0xA1: None}
    touched = []

    # --- PE-Header: the authoritative ICCID -----------------------------
    # The card cross-checks the ICCID announced in storeMetadata against the
    # one inside the profile. If PE-Header and EF.ICCID disagree the install
    # dies with errorReason=13 installFailedDueToDataMismatch, so both have to
    # be set to the same value -- changing only EF.ICCID is worse than
    # changing neither.
    packed_iccid = bytes.fromhex(enc_iccid(opts["iccid"]))
    for i, el in enumerate(elements):
        if el[0] != 0xA0:
            continue
        pe = ProfileElement.from_der(el, pe_sequence=None)
        if pe.to_der() != el:
            raise SystemExit("pysim does not round-trip PE-Header; aborting")
        pe.decoded["iccid"] = packed_iccid
        elements[i] = pe.to_der()
        touched.append(f"header iccid -> {opts['iccid']}")

    # --- MF: EF.ICCID and EF.DIR ---------------------------------------
    for i, el in enumerate(elements):
        if el[0] != 0xB0:
            continue
        pe = ProfileElement.from_der(el, pe_sequence=None)
        if pe.to_der() != el:
            raise SystemExit("pysim does not round-trip PE-MF; aborting")
        set_content(pe, "ef-iccid", packed_iccid)
        touched.append(f"ef-iccid     -> {opts['iccid']}")

        # EF.DIR is what the eUICC uses to decide which application AIDs it
        # exposes. The test UPP lists a 12-byte AID (A0000000871002FF49FF0589)
        # that no phone ever asks for, so SELECT ADF.USIM answers 6A82 and the
        # card behaves like it has no subscription at all. Rewrite record 1
        # with the standard USIM AID; records 2/3 (ISIM, CSIM) stay as they are.
        #
        # EF.DIR decodes as: fileDescriptor, then (fillFileContent,
        # fillFileOffset) pairs -- the offset is the padding up to the end of
        # the 33-byte record, so it has to shrink when the record grows.
        entry = pe.decoded.get("ef-dir")
        if entry:
            rec_len = 33
            new_rec = build_app_template(opts["dir-aid"], b"USIM")
            for k in range(1, len(entry)):
                tag, _val = entry[k]
                if tag != "fillFileContent":
                    continue
                entry[k] = ("fillFileContent", new_rec)
                if k + 1 < len(entry) and entry[k + 1][0] == "fillFileOffset":
                    entry[k + 1] = ("fillFileOffset", rec_len - len(new_rec))
                touched.append(f"ef-dir AID   -> {opts['dir-aid']}"
                               f"  (record1 {len(new_rec)}/{rec_len}B)")
                break

        elements[i] = pe.to_der()

    # --- USIM: EF.IMSI, EF.SPN -----------------------------------------
    spn_flag = int(opts["spn-flag"], 16)
    if not 0 <= spn_flag <= 0xFF:
        raise SystemExit("--spn-flag must be one byte (2 hex chars)")
    for i, el in enumerate(elements):
        if el[0] != 0xB3:
            continue
        pe = ProfileElement.from_der(el, pe_sequence=None)
        if pe.to_der() != el:
            raise SystemExit("pysim does not round-trip PE-USIM; aborting")
        set_content(pe, "ef-imsi", bytes.fromhex(enc_imsi(opts["imsi"])))
        set_content(pe, "ef-spn", build_spn(opts["spn"], spn_flag))
        elements[i] = pe.to_der()
        touched.append(f"ef-imsi -> {opts['imsi']}")
        touched.append(f'ef-spn  -> flag {spn_flag:02X} "{opts["spn"]}"')

    # --- optional alignment with a reference card ----------------------
    # Everything here is a field a phone actually reads, so "make it look like
    # the working card" is not cosmetic: EF.AD=0x80 is type-approval mode, and
    # an empty HPLMNwAcT means the ME has no per-RAT statement for the HPLMN.
    #
    # Sizes are taken from the file already in the profile, so a wrong-sized
    # value is refused instead of silently reshaping the file.
    targets = {}
    if opts["acc"]:
        targets["ef-acc"] = bytes.fromhex(opts["acc"])
    if opts["ad"]:
        targets["ef-ad"] = bytes.fromhex(opts["ad"])
    if opts["hpplmn"]:
        targets["ef-hpplmn"] = bytes.fromhex(opts["hpplmn"])
    if opts["fplmn"]:
        targets["ef-fplmn"] = ("list", opts["fplmn"])
    if opts["smsc"]:
        targets["ef-smsp"] = ("smsp", opts["smsc"])
    for name, key in (("ef-plmnwact", "plmn"), ("ef-oplmnwact", "oplmn"),
                      ("ef-hplmnwact", "hplmn")):
        if opts[key]:
            targets[name] = ("act", opts[key])

    if targets:
        done = set()
        for i, el in enumerate(elements):
            if el[0] not in (0xB3, 0xB4):
                continue
            pe = ProfileElement.from_der(el, pe_sequence=None)
            if pe.to_der() != el:
                raise SystemExit(f"pysim does not round-trip PE "
                                 f"{pe.type!r}; aborting")
            changed = False
            for name, spec in targets.items():
                f = pe.files.get(name)
                if f is None:
                    continue
                size = len(f._body or b"")
                if isinstance(spec, tuple):
                    kind, text = spec
                    if kind == "list":
                        new = enc_plmn_list(text, size)
                    elif kind == "act":
                        new = enc_plmn_act(text, size)
                    else:                                   # smsp
                        fsize, rec = file_sizes(pe, name)
                        if not rec or fsize % rec:
                            raise SystemExit(f"{name}: cannot work out the "
                                             f"record layout (size {fsize}, "
                                             f"record {rec})")
                        new = build_smsp(text, rec, fsize // rec)
                else:
                    new = spec
                if len(new) != size:
                    raise SystemExit(f"{name}: value is {len(new)}B but the "
                                     f"file is {size}B -- refusing to resize")
                set_content(pe, name, new)
                touched.append(f"{name:<13} -> {new.hex().upper()[:40]}")
                done.add(name)
                changed = True
            if changed:
                elements[i] = pe.to_der()
        missing = set(targets) - done
        if missing:
            raise SystemExit(f"not present in this profile: {sorted(missing)}")

    # --- A4 akaParameter: Milenage K / OPc ------------------------------
    # This is the only place a profile package carries the subscription keys.
    # EF.KEYS is a placeholder (07 FF*32) that the eUICC's personalisation
    # agent fills from here, so patching EF.KEYS is pointless and patching
    # A4 is the real thing.
    #
    # Only the two 16-byte strings are replaced: algorithmID, algorithmOptions
    # and the Milenage rotation/xor constants are left exactly as the test UPP
    # has them, so the encoding cannot drift. There are two A4 elements (one
    # per AKA identification), and both have to match.
    if ki:
        seen = 0
        for i, el in enumerate(elements):
            if el[0] != 0xA4:
                continue
            pe = ProfileElement.from_der(el, pe_sequence=None)
            if pe.to_der() != el:
                raise SystemExit("pysim does not round-trip PE-akaParameter; "
                                 "aborting")
            cfg = pe.decoded.get("algoConfiguration")
            if not cfg or cfg[0] != "algoParameter":
                raise SystemExit("akaParameter has no algoParameter "
                                 f"(got {cfg[0] if cfg else None})")
            params = cfg[1]
            params["key"] = ki
            params["opc"] = opc
            if algo_id is not None:
                old = params.get("algorithmID")
                params["algorithmID"] = algo_id
                # algorithmOptions 在 usim-test 里是 02，Milenage/TUAK 按
                # pysim 的 set_milenage()/set_tuak() 都是 00。
                params["algorithmOptions"] = b"\x00"
                print(f"  akaParameter algorithmID: {old} -> {algo_id} ({algo})"
                      "  options 02 -> 00")
            elements[i] = pe.to_der()
            seen += 1
        if not seen:
            raise SystemExit("no PE-akaParameter (A4) in this profile")
        touched.append(f"akaParameter -> K={ki.hex().upper()} "
                       f"OPc={opc.hex().upper()}  ({seen} element(s))")

    # --- GFM: append EF_FF03 -------------------------------------------
    idx = next((i for i, el in enumerate(elements) if el[0] == 0xA1), None)
    if idx is None:
        raise SystemExit("no PE-GenericFileManagement (A1) in this profile")
    pe = ProfileElement.from_der(elements[idx], pe_sequence=None)
    if pe.to_der() != elements[idx]:
        raise SystemExit("pysim does not round-trip this GFM element; aborting")
    cmds = pe.decoded["fileManagementCMD"]
    cmds[0].append(("filePath", bytes.fromhex("3F00")))
    cmds[0].append(("createFCP", {
        "fileDescriptor": bytes.fromhex("4121"),
        "fileID": FID_FF03,
        "securityAttributesReferenced": bytes.fromhex("2F0602"),
        "shortEFID": b"\x40",
        "efFileSize": bytes([len(r1r5)]),
    }))
    cmds[0].append(("fillFileContent", r1r5))
    elements[idx] = pe.to_der()
    touched.append(f"ef-ff03 -> {r1r5.hex().upper()}")

    out = b"".join(elements)
    open(dst, "wb").write(out)
    print(f"written {dst}: {len(out)}B ({len(out) - len(der):+d})")
    for t in touched:
        print(f"  {t}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
