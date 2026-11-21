#!/usr/bin/env python3
"""Verify that the China-Mobile specific EF_FF03 (R1-R5) really survives.

Two independent checks, both driven by pysim:

  1. profile package (UPP / DER)  ->  ProfileElement.from_der() per element.
     Lists every ProfileElement, every file FID + body, and greps for the
     R1-R5 payload read off the working card.

  2. bound profile package (BPP)  ->  structural walk of the BF36 container
     (SGP.22 2.5.4) without the eUICC private key: counts the 0x86 command
     TLVs in sequenceOf86.  The eUICC cannot add or drop a command, so
     N commands == N profile elements in the UPP.

Usage:
    python verify_ff03.py profile.der
    python verify_ff03.py profile.der --bpp bpp.bin
    python verify_ff03.py --bpp bpp.bin

Run from _tmp/, or set PYSIM=<path to a pysim checkout>.
"""
import argparse
import hashlib
import os
import sys

PYSIM = os.environ.get("PYSIM", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "pysim"))
sys.path.insert(0, os.path.abspath(PYSIM))
# pySim imports `smpp` on its way to the SAIP code and upstream smpplib no
# longer ships that module; the stub only satisfies the type annotations.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "_stubs"))

R1R5 = "20132F495B"          # the R1..R5 bytes read off the working card

# K and OPc together are enough to clone a subscription, so they are masked
# unless --show-keys is given. Terminal output has a habit of ending up in
# chat logs, screenshots and bug reports.
SHOW_KEYS = False


def mask(hexstr):
    if not hexstr:
        return "(empty)"
    if len(hexstr) <= 12:
        return hexstr[:2] + "…"
    return f"{hexstr[:8]}…{hexstr[-4:]}"


# ------------------------------------------------------------------- TLV
def split_tlv(data: bytes, off: int = 0):
    tag = data[off]
    off += 1
    if tag & 0x1F == 0x1F:
        tag = (tag << 8) | data[off]
        off += 1
    ln = data[off]
    off += 1
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(data[off:off + k], "big")
        off += k
    return tag, data[off:off + ln], off + ln


def tagstr(t: int) -> str:
    return f"{t:04X}" if t > 0xFF else f"{t:02X}"


def split_all(data: bytes):
    out, off = [], 0
    while off < len(data):
        start = off
        _t, _v, off = split_tlv(data, off)
        out.append(data[start:off])
    return out


# ------------------------------------------------------------------ DER/UPP
def walk_der(path: str):
    from pySim.esim.saip import ProfileElement

    der = open(path, "rb").read()
    print(f"file       : {os.path.basename(path)}")
    print(f"size       : {len(der)} B")
    print(f"sha256     : {hashlib.sha256(der).hexdigest()}")
    print(f"outer tag  : {der[:3].hex(' ').upper()}")

    elements = split_all(der)
    print(f"\n{len(elements)} top-level profile elements:")
    print(f"  {'#':>2}  {'tag':<5} {'type':<22} {'len':>6}  files")
    print(f"  {'-'*2}  {'-'*5} {'-'*22} {'-'*6}  {'-'*5}")

    seen, total_files, found = {}, 0, []
    for i, el in enumerate(elements):
        tag = el[0] if el[0] & 0x1F != 0x1F else int.from_bytes(el[:2], "big")
        try:
            # isolated sequence: pysim refuses two PE-MF in one sequence, and we
            # want to *report* that, not die on it.
            pe = ProfileElement.from_der(el, pe_sequence=None)
            ptype = pe.type
            files = getattr(pe, "files", {}) or {}
        except Exception as e:
            ptype = f"<parse: {type(e).__name__}>"
            files = {}
        seen[ptype] = seen.get(ptype, 0) + 1
        total_files += len(files)
        print(f"  {i:>2}  {tagstr(tag):<5} {ptype:<22} {len(el):>6}  {len(files)}")
        # A4 akaParameter is the only place a profile package carries the
        # subscription keys. Print them masked: a DER still holding the test
        # UPP's 000102...0F / 00...00 installs perfectly and then fails auth,
        # which is what the check below is for -- the full value is only
        # needed when you are diffing against an operator-issued pair, so it
        # is behind --show-keys. Terminal output ends up in chat logs, bug
        # reports and screenshots; K + OPc is everything needed to clone a
        # subscription.
        if ptype == "akaParameter":
            cfg = (getattr(pe, "decoded", {}) or {}).get("algoConfiguration")
            if cfg and cfg[0] == "algoParameter":
                p = cfg[1]
                ident = pe.decoded.get("aka-header", {}).get("identification")
                k = (p.get("key") or b"").hex().upper()
                o = (p.get("opc") or b"").hex().upper()
                if SHOW_KEYS:
                    print(f"        K   = {k}")
                    print(f"        OPc = {o}")
                else:
                    print(f"        K   = {mask(k)}   (--show-keys to reveal)")
                    print(f"        OPc = {mask(o)}")
                print(f"        akaParameter id={ident} algoID={p.get('algorithmID')} "
                      f"opts={(p.get('algorithmOptions') or b'').hex().upper()}")
                if k in ("000102030405060708090A0B0C0D0E0F", "00" * 16):
                    print("        ^ placeholder test key -- the network will "
                          "reject this subscription")
        for pname, f in files.items():
            fid = f"{(f.fid or 0):04X}"
            body = f._body or b""
            mark = "   <<< R1-R5" if body and R1R5 in body.hex().upper() else ""
            # ICCID is packed low-nibble-first (GSM 11.11). Printing the raw
            # bytes as hex reads it backwards -- which is exactly the bug that
            # makes a DP show a red X on a perfectly good profile.
            if fid == "2FE2" and len(body) >= 10:
                iccid = "".join("%X%X" % (b & 0x0F, b >> 4) for b in body)
                print(f"        {pname:<12} FID {fid}  {f.file_type or '?':<3} "
                      f"{len(body):>4} B {iccid}   (packed {body.hex().upper()})")
                continue
            print(f"        {pname:<12} FID {fid}  {f.file_type or '?':<3} "
                  f"{len(body):>4} B {body.hex().upper()[:32]}{mark}")
            if body and R1R5 in body.hex().upper():
                found.append((i, ptype, pname, fid, body.hex().upper()))
        # PE-GenericFileManagement keeps its files in fileManagementCMD, not in
        # .files. asn1tools returns it as list-of-lists of (alternative, value)
        # tuples; flatten and track the running filePath / createFCP so a
        # fillFileContent can be attributed to a FID.
        raw = (getattr(pe, "decoded", {}) or {}).get("fileManagementCMD", []) or []
        flat = [x for grp in raw for x in grp] if raw and isinstance(raw[0], list) else raw
        if flat:
            n_create = sum(1 for a, _v in flat if a == "createFCP")
            print(f"        gfm          {n_create} createFCP, {len(flat)} commands")
            last_path, last_fid = "--", "----"
            for alt, val in flat:
                if alt == "filePath":
                    last_path = val.hex().upper() or "(current)"
                elif alt == "createFCP":
                    last_fid = (f"{int.from_bytes(val['fileID'], 'big'):04X}"
                                if val.get("fileID") else "----")
                elif alt == "fillFileContent" and R1R5 in val.hex().upper():
                    print(f"        gfm          path {last_path} FID {last_fid} "
                          f"{len(val)} B {val.hex().upper()}   <<< R1-R5")
                    found.append((i, ptype, "gfm", last_fid, val.hex().upper()))

    print(f"\ntotal files: {total_files}")

    # SGP.22: exactly one PE-Header, one PE-MF, one PE-End. Everything else
    # (pinCodes, rfm, genericFileManagement, ...) may legally repeat.
    dup = {k: seen[k] for k in ("header", "mf", "end") if seen.get(k, 0) > 1}
    if dup:
        print(f"\nILLEGAL: singleton PE types repeated: {dup}")
        print("  A second PE-MF parses fine as bytes but is not a legal profile:")
        print("  the eUICC's load step or the SM-DP+ validator may reject it.")
        print("  PE-MF is a fixed SEQUENCE (mf/ef-pl/ef-iccid/ef-dir/ef-arr/ef-umpc),")
        print("  so a clone also steals a template slot. Put vendor files into")
        print("  PE-GenericFileManagement (tag A1) instead: it is SEQUENCE OF and")
        print("  accepts arbitrary FIDs (mk_gfm_ff03.py does exactly that).")

    n = der.hex().upper().count(R1R5)
    print(f"\nR1-R5 {R1R5}: {'FOUND' if n else 'MISSING'} "
          f"({n} occurrence{'s' if n != 1 else ''})")
    uniq = {(i, fid, body): (i, ptype, pname, fid, body) for i, ptype, pname, fid, body in found}
    for i, ptype, pname, fid, body in uniq.values():
        print(f"  element #{i} ({ptype}) file {pname} FID {fid} = {body}")
    return len(elements)


# --------------------------------------------------------------------- BPP
def walk_bpp(path: str):
    bpp = open(path, "rb").read()
    print(f"\n=== BPP {os.path.basename(path)} ===")
    print(f"size       : {len(bpp)} B")
    print(f"sha256     : {hashlib.sha256(bpp).hexdigest()}")
    print(f"outer tag  : {bpp[:3].hex(' ').upper()}")

    tag, body, nxt = split_tlv(bpp)
    if tag != 0xBF36:
        print(f"  not a BPP (outer tag {tagstr(tag)})")
        return None
    if nxt != len(bpp):
        print(f"  warning: {len(bpp) - nxt} trailing bytes")

    names = {0xBF23: "InitialiseSecureChannelRequest",
             0xA0: "firstSequenceOf87 (configureISDP)",
             0xA1: "sequenceOf88 (storeMetadata)",
             0xA2: "secondSequenceOf87 (replaceSessionKeys)",
             0xA3: "sequenceOf86 (profile elements)"}
    off, counts, sizes = 0, {}, []
    print("\ntop-level children:")
    while off < len(body):
        t, v, off = split_tlv(body, off)
        inner = 0
        if t in (0xA0, 0xA1, 0xA2, 0xA3):
            for el in split_all(v):
                t2 = el[0] if el[0] & 0x1F != 0x1F else int.from_bytes(el[:2], "big")
                counts[t2] = counts.get(t2, 0) + 1
                if t == 0xA3:
                    sizes.append(len(el))
                inner += 1
        print(f"  {tagstr(t):>4}  {len(v):>7} B  {names.get(t, '?'):<36} {inner} child TLV(s)")
    n86 = counts.get(0x86, 0)
    print(f"\ncommand TLVs (0x86): {n86}")
    if sizes:
        print(f"  sizes: {sizes[:6]}{' ...' if len(sizes) > 6 else ''}")
        print(f"  every 86 TLV = 8-byte C-MAC + AES-CBC payload of one UPP PE.")
    print(f"  R1-R5 lives inside that ciphertext, so grepping the BPP will never")
    print(f"  show it. The count is the proof: the eUICC loads exactly {n86} PEs.")
    return n86


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("der", nargs="?")
    ap.add_argument("--bpp")
    ap.add_argument("--show-keys", action="store_true",
                    help="print K/OPc in full instead of masked")
    a = ap.parse_args()
    if not a.der and not a.bpp:
        ap.print_help()
        return 2
    global SHOW_KEYS
    SHOW_KEYS = a.show_keys
    n_pe = walk_der(a.der) if a.der else None
    n86 = walk_bpp(a.bpp) if a.bpp else None
    if n_pe is not None and n86 is not None:
        print(f"\nPEs in DER = {n_pe},  0x86 commands in BPP = {n86}  "
              f"-> {'MATCH' if n_pe == n86 else 'MISMATCH'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
