#!/usr/bin/env python3
"""Enable an already-installed profile without re-downloading it.

The full download costs ~12.5 kB over a 19200 baud link and a fresh activation
code; when the question is "why is this profile not working", re-running that
is the wrong tool. This does only ES10c: list profiles, enable one, reset, and
report which AIDs the card answers afterwards.

    python enable_profile.py COM4 --iccid=89860012345678901234
    python enable_profile.py COM4 --iccid=89860012345678901234 --refresh

--refresh sends refreshFlag=TRUE. This card answers enableResult=7 for it and
the code falls back to FALSE (the LPA then has to reset the card itself), but
it is worth trying once after a cold boot: if the card ever accepts TRUE it
rebuilds its application table, which is the difference between "the files are
there" and "the phone can select ADF.USIM".
"""
import sys
import time

from euicc_lpa import AID, ISDR_AIDS, Phoenix
from euicc_lpa import parse_tlv, store_data, tlv


def walk(data):
    """把 parse_tlv 摊平成 (tag, value) 序列，省得为嵌套再写一遍循环。"""
    for tag, value, constructed in parse_tlv(data):
        yield tag, value
        if constructed:
            yield from walk(value)

# What we report on after enabling: the stock UPP AID first (that is what a
# freshly loaded test profile registers), then the real ones.
AIDS = [AID["stock"], AID["usim"], AID["cmcc"], AID["isim"]]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    port = sys.argv[1] if sys.argv[1].startswith("COM") else "COM4"
    iccid = next((a.split("=", 1)[1] for a in sys.argv[1:]
                  if a.startswith("--iccid=")), None)
    refresh = "--refresh" in sys.argv

    ph = Phoenix(port)
    atr = ph.reset()
    print(f"ATR: {atr.hex(' ').upper() or '(nothing)'}")
    if not atr:
        print("卡无响应 —— 拔插一次读卡器再试")
        ph.close()
        return 1
    time.sleep(0.2)

    # 列 profile 只用 ES10c GetProfilesInfo，euicc_lpa 自己就能做。
    # euicc_download 顶部 import requests；没装 requests 时至少 --list
    # 不该 traceback，所以那条路径到此为止，不碰 EuiccCard。
    selected = None
    for aid in ISDR_AIDS:
        for p2 in ("04", "0C"):
            _d, sw = ph.send(f"00A4{p2}00{len(aid)//2:02X}{aid}")
            if sw.startswith("90") or sw.startswith("61"):
                selected = aid
                break
        if selected:
            break
    if not selected:
        print("选不到 ISD-R")
        ph.close()
        return 1

    data, sw = store_data(ph, "BF2D00")
    print("\n已安装的 profile:")
    profiles = []
    cur = None
    for tag, value in walk(data):
        if tag == 0xE3:
            cur = {"iccid": b"", "state": None}
            profiles.append(cur)
        elif cur is not None and tag == 0x5A:
            cur["iccid"] = value
        elif cur is not None and tag == 0x9F70 and value:
            cur["state"] = value[0]
    for p in profiles:
        mark = "enabled" if p["state"] == 1 else f"state={p['state']}"
        ic = p["iccid"].hex().upper()
        # SGP.22 的 5A 是 EF.ICCID 原始字节按高半字节在前打印的，
        # 给人看要跟 sim_dump 一样低半字节优先。
        human = "".join(f"{b & 0xF:X}{b >> 4:X}" for b in p["iccid"]).rstrip("F")
        print(f"  {ic}  -> {human}  {mark}")
    if iccid is None:
        print("\n没给 --iccid=，只列不切")
        ph.close()
        return 0

    from euicc_download import EuiccCard
    es = EuiccCard(ph)
    es.select_isdr()
    target = bytes.fromhex(iccid if len(iccid) % 2 == 0 else iccid + "F")
    if "--delete" in sys.argv:
        # ES10c DeleteProfile (BF33 { 5A <iccid> }).  Needed when a re-install
        # with the same ICCID left the card's AID table stale: delete first,
        # then install from a fresh activation code so the profile is really
        # new and the AID table is rebuilt from the new EF.DIR.
        body = tlv(b"\xbf\x33", tlv(b"\x5a", target))
        resp = es._store_data(body, "DeleteProfile")
        print(f"\nDeleteProfile {iccid}: {resp.hex().upper()}")
        ph.close()
        return 0

    print(f"\nEnableProfile {iccid}  refreshFlag={refresh}")
    es.enable_profile(target, refresh=refresh)

    print("\n--- reset + SELECT by AID ---")
    atr = ph.reset()
    print(f"ATR: {atr.hex(' ').upper() or '(nothing)'}")

    def tx(apdu):
        d, sw = ph.transceive(bytes.fromhex(apdu))
        return d, sw.hex().upper()

    for aid in AIDS:
        _d, sw = tx(f"00A40400{len(aid)//2:02X}{aid}")
        print(f"  {aid:<34} {sw}")
    ph.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
