#!/usr/bin/env python3
"""Read EF_FF03 (R1-R5) straight off the card.

This talks to the *USIM application inside the card*, not to ISD-R, so it only
works once a profile has been installed **and enabled**, and the card has been
reset (that is what the REFRESH after EnableProfile does).

    python read_ff03.py [COM4] [19200] [--aid=...]

Exit code 0 = FF03 read successfully, 1 = not found / card not answering.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from euicc_lpa import Phoenix, read_ff03, select_fid, select_usim

R1R5 = "20132F495B"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    aid = next((a.split("=", 1)[1] for a in sys.argv[1:]
                if a.startswith("--aid=")), None)
    port = args[0] if args else "COM4"
    baud = int(args[1]) if len(args) > 1 else 19200

    ph = Phoenix(port, baud)
    atr = ph.reset()
    print(f"ATR: {atr.hex(' ').upper() or '(nothing)'}")
    if not atr:
        print("卡无响应，先拔插读卡器")
        ph.close()
        return 1

    if not select_usim(ph, aid):
        print("USIM 没选上（这张卡的测试 profile 就没有 USIM ADF）——"
              "直接走 MF，先读 EF.ICCID 确认当前服务的是哪个 profile。")

    # Which profile are we inside? EF.ICCID at MF tells us directly, and it is
    # also the cheapest proof that the card is serving a profile at all.
    if select_fid(ph, "3F00") and select_fid(ph, "2FE2"):
        d, sw = ph.send("00B000000A")
        if sw == "9000" and len(d) >= 10:
            iccid = "".join(f"{d[i] & 0x0F:X}{d[i] >> 4:X}" for i in range(10))
            print(f"  当前 profile ICCID: {iccid}")
        else:
            print(f"  EF.ICCID 读不到: {sw}")
    else:
        print("  连 MF 都选不上 —— 卡没在服务任何 profile")

    data = read_ff03(ph)
    ph.close()

    if data is None:
        print("\nFF03 没读到。检查：profile 是否 enable、卡是否 reset 过、"
              "EF.ARR(2F06 rec 2) 是否允许读、以及这张是不是 eUICC"
              "（普通 SIM 没有 ISD-R，也没有这个文件）")
        return 1

    value = data[:5].hex().upper()
    print(f"\nR1-R5 = {value}   {'(与工作卡一致)' if value == R1R5 else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
