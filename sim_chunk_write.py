#!/usr/bin/env python3
"""Replay a chunked STORE DATA (like ES10b AuthenticateServer) over the
Phoenix reader and show exactly what the card answers per block.

The point is to watch for T=0 NULL bytes (0x60) while the card is busy:
they must be skipped, not mistaken for SW1SW2.

    python sim_chunk_write.py [COM4] [19200]
"""
import sys
import time

from euicc_lpa import Phoenix, ISDR_AIDS, tlv

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"
BAUD = int(sys.argv[2]) if len(sys.argv) > 2 else 19200

CHUNK = 120


def store_data_chunked(ph, payload, label=""):
    """Split payload into CHUNK-byte blocks: P1=0x11 intermediate, 0x91 last."""
    blocks = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)]
    print(f"  {label}: {len(payload)} bytes in {len(blocks)} blocks")
    for idx, blk in enumerate(blocks):
        last = idx == len(blocks) - 1
        p1 = 0x91 if last else 0x11
        apdu = bytes([0x81, 0xE2, p1, idx & 0xFF, len(blk)]) + blk
        t0 = time.time()
        try:
            data, sw = ph.transceive(apdu)
            dt = (time.time() - t0) * 1000
            flag = "  <<< 最后一块" if last else ""
            print(f"    block {idx} p1={p1:02X} lc={len(blk):3d} "
                  f"-> sw={sw.hex().upper():6s} {dt:6.0f} ms{flag}")
            if sw and sw[0] == 0x61:
                more, sw2 = ph.transceive(bytes([0x81, 0xC0, 0x00, 0x00, sw[1]]))
                print(f"      GET RESPONSE -> {len(more)} bytes, sw={sw2.hex().upper()}")
        except Exception as e:
            print(f"    block {idx} p1={p1:02X} FAILED: {e}")
            return False
    return True


def main():
    ph = Phoenix(PORT, BAUD)
    atr = ph.reset()
    print("ATR:", atr.hex(" ").upper() or "(nothing)")
    if not atr:
        print("\n卡无响应 —— 先拔插一次读卡器再跑。")
        ph.close()
        return 1
    time.sleep(0.2)

    print("\n--- 开通道 + 选 ISD-R ---")
    d, sw = ph.send("0070000001")
    print(f"  MANAGE CHANNEL: sw={sw} ch={d.hex().upper()}")
    d, sw = ph.send("01A4040010A0000005591010FFFFFFFF8900000100")
    print(f"  SELECT ISD-R  : sw={sw} fci={len(d)} bytes")

    # 一个 700 字节左右的合法 TLV（GetEuiccData 里塞一段无意义数据），
    # 目的不是让卡接受内容，而是逼它走完分块流程并观察 0x60。
    filler = bytes((i * 7) & 0xFF for i in range(700))
    payload = tlv(0xBF3E, filler)
    print("\n--- 分块 STORE DATA（观察 0x60 NULL）---")
    store_data_chunked(ph, payload, "dummy 700B")

    print("\n--- 复位后再读一次 EID，确认链路没被搞坏 ---")
    atr = ph.reset()
    print("  ATR:", atr.hex(" ").upper() or "(nothing)")
    if atr:
        time.sleep(0.2)
        ph.send("0070000001")
        ph.send("01A4040010A0000005591010FFFFFFFF8900000100")
        d, sw = ph.send("81E2910006BF3E035C015A")
        print(f"  GetEID: sw={sw} data={d.hex().upper()[:40]}")
    print(f"\nechoErrors={ph.echo_errors}")
    ph.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
