#!/usr/bin/env python3
"""What does the card actually expose *after* a profile install + enable?

Three questions, in the order that matters:
  1. is the profile we just installed the enabled one (ES10c GetProfilesInfo)
  2. what does EF.DIR (2F00) say -- that is the list the ME discovers
  3. which AIDs does the card answer 9000 for right now

    python probe_after_install.py [COM4]
"""
import sys

from euicc_lpa import PROBE_AIDS as AIDS, Phoenix

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM4"


def main():
    ph = Phoenix(PORT)
    atr = ph.reset()
    print(f"ATR: {atr.hex(' ').upper()}\n")

    def tx(apdu):
        d, sw = ph.transceive(bytes.fromhex(apdu))
        return d, sw.hex().upper()

    # --- EF.DIR ---------------------------------------------------------
    print("--- EF.DIR (2F00) ---")
    tx("00A4000C023F00")
    _d, sw = tx("00A4000C022F00")
    print(f"  SELECT 2F00: {sw}")
    for rec in (1, 2, 3):
        got = None
        for le in (0x21, 0x2B, 0x28, 0x22, 0x1C):
            d, sw = tx(f"00B2{rec:02X}04{le:02X}")
            if sw == "9000":
                got = d
                break
        if got is None:
            print(f"  rec{rec}: {sw} (no record)")
            continue
        print(f"  rec{rec}: {got.hex().upper()}")
        # 61 len 4F len AID [50 len label]
        if len(got) > 4 and got[0] == 0x61:
            i = 2
            while i + 1 < len(got):
                tag, ln = got[i], got[i + 1]
                val = got[i + 2:i + 2 + ln]
                if tag == 0x4F:
                    print(f"        AID   {val.hex().upper()} ({len(val)}B)")
                elif tag == 0x50:
                    print(f"        label {val.decode('latin-1')!r}")
                i += 2 + ln

    # --- AID matrix ------------------------------------------------------
    print("\n--- SELECT by AID ---")
    for aid in AIDS:
        _d, sw = tx(f"00A40400{len(aid)//2:02X}{aid}")
        print(f"  {aid:<34} {sw}")

    # --- which profile is enabled ---------------------------------------
    print("\n--- ES10c GetProfilesInfo ---")
    try:
        from euicc_download import EuiccCard
        es = EuiccCard(ph)
        es.select_isdr()
        for iccid, state in es.get_profiles_info():
            print(f"  {iccid.hex().upper()}  state={state}")
    except Exception as exc:                      # noqa: BLE001
        print(f"  (skipped: {type(exc).__name__}: {exc})")

    ph.close()


if __name__ == "__main__":
    main()
