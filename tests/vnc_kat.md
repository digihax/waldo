# A5 VNC decoder — Known-Answer Test (KAT) fixtures

**Purpose:** independently verify the A5b VNC fixed-key DES decoder in `waldo.ps1` (and the `~/.vnc/passwd`
path in `waldo.sh`). Per the build spec's KAT-provenance rule, every vector here was produced by an engine
**other than Waldo's own decoder**, so a shared implementation bug cannot pass both sides.

## Algorithm under test
- Fixed key `{23,82,107,6,35,78,88,7}` (`0x17526b06234e5807`), with **each byte bit-reversed** → `0xe84ad660c4721ae0`
  (the documented adaptation so standard DES matches the d3des library VNC uses).
- DES-ECB, no padding, decrypt the 8-byte block, treat the result as a C-string (stop at first NUL).

## Vectors and provenance
Raw 8-byte blocks — produced independently by **openssl 3.x (legacy provider) DES-ECB** and cross-checked with
**pycryptodome `Crypto.Cipher.DES`**:

| plaintext | stored 8-byte block (hex) |
|---|---|
| `Secret12` | `50ccb2fc99726c7f` |
| `abc`      | `9c0a172d3482e122` |
| `R00t!Pw`  | `4c995abc1beaff70` |
| `monkey`   | `2005ed6913063a69` |

Reproduce a block independently:
```
printf 'Secret12' | openssl enc -des-ecb -nopad -K e84ad660c4721ae0 -provider legacy -provider default | xxd -p
# -> 50ccb2fc99726c7f
```

UltraVNC INI record — produced by the **Win32 `WritePrivateProfileStruct` API** (not Waldo):
- `passwd=50CCB2FC99726C7F`**`C0`** — an **18-hex profile-struct record** = 8 data bytes + a 1-byte checksum
  (`C0`). `GetPrivateProfileStruct` recomputes and compares that checksum on read.

## Negative cases (must NOT decode)
- **Bad checksum:** flip the trailing checksum byte → `GetPrivateProfileStruct` returns false → not decoded.
- **Wrong length / non-hex:** e.g. `deadbeef` (4 bytes) → decoder returns null; A5a flags such artifacts as
  informational only.
- **Salted PBKDF2 (modern RealVNC):** a non-8-byte value → classified `format=salted_hash`, never decoded.

## Run
```
pwsh -NoProfile -File waldo/tests/vnc_kat.ps1     # exit 0 = all PASS
```
Last run: **7 passed, 0 failed** (4 raw-block + INI-decode + bad-checksum-rejected + malformed-null).
