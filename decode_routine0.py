#!/usr/bin/env python3
"""
Decode a Samsung Routines routine_<id> file into header/body/footer and JSON body.

Decompiled app flow shows the body is JSON, optionally AES-GCM encrypted for
version >= 2.0 using an APK certificate key (not a user password).
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Optional, Tuple


HEADER_SIZE = 512


def _version_gt(a: str, b: str) -> bool:
    """Return True if version a > version b, matching w6.d.c in the app."""
    def _parts(v: str) -> list[int]:
        out = []
        for part in v.split("."):
            try:
                out.append(int(part))
            except ValueError:
                out.append(0)
        return out

    pa = _parts(a)
    pb = _parts(b)
    n = max(len(pa), len(pb))
    for i in range(n):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va > vb:
            return True
        if va < vb:
            return False
    return False


def _read_header(buf: bytes) -> dict:
    header_raw = buf[:HEADER_SIZE]
    if b"\x00" in header_raw:
        header_raw = header_raw.split(b"\x00", 1)[0]
    header_text = header_raw.decode("utf-8", errors="strict").strip()
    return json.loads(header_text)


def _read_footer(buf: bytes, offset: int, size: int) -> dict:
    footer_raw = buf[offset:offset + size]
    footer_text = footer_raw.decode("utf-8", errors="strict").strip()
    return json.loads(footer_text)


def _extract_payload(path: Path) -> bytes:
    data = path.read_bytes()
    if data.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            if not names:
                raise ValueError("zip file has no entries")
            return zf.read(names[0])
    return data


def _decrypt_aes_gcm(body: bytes, key: bytes) -> bytes:
    if len(body) < 13:
        raise ValueError("body too small for AES-GCM (needs 12-byte IV)")
    iv = body[:12]
    ciphertext_and_tag = body[12:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore

        return AESGCM(key).decrypt(iv, ciphertext_and_tag, None)
    except ModuleNotFoundError:
        pass
    except Exception as exc:
        raise ValueError(f"AES-GCM decrypt failed: {exc}") from exc
    try:
        from Crypto.Cipher import AES  # type: ignore

        if len(ciphertext_and_tag) < 16:
            raise ValueError("ciphertext too small for AES-GCM tag")
        ct = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ct, tag)
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "AES-GCM unavailable (install 'cryptography' or 'pycryptodome')"
        ) from exc
    except Exception as exc:
        raise ValueError(f"AES-GCM decrypt failed: {exc}") from exc


def _decode_body(body: bytes, version: str, key: Optional[str], no_decrypt: bool) -> Tuple[bytes, str]:
    needs_decrypt = not _version_gt("2.0", version)
    if needs_decrypt and not no_decrypt:
        if not key:
            raise ValueError("encrypted body; provide --key or use --no-decrypt")
        key_bytes = key.encode("utf-8")
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("invalid AES key length; expected 16/24/32 bytes")
        body = _decrypt_aes_gcm(body, key_bytes)
    text = body.decode("utf-8", errors="replace")
    return body, text


def main() -> int:
    ap = argparse.ArgumentParser(description="Decode Samsung routine_<id> files.")
    ap.add_argument("input", type=Path, help="Path to routine_<id> or .rtn zip.")
    ap.add_argument("--key", help="AES key string (32 chars from app signature).")
    ap.add_argument("--no-decrypt", action="store_true", help="Skip AES-GCM decryption.")
    ap.add_argument("-o", "--outdir", type=Path, default=Path("routine_decoded"))
    ap.add_argument("--print", dest="print_body", action="store_true", help="Print decoded body JSON.")
    args = ap.parse_args()

    data = _extract_payload(args.input)
    if len(data) < HEADER_SIZE:
        raise SystemExit(f"file too small ({len(data)} bytes)")

    header = _read_header(data)
    body_size = int(header.get("body_size", 0))
    footer_size = int(header.get("footer_size", 0))
    version = str(header.get("version", "0.0"))

    body_off = HEADER_SIZE
    footer_off = body_off + body_size
    end_off = footer_off + footer_size
    if end_off > len(data):
        raise SystemExit("header sizes exceed file length")

    body = data[body_off:footer_off]
    footer = _read_footer(data, footer_off, footer_size)

    decoded_body_bytes, decoded_body_text = _decode_body(body, version, args.key, args.no_decrypt)

    args.outdir.mkdir(parents=True, exist_ok=True)
    (args.outdir / "header.json").write_text(json.dumps(header, indent=2), encoding="utf-8")
    (args.outdir / "footer.json").write_text(json.dumps(footer, indent=2), encoding="utf-8")
    (args.outdir / "body.bin").write_bytes(body)
    (args.outdir / "body.decoded.txt").write_text(decoded_body_text, encoding="utf-8")

    if args.print_body:
        print(decoded_body_text)

    print("[+] Wrote:")
    print(f"    {args.outdir / 'header.json'}")
    print(f"    {args.outdir / 'body.bin'}")
    print(f"    {args.outdir / 'body.decoded.txt'}")
    print(f"    {args.outdir / 'footer.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
