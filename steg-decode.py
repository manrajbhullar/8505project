import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass

from Crypto.Cipher import AES
from PIL import Image, UnidentifiedImageError


@dataclass
class DecoderArgs:
    input_image: str
    key: str
    output_file: str


@dataclass
class Payload:
    magic: bytes | None = None
    version: bytes | None = None
    nonce: bytes | None = None
    ciphertext: bytes | None = None
    data: bytes | None = None


@dataclass
class Context:
    args: DecoderArgs | None = None
    error_message: str | None = None
    error_code: int = 1
    image: Image.Image | None = None
    payload: Payload | None = None
    message_bytes: bytes | None = None


def handle_error(ctx: Context):
    sys.stderr.write(f"\nError: {ctx.error_message}\n")
    sys.stderr.write(f"Exit Code: {ctx.error_code}")
    sys.exit(ctx.error_code)


def parse_arguments(ctx: Context, argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="steg-decode",
        description="Extract and decrypt a message hidden in a PNG steganography image.",
    )
    parser.add_argument("-i", dest="input_image", required=True,
                        metavar="<stego.png>", help="path to the stego PNG image")
    parser.add_argument("-k", dest="key", required=True,
                        metavar="<key>", help="decryption key (string)")
    parser.add_argument("-o", dest="output_file", required=False,
                        default="decoded_output.bin",
                        metavar="<output_file>",
                        help="path to write decoded output (default: decoded_output.bin)")

    try:
        parsed = parser.parse_args(argv)
    except SystemExit as exc:
        sys.exit(1 if exc.code else 0)

    ctx.args = DecoderArgs(
        input_image=parsed.input_image,
        key=parsed.key,
        output_file=parsed.output_file,
    )


def handle_arguments(ctx: Context):
    args = ctx.args

    try:
        img = Image.open(args.input_image)
        img.load()
    except FileNotFoundError:
        ctx.error_message = f"input image not found: {args.input_image}"
        handle_error(ctx)
    except UnidentifiedImageError:
        ctx.error_message = f"invalid PNG: {args.input_image}"
        handle_error(ctx)
    except (PermissionError, IsADirectoryError) as exc:
        ctx.error_message = f"cannot read input image: {exc}"
        handle_error(ctx)
    except OSError as exc:
        ctx.error_message = f"invalid PNG: {exc}"
        handle_error(ctx)

    if img.format != "PNG":
        ctx.error_message = f"invalid PNG: {args.input_image} is {img.format}, expected PNG"
        handle_error(ctx)
    if img.mode not in ("RGB", "RGBA"):
        ctx.error_message = f"unsupported image mode {img.mode}; expected RGB or RGBA"
        handle_error(ctx)
    ctx.image = img

    if not args.key:
        ctx.error_message = "key must be a non-empty string"
        handle_error(ctx)


def _extract_lsbs(pixels: bytes, stride: int, n_bytes: int):
    out = bytearray(n_bytes)
    total_bits = n_bytes * 8

    bit_idx = 0
    pixel_idx = 0
    while bit_idx < total_bits:
        base = pixel_idx * stride
        for channel in range(3):
            if bit_idx >= total_bits:
                break
            bit = pixels[base + channel] & 1
            out[bit_idx // 8] |= bit << (7 - bit_idx % 8)
            bit_idx += 1
        pixel_idx += 1
    return bytes(out)


def extract_data(ctx: Context):
    img = ctx.image
    pixels = img.tobytes()
    stride = 4 if img.mode == "RGBA" else 3
    capacity_bytes = (img.width * img.height * 3) // 8

    if capacity_bytes < 9:
        ctx.error_message = "image too small to contain envelope header"
        handle_error(ctx)

    header = _extract_lsbs(pixels, stride, 9)

    if header[:4] != b"STEG" or header[4:5] != b"\x01":
        ctx.error_message = "invalid header: magic or version mismatch"
        handle_error(ctx)

    (total_length,) = struct.unpack(">I", header[5:9])
    full_size = 5 + total_length

    data = _extract_lsbs(pixels, stride, full_size)
    ctx.payload = Payload(data=data)


def parse_payload(ctx: Context):
    p = ctx.payload
    data = p.data

    if len(data) < 9:
        ctx.error_message = "invalid header: payload too short"
        handle_error(ctx)

    magic = data[:4]
    if magic != b"STEG":
        ctx.error_message = "invalid header: magic mismatch"
        handle_error(ctx)

    version = data[4:5]
    if version != b"\x01":
        ctx.error_message = f"invalid header: unsupported version {version[0]}"
        handle_error(ctx)

    (total_length,) = struct.unpack(">I", data[5:9])
    if len(data) != 5 + total_length:
        ctx.error_message = "invalid header: total length does not match payload size"
        handle_error(ctx)

    nonce_len = 12
    if total_length < 4 + nonce_len + 4:
        ctx.error_message = "invalid header: total length too small for nonce and ciphertext length"
        handle_error(ctx)

    nonce = data[9:9 + nonce_len]
    (ciphertext_length,) = struct.unpack(">I", data[9 + nonce_len:9 + nonce_len + 4])

    ct_start = 9 + nonce_len + 4
    if ct_start + ciphertext_length != len(data):
        ctx.error_message = "invalid header: ciphertext length does not match remaining bytes"
        handle_error(ctx)

    p.magic = magic
    p.version = version
    p.nonce = nonce
    p.ciphertext = data[ct_start:ct_start + ciphertext_length]


def decrypt_message(ctx: Context):
    p = ctx.payload
    key = hashlib.sha256(ctx.args.key.encode("utf-8")).digest()

    if len(p.ciphertext) < 16:
        ctx.error_message = "decryption failed: ciphertext too short for GCM tag"
        handle_error(ctx)

    ct = p.ciphertext[:-16]
    tag = p.ciphertext[-16:]

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=p.nonce)
        plaintext = cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        ctx.error_message = "decryption failed (wrong key or corrupted data)"
        handle_error(ctx)
    except Exception as exc:
        ctx.error_message = f"decryption failed: {exc}"
        handle_error(ctx)

    ctx.message_bytes = plaintext


def write_output(ctx: Context):
    try:
        with open(ctx.args.output_file, "wb") as f:
            f.write(ctx.message_bytes)
    except (OSError, ValueError) as exc:
        ctx.error_message = f"failed to write output: {exc}"
        ctx.error_code = 2
        handle_error(ctx)


if __name__ == "__main__":
    print("--------------- STEG DECODE ---------------")
    ctx = Context()
    parse_arguments(ctx)
    handle_arguments(ctx)

    print("\nLoading inputs...")
    pixels = ctx.image.size[0] * ctx.image.size[1]
    print(f"Input Image: {ctx.args.input_image}")

    print("\nExtracting data...")
    extract_data(ctx)
    bits = len(ctx.payload.data) * 8
    pixels_used = (bits + 2) // 3
    print(f"Bits Extracted: {bits:,} ({bits // 8:,} bytes)")
    print(f"Pixels Used: {pixels_used:,} of {pixels:,}")
    print(f"Payload Size: {len(ctx.payload.data):,} bytes")

    print("\nParsing payload...")
    parse_payload(ctx)
    total_length = len(ctx.payload.data) - 5
    print(f"Magic: {ctx.payload.magic.decode('ascii')}")
    print(f"Version: {ctx.payload.version[0]}")
    print(f"Total Length: {total_length:,} bytes (after magic and version)")
    print(f"Nonce: {len(ctx.payload.nonce)} bytes")
    print(f"Ciphertext Length: {len(ctx.payload.ciphertext):,} bytes")
    print(f"Ciphertext: {len(ctx.payload.ciphertext):,} bytes")

    print("\nDecrypting message...")
    decrypt_message(ctx)
    print(f"Algorithm: AES-256-GCM")
    print(f"Key: {ctx.args.key}")
    print(f"Message Size: {len(ctx.message_bytes):,} bytes")

    print("\nWriting output...")
    write_output(ctx)
    print(f"Output File: {ctx.args.output_file}")

    print("\nDecoding complete.")
