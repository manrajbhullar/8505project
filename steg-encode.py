import argparse
import hashlib
import os
import struct
import sys
from dataclasses import dataclass

from Crypto.Cipher import AES
from PIL import Image, UnidentifiedImageError
from PIL.PngImagePlugin import PngInfo


@dataclass
class EncoderArgs:
    input_image: str
    message_file: str
    key: str
    output_image: str


@dataclass
class Payload:
    magic: bytes = b"STEG"
    version: bytes = b"\x01"
    nonce: bytes | None = None
    ciphertext: bytes | None = None
    data: bytes | None = None


@dataclass
class Context:
    args: EncoderArgs | None = None
    error_message: str | None = None
    error_code: int = 1
    image: Image.Image | None = None
    modified_image: Image.Image | None = None
    message_bytes: bytes | None = None
    payload: Payload | None = None


def handle_error(ctx: Context):
    sys.stderr.write(f"\nError: {ctx.error_message}\n")
    sys.stderr.write(f"Exit Code: {ctx.error_code}")
    sys.exit(ctx.error_code)


def parse_arguments(ctx: Context, argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="steg-encode",
        description="Embed an encrypted message into a PNG image using LSB steganography.",
    )
    parser.add_argument("-i", dest="input_image", required=True,
                        metavar="<input.png>", help="path to the input PNG image")
    parser.add_argument("-m", dest="message_file", required=True,
                        metavar="<message_file>", help="path to the message file to embed")
    parser.add_argument("-k", dest="key", required=True,
                        metavar="<key>", help="encryption key (string)")
    parser.add_argument("-o", dest="output_image", required=True,
                        metavar="<output.png>", help="path to write the stego PNG")

    try:
        parsed = parser.parse_args(argv)
    except SystemExit as exc:
        sys.exit(1 if exc.code else 0)

    ctx.args = EncoderArgs(
        input_image=parsed.input_image,
        message_file=parsed.message_file,
        key=parsed.key,
        output_image=parsed.output_image,
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

    try:
        with open(args.message_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        ctx.error_message = f"message file not found: {args.message_file}"
        handle_error(ctx)
    except (PermissionError, IsADirectoryError) as exc:
        ctx.error_message = f"cannot read message file: {exc}"
        handle_error(ctx)
    except OSError as exc:
        ctx.error_message = f"cannot read message file: {exc}"
        handle_error(ctx)

    if len(data) == 0:
        ctx.error_message = f"message file is empty: {args.message_file}"
        handle_error(ctx)
    ctx.message_bytes = data

    if not args.key:
        ctx.error_message = "key must be a non-empty string"
        handle_error(ctx)

    if not args.output_image:
        ctx.error_message = "output image path must be a non-empty string"
        handle_error(ctx)


def encrypt_message(ctx: Context):
    key = hashlib.sha256(ctx.args.key.encode("utf-8")).digest()
    nonce = os.urandom(12)
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(ctx.message_bytes)
    except Exception as exc:
        ctx.error_message = f"encryption failed: {exc}"
        handle_error(ctx)

    ctx.payload = Payload(nonce=nonce, ciphertext=ct + tag)


def build_payload(ctx: Context):
    p = ctx.payload
    ciphertext_length = struct.pack(">I", len(p.ciphertext))
    total_length = struct.pack(">I", 4 + len(p.nonce) + 4 + len(p.ciphertext))
    p.data = (
        p.magic
        + p.version
        + total_length
        + p.nonce
        + ciphertext_length
        + p.ciphertext
    )


def embed_data(ctx: Context):
    img = ctx.image
    data = ctx.payload.data

    capacity_bytes = (img.width * img.height * 3) // 8
    if len(data) > capacity_bytes:
        ctx.error_message = (
            f"insufficient capacity: payload is {len(data)} bytes, "
            f"image holds {capacity_bytes} bytes"
        )
        handle_error(ctx)

    pixels = bytearray(img.tobytes())
    stride = 4 if img.mode == "RGBA" else 3
    total_bits = len(data) * 8

    bit_idx = 0
    pixel_idx = 0
    while bit_idx < total_bits:
        base = pixel_idx * stride
        for channel in range(3):
            if bit_idx >= total_bits:
                break
            byte = data[bit_idx // 8]
            bit = (byte >> (7 - bit_idx % 8)) & 1
            pixels[base + channel] = (pixels[base + channel] & 0xFE) | bit
            bit_idx += 1
        pixel_idx += 1

    modified = Image.frombytes(img.mode, img.size, bytes(pixels))
    modified.info = img.info
    ctx.modified_image = modified


def write_output(ctx: Context):
    info = ctx.image.info
    pnginfo = PngInfo()
    for key, value in info.items():
        if isinstance(value, str):
            pnginfo.add_text(key, value)

    save_kwargs = {"format": "PNG", "pnginfo": pnginfo}
    for k in ("dpi", "gamma", "icc_profile", "transparency", "chromaticity", "srgb"):
        if k in info:
            save_kwargs[k] = info[k]

    try:
        ctx.modified_image.save(ctx.args.output_image, **save_kwargs)
    except (OSError, ValueError) as exc:
        ctx.error_message = f"failed to write output: {exc}"
        ctx.error_code = 2
        handle_error(ctx)


if __name__ == "__main__":
    print("--------------- STEG ENCODE ---------------")
    ctx = Context()
    parse_arguments(ctx)
    handle_arguments(ctx)

    print("\nLoading inputs...")
    w, h = ctx.image.size
    pixels = w * h
    capacity = (pixels * 3) // 8
    print(f"Input Image: {ctx.args.input_image}")
    print(f"Mode: {ctx.image.mode}")
    print(f"Resolution: {w}x{h}")
    print(f"Pixels: {pixels:,}")
    print(f"Capacity: {capacity:,} bytes ({capacity / 1024:.1f} KB)")
    print(f"Message File: {ctx.args.message_file}")
    print(f"Message Size: {len(ctx.message_bytes):,} bytes")

    print("\nEncrypting message...")
    encrypt_message(ctx)
    print(f"Algorithm: AES-256-GCM")
    print(f"Key: {ctx.args.key}")
    print(f"Nonce: {len(ctx.payload.nonce)} bytes")
    print(f"Ciphertext: {len(ctx.payload.ciphertext)} bytes (includes 16-byte GCM tag)")

    print("\nBuilding payload...")
    build_payload(ctx)
    header_size = len(ctx.payload.data) - len(ctx.payload.ciphertext)
    print(f"Header Size: {header_size} bytes")
    print(f"Payload Size: {len(ctx.payload.data):,} bytes")

    print("\nEmbedding data...")
    embed_data(ctx)
    bits = len(ctx.payload.data) * 8
    pixels_used = (bits + 2) // 3
    print(f"Bits Embedded: {bits:,} ({bits // 8:,} bytes)")
    print(f"Pixels Used: {pixels_used:,} of {pixels:,}")

    print("\nWriting output...")
    write_output(ctx)
    print(f"Output Image: {ctx.args.output_image}")

    print("\nEncoding complete.")
