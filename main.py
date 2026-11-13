#!/usr/bin/env python3
"""Matching Scarves - entry program for make.fun cutest-picture-01.

The artwork ships in this repository as artwork.jpg, a 1024x1024 JPEG:
a cream kitten with big blue eyes and a mint knitted scarf hugging a
sleeping duckling that wears a tiny matching scarf of its own, on a
picnic blanket at golden hour.

The competition reads /output/entry.png and accepts either a PNG or a
JPEG there (told apart by first bytes), at most 1 MiB and at most
1024x1024 pixels. This program therefore inspects the artwork's real
structure - format signature, segment/chunk walk, frame dimensions,
end marker - checks it against that gate, and only then publishes it.
"""

import hashlib
import os
import struct
import sys
import zlib

MAX_BYTES = 1_048_576
MAX_WIDTH = 1024
MAX_HEIGHT = 1024

JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# JPEG markers that carry no length field and no payload.
STANDALONE_MARKERS = {0x01, 0xD8, 0xD9} | set(range(0xD0, 0xD8))
# Start-of-frame markers that hold the frame dimensions.
SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
               0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
SOS_MARKER = 0xDA


def jpeg_dimensions(data):
    """Walk the JPEG marker stream and return (width, height).

    Raises ValueError on any structural surprise so a truncated or
    mislabelled file never reaches the output directory.
    """
    if len(data) < 4 or data[:2] != JPEG_SOI:
        raise ValueError("missing JPEG start-of-image signature")
    if data[-2:] != JPEG_EOI:
        raise ValueError("missing JPEG end-of-image marker")
    pos = 2
    size = len(data)
    while pos + 1 < size:
        if data[pos] != 0xFF:
            raise ValueError(f"expected marker at offset {pos}")
        marker = data[pos + 1]
        pos += 2
        if marker in STANDALONE_MARKERS:
            continue
        if pos + 1 >= size:
            raise ValueError("truncated marker segment")
        (seg_len,) = struct.unpack(">H", data[pos:pos + 2])
        if seg_len < 2 or pos + seg_len > size:
            raise ValueError("marker segment runs past end of file")
        if marker in SOF_MARKERS:
            if seg_len < 7:
                raise ValueError("start-of-frame segment too short")
            (height,) = struct.unpack(">H", data[pos + 3:pos + 5])
            (width,) = struct.unpack(">H", data[pos + 5:pos + 7])
            return width, height
        if marker == SOS_MARKER:
            break  # entropy-coded data follows; dimensions already known or absent
        pos += seg_len
    raise ValueError("no start-of-frame marker found")


def png_dimensions(data):
    """Walk the PNG chunk stream and return (width, height).

    Every chunk's CRC is verified and the walk must end exactly at the
    IEND chunk, so a truncated or corrupted PNG is rejected here rather
    than by the competition's sealed gate.
    """
    if data[:8] != PNG_SIGNATURE:
        raise ValueError("missing PNG signature")
    pos = 8
    size = len(data)
    width = height = None
    while pos + 8 <= size:
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        end = pos + 8 + length + 4
        if end > size:
            raise ValueError("PNG chunk runs past end of file")
        payload = data[pos + 8:pos + 8 + length]
        (stored_crc,) = struct.unpack(">I", data[pos + 8 + length:end])
        if zlib.crc32(ctype + payload) & 0xFFFFFFFF != stored_crc:
            raise ValueError(f"PNG chunk {ctype!r} has a bad CRC")
        if ctype == b"IHDR":
            if length < 8:
                raise ValueError("IHDR chunk too short")
            (width,) = struct.unpack(">I", payload[0:4])
            (height,) = struct.unpack(">I", payload[4:8])
        if ctype == b"IEND":
            if end != size:
                raise ValueError("trailing bytes after IEND chunk")
            if width is None:
                raise ValueError("no IHDR chunk found")
            return width, height
        pos = end
    raise ValueError("no IEND chunk found")


def dimensions(data):
    """Return (width, height) for a JPEG or PNG byte string.

    The competition tells the two formats apart by their first bytes,
    and so does this dispatcher: anything else is not an entry image.
    """
    if data[:2] == JPEG_SOI:
        return jpeg_dimensions(data)
    if data[:8] == PNG_SIGNATURE:
        return png_dimensions(data)
    raise ValueError("unrecognised image format (neither JPEG nor PNG)")


def check_gate(data, width, height):
    """Return a list of gate violations; empty means the art may ship."""
    problems = []
    if len(data) > MAX_BYTES:
        problems.append(f"{len(data)} bytes exceeds the {MAX_BYTES}-byte gate")
    if width > MAX_WIDTH or height > MAX_HEIGHT:
        problems.append(f"{width}x{height} exceeds the {MAX_WIDTH}x{MAX_HEIGHT} gate")
    if width != height:
        problems.append(f"{width}x{height} is not the square format this entry ships")
    return problems


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    source = os.path.join(here, "artwork.jpg")
    with open(source, "rb") as fh:
        data = fh.read()
    width, height = dimensions(data)
    problems = check_gate(data, width, height)
    if problems:
        for problem in problems:
            print(f"gate check failed: {problem}", file=sys.stderr)
        return 1
    out_dir = os.environ.get("MAKEFUN_OUTPUT_DIR", "/output")
    os.makedirs(out_dir, exist_ok=True)
    target = os.path.join(out_dir, "entry.png")
    with open(target, "wb") as fh:
        fh.write(data)
    digest = hashlib.sha256(data).hexdigest()
    # Round-trip check: what landed on disk must parse as the same image.
    with open(target, "rb") as fh:
        landed = fh.read()
    if hashlib.sha256(landed).hexdigest() != digest:
        print("gate check failed: written file differs from the source", file=sys.stderr)
        return 1
    landed_w, landed_h = dimensions(landed)
    if (landed_w, landed_h) != (width, height):
        print("gate check failed: written file has different dimensions", file=sys.stderr)
        return 1
    print(f"wrote {target}: {width}x{height}, {len(data)} bytes, sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
