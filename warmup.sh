#!/bin/bash
echo "[*] Warming up..."
for i in {1..20}; do
  # Run inside container; read kernel process filesystem metadata.
  # /proc/self/mountinfo = mount table; /proc/self/maps = virtual memory map.
  # Discard stdout+stderr to keep output silent; repeated reads warm caches/allocator paths.
  docker exec mongobleed-target cat /proc/self/mountinfo >/dev/null 2>&1
  docker exec mongobleed-target cat /proc/self/maps >/dev/null 2>&1
done
echo "[*] Warmup complete"