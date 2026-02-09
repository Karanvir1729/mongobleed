#!/bin/bash
# Warmup - aggressively loads /proc/mountinfo into MongoDB's heap memory
echo "[*] Warming up..."
for i in {1..20}; do 
  docker exec mongobleed-target cat /proc/self/mountinfo > /dev/null 2>&1
  docker exec mongobleed-target cat /proc/self/maps > /dev/null 2>&1
done
echo "[*] Warmup complete"
