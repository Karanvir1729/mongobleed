#!/bin/bash
# warmup.sh - Keep secrets "hot" in MongoDB memory before running the exploit
# This script queries all sensitive collections multiple times to ensure
# data is loaded into MongoDB's memory cache for leak detection.

set -e

HOST="${MONGO_HOST:-localhost}"
PORT="${MONGO_PORT:-27017}"
USER="admin"
PASS="SuperSecret123!"

echo "[*] MongoBleed Warmup Script"
echo "[*] Target: $HOST:$PORT"
echo "[*] Warming up sensitive data in memory..."
echo

# Function to run mongosh commands
run_mongo() {
    docker exec mongobleed-target mongosh \
        -u "$USER" -p "$PASS" \
        --authenticationDatabase admin \
        --quiet \
        --eval "$1"
}

# Query each collection multiple times to keep data hot in memory
for i in {1..10}; do
    echo "[*] Warmup iteration $i/10..."
    
    # Query honey_tokens (our special leak detection collection)
    run_mongo 'db.getSiblingDB("secretdb").honey_tokens.find().toArray()'
    
    # Query API keys
    run_mongo 'db.getSiblingDB("secretdb").api_keys.find().toArray()'
    
    # Query internal users with passwords
    run_mongo 'db.getSiblingDB("secretdb").internal_users.find().toArray()'
    
    # Query encryption keys
    run_mongo 'db.getSiblingDB("secretdb").encryption_keys.find().toArray()'
    
    # Query customer PII
    run_mongo 'db.getSiblingDB("customers").profiles.find().toArray()'
    
    # Query transactions
    run_mongo 'db.getSiblingDB("customers").transactions.find().toArray()'
    
    # Small delay between iterations
    sleep 0.5
done

echo
echo "[+] Warmup complete! Sensitive data should now be hot in memory."
echo "[*] Run the exploit now: python3 mongobleed.py --host localhost --max-offset 50000 --output leaked.bin"
