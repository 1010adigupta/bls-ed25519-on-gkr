#!/bin/bash
echo "Starting benchmarking..."
# Build the project in release mode first
cargo build --release

echo "Running witness generation..."
# Run the main program and capture witness generation time
WITNESS_TIME=$(cargo run --release | grep "WITNESS_TIME:" | cut -d' ' -f2)

cd Expander
echo "Running prover..."
# Measure proving time
PROVE_START=$(date +%s%N)
cargo run --bin expander-exec --release -- prove ../circuit.txt ../witness.txt ../proof.txt
PROVE_END=$(date +%s%N)
PROVE_TIME=$((($PROVE_END - $PROVE_START)/1000000)) # Convert to milliseconds

echo "Running verifier..."
# Measure verification time
VERIFY_START=$(date +%s%N)
cargo run --bin expander-exec --release -- ../circuit.txt ../witness.txt ../proof.txt
VERIFY_END=$(date +%s%N)
VERIFY_TIME=$((($VERIFY_END - $VERIFY_START)/1000000)) # Convert to milliseconds

# Print results
echo "----------------------------------------"
echo "Performance Measurements"
echo "----------------------------------------"
echo "Witness Generation Time: $WITNESS_TIME ms"
echo "Proving Time: $PROVE_TIME ms"
echo "Verification Time: $VERIFY_TIME ms"
echo "----------------------------------------"
