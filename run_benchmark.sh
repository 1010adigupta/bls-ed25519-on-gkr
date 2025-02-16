#!/bin/bash
echo "Starting benchmarks..."
# Build the project in release mode first
cargo build --release

echo "Running witness generation..."
# Run the main program
cargo run --release
WITNESS_TIME=$(cat witness_time.txt)

cd ..
cd Expander
echo "Running prover..."
# Measure proving time using time command
PROVE_TIME=$( { time cargo run --bin expander-exec --release -- prove ../circuit.txt ../witness.txt ../proof.txt ; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m\([0-9.]*\)s/\1/' | awk '{printf "%.0f\n", $1 * 1000}' )

echo "Running verifier..."
# Measure verification time using time command
VERIFY_TIME=$( { time cargo run --bin expander-exec --release -- ../circuit.txt ../witness.txt ../proof.txt ; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m\([0-9.]*\)s/\1/' | awk '{printf "%.0f\n", $1 * 1000}' )

# Print results
echo "----------------------------------------"
echo "Performance Measurements"
echo "----------------------------------------"
echo "Witness Generation Time: $WITNESS_TIME ms"
echo "Proving Time: $PROVE_TIME ms"
echo "Verification Time: $VERIFY_TIME ms"
echo "----------------------------------------"
