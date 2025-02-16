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
PROVE_TIME=$( { time RUSTFLAGS="-C target-cpu=native" cargo run --bin expander-exec --release -- prove ../bls-ed25519-on-gkr/circuit.txt ../bls-ed25519-on-gkr/witness.txt ../bls-ed25519-on-gkr/proof.txt ; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m\([0-9.]*\)s/\1/' | awk '{printf "%.0f\n", $1 * 1000}' )

echo "Running verifier..."
# Measure verification time using time command
VERIFY_TIME=$( { time RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --bin expander-exec --release -- verify ../bls-ed25519-on-gkr/circuit.txt ../bls-ed25519-on-gkr/witness.txt ../bls-ed25519-on-gkr/proof.txt ; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m\([0-9.]*\)s/\1/' | awk '{printf "%.0f\n", $1 * 1000}' )

# Print results
echo "----------------------------------------"
echo "Performance Measurements"
echo "----------------------------------------"
echo "Witness Generation Time: $WITNESS_TIME ms"
echo "Proving Time: $PROVE_TIME ms"
echo "Verification Time: $VERIFY_TIME ms"
echo "----------------------------------------"
