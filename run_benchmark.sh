#!/bin/bash
echo "Starting benchmarks..."
# Build the project in release mode first
cargo build --release

echo "Running witness generation..."
# Run the main program
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --release
WITNESS_TIME=$(cat witness_time.txt)

cd ..
cd Expander

echo "Running prover..."
echo "----------------------------------------"
# Run prover and show output
time RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --bin expander-exec --release -- prove ../bls-ed25519-on-gkr/circuit.txt ../bls-ed25519-on-gkr/witness.txt ../bls-ed25519-on-gkr/proof.txt
PROVE_TIME=$?
echo "----------------------------------------"

echo "Running verifier..."
echo "----------------------------------------"
# Run verifier and show output
time RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --bin expander-exec --release -- verify ../bls-ed25519-on-gkr/circuit.txt ../bls-ed25519-on-gkr/witness.txt ../bls-ed25519-on-gkr/proof.txt
VERIFY_TIME=$?
echo "----------------------------------------"

# Print results
echo "----------------------------------------"
echo "Performance Measurements"
echo "----------------------------------------"
echo "Witness Generation Time: $WITNESS_TIME ms"
echo "Proving Exit Code: $PROVE_TIME"
echo "Verification Exit Code: $VERIFY_TIME"
echo "----------------------------------------"
