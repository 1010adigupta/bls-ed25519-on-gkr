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

# Create a directory for parallel runs
mkdir -p parallel_runs

# Function to run proving instance
run_proving() {
    local instance=$1
    local outdir="parallel_runs/run_${instance}"
    mkdir -p "$outdir"
    
    # Copy necessary files from parent directory
    cp ../bls-ed25519-on-gkr/circuit.txt ../bls-ed25519-on-gkr/witness.txt "$outdir/"
    
    # Run prover and capture time
    PROVE_TIME=$( { time RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --bin expander-exec --release -- prove "$outdir/circuit.txt" "$outdir/witness.txt" "$outdir/proof.txt" ; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m\([0-9.]*\)s/\1/' | awk '{printf "%.0f\n", $1 * 1000}' )
    
    # Save time to result file
    echo "Instance $instance: Prove Time: ${PROVE_TIME}ms" > "$outdir/prove_results.txt"
}

# Function to run verification instance
run_verification() {
    local instance=$1
    local outdir="parallel_runs/run_${instance}"
    
    # Run verifier and capture time
    VERIFY_TIME=$( { time RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --bin expander-exec --release -- "$outdir/circuit.txt" "$outdir/witness.txt" "$outdir/proof.txt" ; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m\([0-9.]*\)s/\1/' | awk '{printf "%.0f\n", $1 * 1000}' )
    
    # Save time to result file
    echo "Instance $instance: Verify Time: ${VERIFY_TIME}ms" > "$outdir/verify_results.txt"
}

export -f run_proving
export -f run_verification

echo "Starting parallel execution of 64 proving instances..."
# Record start time for proving
PROVE_START=$(date +%s%N)

# Run 64 proving instances in parallel
seq 1 64 | parallel -j 64 run_proving

# Record end time and calculate total duration for proving
PROVE_END=$(date +%s%N)
TOTAL_PROVE_PARALLEL_TIME=$(( ($PROVE_END - $PROVE_START) / 1000000 )) # Convert nanoseconds to milliseconds

echo "Starting parallel execution of 64 verification instances..."
# Record start time for verification
VERIFY_START=$(date +%s%N)

# Run 64 verification instances in parallel
seq 1 64 | parallel -j 64 run_verification

# Record end time and calculate total duration for verification
VERIFY_END=$(date +%s%N)
TOTAL_VERIFY_PARALLEL_TIME=$(( ($VERIFY_END - $VERIFY_START) / 1000000 )) # Convert nanoseconds to milliseconds

# Calculate total CPU times
TOTAL_PROVE_CPU_TIME=$(cat parallel_runs/run_*/prove_results.txt | grep -o "Prove Time: [0-9]*" | awk '{sum += $3} END {print sum}')
TOTAL_VERIFY_CPU_TIME=$(cat parallel_runs/run_*/verify_results.txt | grep -o "Verify Time: [0-9]*" | awk '{sum += $3} END {print sum}')

# Print results
echo "----------------------------------------"
echo "Performance Measurements"
echo "----------------------------------------"
echo "Witness Generation Time: $WITNESS_TIME ms"
echo ""
echo "Proving Phase:"
echo "Total CPU Time for 64 Proving Instances: ${TOTAL_PROVE_CPU_TIME}ms"
echo "Total Wall Clock Time for Proving (Parallel): ${TOTAL_PROVE_PARALLEL_TIME}ms"
echo ""
echo "Verification Phase:"
echo "Total CPU Time for 64 Verification Instances: ${TOTAL_VERIFY_CPU_TIME}ms"
echo "Total Wall Clock Time for Verification (Parallel): ${TOTAL_VERIFY_PARALLEL_TIME}ms"
echo "----------------------------------------"
