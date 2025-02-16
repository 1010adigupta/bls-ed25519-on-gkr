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

# Function to run a single instance
run_instance() {
    local instance=$1
    local outdir="parallel_runs/run_${instance}"
    mkdir -p "$outdir"
    
    # Copy necessary files
    cp circuit.txt witness.txt "$outdir/"
    
    # Run prover and capture time
    PROVE_TIME=$( { time RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --bin expander-exec --release -- prove "$outdir/circuit.txt" "$outdir/witness.txt" "$outdir/proof.txt" ; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m\([0-9.]*\)s/\1/' | awk '{printf "%.0f\n", $1 * 1000}' )
    
    # Run verifier and capture time
    VERIFY_TIME=$( { time RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --bin expander-exec --release -- "$outdir/circuit.txt" "$outdir/witness.txt" "$outdir/proof.txt" ; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m\([0-9.]*\)s/\1/' | awk '{printf "%.0f\n", $1 * 1000}' )
    
    # Save times to result file
    echo "Instance $instance: Prove Time: ${PROVE_TIME}ms, Verify Time: ${VERIFY_TIME}ms" > "$outdir/results.txt"
}

export -f run_instance

echo "Starting parallel execution of 64 instances..."
# Record start time
PARALLEL_START=$(date +%s%N)

# Run 64 instances in parallel
seq 1 64 | parallel -j 64 run_instance

# Record end time and calculate total duration
PARALLEL_END=$(date +%s%N)
TOTAL_PARALLEL_TIME=$(( ($PARALLEL_END - $PARALLEL_START) / 1000000 )) # Convert nanoseconds to milliseconds

# Collect and display results
echo "All runs completed. Results:"
cat parallel_runs/run_*/results.txt

# Calculate total times
TOTAL_PROVE_TIME=$(cat parallel_runs/run_*/results.txt | grep -o "Prove Time: [0-9]*" | awk '{sum += $3} END {print sum}')
TOTAL_VERIFY_TIME=$(cat parallel_runs/run_*/results.txt | grep -o "Verify Time: [0-9]*" | awk '{sum += $3} END {print sum}')

# Print results
echo "----------------------------------------"
echo "Performance Measurements"
echo "----------------------------------------"
echo "Witness Generation Time: $WITNESS_TIME ms"
echo "Total CPU Time for 64 Proving Instances: ${TOTAL_PROVE_TIME}ms"
echo "Total CPU Time for 64 Verification Instances: ${TOTAL_VERIFY_TIME}ms"
echo "Total Wall Clock Time (Parallel Execution): ${TOTAL_PARALLEL_TIME}ms"
echo "----------------------------------------"
