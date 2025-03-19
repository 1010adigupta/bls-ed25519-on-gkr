#!/bin/bash
echo "Starting benchmarks..."
# Build the project in release mode first
RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo build --release

# Run benchmarks with different numbers of assignments
for num in 32 64 128 256; do
  echo "Running benchmark with $num assignments..."
  RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f" cargo run --release -- $num
  echo ""
  echo "Benchmark with $num assignments completed."
  echo "----------------------------------------"
done

echo "All benchmarks completed."
