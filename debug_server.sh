#!/bin/bash

echo "🔍 Debugging WAF Detector Server..."

echo "1. Checking Rust environment..."
rustc --version
cargo --version

echo "2. Checking project structure..."
ls -la src/

echo "3. Checking Cargo.toml..."
grep -A 5 "\[\[bin\]\]" Cargo.toml

echo "4. Building project with verbose output..."
cargo build --release --verbose 2>&1 | tail -20

echo "5. Checking if binary exists..."
ls -la target/release/ | grep waf

echo "6. Testing basic CLI functionality..."
cargo run --bin waf-detect -- --help 2>&1 | head -10

echo "7. Attempting to start web server with debugging..."
echo "Starting server with RUST_LOG=debug..."
timeout 10s cargo run --bin waf-detect -- --web --port 8080 2>&1 &
SERVER_PID=$!

echo "Waiting 5 seconds for server to start..."
sleep 5

echo "8. Testing if server is listening..."
curl -s http://localhost:8080/api/status || echo "❌ Server not responding"

echo "9. Cleaning up..."
kill $SERVER_PID 2>/dev/null

echo "�� Debug complete!" 