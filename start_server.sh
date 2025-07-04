#!/bin/bash

echo "🌐 Starting WAF Detector Web Server..."
echo "📦 Building project..."

# Build the project
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✅ Build successful!"
echo "🚀 Starting web server on port 8080..."

# Create web directory if it doesn't exist
mkdir -p web/static

# Start the web server
cargo run --bin waf-detect -- --web --port 8080

echo "🌐 Server should be available at: http://localhost:8080"
echo "📊 Dashboard: http://localhost:8080/dashboard" 
echo "📖 API Docs: http://localhost:8080/api-docs" 