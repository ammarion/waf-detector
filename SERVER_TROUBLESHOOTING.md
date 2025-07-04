# WAF Detector Web Server Troubleshooting

## Quick Start

Due to some shell execution issues, here are manual steps to start the web server:

### Option 1: Use the startup script
```bash
chmod +x start_server.sh
./start_server.sh
```

### Option 2: Manual commands
```bash
# 1. Build the project
cargo build --release

# 2. Create web directory
mkdir -p web/static

# 3. Start the web server
cargo run --bin waf-detect -- --web --port 8080
```

### Option 3: Debug mode
```bash
chmod +x debug_server.sh
./debug_server.sh
```

## Common Issues and Solutions

### 1. "Connection Refused" Error
- **Cause**: Server not started or crashed during startup
- **Solution**: Check for compilation errors, ensure all dependencies are installed

### 2. Build Failures
- **Cause**: Missing dependencies or Rust toolchain issues
- **Solution**: 
  ```bash
  rustup update
  cargo clean
  cargo build --release
  ```

### 3. Port Already in Use
- **Cause**: Another process using port 8080
- **Solution**: 
  ```bash
  # Use a different port
  cargo run --bin waf-detect -- --web --port 3000
  
  # Or kill existing process
  lsof -ti:8080 | xargs kill -9
  ```

### 4. Static Files Not Found
- **Cause**: Missing web/static directory
- **Solution**: 
  ```bash
  mkdir -p web/static
  ```

## Verifying Server Status

Once the server starts, you should see:
```
🌐 WAF Detector Web Server starting on http://localhost:8080
📊 Dashboard: http://localhost:8080/dashboard  
📖 API Docs: http://localhost:8080/api-docs
```

Test the server:
```bash
# Check server status
curl http://localhost:8080/api/status

# Test the dashboard
curl http://localhost:8080/
```

## Expected Output

When working correctly:
- **Status endpoint**: `{"success":true,"status":"healthy",...}`
- **Dashboard**: HTML content with the WAF detector interface
- **Server logs**: Show successful startup messages

## Web Interface URLs

- **Main Dashboard**: http://localhost:8080/
- **API Documentation**: http://localhost:8080/api-docs
- **Server Status**: http://localhost:8080/api/status
- **Scan API**: http://localhost:8080/api/scan (POST)
- **Providers List**: http://localhost:8080/api/providers

## Browser Testing

Open your browser and navigate to:
- http://localhost:8080/

You should see the WAF Detector dashboard with:
- URL input field
- Scan button
- Results display area
- Provider information
- Timing and DNS analysis indicators

## If Nothing Works

1. Check Rust installation: `rustc --version`
2. Check cargo: `cargo --version`
3. Clean and rebuild: `cargo clean && cargo build --release`
4. Check for processes using port 8080: `lsof -i :8080`
5. Try a different port: `cargo run --bin waf-detect -- --web --port 3000` 