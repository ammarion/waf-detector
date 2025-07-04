#!/usr/bin/env python3
"""
Test script for the WAF Detector Web Server
This script starts the web server and tests basic functionality
"""

import subprocess
import time
import requests
import json
import sys
import signal
import os

def test_web_server():
    print("🌐 Testing WAF Detector Web Server...")
    
    # Start the web server
    print("📦 Starting web server...")
    try:
        # Try to build first
        print("🔧 Building project...")
        build_result = subprocess.run(['cargo', 'build', '--release'], 
                                    capture_output=True, text=True, timeout=60)
        if build_result.returncode != 0:
            print(f"❌ Build failed: {build_result.stderr}")
            return False
        
        print("✅ Build successful!")
        
        # Start the server
        server_process = subprocess.Popen(
            ['cargo', 'run', '--bin', 'waf-detect', '--', '--web', '--port', '8080'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for server to start
        print("⏳ Waiting for server to start...")
        time.sleep(5)
        
        # Test server health
        print("🔍 Testing server health...")
        try:
            response = requests.get('http://localhost:8080/api/status', timeout=10)
            if response.status_code == 200:
                print("✅ Server is healthy!")
                print(f"📊 Status: {response.json()}")
            else:
                print(f"❌ Server health check failed: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to connect to server: {e}")
            return False
        
        # Test dashboard
        print("🎨 Testing dashboard...")
        try:
            response = requests.get('http://localhost:8080/', timeout=10)
            if response.status_code == 200:
                print("✅ Dashboard is accessible!")
                print(f"📏 Dashboard size: {len(response.text)} characters")
            else:
                print(f"❌ Dashboard failed: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to access dashboard: {e}")
            return False
        
        # Test scan endpoint
        print("🔍 Testing scan endpoint...")
        try:
            scan_data = {
                "url": "https://cloudflare.com",
                "debug": True
            }
            response = requests.post('http://localhost:8080/api/scan', 
                                   json=scan_data, timeout=30)
            if response.status_code == 200:
                result = response.json()
                print("✅ Scan endpoint working!")
                print(f"📊 Scan result: {result['success']}")
                if result['success'] and result['result']:
                    detection = result['result']
                    print(f"🛡️  WAF: {detection.get('detected_waf', 'Not detected')}")
                    print(f"🌐 CDN: {detection.get('detected_cdn', 'Not detected')}")
                    print(f"⏱️  Time: {detection.get('detection_time_ms', 0)}ms")
            else:
                print(f"❌ Scan failed: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Scan request failed: {e}")
            return False
        
        # Test providers endpoint
        print("📋 Testing providers endpoint...")
        try:
            response = requests.get('http://localhost:8080/api/providers', timeout=10)
            if response.status_code == 200:
                providers = response.json()
                print("✅ Providers endpoint working!")
                print(f"🔌 Providers: {len(providers.get('providers', []))}")
                for provider in providers.get('providers', []):
                    print(f"  • {provider.get('name', 'Unknown')}")
            else:
                print(f"❌ Providers failed: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Providers request failed: {e}")
            return False
        
        print("\n🎉 All tests passed!")
        print("🌐 Web server is working correctly!")
        print("📊 Dashboard: http://localhost:8080/")
        print("📖 API Docs: http://localhost:8080/api-docs")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    
    finally:
        # Clean up
        if 'server_process' in locals():
            print("🧹 Stopping web server...")
            server_process.terminate()
            server_process.wait(timeout=5)

if __name__ == "__main__":
    success = test_web_server()
    sys.exit(0 if success else 1) 