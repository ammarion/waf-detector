#!/usr/bin/env python3
"""
Quick UI Test - Verify web interface is working
"""
import requests
import json

def test_server():
    base_url = "http://localhost:8080"
    
    print("🧪 Quick UI Tests")
    print("=" * 40)
    
    # Test 1: Server health
    try:
        response = requests.get(f"{base_url}/api/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Server Health:", data.get("status", "unknown"))
        else:
            print("❌ Server Health: Failed")
    except Exception as e:
        print("❌ Server Health: Not running")
        return False
    
    # Test 2: Dashboard
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            content = response.text
            has_ui = 'input' in content and 'button' in content
            print(f"✅ Dashboard: Accessible ({len(content)} chars, UI elements: {has_ui})")
        else:
            print("❌ Dashboard: Failed")
    except Exception as e:
        print("❌ Dashboard: Error")
        
    # Test 3: API scan
    try:
        scan_data = {"url": "https://cloudflare.com"}
        response = requests.post(f"{base_url}/api/scan", json=scan_data, timeout=15)
        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                detection = result.get("result", {})
                waf = detection.get("detected_waf")
                cdn = detection.get("detected_cdn")
                evidence = len(detection.get("evidence_map", {}))
                print(f"✅ Scan API: Working (WAF: {waf.get('name') if waf else 'None'}, CDN: {cdn.get('name') if cdn else 'None'}, Evidence: {evidence})")
            else:
                print("❌ Scan API: Failed")
        else:
            print("❌ Scan API: HTTP error")
    except Exception as e:
        print("❌ Scan API: Exception")
        
    print("\n📊 Test complete!")
    print("🌐 Open http://localhost:8080 in your browser to test the UI manually")

if __name__ == "__main__":
    test_server() 