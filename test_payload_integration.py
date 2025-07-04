#!/usr/bin/env python3
"""
Test payload-based probing integration
"""
import requests
import json

def test_payload_integration():
    base_url = "http://localhost:8080"
    
    print("🧪 Testing Payload-Based Probing Integration")
    print("=" * 50)
    
    # Test server health first
    try:
        response = requests.get(f"{base_url}/api/status", timeout=5)
        if response.status_code != 200:
            print("❌ Server not running")
            return False
        print("✅ Server is running")
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        return False
    
    # Test payload detection on a known WAF site
    test_urls = [
        "https://cloudflare.com",  # Known WAF site 
        "https://aws.amazon.com",  # AWS site that might have WAF
    ]
    
    for url in test_urls:
        print(f"\n🔍 Testing payload analysis for: {url}")
        
        try:
            scan_data = {"url": url}
            response = requests.post(f"{base_url}/api/scan", json=scan_data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    detection = result.get("result", {})
                    evidence_map = detection.get("evidence_map", {})
                    
                    # Check if PayloadAnalysis is in the evidence map
                    payload_evidence = evidence_map.get("PayloadAnalysis", [])
                    print(f"   📊 Payload evidence count: {len(payload_evidence)}")
                    
                    # Check for payload-related evidence in any provider
                    payload_found = False
                    for provider, evidence_list in evidence_map.items():
                        for evidence in evidence_list:
                            if evidence.get("method_type") == "Payload":
                                payload_found = True
                                print(f"   🛡️ Payload evidence found in {provider}: {evidence.get('description', 'N/A')}")
                                print(f"      Confidence: {evidence.get('confidence', 0) * 100:.1f}%")
                                print(f"      Data: {evidence.get('raw_data', 'N/A')}")
                    
                    if not payload_found:
                        print("   ℹ️ No payload evidence detected (expected for sites without strict WAF blocking)")
                    
                    # Check overall detection
                    waf = detection.get("detected_waf")
                    cdn = detection.get("detected_cdn")
                    providers = list(evidence_map.keys())
                    
                    print(f"   🎯 WAF: {waf.get('name') if waf else 'None'}")
                    print(f"   🌐 CDN: {cdn.get('name') if cdn else 'None'}")
                    print(f"   📋 Active providers: {', '.join(providers)}")
                    
                else:
                    print(f"   ❌ Scan failed: {result.get('error', 'Unknown error')}")
            else:
                print(f"   ❌ HTTP error: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Exception: {e}")
    
    print("\n🏁 Payload integration test complete!")
    print("\n💡 Key Points:")
    print("   • PayloadAnalysis should appear in evidence_map")
    print("   • Payload evidence may be limited on production sites")
    print("   • Look for method_type: 'Payload' in evidence")
    print("   • Web UI should show 🛡️ payload evidence with pink highlighting")
    
    return True

if __name__ == "__main__":
    test_payload_integration() 