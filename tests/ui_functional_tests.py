#!/usr/bin/env python3
"""
Comprehensive UI and Functional Test Suite for WAF Detector Web Interface
Tests all current functionality including DNS analysis, timing analysis, and WAF detection
"""

import requests
import json
import time
import sys
from typing import Dict, List, Optional
import re
from urllib.parse import urlparse

class WafDetectorUITester:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"    📝 {details}")
        self.test_results.append({
            "name": test_name,
            "success": success,
            "details": details
        })
        
    def test_server_health(self) -> bool:
        """Test server health endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/api/status", timeout=10)
            if response.status_code == 200:
                data = response.json()
                success = data.get("success", False) and data.get("status") == "healthy"
                self.log_test("Server Health Check", success, f"Status: {data.get('status')}")
                return success
            else:
                self.log_test("Server Health Check", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Server Health Check", False, f"Exception: {e}")
            return False
            
    def test_dashboard_accessibility(self) -> bool:
        """Test dashboard HTML page accessibility"""
        try:
            response = self.session.get(f"{self.base_url}/", timeout=10)
            if response.status_code == 200:
                html_content = response.text
                
                # Check for essential UI elements
                ui_elements = [
                    ("URL input field", 'input[type="url"]' in html_content or 'id="url"' in html_content),
                    ("Scan button", 'button' in html_content and ('scan' in html_content.lower() or 'detect' in html_content.lower())),
                    ("Results container", 'results' in html_content.lower() or 'detection' in html_content.lower()),
                    ("CSS styling", '<style>' in html_content or '.css' in html_content),
                    ("JavaScript functionality", '<script>' in html_content or '.js' in html_content)
                ]
                
                all_present = all(present for _, present in ui_elements)
                missing_elements = [name for name, present in ui_elements if not present]
                
                details = f"Page size: {len(html_content)} chars"
                if missing_elements:
                    details += f", Missing: {', '.join(missing_elements)}"
                    
                self.log_test("Dashboard Accessibility", all_present, details)
                return all_present
            else:
                self.log_test("Dashboard Accessibility", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Dashboard Accessibility", False, f"Exception: {e}")
            return False
            
    def test_providers_endpoint(self) -> bool:
        """Test providers API endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/api/providers", timeout=10)
            if response.status_code == 200:
                data = response.json()
                providers = data.get("providers", [])
                success = len(providers) > 0
                
                provider_names = [p.get("name", "Unknown") for p in providers]
                details = f"Providers: {', '.join(provider_names)}"
                
                self.log_test("Providers Endpoint", success, details)
                return success
            else:
                self.log_test("Providers Endpoint", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Providers Endpoint", False, f"Exception: {e}")
            return False
            
    def test_scan_functionality(self, test_urls: List[str]) -> bool:
        """Test scan functionality with multiple URLs"""
        all_successful = True
        
        for url in test_urls:
            try:
                scan_data = {"url": url}
                response = self.session.post(f"{self.base_url}/api/scan", 
                                           json=scan_data, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        detection_result = result.get("result", {})
                        
                        # Analyze detection results
                        waf_detected = detection_result.get("detected_waf")
                        cdn_detected = detection_result.get("detected_cdn")
                        evidence_map = detection_result.get("evidence_map", {})
                        detection_time = detection_result.get("detection_time_ms", 0)
                        
                        # Check for timing analysis evidence
                        timing_evidence = any("Timing" in provider or "timing" in str(evidence).lower() 
                                            for provider, evidence_list in evidence_map.items() 
                                            for evidence in evidence_list)
                        
                        # Check for DNS analysis evidence  
                        dns_evidence = any("DNS" in provider or "dns" in str(evidence).lower()
                                         for provider, evidence_list in evidence_map.items()
                                         for evidence in evidence_list)
                        
                        details = f"WAF: {waf_detected.get('name') if waf_detected else 'None'}, "
                        details += f"CDN: {cdn_detected.get('name') if cdn_detected else 'None'}, "
                        details += f"Time: {detection_time}ms, "
                        details += f"Timing: {'Yes' if timing_evidence else 'No'}, "
                        details += f"DNS: {'Yes' if dns_evidence else 'No'}"
                        
                        self.log_test(f"Scan: {url}", True, details)
                    else:
                        self.log_test(f"Scan: {url}", False, f"API returned success=false")
                        all_successful = False
                else:
                    self.log_test(f"Scan: {url}", False, f"HTTP {response.status_code}")
                    all_successful = False
                    
            except Exception as e:
                self.log_test(f"Scan: {url}", False, f"Exception: {e}")
                all_successful = False
                
        return all_successful
        
    def test_evidence_analysis(self, url: str) -> bool:
        """Test detailed evidence analysis for specific URL"""
        try:
            scan_data = {"url": url}
            response = self.session.post(f"{self.base_url}/api/scan", 
                                       json=scan_data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    detection_result = result.get("result", {})
                    evidence_map = detection_result.get("evidence_map", {})
                    
                    # Analyze evidence types
                    evidence_types = set()
                    confidence_scores = []
                    
                    for provider, evidence_list in evidence_map.items():
                        for evidence in evidence_list:
                            if isinstance(evidence, dict):
                                method_type = evidence.get("method_type")
                                confidence = evidence.get("confidence", 0)
                                confidence_scores.append(confidence)
                                
                                if method_type:
                                    if isinstance(method_type, dict):
                                        # Handle DNS/Timing evidence types
                                        if "DNS" in method_type:
                                            evidence_types.add("DNS")
                                        elif "Timing" in method_type:
                                            evidence_types.add("Timing")
                                    elif isinstance(method_type, str):
                                        evidence_types.add(method_type)
                    
                    avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
                    
                    details = f"Evidence types: {', '.join(evidence_types)}, "
                    details += f"Avg confidence: {avg_confidence:.2f}, "
                    details += f"Evidence count: {len(confidence_scores)}"
                    
                    success = len(evidence_types) > 0
                    self.log_test(f"Evidence Analysis: {url}", success, details)
                    return success
                else:
                    self.log_test(f"Evidence Analysis: {url}", False, "API returned success=false")
                    return False
            else:
                self.log_test(f"Evidence Analysis: {url}", False, f"HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test(f"Evidence Analysis: {url}", False, f"Exception: {e}")
            return False
            
    def test_confidence_scoring(self, urls: List[str]) -> bool:
        """Test confidence scoring across multiple URLs"""
        confidence_results = []
        
        for url in urls:
            try:
                scan_data = {"url": url}
                response = self.session.post(f"{self.base_url}/api/scan", 
                                           json=scan_data, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        detection_result = result.get("result", {})
                        
                        waf_confidence = 0
                        cdn_confidence = 0
                        
                        if detection_result.get("detected_waf"):
                            waf_confidence = detection_result["detected_waf"].get("confidence", 0)
                            
                        if detection_result.get("detected_cdn"):
                            cdn_confidence = detection_result["detected_cdn"].get("confidence", 0)
                            
                        confidence_results.append({
                            "url": url,
                            "waf_confidence": waf_confidence,
                            "cdn_confidence": cdn_confidence
                        })
                        
            except Exception as e:
                print(f"⚠️  Error testing confidence for {url}: {e}")
                
        # Analyze confidence distribution
        if confidence_results:
            high_confidence_count = sum(1 for r in confidence_results 
                                      if r["waf_confidence"] > 0.8 or r["cdn_confidence"] > 0.8)
            
            avg_waf_confidence = sum(r["waf_confidence"] for r in confidence_results) / len(confidence_results)
            avg_cdn_confidence = sum(r["cdn_confidence"] for r in confidence_results) / len(confidence_results)
            
            details = f"High confidence: {high_confidence_count}/{len(confidence_results)}, "
            details += f"Avg WAF: {avg_waf_confidence:.2f}, Avg CDN: {avg_cdn_confidence:.2f}"
            
            success = len(confidence_results) > 0
            self.log_test("Confidence Scoring Analysis", success, details)
            return success
        else:
            self.log_test("Confidence Scoring Analysis", False, "No confidence data collected")
            return False
            
    def test_api_docs_accessibility(self) -> bool:
        """Test API documentation accessibility"""
        try:
            response = self.session.get(f"{self.base_url}/api-docs", timeout=10)
            if response.status_code == 200:
                html_content = response.text
                
                # Check for API documentation elements
                api_elements = [
                    ("API endpoints", '/api/' in html_content),
                    ("Documentation structure", 'endpoint' in html_content.lower() or 'api' in html_content.lower()),
                    ("Content length", len(html_content) > 1000)
                ]
                
                all_present = all(present for _, present in api_elements)
                self.log_test("API Documentation", all_present, f"Content: {len(html_content)} chars")
                return all_present
            else:
                self.log_test("API Documentation", False, f"HTTP {response.status_code}")
                return False
        except Exception as e:
            self.log_test("API Documentation", False, f"Exception: {e}")
            return False
            
    def run_comprehensive_tests(self) -> bool:
        """Run all UI and functional tests"""
        print("🧪 Starting Comprehensive UI & Functional Tests")
        print("=" * 60)
        
        # Test URLs for different scenarios
        test_urls = [
            "https://cloudflare.com",  # Known CloudFlare
            "https://aws.amazon.com",  # Known AWS
            "https://github.com",      # Known Fastly
            "https://discord.com",     # Known CloudFlare
        ]
        
        test_methods = [
            ("Server Health", self.test_server_health),
            ("Dashboard", self.test_dashboard_accessibility),
            ("Providers API", self.test_providers_endpoint),
            ("API Documentation", self.test_api_docs_accessibility),
            ("Scan Functionality", lambda: self.test_scan_functionality(test_urls)),
            ("Evidence Analysis", lambda: self.test_evidence_analysis("https://cloudflare.com")),
            ("Confidence Scoring", lambda: self.test_confidence_scoring(test_urls[:2])),
        ]
        
        print("\n🔍 Running Individual Tests:")
        print("-" * 40)
        
        all_passed = True
        for test_name, test_method in test_methods:
            try:
                result = test_method()
                if not result:
                    all_passed = False
            except Exception as e:
                print(f"❌ FAIL {test_name} - Exception: {e}")
                all_passed = False
                
        print("\n📊 Test Summary:")
        print("-" * 40)
        
        passed_count = sum(1 for result in self.test_results if result["success"])
        total_count = len(self.test_results)
        
        print(f"Total Tests: {total_count}")
        print(f"Passed: {passed_count}")
        print(f"Failed: {total_count - passed_count}")
        print(f"Success Rate: {(passed_count/total_count)*100:.1f}%")
        
        if all_passed:
            print("\n🎉 All tests passed! UI is functioning correctly.")
        else:
            print("\n⚠️  Some tests failed. Check individual results above.")
            
        return all_passed

def main():
    """Main test runner"""
    tester = WafDetectorUITester()
    
    # Check if server is running
    try:
        response = requests.get("http://localhost:8080/api/status", timeout=5)
        if response.status_code != 200:
            print("❌ Server not running on localhost:8080")
            print("💡 Start the server with: cargo run --bin waf-detect -- --web --port 8080")
            sys.exit(1)
    except requests.exceptions.RequestException:
        print("❌ Cannot connect to server on localhost:8080")
        print("💡 Start the server with: cargo run --bin waf-detect -- --web --port 8080")
        sys.exit(1)
        
    # Run comprehensive tests
    success = tester.run_comprehensive_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 