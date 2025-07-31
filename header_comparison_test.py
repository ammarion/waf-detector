#!/usr/bin/env python3
"""
Header Comparison Test - Systematic comparison of HTTP headers with detection results

This script:
1. Fetches actual HTTP headers from target sites
2. Runs WAF detector on the same sites
3. Compares detection results with header analysis
4. Identifies patterns that might be missed
"""

import asyncio
import json
import re
import subprocess
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import aiohttp
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HeaderAnalyzer:
    """Analyzes HTTP headers for WAF/CDN signatures"""
    
    # Known header patterns for each provider
    HEADER_PATTERNS = {
        "CloudFlare": {
            "headers": {
                "cf-ray": r".*",
                "cf-cache-status": r".*",
                "cf-request-id": r".*",
                "server": r"cloudflare",
            },
            "cookies": {
                "__cfduid": r".*",
                "__cf_bm": r".*",
            }
        },
        "AWS": {
            "headers": {
                "x-amz-cf-id": r".*",
                "x-amz-cf-pop": r".*",
                "x-amz-request-id": r".*",
                "x-amz-id-2": r".*",
                "x-cache": r".*CloudFront.*",
                "via": r".*cloudfront.*",
            },
            "cookies": {}
        },
        "Akamai": {
            "headers": {
                "x-akamai-transformed": r".*",
                "x-cache": r".*akamai.*",
                "x-cache-key": r".*akamai.*",
                "x-check-session": r".*",
                "server": r"AkamaiGHost|AkamaiNetStorage",
                "x-akamai-request-id": r".*",
            },
            "cookies": {
                "AKA_A2": r".*",
            }
        },
        "Fastly": {
            "headers": {
                "x-served-by": r"cache-.*",
                "x-cache": r"(HIT|MISS).*",
                "x-cache-hits": r"\d+",
                "x-timer": r"S\d+\.\d+,VS0,VE\d+",
                "fastly-stats": r".*",
                "via": r".*varnish.*",
            },
            "cookies": {}
        },
        "Vercel": {
            "headers": {
                "x-vercel-id": r".*",
                "x-vercel-cache": r".*",
                "server": r"Vercel",
                "x-vercel-ip-country": r".*",
                "x-vercel-ip-city": r".*",
            },
            "cookies": {}
        },
        "Azure": {
            "headers": {
                "x-azure-ref": r".*",
                "x-azure-fdid": r".*",
                "x-ms-request-id": r".*",
                "x-ms-routing-request-id": r".*",
                "x-powered-by": r"ASP\.NET",
                "arr-disable-session-affinity": r".*",
            },
            "cookies": {
                "ARRAffinity": r".*",
                "ARRAffinitySameSite": r".*",
            }
        },
        "F5": {
            "headers": {
                "x-f5-new-session": r".*",
                "x-waf-status": r".*",
                "x-asm-ver": r".*",
                "server": r"BigIP|BIG-IP|F5",
            },
            "cookies": {
                "BIGipServer": r".*",
                "TS": r"[0-9a-f]{8}",
                "F5-BIGIP-SESSION": r".*",
            }
        },
        "Imperva": {
            "headers": {
                "x-cdn": r"Incapsula",
                "x-iinfo": r".*",
            },
            "cookies": {
                "incap_ses_": r".*",
                "visid_incap_": r".*",
            }
        },
        "Sucuri": {
            "headers": {
                "x-sucuri-id": r".*",
                "x-sucuri-cache": r".*",
                "server": r"Sucuri/Cloudproxy",
            },
            "cookies": {}
        },
        "Barracuda": {
            "headers": {
                "x-barracuda": r".*",
            },
            "cookies": {
                "barra": r".*",
            }
        }
    }
    
    @classmethod
    def analyze_headers(cls, headers: Dict[str, str], cookies: Dict[str, str]) -> Dict[str, List[str]]:
        """Analyze headers and cookies for WAF/CDN signatures"""
        detected_providers = defaultdict(list)
        
        # Normalize headers to lowercase for comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for provider, patterns in cls.HEADER_PATTERNS.items():
            # Check headers
            for header_name, pattern in patterns["headers"].items():
                if header_name.lower() in headers_lower:
                    header_value = headers_lower[header_name.lower()]
                    if re.search(pattern, header_value, re.IGNORECASE):
                        detected_providers[provider].append(
                            f"Header '{header_name}': '{header_value}' matches pattern '{pattern}'"
                        )
            
            # Check cookies
            for cookie_name, pattern in patterns["cookies"].items():
                if cookie_name in cookies:
                    cookie_value = cookies[cookie_name]
                    if re.search(pattern, cookie_value, re.IGNORECASE):
                        detected_providers[provider].append(
                            f"Cookie '{cookie_name}': '{cookie_value}' matches pattern '{pattern}'"
                        )
        
        return dict(detected_providers)
    
    @classmethod
    def get_confidence_from_evidence(cls, evidence_count: int) -> float:
        """Calculate confidence based on evidence count"""
        if evidence_count >= 3:
            return 0.95
        elif evidence_count == 2:
            return 0.85
        elif evidence_count == 1:
            return 0.70
        return 0.0

class HeaderComparisonTest:
    """Main test class for header comparison"""
    
    def __init__(self, waf_detector_binary: str = "./target/debug/waf-detector"):
        self.waf_detector_binary = waf_detector_binary
        self.test_sites = self._get_test_sites()
        
    def _get_test_sites(self) -> List[str]:
        """Get list of test sites"""
        return [
            # Known WAF/CDN sites
            "https://cloudflare.com",
            "https://discord.com",
            "https://aws.amazon.com",
            "https://github.com",
            "https://www.apple.com",
            "https://www.netflix.com",
            "https://www.reddit.com",
            "https://stackoverflow.com",
            "https://vercel.com",
            "https://azure.microsoft.com",
            "https://docs.microsoft.com",
            "https://www.f5.com",
            
            # Additional test sites
            "https://www.nike.com",
            "https://www.spotify.com",
            "https://www.airbnb.com",
            "https://www.uber.com",
            "https://www.pinterest.com",
            "https://www.linkedin.com",
            "https://www.twitter.com",
            "https://www.instagram.com",
            
            # Sites that might not have WAF/CDN
            "https://example.com",
            "https://httpbin.org",
        ]
    
    async def fetch_site_info(self, url: str) -> Dict:
        """Fetch headers and cookies from a site"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, ssl=False, timeout=10) as response:
                    # Extract cookies
                    cookies = {}
                    for cookie in session.cookie_jar:
                        cookies[cookie.key] = cookie.value
                    
                    return {
                        "url": url,
                        "status": response.status,
                        "headers": dict(response.headers),
                        "cookies": cookies,
                        "error": None
                    }
        except Exception as e:
            return {
                "url": url,
                "status": None,
                "headers": {},
                "cookies": {},
                "error": str(e)
            }
    
    def run_waf_detector(self, url: str) -> Dict:
        """Run WAF detector and get results"""
        try:
            cmd = [self.waf_detector_binary, url, "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return {"error": f"WAF detector failed: {result.stderr}"}
            
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
    
    async def compare_single_site(self, url: str) -> Dict:
        """Compare header analysis with WAF detector results"""
        logger.info(f"Testing {url}")
        
        # Fetch site info
        site_info = await self.fetch_site_info(url)
        
        if site_info["error"]:
            return {
                "url": url,
                "error": site_info["error"],
                "header_analysis": {},
                "waf_detector_result": {},
                "comparison": {}
            }
        
        # Analyze headers
        header_analysis = HeaderAnalyzer.analyze_headers(
            site_info["headers"], 
            site_info["cookies"]
        )
        
        # Run WAF detector
        waf_result = self.run_waf_detector(url)
        
        # Compare results
        comparison = self._compare_results(header_analysis, waf_result)
        
        return {
            "url": url,
            "status": site_info["status"],
            "header_analysis": header_analysis,
            "waf_detector_result": waf_result,
            "comparison": comparison,
            "raw_headers": site_info["headers"],
            "cookies": site_info["cookies"]
        }
    
    def _compare_results(self, header_analysis: Dict, waf_result: Dict) -> Dict:
        """Compare header analysis with WAF detector results"""
        comparison = {
            "header_detected": list(header_analysis.keys()),
            "waf_detected": [],
            "matches": [],
            "header_only": [],
            "waf_only": [],
            "discrepancies": []
        }
        
        # Extract detected providers from WAF result
        if "detected_waf" in waf_result and waf_result["detected_waf"]:
            comparison["waf_detected"].append(waf_result["detected_waf"]["name"])
        
        if "detected_cdn" in waf_result and waf_result["detected_cdn"]:
            cdn_name = waf_result["detected_cdn"]["name"]
            if cdn_name not in comparison["waf_detected"]:
                comparison["waf_detected"].append(cdn_name)
        
        # Find matches and differences
        header_set = set(comparison["header_detected"])
        waf_set = set(comparison["waf_detected"])
        
        comparison["matches"] = list(header_set & waf_set)
        comparison["header_only"] = list(header_set - waf_set)
        comparison["waf_only"] = list(waf_set - header_set)
        
        # Identify specific discrepancies
        if comparison["header_only"]:
            for provider in comparison["header_only"]:
                evidence = header_analysis[provider]
                comparison["discrepancies"].append({
                    "type": "missed_by_waf_detector",
                    "provider": provider,
                    "evidence": evidence
                })
        
        if comparison["waf_only"]:
            for provider in comparison["waf_only"]:
                comparison["discrepancies"].append({
                    "type": "false_positive",
                    "provider": provider,
                    "note": "Detected by WAF detector but no header evidence found"
                })
        
        return comparison
    
    async def run_all_tests(self) -> List[Dict]:
        """Run tests on all sites"""
        results = []
        
        for url in self.test_sites:
            result = await self.compare_single_site(url)
            results.append(result)
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(0.5)
        
        return results
    
    def generate_report(self, results: List[Dict]) -> str:
        """Generate comparison report"""
        report_lines = [
            "# Header Comparison Test Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Sites Tested: {len(results)}",
            "",
            "## Summary",
            ""
        ]
        
        # Calculate statistics
        total_matches = 0
        total_header_only = 0
        total_waf_only = 0
        missed_providers = defaultdict(int)
        false_positive_providers = defaultdict(int)
        
        for result in results:
            if "comparison" in result and result["comparison"]:
                comp = result["comparison"]
                total_matches += len(comp["matches"])
                total_header_only += len(comp["header_only"])
                total_waf_only += len(comp["waf_only"])
                
                for provider in comp["header_only"]:
                    missed_providers[provider] += 1
                
                for provider in comp["waf_only"]:
                    false_positive_providers[provider] += 1
        
        report_lines.extend([
            f"- Total Matches: {total_matches}",
            f"- Detected by Headers Only: {total_header_only}",
            f"- Detected by WAF Detector Only: {total_waf_only}",
            "",
            "## Providers Missed by WAF Detector",
            ""
        ])
        
        for provider, count in sorted(missed_providers.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"- {provider}: {count} sites")
        
        report_lines.extend([
            "",
            "## False Positives by WAF Detector",
            ""
        ])
        
        for provider, count in sorted(false_positive_providers.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"- {provider}: {count} sites")
        
        # Detailed discrepancies
        report_lines.extend([
            "",
            "## Detailed Discrepancies",
            ""
        ])
        
        for result in results:
            if "comparison" in result and result["comparison"]["discrepancies"]:
                report_lines.extend([
                    f"### {result['url']}",
                    ""
                ])
                
                for discrepancy in result["comparison"]["discrepancies"]:
                    if discrepancy["type"] == "missed_by_waf_detector":
                        report_lines.extend([
                            f"**Missed: {discrepancy['provider']}**",
                            "Evidence found in headers:"
                        ])
                        for evidence in discrepancy["evidence"]:
                            report_lines.append(f"- {evidence}")
                    else:
                        report_lines.append(
                            f"**False Positive: {discrepancy['provider']}** - {discrepancy['note']}"
                        )
                
                report_lines.append("")
        
        # Sites with perfect matches
        perfect_matches = [r for r in results if "comparison" in r and 
                          r["comparison"]["matches"] and 
                          not r["comparison"]["header_only"] and 
                          not r["comparison"]["waf_only"]]
        
        if perfect_matches:
            report_lines.extend([
                "## Perfect Matches",
                ""
            ])
            
            for result in perfect_matches[:10]:  # Show first 10
                providers = ", ".join(result["comparison"]["matches"])
                report_lines.append(f"- {result['url']}: {providers}")
        
        return "\n".join(report_lines)
    
    def save_results(self, results: List[Dict]):
        """Save test results"""
        # Save raw results
        with open("header_comparison_results.json", "w") as f:
            json.dump(results, f, indent=2)
        
        # Save report
        report = self.generate_report(results)
        with open("header_comparison_report.md", "w") as f:
            f.write(report)
        
        # Save header patterns found but not detected
        missed_patterns = defaultdict(list)
        
        for result in results:
            if "comparison" in result and result["comparison"]["header_only"]:
                for provider in result["comparison"]["header_only"]:
                    if provider in result["header_analysis"]:
                        for evidence in result["header_analysis"][provider]:
                            missed_patterns[provider].append({
                                "url": result["url"],
                                "evidence": evidence
                            })
        
        with open("missed_header_patterns.json", "w") as f:
            json.dump(dict(missed_patterns), f, indent=2)
        
        logger.info("Results saved to:")
        logger.info("- header_comparison_results.json")
        logger.info("- header_comparison_report.md")
        logger.info("- missed_header_patterns.json")

async def main():
    """Main entry point"""
    # Build if needed
    binary_path = "./target/debug/waf-detector"
    if subprocess.run(["test", "-f", binary_path], capture_output=True).returncode != 0:
        logger.info("Building WAF detector...")
        subprocess.run(["cargo", "build"], check=True)
    
    # Run tests
    tester = HeaderComparisonTest(binary_path)
    results = await tester.run_all_tests()
    
    # Save results
    tester.save_results(results)
    
    # Print summary
    print("\n" + "="*60)
    print("HEADER COMPARISON TEST COMPLETE")
    print("="*60)
    
    # Quick summary
    total_sites = len(results)
    sites_with_discrepancies = sum(1 for r in results if "comparison" in r and 
                                  (r["comparison"]["header_only"] or r["comparison"]["waf_only"]))
    
    print(f"\nTotal sites tested: {total_sites}")
    print(f"Sites with discrepancies: {sites_with_discrepancies}")
    print(f"Discrepancy rate: {sites_with_discrepancies/total_sites:.1%}")

if __name__ == "__main__":
    asyncio.run(main())