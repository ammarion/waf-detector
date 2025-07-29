#!/usr/bin/env python3
"""
CI/CD Validation Script for WAF Detector

This script is designed to run in CI/CD pipelines to ensure:
1. No regression in detection accuracy
2. All providers are working correctly
3. Performance benchmarks are met
4. No false positives on known negative cases
"""

import asyncio
import json
import sys
import time
import subprocess
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CIValidator:
    """CI/CD validation for WAF Detector"""
    
    # Minimum required metrics
    REQUIRED_METRICS = {
        "overall_accuracy": 0.85,  # 85% overall accuracy
        "waf_precision": 0.90,     # 90% precision for WAF detection
        "waf_recall": 0.80,        # 80% recall for WAF detection
        "cdn_precision": 0.90,     # 90% precision for CDN detection
        "cdn_recall": 0.80,        # 80% recall for CDN detection
        "max_detection_time": 5.0,  # Max 5 seconds per detection
        "avg_detection_time": 2.0,  # Average 2 seconds per detection
    }
    
    # Required test cases that must pass
    REQUIRED_TEST_CASES = [
        {
            "url": "https://cloudflare.com",
            "expected_waf": "CloudFlare",
            "expected_cdn": "CloudFlare",
            "description": "CloudFlare official site"
        },
        {
            "url": "https://aws.amazon.com",
            "expected_waf": "AWS",
            "expected_cdn": "AWS",
            "description": "AWS official site"
        },
        {
            "url": "https://www.fastly.com",
            "expected_waf": "Fastly",
            "expected_cdn": "Fastly",
            "description": "Fastly official site"
        },
        {
            "url": "https://example.com",
            "expected_waf": None,
            "expected_cdn": None,
            "description": "Negative test - no WAF/CDN"
        }
    ]
    
    # Performance test cases
    PERFORMANCE_TEST_URLS = [
        "https://cloudflare.com",
        "https://github.com",
        "https://aws.amazon.com",
        "https://example.com",
        "https://httpbin.org"
    ]
    
    def __init__(self, binary_path: str = "./target/debug/waf-detector"):
        self.binary_path = binary_path
        self.results = {
            "passed": True,
            "metrics": {},
            "failed_tests": [],
            "performance": {},
            "errors": []
        }
    
    def run_detector(self, url: str, timeout: int = 10) -> Tuple[Dict, float]:
        """Run WAF detector and measure time"""
        start_time = time.time()
        
        try:
            cmd = [self.binary_path, url, "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            elapsed_time = time.time() - start_time
            
            if result.returncode != 0:
                return {"error": f"Exit code {result.returncode}: {result.stderr}"}, elapsed_time
            
            return json.loads(result.stdout), elapsed_time
        except subprocess.TimeoutExpired:
            return {"error": "timeout"}, timeout
        except json.JSONDecodeError:
            return {"error": "invalid json output"}, time.time() - start_time
        except Exception as e:
            return {"error": str(e)}, time.time() - start_time
    
    async def test_required_cases(self):
        """Test required test cases"""
        logger.info("Testing required cases...")
        
        for test_case in self.REQUIRED_TEST_CASES:
            result, elapsed_time = self.run_detector(test_case["url"])
            
            if "error" in result:
                self.results["failed_tests"].append({
                    "test": test_case["description"],
                    "url": test_case["url"],
                    "error": result["error"]
                })
                continue
            
            # Check WAF detection
            detected_waf = None
            if "detected_waf" in result and result["detected_waf"]:
                detected_waf = result["detected_waf"]["name"]
            
            # Check CDN detection
            detected_cdn = None
            if "detected_cdn" in result and result["detected_cdn"]:
                detected_cdn = result["detected_cdn"]["name"]
            
            # Validate results
            waf_correct = detected_waf == test_case["expected_waf"]
            cdn_correct = detected_cdn == test_case["expected_cdn"]
            
            if not (waf_correct and cdn_correct):
                self.results["failed_tests"].append({
                    "test": test_case["description"],
                    "url": test_case["url"],
                    "expected_waf": test_case["expected_waf"],
                    "detected_waf": detected_waf,
                    "expected_cdn": test_case["expected_cdn"],
                    "detected_cdn": detected_cdn
                })
            
            logger.info(f"  {test_case['description']}: {'PASS' if waf_correct and cdn_correct else 'FAIL'}")
    
    async def test_all_providers(self):
        """Test that all providers can be detected"""
        logger.info("Testing all providers...")
        
        provider_tests = [
            ("CloudFlare", "https://cloudflare.com"),
            ("AWS", "https://aws.amazon.com"),
            ("Akamai", "https://www.akamai.com"),
            ("Fastly", "https://www.fastly.com"),
            ("Vercel", "https://vercel.com"),
            ("Azure", "https://azure.microsoft.com"),
            ("F5", "https://www.f5.com")
        ]
        
        for provider_name, url in provider_tests:
            result, _ = self.run_detector(url)
            
            if "error" in result:
                self.results["errors"].append(f"Failed to test {provider_name}: {result['error']}")
                continue
            
            # Check if provider was detected (either as WAF or CDN)
            detected = False
            if "detected_waf" in result and result["detected_waf"]:
                if result["detected_waf"]["name"] == provider_name:
                    detected = True
            if "detected_cdn" in result and result["detected_cdn"]:
                if result["detected_cdn"]["name"] == provider_name:
                    detected = True
            
            if not detected:
                self.results["failed_tests"].append({
                    "test": f"{provider_name} provider detection",
                    "url": url,
                    "error": f"{provider_name} not detected on its official site"
                })
            
            logger.info(f"  {provider_name}: {'PASS' if detected else 'FAIL'}")
    
    async def test_performance(self):
        """Test performance benchmarks"""
        logger.info("Testing performance...")
        
        times = []
        for url in self.PERFORMANCE_TEST_URLS:
            _, elapsed_time = self.run_detector(url)
            times.append(elapsed_time)
            
            if elapsed_time > self.REQUIRED_METRICS["max_detection_time"]:
                self.results["failed_tests"].append({
                    "test": "Performance",
                    "url": url,
                    "error": f"Detection took {elapsed_time:.2f}s (max allowed: {self.REQUIRED_METRICS['max_detection_time']}s)"
                })
        
        avg_time = sum(times) / len(times) if times else 0
        max_time = max(times) if times else 0
        
        self.results["performance"] = {
            "average_time": avg_time,
            "max_time": max_time,
            "times": times
        }
        
        if avg_time > self.REQUIRED_METRICS["avg_detection_time"]:
            self.results["failed_tests"].append({
                "test": "Average performance",
                "error": f"Average detection time {avg_time:.2f}s exceeds limit of {self.REQUIRED_METRICS['avg_detection_time']}s"
            })
        
        logger.info(f"  Average time: {avg_time:.2f}s")
        logger.info(f"  Max time: {max_time:.2f}s")
    
    async def calculate_accuracy_metrics(self):
        """Calculate accuracy metrics using a subset of test data"""
        logger.info("Calculating accuracy metrics...")
        
        # Simplified accuracy test with key sites
        test_data = [
            ("https://cloudflare.com", "CloudFlare", "CloudFlare"),
            ("https://discord.com", "CloudFlare", "CloudFlare"),
            ("https://aws.amazon.com", "AWS", "AWS"),
            ("https://github.com", "Fastly", "Fastly"),
            ("https://vercel.com", "Vercel", "Vercel"),
            ("https://example.com", None, None),
            ("https://httpbin.org", None, None),
        ]
        
        waf_tp = waf_fp = waf_tn = waf_fn = 0
        cdn_tp = cdn_fp = cdn_tn = cdn_fn = 0
        
        for url, expected_waf, expected_cdn in test_data:
            result, _ = self.run_detector(url)
            
            if "error" in result:
                continue
            
            # WAF metrics
            detected_waf = None
            if "detected_waf" in result and result["detected_waf"]:
                detected_waf = result["detected_waf"]["name"]
            
            if expected_waf and detected_waf == expected_waf:
                waf_tp += 1
            elif expected_waf and detected_waf != expected_waf:
                waf_fn += 1
            elif not expected_waf and detected_waf:
                waf_fp += 1
            else:
                waf_tn += 1
            
            # CDN metrics
            detected_cdn = None
            if "detected_cdn" in result and result["detected_cdn"]:
                detected_cdn = result["detected_cdn"]["name"]
            
            if expected_cdn and detected_cdn == expected_cdn:
                cdn_tp += 1
            elif expected_cdn and detected_cdn != expected_cdn:
                cdn_fn += 1
            elif not expected_cdn and detected_cdn:
                cdn_fp += 1
            else:
                cdn_tn += 1
        
        # Calculate metrics
        total = len(test_data)
        waf_precision = waf_tp / (waf_tp + waf_fp) if (waf_tp + waf_fp) > 0 else 0
        waf_recall = waf_tp / (waf_tp + waf_fn) if (waf_tp + waf_fn) > 0 else 0
        cdn_precision = cdn_tp / (cdn_tp + cdn_fp) if (cdn_tp + cdn_fp) > 0 else 0
        cdn_recall = cdn_tp / (cdn_tp + cdn_fn) if (cdn_tp + cdn_fn) > 0 else 0
        overall_accuracy = (waf_tp + waf_tn + cdn_tp + cdn_tn) / (2 * total) if total > 0 else 0
        
        self.results["metrics"] = {
            "overall_accuracy": overall_accuracy,
            "waf_precision": waf_precision,
            "waf_recall": waf_recall,
            "cdn_precision": cdn_precision,
            "cdn_recall": cdn_recall,
        }
        
        # Check if metrics meet requirements
        for metric, value in self.results["metrics"].items():
            required = self.REQUIRED_METRICS.get(metric)
            if required and value < required:
                self.results["failed_tests"].append({
                    "test": f"Metric: {metric}",
                    "error": f"Value {value:.2%} is below required {required:.2%}"
                })
        
        logger.info(f"  Overall accuracy: {overall_accuracy:.2%}")
        logger.info(f"  WAF precision: {waf_precision:.2%}, recall: {waf_recall:.2%}")
        logger.info(f"  CDN precision: {cdn_precision:.2%}, recall: {cdn_recall:.2%}")
    
    async def run_all_tests(self):
        """Run all validation tests"""
        logger.info("Starting CI validation...")
        
        # Run all test suites
        await self.test_required_cases()
        await self.test_all_providers()
        await self.test_performance()
        await self.calculate_accuracy_metrics()
        
        # Determine overall pass/fail
        self.results["passed"] = len(self.results["failed_tests"]) == 0
        
        return self.results
    
    def generate_report(self) -> str:
        """Generate CI report"""
        lines = [
            "# CI Validation Report",
            "",
            f"Status: {'PASSED' if self.results['passed'] else 'FAILED'}",
            "",
            "## Metrics",
            f"- Overall Accuracy: {self.results['metrics'].get('overall_accuracy', 0):.2%}",
            f"- WAF Precision: {self.results['metrics'].get('waf_precision', 0):.2%}",
            f"- WAF Recall: {self.results['metrics'].get('waf_recall', 0):.2%}",
            f"- CDN Precision: {self.results['metrics'].get('cdn_precision', 0):.2%}",
            f"- CDN Recall: {self.results['metrics'].get('cdn_recall', 0):.2%}",
            "",
            "## Performance",
            f"- Average Detection Time: {self.results['performance'].get('average_time', 0):.2f}s",
            f"- Max Detection Time: {self.results['performance'].get('max_time', 0):.2f}s",
            ""
        ]
        
        if self.results["failed_tests"]:
            lines.extend([
                "## Failed Tests",
                ""
            ])
            for failure in self.results["failed_tests"]:
                lines.append(f"- {failure.get('test', 'Unknown')}: {failure.get('error', 'Unknown error')}")
        
        if self.results["errors"]:
            lines.extend([
                "",
                "## Errors",
                ""
            ])
            for error in self.results["errors"]:
                lines.append(f"- {error}")
        
        return "\n".join(lines)

async def main():
    """Main entry point"""
    # Parse arguments
    binary_path = sys.argv[1] if len(sys.argv) > 1 else "./target/debug/waf-detector"
    
    # Ensure binary exists
    if subprocess.run(["test", "-f", binary_path], capture_output=True).returncode != 0:
        logger.error(f"Binary not found at {binary_path}")
        sys.exit(1)
    
    # Run validation
    validator = CIValidator(binary_path)
    results = await validator.run_all_tests()
    
    # Generate report
    report = validator.generate_report()
    print("\n" + report)
    
    # Save results
    with open("ci_validation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    # Exit with appropriate code
    sys.exit(0 if results["passed"] else 1)

if __name__ == "__main__":
    asyncio.run(main())