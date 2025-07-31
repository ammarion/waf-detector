#!/usr/bin/env python3
"""
Comprehensive Accuracy Validation System for WAF Detector

This script validates the accuracy of WAF/CDN detection by:
1. Testing against known sites with confirmed WAF/CDN providers
2. Comparing detection results with actual HTTP headers
3. Calculating accuracy metrics (precision, recall, F1 score)
4. Identifying false positives and false negatives
5. Generating detailed reports
"""

import asyncio
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import aiohttp
import yaml
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class GroundTruthEntry:
    """Represents a known WAF/CDN configuration for testing"""
    url: str
    waf_provider: Optional[str] = None
    cdn_provider: Optional[str] = None
    confidence_level: float = 0.9
    notes: str = ""
    expected_headers: Dict[str, str] = field(default_factory=dict)
    
@dataclass
class ValidationResult:
    """Result of a single validation test"""
    ground_truth: GroundTruthEntry
    detected_waf: Optional[str] = None
    detected_cdn: Optional[str] = None
    detection_confidence: float = 0.0
    actual_headers: Dict[str, str] = field(default_factory=dict)
    is_correct_waf: bool = False
    is_correct_cdn: bool = False
    detection_time: float = 0.0
    error: Optional[str] = None
    evidence: List[Dict] = field(default_factory=list)

class AccuracyValidator:
    """Main validation system for WAF Detector accuracy"""
    
    def __init__(self, waf_detector_binary: str = "./target/debug/waf-detector"):
        self.waf_detector_binary = waf_detector_binary
        self.ground_truth_data = self._load_ground_truth()
        self.results: List[ValidationResult] = []
        
    def _load_ground_truth(self) -> List[GroundTruthEntry]:
        """Load ground truth data for validation"""
        return [
            # CloudFlare sites
            GroundTruthEntry(
                url="https://cloudflare.com",
                waf_provider="CloudFlare",
                cdn_provider="CloudFlare",
                confidence_level=0.98,
                notes="Official CloudFlare site",
                expected_headers={"cf-ray": "*", "server": "cloudflare"}
            ),
            GroundTruthEntry(
                url="https://discord.com",
                waf_provider="CloudFlare",
                cdn_provider="CloudFlare",
                confidence_level=0.95,
                notes="Discord uses CloudFlare",
                expected_headers={"cf-ray": "*"}
            ),
            GroundTruthEntry(
                url="https://www.cloudflare.com/api/v4/",
                waf_provider="CloudFlare",
                cdn_provider="CloudFlare",
                confidence_level=0.98,
                notes="CloudFlare API endpoint"
            ),
            
            # AWS CloudFront sites
            GroundTruthEntry(
                url="https://aws.amazon.com",
                waf_provider="AWS",
                cdn_provider="AWS",
                confidence_level=0.95,
                notes="Official AWS site",
                expected_headers={"x-amz-cf-id": "*"}
            ),
            GroundTruthEntry(
                url="https://d1.awsstatic.com/",
                waf_provider="AWS",
                cdn_provider="AWS",
                confidence_level=0.98,
                notes="AWS static content",
                expected_headers={"x-amz-cf-id": "*", "x-cache": "*CloudFront*"}
            ),
            
            # Akamai sites
            GroundTruthEntry(
                url="https://www.akamai.com",
                waf_provider="Akamai",
                cdn_provider="Akamai",
                confidence_level=0.98,
                notes="Official Akamai site",
                expected_headers={"server": "*akamai*"}
            ),
            GroundTruthEntry(
                url="https://www.apple.com",
                waf_provider="Akamai",
                cdn_provider="Akamai",
                confidence_level=0.90,
                notes="Apple uses Akamai",
                expected_headers={"x-cache": "*akamai*"}
            ),
            
            # Fastly sites
            GroundTruthEntry(
                url="https://www.fastly.com",
                waf_provider="Fastly",
                cdn_provider="Fastly",
                confidence_level=0.98,
                notes="Official Fastly site",
                expected_headers={"x-served-by": "*", "x-cache": "*"}
            ),
            GroundTruthEntry(
                url="https://github.com",
                waf_provider="Fastly",
                cdn_provider="Fastly",
                confidence_level=0.95,
                notes="GitHub uses Fastly"
            ),
            
            # Vercel sites
            GroundTruthEntry(
                url="https://vercel.com",
                waf_provider="Vercel",
                cdn_provider="Vercel",
                confidence_level=0.98,
                notes="Official Vercel site",
                expected_headers={"x-vercel-id": "*"}
            ),
            
            # Azure sites
            GroundTruthEntry(
                url="https://azure.microsoft.com",
                waf_provider="Azure",
                cdn_provider="Azure",
                confidence_level=0.95,
                notes="Official Azure site",
                expected_headers={"x-ms-request-id": "*"}
            ),
            GroundTruthEntry(
                url="https://docs.microsoft.com",
                waf_provider="Azure",
                cdn_provider="Azure",
                confidence_level=0.90,
                notes="Microsoft Docs on Azure"
            ),
            
            # F5 sites (harder to find public examples)
            GroundTruthEntry(
                url="https://www.f5.com",
                waf_provider="F5",
                cdn_provider="F5",
                confidence_level=0.85,
                notes="Official F5 site (may use their own products)"
            ),
            
            # Sites without WAF/CDN (negative tests)
            GroundTruthEntry(
                url="https://example.com",
                waf_provider=None,
                cdn_provider=None,
                confidence_level=0.90,
                notes="Simple example site, no WAF/CDN"
            ),
            GroundTruthEntry(
                url="https://httpbin.org",
                waf_provider=None,
                cdn_provider=None,
                confidence_level=0.85,
                notes="HTTP testing service"
            ),
            
            # Mixed configurations
            GroundTruthEntry(
                url="https://www.reddit.com",
                waf_provider="Fastly",
                cdn_provider="Fastly",
                confidence_level=0.90,
                notes="Reddit uses Fastly"
            ),
            GroundTruthEntry(
                url="https://stackoverflow.com",
                waf_provider="Fastly",
                cdn_provider="Fastly", 
                confidence_level=0.85,
                notes="Stack Overflow uses Fastly"
            ),
        ]
    
    async def fetch_actual_headers(self, url: str) -> Dict[str, str]:
        """Fetch actual HTTP headers from a URL"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; WAF-Detector-Validator/1.0)'
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, ssl=False, timeout=10) as response:
                    return dict(response.headers)
        except Exception as e:
            logger.warning(f"Failed to fetch headers for {url}: {e}")
            return {}
    
    def run_waf_detector(self, url: str) -> Dict:
        """Run the WAF detector binary and parse results"""
        try:
            # Run with JSON output
            cmd = [self.waf_detector_binary, url, "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.error(f"WAF detector failed for {url}: {result.stderr}")
                return {}
            
            # Parse JSON output
            return json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            logger.error(f"WAF detector timeout for {url}")
            return {"error": "timeout"}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON output for {url}: {e}")
            logger.error(f"Output was: {result.stdout}")
            return {"error": "json_parse_error"}
        except Exception as e:
            logger.error(f"Failed to run WAF detector for {url}: {e}")
            return {"error": str(e)}
    
    async def validate_single_site(self, ground_truth: GroundTruthEntry) -> ValidationResult:
        """Validate detection for a single site"""
        logger.info(f"Validating: {ground_truth.url}")
        
        # Start timing
        start_time = time.time()
        
        # Run WAF detector
        detection_result = self.run_waf_detector(ground_truth.url)
        
        # Fetch actual headers
        actual_headers = await self.fetch_actual_headers(ground_truth.url)
        
        detection_time = time.time() - start_time
        
        # Parse detection results
        result = ValidationResult(
            ground_truth=ground_truth,
            actual_headers=actual_headers,
            detection_time=detection_time
        )
        
        if "error" in detection_result:
            result.error = detection_result["error"]
            return result
        
        # Extract detected providers
        if "detected_waf" in detection_result and detection_result["detected_waf"]:
            result.detected_waf = detection_result["detected_waf"]["name"]
            result.detection_confidence = detection_result["detected_waf"]["confidence"]
        
        if "detected_cdn" in detection_result and detection_result["detected_cdn"]:
            result.detected_cdn = detection_result["detected_cdn"]["name"]
            if not result.detection_confidence:
                result.detection_confidence = detection_result["detected_cdn"]["confidence"]
        
        # Store evidence
        if "evidence" in detection_result:
            result.evidence = detection_result["evidence"]
        
        # Check correctness
        result.is_correct_waf = self._check_correctness(
            ground_truth.waf_provider, result.detected_waf
        )
        result.is_correct_cdn = self._check_correctness(
            ground_truth.cdn_provider, result.detected_cdn
        )
        
        return result
    
    def _check_correctness(self, expected: Optional[str], detected: Optional[str]) -> bool:
        """Check if detection matches expected value"""
        if expected is None and detected is None:
            return True
        if expected is None or detected is None:
            return False
        return expected.lower() == detected.lower()
    
    def _check_header_match(self, expected_headers: Dict[str, str], actual_headers: Dict[str, str]) -> bool:
        """Check if expected headers are present in actual headers"""
        for header, pattern in expected_headers.items():
            header_lower = header.lower()
            found = False
            
            for actual_header, value in actual_headers.items():
                if actual_header.lower() == header_lower:
                    if pattern == "*" or pattern.lower() in value.lower():
                        found = True
                        break
            
            if not found:
                return False
        
        return True
    
    async def validate_all(self):
        """Run validation on all ground truth entries"""
        logger.info(f"Starting validation of {len(self.ground_truth_data)} sites...")
        
        for entry in self.ground_truth_data:
            result = await self.validate_single_site(entry)
            self.results.append(result)
            
            # Log immediate feedback
            waf_status = "✓" if result.is_correct_waf else "✗"
            cdn_status = "✓" if result.is_correct_cdn else "✗"
            logger.info(f"  WAF: {waf_status} (Expected: {entry.waf_provider}, Detected: {result.detected_waf})")
            logger.info(f"  CDN: {cdn_status} (Expected: {entry.cdn_provider}, Detected: {result.detected_cdn})")
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(0.5)
    
    def calculate_metrics(self) -> Dict:
        """Calculate accuracy metrics"""
        metrics = {
            "waf": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
            "cdn": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
            "combined": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
            "per_provider": defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        }
        
        for result in self.results:
            if result.error:
                continue
            
            # WAF metrics
            if result.ground_truth.waf_provider and result.detected_waf:
                if result.is_correct_waf:
                    metrics["waf"]["tp"] += 1
                    metrics["per_provider"][result.ground_truth.waf_provider]["tp"] += 1
                else:
                    metrics["waf"]["fp"] += 1
                    metrics["per_provider"][result.detected_waf]["fp"] += 1
            elif result.ground_truth.waf_provider and not result.detected_waf:
                metrics["waf"]["fn"] += 1
                metrics["per_provider"][result.ground_truth.waf_provider]["fn"] += 1
            elif not result.ground_truth.waf_provider and result.detected_waf:
                metrics["waf"]["fp"] += 1
                metrics["per_provider"][result.detected_waf]["fp"] += 1
            else:
                metrics["waf"]["tn"] += 1
            
            # CDN metrics
            if result.ground_truth.cdn_provider and result.detected_cdn:
                if result.is_correct_cdn:
                    metrics["cdn"]["tp"] += 1
                else:
                    metrics["cdn"]["fp"] += 1
            elif result.ground_truth.cdn_provider and not result.detected_cdn:
                metrics["cdn"]["fn"] += 1
            elif not result.ground_truth.cdn_provider and result.detected_cdn:
                metrics["cdn"]["fp"] += 1
            else:
                metrics["cdn"]["tn"] += 1
            
            # Combined metrics
            if result.is_correct_waf and result.is_correct_cdn:
                metrics["combined"]["tp"] += 1
            elif not result.ground_truth.waf_provider and not result.ground_truth.cdn_provider and \
                 not result.detected_waf and not result.detected_cdn:
                metrics["combined"]["tn"] += 1
            elif (result.ground_truth.waf_provider or result.ground_truth.cdn_provider) and \
                 not result.detected_waf and not result.detected_cdn:
                metrics["combined"]["fn"] += 1
            else:
                metrics["combined"]["fp"] += 1
        
        # Calculate derived metrics
        for category in ["waf", "cdn", "combined"]:
            m = metrics[category]
            total = m["tp"] + m["fp"] + m["tn"] + m["fn"]
            
            if total > 0:
                m["accuracy"] = (m["tp"] + m["tn"]) / total
            else:
                m["accuracy"] = 0
            
            if m["tp"] + m["fp"] > 0:
                m["precision"] = m["tp"] / (m["tp"] + m["fp"])
            else:
                m["precision"] = 0
            
            if m["tp"] + m["fn"] > 0:
                m["recall"] = m["tp"] / (m["tp"] + m["fn"])
            else:
                m["recall"] = 0
            
            if m["precision"] + m["recall"] > 0:
                m["f1_score"] = 2 * m["precision"] * m["recall"] / (m["precision"] + m["recall"])
            else:
                m["f1_score"] = 0
        
        return metrics
    
    def generate_report(self) -> str:
        """Generate comprehensive validation report"""
        metrics = self.calculate_metrics()
        
        report_lines = [
            "# WAF Detector Accuracy Validation Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Sites Tested: {len(self.results)}",
            "",
            "## Overall Metrics",
            "",
            "### WAF Detection",
            f"- Accuracy: {metrics['waf']['accuracy']:.2%}",
            f"- Precision: {metrics['waf']['precision']:.2%}",
            f"- Recall: {metrics['waf']['recall']:.2%}",
            f"- F1 Score: {metrics['waf']['f1_score']:.2%}",
            "",
            "### CDN Detection",
            f"- Accuracy: {metrics['cdn']['accuracy']:.2%}",
            f"- Precision: {metrics['cdn']['precision']:.2%}",
            f"- Recall: {metrics['cdn']['recall']:.2%}",
            f"- F1 Score: {metrics['cdn']['f1_score']:.2%}",
            "",
            "### Combined Detection",
            f"- Accuracy: {metrics['combined']['accuracy']:.2%}",
            f"- Precision: {metrics['combined']['precision']:.2%}",
            f"- Recall: {metrics['combined']['recall']:.2%}",
            f"- F1 Score: {metrics['combined']['f1_score']:.2%}",
            "",
            "## Per-Provider Performance",
            ""
        ]
        
        # Per-provider metrics
        for provider, provider_metrics in metrics["per_provider"].items():
            if isinstance(provider_metrics, dict) and any(provider_metrics.values()):
                total = sum(provider_metrics.values())
                if provider_metrics["tp"] + provider_metrics["fp"] > 0:
                    precision = provider_metrics["tp"] / (provider_metrics["tp"] + provider_metrics["fp"])
                else:
                    precision = 0
                
                report_lines.extend([
                    f"### {provider}",
                    f"- True Positives: {provider_metrics['tp']}",
                    f"- False Positives: {provider_metrics['fp']}",
                    f"- False Negatives: {provider_metrics['fn']}",
                    f"- Precision: {precision:.2%}",
                    ""
                ])
        
        # Detailed results
        report_lines.extend([
            "## Detailed Results",
            "",
            "### Correct Detections",
            ""
        ])
        
        correct_results = [r for r in self.results if r.is_correct_waf and r.is_correct_cdn and not r.error]
        for result in correct_results[:5]:  # Show first 5
            report_lines.extend([
                f"- **{result.ground_truth.url}**",
                f"  - Expected: WAF={result.ground_truth.waf_provider}, CDN={result.ground_truth.cdn_provider}",
                f"  - Detected: WAF={result.detected_waf}, CDN={result.detected_cdn}",
                f"  - Confidence: {result.detection_confidence:.2f}",
                f"  - Time: {result.detection_time:.2f}s",
                ""
            ])
        
        # False positives
        report_lines.extend([
            "### False Positives",
            ""
        ])
        
        false_positives = [r for r in self.results if not r.error and (
            (r.ground_truth.waf_provider != r.detected_waf and r.detected_waf) or
            (r.ground_truth.cdn_provider != r.detected_cdn and r.detected_cdn)
        )]
        
        for result in false_positives:
            report_lines.extend([
                f"- **{result.ground_truth.url}**",
                f"  - Expected: WAF={result.ground_truth.waf_provider}, CDN={result.ground_truth.cdn_provider}",
                f"  - Detected: WAF={result.detected_waf}, CDN={result.detected_cdn}",
                f"  - Notes: {result.ground_truth.notes}",
                ""
            ])
        
        # False negatives
        report_lines.extend([
            "### False Negatives",
            ""
        ])
        
        false_negatives = [r for r in self.results if not r.error and (
            (r.ground_truth.waf_provider and not r.detected_waf) or
            (r.ground_truth.cdn_provider and not r.detected_cdn)
        )]
        
        for result in false_negatives:
            report_lines.extend([
                f"- **{result.ground_truth.url}**",
                f"  - Expected: WAF={result.ground_truth.waf_provider}, CDN={result.ground_truth.cdn_provider}",
                f"  - Detected: WAF={result.detected_waf}, CDN={result.detected_cdn}",
                f"  - Notes: {result.ground_truth.notes}",
                ""
            ])
            
            # Show evidence for debugging
            if result.evidence:
                report_lines.append("  - Evidence found:")
                for evidence in result.evidence[:3]:  # Show first 3 pieces
                    report_lines.append(f"    - {evidence.get('type', 'Unknown')}: {evidence.get('data', 'N/A')}")
                report_lines.append("")
        
        # Errors
        errors = [r for r in self.results if r.error]
        if errors:
            report_lines.extend([
                "### Errors",
                ""
            ])
            
            for result in errors:
                report_lines.extend([
                    f"- **{result.ground_truth.url}**",
                    f"  - Error: {result.error}",
                    ""
                ])
        
        # Average detection time
        valid_times = [r.detection_time for r in self.results if not r.error and r.detection_time > 0]
        if valid_times:
            avg_time = sum(valid_times) / len(valid_times)
            report_lines.extend([
                "## Performance Metrics",
                f"- Average Detection Time: {avg_time:.2f}s",
                f"- Min Detection Time: {min(valid_times):.2f}s",
                f"- Max Detection Time: {max(valid_times):.2f}s",
                ""
            ])
        
        return "\n".join(report_lines)
    
    def save_results(self, output_dir: str = "."):
        """Save validation results to files"""
        # Save detailed results as JSON
        results_data = []
        for result in self.results:
            results_data.append({
                "url": result.ground_truth.url,
                "expected_waf": result.ground_truth.waf_provider,
                "expected_cdn": result.ground_truth.cdn_provider,
                "detected_waf": result.detected_waf,
                "detected_cdn": result.detected_cdn,
                "is_correct_waf": result.is_correct_waf,
                "is_correct_cdn": result.is_correct_cdn,
                "confidence": result.detection_confidence,
                "detection_time": result.detection_time,
                "error": result.error,
                "evidence": result.evidence,
                "actual_headers": result.actual_headers
            })
        
        with open(f"{output_dir}/validation_results.json", "w") as f:
            json.dump(results_data, f, indent=2)
        
        # Save report as markdown
        report = self.generate_report()
        with open(f"{output_dir}/validation_report.md", "w") as f:
            f.write(report)
        
        # Save metrics summary
        metrics = self.calculate_metrics()
        with open(f"{output_dir}/validation_metrics.json", "w") as f:
            json.dump(metrics, f, indent=2)
        
        logger.info(f"Results saved to {output_dir}/")

async def main():
    """Main entry point"""
    # Check if binary exists
    binary_path = "./target/debug/waf-detector"
    if not subprocess.run(["test", "-f", binary_path], capture_output=True).returncode == 0:
        logger.error(f"WAF detector binary not found at {binary_path}")
        logger.info("Building WAF detector...")
        subprocess.run(["cargo", "build"], check=True)
    
    # Run validation
    validator = AccuracyValidator(binary_path)
    await validator.validate_all()
    
    # Generate and save reports
    validator.save_results()
    
    # Print summary
    print("\n" + "="*60)
    print("VALIDATION COMPLETE")
    print("="*60)
    
    metrics = validator.calculate_metrics()
    print(f"\nOverall Accuracy: {metrics['combined']['accuracy']:.2%}")
    print(f"WAF Detection F1 Score: {metrics['waf']['f1_score']:.2%}")
    print(f"CDN Detection F1 Score: {metrics['cdn']['f1_score']:.2%}")
    
    print("\nDetailed reports saved:")
    print("- validation_report.md")
    print("- validation_results.json")
    print("- validation_metrics.json")

if __name__ == "__main__":
    asyncio.run(main())