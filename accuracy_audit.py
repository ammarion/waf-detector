#!/usr/bin/env python3
"""
WAF Detection Accuracy Audit Script

This script performs a comprehensive accuracy audit by:
1. Testing against known WAF/CDN providers
2. Identifying false positives and false negatives
3. Analyzing confidence scoring accuracy
4. Generating detailed diagnostic reports
"""

import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

class AccuracyAudit:
    """Comprehensive accuracy audit for WAF detection"""

    # Ground truth: Sites with confirmed WAF/CDN providers
    GROUND_TRUTH = [
        # CloudFlare sites (high confidence)
        {"url": "https://cloudflare.com", "waf": "CloudFlare", "cdn": "CloudFlare", "confidence": 0.99},
        {"url": "https://discord.com", "waf": "CloudFlare", "cdn": "CloudFlare", "confidence": 0.95},
        {"url": "https://www.cloudflare.com/cdn-cgi/trace", "waf": "CloudFlare", "cdn": "CloudFlare", "confidence": 0.99},

        # AWS CloudFront sites
        {"url": "https://aws.amazon.com", "waf": "AWS", "cdn": "AWS", "confidence": 0.95},
        {"url": "https://d1.awsstatic.com/", "waf": "AWS", "cdn": "AWS", "confidence": 0.98},

        # Fastly sites
        {"url": "https://www.fastly.com", "waf": "Fastly", "cdn": "Fastly", "confidence": 0.98},
        {"url": "https://github.com", "waf": "Fastly", "cdn": "Fastly", "confidence": 0.95},
        {"url": "https://stackoverflow.com", "waf": "Fastly", "cdn": "Fastly", "confidence": 0.90},

        # Akamai sites
        {"url": "https://www.akamai.com", "waf": "Akamai", "cdn": "Akamai", "confidence": 0.98},
        {"url": "https://www.apple.com", "waf": "Akamai", "cdn": "Akamai", "confidence": 0.90},

        # Vercel sites
        {"url": "https://vercel.com", "waf": "Vercel", "cdn": "Vercel", "confidence": 0.98},

        # Azure sites
        {"url": "https://azure.microsoft.com", "waf": "Azure", "cdn": "Azure", "confidence": 0.95},
        {"url": "https://docs.microsoft.com", "waf": "Azure", "cdn": "Azure", "confidence": 0.90},

        # Sites WITHOUT WAF/CDN (negative tests - crucial for false positive detection)
        {"url": "https://example.com", "waf": None, "cdn": None, "confidence": 0.90},
        {"url": "https://httpbin.org", "waf": None, "cdn": None, "confidence": 0.85},
    ]

    def __init__(self, binary_path: str = "./target/release/waf-detect"):
        self.binary_path = binary_path
        self.results = []
        self.issues = defaultdict(list)

    def run_detection(self, url: str, timeout: int = 30) -> Tuple[Optional[Dict], float]:
        """Run WAF detection and return result + time"""
        start = time.time()
        try:
            result = subprocess.run(
                [self.binary_path, url, "--json"],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            elapsed = time.time() - start

            if result.returncode != 0:
                print(f"  ❌ Error: {result.stderr}")
                return None, elapsed

            return json.loads(result.stdout), elapsed
        except subprocess.TimeoutExpired:
            return None, timeout
        except Exception as e:
            print(f"  ❌ Exception: {e}")
            return None, time.time() - start

    def audit_detection(self, test_case: Dict) -> Dict:
        """Audit a single detection"""
        url = test_case["url"]
        expected_waf = test_case["waf"]
        expected_cdn = test_case["cdn"]
        expected_confidence = test_case["confidence"]

        print(f"\n🔍 Testing: {url}")
        print(f"   Expected: WAF={expected_waf}, CDN={expected_cdn}")

        result, detection_time = self.run_detection(url)

        if result is None:
            issue = {
                "url": url,
                "type": "detection_failure",
                "message": "Detection failed or timed out",
                "expected_waf": expected_waf,
                "expected_cdn": expected_cdn
            }
            self.issues["detection_failures"].append(issue)
            return {
                "url": url,
                "status": "failed",
                "expected_waf": expected_waf,
                "expected_cdn": expected_cdn,
                "detection_time": detection_time
            }

        detected_waf = result.get("detected_waf", {}).get("name") if result.get("detected_waf") else None
        detected_cdn = result.get("detected_cdn", {}).get("name") if result.get("detected_cdn") else None
        detected_confidence = result.get("detected_waf", {}).get("confidence", 0) if result.get("detected_waf") else 0

        print(f"   Detected: WAF={detected_waf}, CDN={detected_cdn}, Confidence={detected_confidence:.2f}")

        # Check for issues
        waf_correct = (expected_waf == detected_waf)
        cdn_correct = (expected_cdn == detected_cdn)

        # False positive: Detected WAF/CDN when none should exist
        if not expected_waf and detected_waf:
            issue = {
                "url": url,
                "type": "false_positive_waf",
                "message": f"Detected WAF '{detected_waf}' when none should exist",
                "detected_waf": detected_waf,
                "confidence": detected_confidence,
                "evidence": result.get("evidence_map", {}).get(detected_waf, [])
            }
            self.issues["false_positives"].append(issue)
            print(f"   ⚠️  FALSE POSITIVE: Detected {detected_waf} WAF incorrectly")

        if not expected_cdn and detected_cdn:
            issue = {
                "url": url,
                "type": "false_positive_cdn",
                "message": f"Detected CDN '{detected_cdn}' when none should exist",
                "detected_cdn": detected_cdn
            }
            self.issues["false_positives"].append(issue)
            print(f"   ⚠️  FALSE POSITIVE: Detected {detected_cdn} CDN incorrectly")

        # False negative: Failed to detect expected WAF/CDN
        if expected_waf and not detected_waf:
            issue = {
                "url": url,
                "type": "false_negative_waf",
                "message": f"Failed to detect expected WAF '{expected_waf}'",
                "expected_waf": expected_waf,
                "all_evidence": result.get("evidence_map", {}),
                "provider_scores": result.get("provider_scores", {})
            }
            self.issues["false_negatives"].append(issue)
            print(f"   ❌ FALSE NEGATIVE: Failed to detect {expected_waf} WAF")

        if expected_cdn and not detected_cdn:
            issue = {
                "url": url,
                "type": "false_negative_cdn",
                "message": f"Failed to detect expected CDN '{expected_cdn}'",
                "expected_cdn": expected_cdn
            }
            self.issues["false_negatives"].append(issue)
            print(f"   ❌ FALSE NEGATIVE: Failed to detect {expected_cdn} CDN")

        # Wrong detection: Detected different provider
        if expected_waf and detected_waf and expected_waf != detected_waf:
            issue = {
                "url": url,
                "type": "wrong_detection_waf",
                "message": f"Detected '{detected_waf}' instead of '{expected_waf}'",
                "expected_waf": expected_waf,
                "detected_waf": detected_waf,
                "confidence": detected_confidence,
                "evidence": result.get("evidence_map", {})
            }
            self.issues["wrong_detections"].append(issue)
            print(f"   ❌ WRONG DETECTION: Detected {detected_waf} instead of {expected_waf}")

        # Confidence issues
        if detected_waf and waf_correct:
            if detected_confidence < expected_confidence - 0.2:
                issue = {
                    "url": url,
                    "type": "low_confidence",
                    "message": f"Confidence {detected_confidence:.2f} is too low (expected ~{expected_confidence:.2f})",
                    "detected_confidence": detected_confidence,
                    "expected_confidence": expected_confidence,
                    "provider": detected_waf
                }
                self.issues["confidence_issues"].append(issue)
                print(f"   ⚠️  LOW CONFIDENCE: {detected_confidence:.2f} < {expected_confidence:.2f}")

        # Performance issues
        if detection_time > 10.0:
            issue = {
                "url": url,
                "type": "slow_detection",
                "message": f"Detection took {detection_time:.2f}s (> 10s threshold)",
                "detection_time": detection_time
            }
            self.issues["performance_issues"].append(issue)
            print(f"   ⚠️  SLOW: {detection_time:.2f}s")

        status = "✅ PASS" if waf_correct and cdn_correct else "❌ FAIL"
        print(f"   {status}")

        return {
            "url": url,
            "status": "pass" if waf_correct and cdn_correct else "fail",
            "expected_waf": expected_waf,
            "expected_cdn": expected_cdn,
            "detected_waf": detected_waf,
            "detected_cdn": detected_cdn,
            "waf_correct": waf_correct,
            "cdn_correct": cdn_correct,
            "confidence": detected_confidence,
            "detection_time": detection_time,
            "result": result
        }

    def run_audit(self):
        """Run complete audit"""
        print("="*70)
        print("WAF DETECTION ACCURACY AUDIT")
        print("="*70)
        print(f"Binary: {self.binary_path}")
        print(f"Test cases: {len(self.GROUND_TRUTH)}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        for test_case in self.GROUND_TRUTH:
            result = self.audit_detection(test_case)
            self.results.append(result)
            time.sleep(0.5)  # Rate limiting

        self.print_summary()
        self.save_report()

    def print_summary(self):
        """Print audit summary"""
        print("\n" + "="*70)
        print("AUDIT SUMMARY")
        print("="*70)

        total = len(self.results)
        passed = len([r for r in self.results if r["status"] == "pass"])
        failed = len([r for r in self.results if r["status"] == "fail"])

        print(f"\n📊 Overall Results:")
        print(f"   Total tests: {total}")
        print(f"   Passed: {passed} ({passed/total*100:.1f}%)")
        print(f"   Failed: {failed} ({failed/total*100:.1f}%)")

        # Calculate metrics
        waf_tp = len([r for r in self.results if r["expected_waf"] and r["detected_waf"] and r["waf_correct"]])
        waf_fp = len([r for r in self.results if not r["expected_waf"] and r["detected_waf"]])
        waf_fn = len([r for r in self.results if r["expected_waf"] and not r["detected_waf"]])
        waf_tn = len([r for r in self.results if not r["expected_waf"] and not r["detected_waf"]])

        waf_precision = waf_tp / (waf_tp + waf_fp) if (waf_tp + waf_fp) > 0 else 0
        waf_recall = waf_tp / (waf_tp + waf_fn) if (waf_tp + waf_fn) > 0 else 0
        waf_accuracy = (waf_tp + waf_tn) / total if total > 0 else 0

        print(f"\n📈 WAF Detection Metrics:")
        print(f"   Accuracy:  {waf_accuracy:.2%}")
        print(f"   Precision: {waf_precision:.2%}")
        print(f"   Recall:    {waf_recall:.2%}")
        print(f"   F1 Score:  {2*waf_precision*waf_recall/(waf_precision+waf_recall) if waf_precision+waf_recall > 0 else 0:.2%}")

        # Issue breakdown
        print(f"\n🔍 Issues Found:")
        print(f"   False Positives: {len(self.issues['false_positives'])}")
        print(f"   False Negatives: {len(self.issues['false_negatives'])}")
        print(f"   Wrong Detections: {len(self.issues['wrong_detections'])}")
        print(f"   Confidence Issues: {len(self.issues['confidence_issues'])}")
        print(f"   Performance Issues: {len(self.issues['performance_issues'])}")
        print(f"   Detection Failures: {len(self.issues['detection_failures'])}")

        # Detailed issue reporting
        if self.issues['false_positives']:
            print(f"\n❌ False Positives (Detected WAF/CDN when none exists):")
            for issue in self.issues['false_positives']:
                print(f"   • {issue['url']}: {issue['message']}")
                if 'evidence' in issue and issue['evidence']:
                    print(f"     Evidence: {len(issue['evidence'])} pieces found")
                    for ev in issue['evidence'][:2]:
                        print(f"       - {ev.get('description', 'N/A')}")

        if self.issues['false_negatives']:
            print(f"\n❌ False Negatives (Failed to detect expected WAF/CDN):")
            for issue in self.issues['false_negatives']:
                print(f"   • {issue['url']}: {issue['message']}")
                if 'provider_scores' in issue:
                    scores = issue['provider_scores']
                    print(f"     Provider scores: {', '.join([f'{k}={v:.2f}' for k,v in scores.items()])}")

        if self.issues['wrong_detections']:
            print(f"\n❌ Wrong Detections:")
            for issue in self.issues['wrong_detections']:
                print(f"   • {issue['url']}: {issue['message']}")
                print(f"     Confidence: {issue.get('confidence', 0):.2f}")

        if self.issues['confidence_issues']:
            print(f"\n⚠️  Confidence Issues:")
            for issue in self.issues['confidence_issues']:
                print(f"   • {issue['url']}: {issue['message']}")

        # Performance stats
        times = [r["detection_time"] for r in self.results if r["status"] != "failed"]
        if times:
            print(f"\n⏱️  Performance:")
            print(f"   Average: {sum(times)/len(times):.2f}s")
            print(f"   Min:     {min(times):.2f}s")
            print(f"   Max:     {max(times):.2f}s")

    def save_report(self):
        """Save detailed audit report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "binary": self.binary_path,
            "total_tests": len(self.results),
            "passed": len([r for r in self.results if r["status"] == "pass"]),
            "failed": len([r for r in self.results if r["status"] == "fail"]),
            "issues": dict(self.issues),
            "results": self.results
        }

        filename = f"accuracy_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n💾 Detailed report saved: {filename}")

def main():
    binary_path = "./target/release/waf-detect"

    # Check if binary exists
    result = subprocess.run(["test", "-f", binary_path], capture_output=True)
    if result.returncode != 0:
        print(f"❌ Binary not found: {binary_path}")
        print("Building release binary...")
        subprocess.run(["cargo", "build", "--release"], check=True)

    audit = AccuracyAudit(binary_path)
    audit.run_audit()

if __name__ == "__main__":
    main()