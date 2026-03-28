"""
Summary quality metrics for evaluating generated summaries.

Measures objective qualities of summaries:
- Length (word count)
- Code coverage (mentions vulnerable patterns)
- Context relevance (mentions related methods/classes)
- Specificity (not generic text)
"""

import re
import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


class SummaryQualityMetrics:
    """
    Evaluates quality of generated summaries using objective metrics.
    """

    # Generic phrases that indicate low specificity
    GENERIC_PHRASES = [
        "this method",
        "this class",
        "this code",
        "handles data",
        "processes information",
        "performs operations",
        "manages resources",
        "implements functionality",
        "provides features",
        "contains logic",
        "executes tasks",
    ]

    def __init__(self):
        pass

    def calculate_length_metric(self, summary: str) -> Dict:
        """
        Calculate length-based metrics.

        Returns:
            {
                "word_count": int,
                "char_count": int,
                "is_adequate_length": bool  # 10-50 words is good
            }
        """
        words = summary.split()
        word_count = len(words)
        char_count = len(summary)

        # Good summaries are concise but informative (10-50 words)
        is_adequate = 10 <= word_count <= 50

        return {
            "word_count": word_count,
            "char_count": char_count,
            "is_adequate_length": is_adequate
        }

    def calculate_code_coverage(
        self,
        summary: str,
        vulnerable_code: str,
        vulnerability_type: str
    ) -> Dict:
        """
        Check if summary mentions key code patterns from the vulnerability.

        Args:
            summary: Generated summary text
            vulnerable_code: The actual vulnerable code snippet
            vulnerability_type: Type of vulnerability (e.g., "android_logging")

        Returns:
            {
                "mentions_vulnerability_keyword": bool,
                "mentions_code_pattern": bool,
                "keyword_found": str or None,
                "pattern_coverage": float  # 0.0-1.0
            }
        """
        summary_lower = summary.lower()
        code_lower = vulnerable_code.lower()

        # Vulnerability-specific keywords
        vuln_keywords = {
            "android_logging": ["log", "logging", "log.d", "log.e", "log.i", "log.v"],
            "android_hidden_ui": ["visible", "visibility", "gone", "invisible", "setvisibility"],
            "hardcoded_secret": ["password", "secret", "key", "token", "credential", "hardcoded"],
            "android_webview": ["webview", "loadurl", "javascript", "jsenabled"],
            "android_crypto": ["encrypt", "decrypt", "cipher", "crypto", "aes", "des"],
        }

        # Check if summary mentions vulnerability-specific keywords
        keywords = vuln_keywords.get(vulnerability_type.lower(), [])
        keyword_found = None
        mentions_keyword = False

        for keyword in keywords:
            if keyword in summary_lower:
                mentions_keyword = True
                keyword_found = keyword
                break

        # Extract important identifiers from code (method names, variables)
        code_identifiers = self._extract_identifiers(vulnerable_code)

        # Check how many code identifiers are mentioned in summary
        mentioned_count = sum(1 for ident in code_identifiers if ident.lower() in summary_lower)
        pattern_coverage = mentioned_count / len(code_identifiers) if code_identifiers else 0.0

        return {
            "mentions_vulnerability_keyword": mentions_keyword,
            "mentions_code_pattern": pattern_coverage > 0,
            "keyword_found": keyword_found,
            "pattern_coverage": pattern_coverage
        }

    def calculate_context_relevance(
        self,
        summary: str,
        method_calls: List[str],
        class_name: str,
        related_classes: List[str] = None
    ) -> Dict:
        """
        Check if summary mentions relevant context (method calls, classes).

        Args:
            summary: Generated summary text
            method_calls: List of methods called within the code
            class_name: Name of the class being summarized
            related_classes: List of related class names (optional)

        Returns:
            {
                "mentions_class_name": bool,
                "mentions_method_calls": bool,
                "method_call_coverage": float,  # 0.0-1.0
                "mentions_related_classes": bool
            }
        """
        summary_lower = summary.lower()

        # Check if class name is mentioned
        mentions_class = class_name.lower() in summary_lower if class_name else False

        # Check method call coverage
        if method_calls:
            mentioned_methods = sum(1 for m in method_calls if m.lower() in summary_lower)
            method_coverage = mentioned_methods / len(method_calls)
            mentions_methods = method_coverage > 0
        else:
            method_coverage = 0.0
            mentions_methods = False

        # Check related classes
        mentions_related = False
        if related_classes:
            mentions_related = any(rc.lower() in summary_lower for rc in related_classes)

        return {
            "mentions_class_name": mentions_class,
            "mentions_method_calls": mentions_methods,
            "method_call_coverage": method_coverage,
            "mentions_related_classes": mentions_related
        }

    def calculate_specificity(self, summary: str) -> Dict:
        """
        Check if summary is specific vs generic.

        Returns:
            {
                "is_specific": bool,
                "generic_phrase_count": int,
                "specificity_score": float  # 0.0-1.0
            }
        """
        summary_lower = summary.lower()

        # Count generic phrases
        generic_count = sum(1 for phrase in self.GENERIC_PHRASES if phrase in summary_lower)

        # Check for specific indicators (numbers, technical terms, names)
        specific_indicators = 0

        # Has numbers (line numbers, counts, etc.)
        if re.search(r'\b\d+\b', summary):
            specific_indicators += 1

        # Has CamelCase identifiers (likely class/method names)
        if re.search(r'\b[A-Z][a-z]+[A-Z][a-zA-Z]*\b', summary):
            specific_indicators += 1

        # Has technical terms (parentheses suggest method names)
        if '(' in summary or ')' in summary:
            specific_indicators += 1

        # Has code-like patterns (dots for method calls)
        if re.search(r'\w+\.\w+', summary):
            specific_indicators += 1

        # Specificity score: high specific indicators, low generic phrases
        specificity_score = min(1.0, specific_indicators / 4.0)
        if generic_count > 0:
            specificity_score *= max(0.5, 1.0 - (generic_count * 0.2))

        is_specific = specificity_score >= 0.5

        return {
            "is_specific": is_specific,
            "generic_phrase_count": generic_count,
            "specificity_score": specificity_score
        }

    def _extract_identifiers(self, code: str) -> Set[str]:
        """
        Extract identifiers (variable names, method names) from code.
        """
        # Pattern for Java identifiers
        pattern = r'\b[a-z][a-zA-Z0-9_]*\b'
        matches = re.findall(pattern, code)

        # Filter out Java keywords
        java_keywords = {
            'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
            'return', 'void', 'int', 'long', 'float', 'double', 'boolean', 'char',
            'byte', 'short', 'class', 'public', 'private', 'protected', 'static',
            'final', 'abstract', 'new', 'this', 'super', 'null', 'true', 'false',
            'try', 'catch', 'throw', 'throws', 'finally', 'import', 'package'
        }

        identifiers = set(m for m in matches if m not in java_keywords and len(m) > 2)
        return identifiers

    def evaluate_summary(
        self,
        summary: str,
        vulnerable_code: str,
        vulnerability_type: str,
        method_calls: List[str] = None,
        class_name: str = None,
        related_classes: List[str] = None
    ) -> Dict:
        """
        Comprehensive summary quality evaluation.

        Returns:
            {
                "overall_score": float,  # 0.0-1.0
                "length": {...},
                "code_coverage": {...},
                "context_relevance": {...},
                "specificity": {...},
                "is_high_quality": bool
            }
        """
        # Calculate individual metrics
        length_metrics = self.calculate_length_metric(summary)
        coverage_metrics = self.calculate_code_coverage(summary, vulnerable_code, vulnerability_type)
        context_metrics = self.calculate_context_relevance(
            summary,
            method_calls or [],
            class_name or "",
            related_classes
        )
        specificity_metrics = self.calculate_specificity(summary)

        # Calculate overall score (weighted average)
        weights = {
            "length": 0.1,        # 10% - length is adequate
            "coverage": 0.4,      # 40% - mentions vulnerability pattern
            "context": 0.3,       # 30% - includes relevant context
            "specificity": 0.2    # 20% - specific vs generic
        }

        length_score = 1.0 if length_metrics["is_adequate_length"] else 0.5
        coverage_score = (
            (0.5 if coverage_metrics["mentions_vulnerability_keyword"] else 0.0) +
            (0.5 * coverage_metrics["pattern_coverage"])
        )
        context_score = (
            (0.3 if context_metrics["mentions_class_name"] else 0.0) +
            (0.5 * context_metrics["method_call_coverage"]) +
            (0.2 if context_metrics["mentions_related_classes"] else 0.0)
        )
        specificity_score = specificity_metrics["specificity_score"]

        overall_score = (
            weights["length"] * length_score +
            weights["coverage"] * coverage_score +
            weights["context"] * context_score +
            weights["specificity"] * specificity_score
        )

        # High quality threshold: overall score >= 0.6
        is_high_quality = overall_score >= 0.6

        return {
            "overall_score": round(overall_score, 3),
            "length": length_metrics,
            "code_coverage": coverage_metrics,
            "context_relevance": context_metrics,
            "specificity": specificity_metrics,
            "is_high_quality": is_high_quality
        }


def evaluate_all_summaries(results_file: str, output_file: str = None) -> Dict:
    """
    Evaluate all summaries in a results.json file.

    Args:
        results_file: Path to results.json
        output_file: Path to save metrics (default: summary_quality_metrics.json)

    Returns:
        Dictionary with aggregate metrics
    """
    import json
    import os

    logger.info("Loading results for summary quality evaluation...")
    with open(results_file, 'r') as f:
        results = json.load(f)

    evaluator = SummaryQualityMetrics()

    all_metrics = []
    for vuln in results.get("results", []):
        method_summary = vuln.get("summaries", {}).get("method", "")
        class_summary = vuln.get("summaries", {}).get("class", "")
        cluster_summary = vuln.get("summaries", {}).get("cluster", "")

        # Evaluate method summary
        if method_summary:
            metrics = evaluator.evaluate_summary(
                summary=method_summary,
                vulnerable_code=vuln.get("match", ""),
                vulnerability_type=vuln.get("vulnerability", ""),
                class_name=vuln.get("method", "").split(".")[0] if "." in vuln.get("method", "") else None
            )

            all_metrics.append({
                "vulnerability": vuln.get("vulnerability"),
                "file": vuln.get("file"),
                "line": vuln.get("line"),
                "method": vuln.get("method"),
                "summary_type": "method",
                "summary": method_summary,
                "metrics": metrics
            })

    # Aggregate statistics
    if all_metrics:
        avg_overall = sum(m["metrics"]["overall_score"] for m in all_metrics) / len(all_metrics)
        high_quality_count = sum(1 for m in all_metrics if m["metrics"]["is_high_quality"])

        avg_coverage = sum(m["metrics"]["code_coverage"]["pattern_coverage"] for m in all_metrics) / len(all_metrics)
        avg_specificity = sum(m["metrics"]["specificity"]["specificity_score"] for m in all_metrics) / len(all_metrics)

        aggregate = {
            "total_summaries_evaluated": len(all_metrics),
            "average_overall_score": round(avg_overall, 3),
            "high_quality_count": high_quality_count,
            "high_quality_percentage": round(high_quality_count / len(all_metrics) * 100, 1),
            "average_code_coverage": round(avg_coverage, 3),
            "average_specificity": round(avg_specificity, 3)
        }
    else:
        aggregate = {
            "total_summaries_evaluated": 0,
            "average_overall_score": 0.0,
            "high_quality_count": 0,
            "high_quality_percentage": 0.0
        }

    output = {
        "aggregate": aggregate,
        "individual_metrics": all_metrics
    }

    # Save to file
    if output_file is None:
        output_dir = os.path.dirname(results_file)
        output_file = os.path.join(output_dir, "summary_quality_metrics.json")

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    logger.info(f"✓ Summary quality metrics saved to: {output_file}")
    logger.info(f"  Average overall score: {aggregate['average_overall_score']}")
    logger.info(f"  High quality summaries: {aggregate['high_quality_count']}/{aggregate['total_summaries_evaluated']} ({aggregate['high_quality_percentage']}%)")

    return output
