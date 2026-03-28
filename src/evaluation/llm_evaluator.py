"""
LLM-based vulnerability evaluation and summary quality assessment.

After all analysis is complete, this module uses the LLM to:
1. Predict if each vulnerability is a TRUE POSITIVE or FALSE POSITIVE
2. Provide feedback on whether summaries were helpful
3. Suggest improvements to summaries if needed
4. Calculate objective summary quality metrics
"""

import json
import logging
from typing import Dict, List
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from .summary_metrics import SummaryQualityMetrics, evaluate_all_summaries

logger = logging.getLogger(__name__)


class LLMEvaluator:
    """
    Uses LLaMA to evaluate vulnerabilities and assess summary quality.
    """

    def __init__(self, model_name="codellama/CodeLlama-7b-Instruct-hf"):
        """
        Initialize evaluator with CodeLlama (same model as summarization).
        Using consistent model across pipeline ensures coherent analysis.
        """
        logger.info(f"Loading CodeLlama evaluator model: {model_name}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            load_in_8bit=True,
            device_map="auto",
            torch_dtype=torch.bfloat16
        )
        self.model.eval()
        logger.info("✓ CodeLlama evaluator model loaded!")

    def evaluate_vulnerability(
        self,
        vulnerability_type: str,
        vulnerability_description: str,
        method_code: str,
        method_summary: str,
        class_summary: str,
        cluster_summary: str,
        file_path: str,
        line_number: int
    ) -> Dict:
        """
        Evaluate a single vulnerability instance.

        Returns:
            {
                "prediction": "TRUE_POSITIVE" or "FALSE_POSITIVE",
                "confidence": 0.0-1.0,
                "reasoning": "why the LLM made this decision",
                "summary_feedback": {
                    "helpful": True/False,
                    "missing_info": "what information was missing",
                    "suggestions": "how to improve summaries"
                }
            }
        """

        prompt = self._build_evaluation_prompt(
            vulnerability_type,
            vulnerability_description,
            method_code,
            method_summary,
            class_summary,
            cluster_summary,
            file_path,
            line_number
        )

        # Generate LLM response
        response = self._generate_response(prompt)

        # Parse response
        evaluation = self._parse_evaluation_response(response)

        return evaluation

    def _build_evaluation_prompt(
        self,
        vuln_type: str,
        vuln_desc: str,
        code: str,
        method_sum: str,
        class_sum: str,
        cluster_sum: str,
        file_path: str,
        line: int
    ) -> str:
        """Build the prompt for vulnerability evaluation."""

        prompt = f"""[INST] You are a security expert evaluating Android vulnerabilities.

VULNERABILITY DETAILS:
- Type: {vuln_type}
- Description: {vuln_desc}
- Location: {file_path}:{line}

METHOD CODE:
```java
{code[:1000]}
```

SUMMARIES PROVIDED:
- Method Summary: {method_sum}
- Class Summary: {class_sum}
- Cluster Summary: {cluster_sum}

YOUR TASK:
1. Determine if this is a TRUE POSITIVE (real security issue) or FALSE POSITIVE (not actually vulnerable)
2. Evaluate if the summaries helped you make this decision
3. Suggest what information would improve the summaries

RESPOND IN THIS EXACT FORMAT:

PREDICTION: [TRUE_POSITIVE or FALSE_POSITIVE]
CONFIDENCE: [0.0-1.0]
REASONING: [Your reasoning in 2-3 sentences]

SUMMARY_EVALUATION:
HELPFUL: [YES or NO]
MISSING_INFO: [What critical information was missing from summaries, if any]
SUGGESTIONS: [How to improve summaries for better vulnerability assessment]
[/INST]"""

        return prompt

    def _generate_response(self, prompt: str, max_new_tokens: int = 300) -> str:
        """Generate LLM response for the prompt."""

        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
        inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=0.7,
                do_sample=True,
                top_p=0.9
            )

        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

        # Extract only the generated part (after the prompt)
        response = response.split("[/INST]")[-1].strip()

        return response

    def _parse_evaluation_response(self, response: str) -> Dict:
        """Parse the LLM response into structured evaluation."""

        evaluation = {
            "prediction": "UNKNOWN",
            "confidence": 0.5,
            "reasoning": "",
            "summary_feedback": {
                "helpful": False,
                "missing_info": "",
                "suggestions": ""
            }
        }

        try:
            # Extract prediction
            if "PREDICTION:" in response:
                pred_line = [l for l in response.split("\n") if "PREDICTION:" in l][0]
                if "TRUE_POSITIVE" in pred_line.upper():
                    evaluation["prediction"] = "TRUE_POSITIVE"
                elif "FALSE_POSITIVE" in pred_line.upper():
                    evaluation["prediction"] = "FALSE_POSITIVE"

            # Extract confidence
            if "CONFIDENCE:" in response:
                conf_line = [l for l in response.split("\n") if "CONFIDENCE:" in l][0]
                conf_str = conf_line.split("CONFIDENCE:")[-1].strip()
                try:
                    evaluation["confidence"] = float(conf_str)
                except:
                    pass

            # Extract reasoning
            if "REASONING:" in response:
                reasoning_start = response.find("REASONING:") + len("REASONING:")
                reasoning_end = response.find("SUMMARY_EVALUATION:")
                if reasoning_end == -1:
                    reasoning_end = len(response)
                evaluation["reasoning"] = response[reasoning_start:reasoning_end].strip()

            # Extract summary feedback
            if "HELPFUL:" in response:
                helpful_line = [l for l in response.split("\n") if "HELPFUL:" in l][0]
                evaluation["summary_feedback"]["helpful"] = "YES" in helpful_line.upper()

            if "MISSING_INFO:" in response:
                missing_start = response.find("MISSING_INFO:") + len("MISSING_INFO:")
                missing_end = response.find("SUGGESTIONS:")
                if missing_end == -1:
                    missing_end = len(response)
                evaluation["summary_feedback"]["missing_info"] = response[missing_start:missing_end].strip()

            if "SUGGESTIONS:" in response:
                suggestions_start = response.find("SUGGESTIONS:") + len("SUGGESTIONS:")
                evaluation["summary_feedback"]["suggestions"] = response[suggestions_start:].strip()

        except Exception as e:
            logger.warning(f"Error parsing evaluation response: {e}")

        return evaluation


def evaluate_all_vulnerabilities(output_dir: str) -> Dict:
    """
    Evaluate all vulnerabilities in the results.json file.

    Args:
        output_dir: Directory containing results.json, summaries.json, etc.

    Returns:
        Dictionary with evaluation results for each vulnerability
    """

    import os

    logger.info("="*60)
    logger.info("Starting LLM-based vulnerability evaluation...")
    logger.info("="*60)

    # Load results and summaries
    results_path = os.path.join(output_dir, "results.json")
    summaries_path = os.path.join(output_dir, "summaries.json")
    mobsf_path = os.path.join(output_dir, "mobsf_scan.json")

    logger.info("Loading results and summaries...")
    with open(results_path, "r") as f:
        results = json.load(f)
    with open(summaries_path, "r") as f:
        summaries = json.load(f)
    with open(mobsf_path, "r") as f:
        mobsf_scan = json.load(f)

    # Initialize evaluator
    logger.info("⚠️  Loading LLaMA evaluator - this may take a few minutes...")
    evaluator = LLMEvaluator()

    # Evaluate each vulnerability
    evaluations = []
    vulnerability_instances = results.get("results", [])

    logger.info(f"Evaluating {len(vulnerability_instances)} vulnerability instances...")

    for idx, vuln in enumerate(vulnerability_instances, 1):
        logger.info(f"Evaluating {idx}/{len(vulnerability_instances)}: {vuln['vulnerability']} at {vuln['file']}:{vuln['line']}")

        # Get vulnerability metadata
        vuln_type = vuln["vulnerability"]
        vuln_metadata = mobsf_scan.get("results", {}).get(vuln_type, {}).get("metadata", {})
        vuln_description = vuln_metadata.get("description", "No description available")

        # Get summaries
        method_key = vuln.get("method", "")
        method_summary = vuln.get("summaries", {}).get("method", "")
        class_summary = vuln.get("summaries", {}).get("class", "")
        cluster_summary = vuln.get("summaries", {}).get("cluster", "")

        # Get method code (from match string or full code if available)
        method_code = vuln.get("match", "Code not available")

        # Evaluate
        evaluation = evaluator.evaluate_vulnerability(
            vulnerability_type=vuln_type,
            vulnerability_description=vuln_description,
            method_code=method_code,
            method_summary=method_summary,
            class_summary=class_summary,
            cluster_summary=cluster_summary,
            file_path=vuln["file"],
            line_number=vuln["line"]
        )

        # Store evaluation with vulnerability info
        evaluations.append({
            "vulnerability": vuln_type,
            "file": vuln["file"],
            "line": vuln["line"],
            "method": method_key,
            "evaluation": evaluation
        })

        logger.info(f"  → Prediction: {evaluation['prediction']} (confidence: {evaluation['confidence']:.2f})")
        logger.info(f"  → Summaries helpful: {'YES' if evaluation['summary_feedback']['helpful'] else 'NO'}")

    # Generate summary statistics
    true_positives = sum(1 for e in evaluations if e["evaluation"]["prediction"] == "TRUE_POSITIVE")
    false_positives = sum(1 for e in evaluations if e["evaluation"]["prediction"] == "FALSE_POSITIVE")
    summaries_helpful = sum(1 for e in evaluations if e["evaluation"]["summary_feedback"]["helpful"])

    summary_stats = {
        "total_vulnerabilities": len(evaluations),
        "predicted_true_positives": true_positives,
        "predicted_false_positives": false_positives,
        "summaries_helpful_count": summaries_helpful,
        "summaries_helpful_percentage": (summaries_helpful / len(evaluations) * 100) if evaluations else 0
    }

    logger.info("="*60)
    logger.info("Evaluation complete!")
    logger.info(f"  Total vulnerabilities: {summary_stats['total_vulnerabilities']}")
    logger.info(f"  Predicted TRUE POSITIVES: {true_positives}")
    logger.info(f"  Predicted FALSE POSITIVES: {false_positives}")
    logger.info(f"  Summaries helpful: {summaries_helpful}/{len(evaluations)} ({summary_stats['summaries_helpful_percentage']:.1f}%)")
    logger.info("="*60)

    # Save evaluation results
    evaluation_output = {
        "summary": summary_stats,
        "evaluations": evaluations
    }

    evaluation_path = os.path.join(output_dir, "evaluation.json")
    with open(evaluation_path, "w") as f:
        json.dump(evaluation_output, f, indent=2)

    logger.info(f"✓ Evaluation results saved to: {evaluation_path}")

    # Calculate objective summary quality metrics
    logger.info("")
    logger.info("="*60)
    logger.info("Calculating objective summary quality metrics...")
    logger.info("="*60)

    results_path = os.path.join(output_dir, "results.json")
    metrics_output = evaluate_all_summaries(results_path)

    logger.info("="*60)
    logger.info(f"Summary quality: {metrics_output['aggregate']['high_quality_percentage']:.1f}% high quality")
    logger.info(f"Average overall score: {metrics_output['aggregate']['average_overall_score']:.2f}/1.0")
    logger.info(f"Average code coverage: {metrics_output['aggregate']['average_code_coverage']:.2f}")
    logger.info(f"Average specificity: {metrics_output['aggregate']['average_specificity']:.2f}")
    logger.info("="*60)

    return evaluation_output
