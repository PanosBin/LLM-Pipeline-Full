#!/usr/bin/env python3
"""
Stress Test & Experiment Runner for LLM-Pipeline

Runs comprehensive experiments to test:
- Pipeline performance on multiple apps
- Different configurations (with/without summarization, evaluation)
- Resource usage and timing
- Output validation
"""

import subprocess
import json
import time
import os
import sys
from pathlib import Path
from datetime import datetime
import argparse


class ExperimentRunner:
    def __init__(self, output_base="experiments"):
        self.output_base = output_base
        self.results = []
        os.makedirs(output_base, exist_ok=True)

    def run_pipeline(self, app_dir, experiment_name, flags=None):
        """Run pipeline with timing and error handling"""
        print(f"\n{'='*70}")
        print(f"EXPERIMENT: {experiment_name}")
        print(f"App: {app_dir}")
        print(f"Flags: {flags or 'default'}")
        print(f"{'='*70}\n")

        start_time = time.time()

        # Build command
        cmd = ["poetry", "run", "python", "main_file.py", "--dir", app_dir]

        if flags:
            cmd.extend(flags)

        # Add output name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_name = f"{experiment_name}_{timestamp}"
        cmd.extend(["--output-name", output_name])

        print(f"Command: {' '.join(cmd)}\n")

        # Run pipeline
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour max
            )

            elapsed_time = time.time() - start_time

            success = result.returncode == 0

            experiment_result = {
                "experiment_name": experiment_name,
                "app_dir": app_dir,
                "flags": flags or [],
                "output_name": output_name,
                "success": success,
                "elapsed_time": elapsed_time,
                "returncode": result.returncode,
                "timestamp": timestamp
            }

            # Parse output for metrics
            if success:
                output_dir = f"out_{output_name}"
                experiment_result["outputs"] = self.validate_outputs(output_dir, flags or [])

            self.results.append(experiment_result)

            print(f"\n{'='*70}")
            print(f"✓ COMPLETED: {experiment_name}")
            print(f"Status: {'SUCCESS' if success else 'FAILED'}")
            print(f"Time: {elapsed_time:.1f}s ({elapsed_time/60:.1f} min)")
            print(f"Output: out_{output_name}")
            print(f"{'='*70}\n")

            return experiment_result

        except subprocess.TimeoutExpired:
            print(f"\n✗ TIMEOUT: {experiment_name} (>1 hour)")
            elapsed_time = time.time() - start_time
            experiment_result = {
                "experiment_name": experiment_name,
                "app_dir": app_dir,
                "flags": flags or [],
                "success": False,
                "elapsed_time": elapsed_time,
                "error": "timeout",
                "timestamp": timestamp
            }
            self.results.append(experiment_result)
            return experiment_result

        except Exception as e:
            print(f"\n✗ ERROR: {experiment_name} - {str(e)}")
            elapsed_time = time.time() - start_time
            experiment_result = {
                "experiment_name": experiment_name,
                "app_dir": app_dir,
                "flags": flags or [],
                "success": False,
                "elapsed_time": elapsed_time,
                "error": str(e),
                "timestamp": timestamp
            }
            self.results.append(experiment_result)
            return experiment_result

    def validate_outputs(self, output_dir, flags):
        """Validate expected output files exist"""
        validation = {}

        expected_files = [
            "mobsf_raw_scan.json",
            "mobsf_scan.json",
            "parsed_files.json",
            "clusters.json",
            "summaries.json",
            "results.json"
        ]

        if "--evaluate" in flags:
            expected_files.extend([
                "evaluation.json",
                "summary_quality_metrics.json"
            ])

        for filename in expected_files:
            filepath = os.path.join(output_dir, filename)
            exists = os.path.exists(filepath)
            validation[filename] = {
                "exists": exists,
                "size_kb": os.path.getsize(filepath) / 1024 if exists else 0
            }

            # Load and count items
            if exists and filename.endswith('.json'):
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)

                    if filename == "mobsf_scan.json":
                        validation[filename]["vulnerability_types"] = len(data.get("results", {}))
                    elif filename == "clusters.json":
                        validation[filename]["num_clusters"] = len(data) if isinstance(data, list) else 0
                    elif filename == "results.json":
                        validation[filename]["vulnerability_instances"] = len(data.get("results", []))
                    elif filename == "evaluation.json":
                        validation[filename]["total_evaluated"] = data.get("summary", {}).get("total_vulnerabilities", 0)
                        validation[filename]["true_positives"] = data.get("summary", {}).get("predicted_true_positives", 0)
                    elif filename == "summary_quality_metrics.json":
                        validation[filename]["avg_quality_score"] = data.get("aggregate", {}).get("average_overall_score", 0)
                except:
                    validation[filename]["parse_error"] = True

        return validation

    def save_results(self):
        """Save experiment results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = os.path.join(self.output_base, f"experiment_results_{timestamp}.json")

        summary = {
            "total_experiments": len(self.results),
            "successful": sum(1 for r in self.results if r["success"]),
            "failed": sum(1 for r in self.results if not r["success"]),
            "total_time": sum(r["elapsed_time"] for r in self.results),
            "timestamp": timestamp
        }

        output = {
            "summary": summary,
            "experiments": self.results
        }

        with open(results_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"\n{'='*70}")
        print(f"EXPERIMENT RESULTS SAVED")
        print(f"{'='*70}")
        print(f"File: {results_file}")
        print(f"Total experiments: {summary['total_experiments']}")
        print(f"Successful: {summary['successful']}")
        print(f"Failed: {summary['failed']}")
        print(f"Total time: {summary['total_time']/60:.1f} minutes")
        print(f"{'='*70}\n")

        return results_file


def main():
    parser = argparse.ArgumentParser(description="Run LLM Pipeline experiments")
    parser.add_argument("--quick", action="store_true", help="Run quick tests only (scan-only)")
    parser.add_argument("--full", action="store_true", help="Run full experiments with evaluation")
    parser.add_argument("--app", type=str, help="Test specific app only")
    args = parser.parse_args()

    runner = ExperimentRunner()

    # Define test apps
    test_apps = [
        "./data/apps/Damn-Vulnerable-Bank",
    ]

    if args.app:
        if os.path.exists(args.app):
            test_apps = [args.app]
        else:
            print(f"Error: App directory not found: {args.app}")
            sys.exit(1)

    print(f"""
{'='*70}
LLM PIPELINE STRESS TEST & EXPERIMENT RUNNER
{'='*70}

Apps to test: {len(test_apps)}
{chr(10).join(f'  - {app}' for app in test_apps)}

{'='*70}
""")

    # Experiment configurations
    experiments = []

    for app in test_apps:
        app_name = os.path.basename(app)

        if args.quick:
            # Quick tests (scan only)
            experiments.extend([
                {
                    "name": f"{app_name}_scan_only",
                    "app": app,
                    "flags": ["--scan-only"]
                },
                {
                    "name": f"{app_name}_no_summarize",
                    "app": app,
                    "flags": ["--scan", "--no-summarize"]
                }
            ])

        elif args.full:
            # Full experiments
            experiments.extend([
                {
                    "name": f"{app_name}_scan_only",
                    "app": app,
                    "flags": ["--scan-only"]
                },
                {
                    "name": f"{app_name}_no_summarize",
                    "app": app,
                    "flags": ["--scan", "--no-summarize"]
                },
                {
                    "name": f"{app_name}_with_summaries",
                    "app": app,
                    "flags": ["--scan"]
                },
                {
                    "name": f"{app_name}_with_evaluation",
                    "app": app,
                    "flags": ["--scan", "--evaluate"]
                }
            ])
        else:
            # Default: basic tests
            experiments.extend([
                {
                    "name": f"{app_name}_scan_only",
                    "app": app,
                    "flags": ["--scan-only"]
                },
                {
                    "name": f"{app_name}_full_pipeline",
                    "app": app,
                    "flags": ["--scan"]
                }
            ])

    print(f"Running {len(experiments)} experiments...\n")

    # Run all experiments
    for i, exp in enumerate(experiments, 1):
        print(f"\nExperiment {i}/{len(experiments)}")
        runner.run_pipeline(
            app_dir=exp["app"],
            experiment_name=exp["name"],
            flags=exp["flags"]
        )

        # Small delay between experiments
        if i < len(experiments):
            time.sleep(2)

    # Save results
    results_file = runner.save_results()

    # Print summary table
    print("\nRESULTS SUMMARY:")
    print(f"{'Experiment':<40} {'Status':<10} {'Time (min)':<12}")
    print("-" * 70)
    for r in runner.results:
        status = "✓ SUCCESS" if r["success"] else "✗ FAILED"
        time_min = r["elapsed_time"] / 60
        print(f"{r['experiment_name']:<40} {status:<10} {time_min:>10.1f}")

    print(f"\n{'='*70}")
    print(f"All experiments completed!")
    print(f"Results: {results_file}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
