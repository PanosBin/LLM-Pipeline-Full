#!/usr/bin/env python3
"""
Standalone script to generate results.json from existing pipeline outputs.
This replicates the logic from results_final.ipynb

Usage:
    python generate_results_standalone.py --output-dir <path_to_output_directory>

Example:
    python generate_results_standalone.py --output-dir /Users/panagiotisbinikos/Desktop/CB_Thesis/code/LLM-Pipeline/out_Damn-Vulnerable-Bank/
"""
import argparse
import logging
from src.generate_results import generate_final_results

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)-8s] --- %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Generate final results.json from pipeline outputs"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        required=True,
        help="Directory containing pipeline outputs (mobsf_scan.json, parsed_files.json, clusters.json, summaries.json)"
    )
    args = parser.parse_args()

    logger.info(f"Processing outputs from: {args.output_dir}")

    try:
        results = generate_final_results(args.output_dir)
        logger.info(f"✅ Successfully generated results.json with {len(results['results'])} entries")
    except FileNotFoundError as e:
        logger.error(f"❌ Error: Required file not found - {e}")
        logger.error("Make sure the output directory contains:")
        logger.error("  - mobsf_scan.json")
        logger.error("  - parsed_files.json")
        logger.error("  - clusters.json")
        logger.error("  - summaries.json")
        return 1
    except Exception as e:
        logger.error(f"❌ Error generating results: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
