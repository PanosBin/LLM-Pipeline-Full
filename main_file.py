# main_file.py - PER-FILE clustering version
import json
import argparse
import logging
from pathlib import Path
import os
import subprocess
from datetime import datetime

# --- Imports ---
from src.parsers.parsing import TreeSitterParser
from src.clustering.clustering import cluster_classes_semantically  # GLOBAL clustering
from src.summarizing.enhanced_summarizer import EnhancedLlamaSummarizer  # LLM-based summarizer
from src.summarizing.file_context_summarizer import FileContextSummarizer  # Fallback rule-based
from src.generate_results import generate_final_results
from src.evaluation.llm_evaluator import evaluate_all_vulnerabilities  # LLM evaluation

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)-8s] --- %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Create timestamped output directory for each run
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = os.path.join(os.getcwd(), f"out_{timestamp}")
os.makedirs(OUTPUT_DIR, exist_ok=True)
logger.info(f"Output directory: {OUTPUT_DIR}")



# ============================
# 1. Scan with MobSF
# ============================
import os
import subprocess
import json
import logging

def scan_with_mobsf(source_folder: str) -> dict:
    logger.info(f"Running MobSF scan on: {source_folder}")

    # 1. Setup permanent output directory
    mobsf_raw_output = os.path.join(OUTPUT_DIR, "mobsf_raw_scan.json")

    # 2. Execute MobSF scanner
    cmd = ["mobsfscan", "--json", "-o", mobsf_raw_output, source_folder]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # MobSF often returns non-zero codes when vulnerabilities are found
    if result.returncode != 0:
        logger.warning(f"MobSF returned non-zero exit code {result.returncode}")
        logger.warning("This is NORMAL when vulnerabilities are found - continuing...")

    # Verify the scan produced an output file
    if not os.path.exists(mobsf_raw_output):
        logger.error("MobSF scan produced no output file")
        return {"results": {}, "errors": []}

    logger.info(f"✓ Raw MobSF results saved to: {mobsf_raw_output}")

    # 3. Load results for filtering
    with open(mobsf_raw_output, "r") as f:
        results = json.load(f)

    # 4. Filter for Java files only
    filtered = {"results": {}, "errors": []}
    for vuln_name, vuln_data in results.get("results", {}).items():
        # Skip non-Java files (like XML manifests or config files)
        java_files = [
            entry for entry in vuln_data.get("files", [])
            if entry.get("file_path", "").endswith(".java")
        ]
        
        if java_files:
            filtered["results"][vuln_name] = {
                "files": java_files,
                "metadata": vuln_data.get("metadata", {})
            }

    # 5. Detailed Logging and Statistics
    # Calculate total instances across all filtered Java vulnerabilities
    total_instances = sum(len(v["files"]) for v in filtered["results"].values())
    
    logger.info("=" * 60)
    logger.info(f"MobSF Scan Summary: {total_instances} Java instances found across {len(filtered['results'])} types.")
    logger.info("=" * 60)

    # Iterate through each type and log every specific occurrence
    for vuln_name, vuln_data in filtered["results"].items():
        severity = vuln_data.get("metadata", {}).get("severity", "INFO")
        logger.info(f"[{severity}] Type: {vuln_name}")
        
        for file_info in vuln_data["files"]:
            # Extract just the filename for cleaner logging
            filename = file_info.get("file_path", "").split("/")[-1]
            lines = file_info.get("match_lines", [])
            
            # Log the exact location of each vulnerability instance
            logger.info(f"  ↳ Found in {filename} at line {lines[0]}")
    
    logger.info("-" * 60)
    logger.info(f"MobSF scan complete. Results ready for processing.")
    
    return filtered

# ============================
# 2. Parse codebase
# ============================
def parse_codebase(source_dir: str) -> list:
    logger.info(f"Parsing Java files in: '{source_dir}'")
    parser = TreeSitterParser()
    parsed_files = []
    for file_path in Path(source_dir).rglob("*.java"):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            java_file = parser.parse_java_file(source_code, str(file_path))
            if java_file and java_file.classes:
                parsed_files.append(java_file)
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}", exc_info=True)
    logger.info(f"Parsed {len(parsed_files)} Java files successfully.")
    return parsed_files

# ============================
# 3. Cluster classes (NEW: Changed from methods to classes)
# ============================
def cluster_classes(parsed_files: list):
    logger.info("Starting semantic clustering of classes...")
    clusters, clusterer_obj = cluster_classes_semantically(parsed_files)
    logger.info(f"Generated {len(clusters)} class clusters.")
    return clusters, clusterer_obj

# ============================
# 4. Identify vulnerable methods
# ============================


def is_position_within_method(mobsf_position, mobsf_lines, method_pos):
    if not method_pos:
        return False
    if mobsf_lines[0] == mobsf_lines[1]:  # single-line vulnerability
        if method_pos.start_line < mobsf_lines[0] < method_pos.end_line:
            return True
        elif method_pos.start_line == mobsf_lines[0] or method_pos.end_line == mobsf_lines[0]:
            return (method_pos.start_column <= mobsf_position[0] and 
                    method_pos.end_column >= mobsf_position[1])
    else:  # multi-line vulnerability
        if method_pos.start_line <= mobsf_lines[0] and method_pos.end_line >= mobsf_lines[1]:
            return True
        elif method_pos.start_line == mobsf_lines[0]:
            return method_pos.start_column <= mobsf_position[0]
    return False

def identify_vulnerable_methods(scan_results, parsed_files):
    """Maps vulnerabilities to specific methods and classes"""
    vulnerable_methods = []

    def normalize_path(path):
        """Normalize path for better matching"""
        return path.replace("\\", "/").lower()

    def paths_match(mobsf_path, parsed_path):
        """Check if two paths refer to the same file"""
        mobsf_norm = normalize_path(mobsf_path)
        parsed_norm = normalize_path(parsed_path)

        # Get filename
        mobsf_filename = mobsf_norm.split("/")[-1]
        parsed_filename = parsed_norm.split("/")[-1]

        # Must have same filename
        if mobsf_filename != parsed_filename:
            return False

        # Check if one path contains the other's key components
        # Extract package-like path (after java/ or kotlin/)
        for anchor in ["/java/", "/kotlin/"]:
            if anchor in mobsf_norm and anchor in parsed_norm:
                mobsf_package = mobsf_norm.split(anchor)[-1]
                parsed_package = parsed_norm.split(anchor)[-1]
                return mobsf_package == parsed_package

        # Fallback: check last few path components match
        mobsf_parts = [p for p in mobsf_norm.split("/") if p][-5:]
        parsed_parts = [p for p in parsed_norm.split("/") if p][-5:]

        # Count matching tail components
        matches = sum(1 for m, p in zip(reversed(mobsf_parts), reversed(parsed_parts)) if m == p)
        return matches >= 3  # At least 3 components must match

    for result_key, vulnerability in scan_results.get("results", {}).items():
        for vuln_file in vulnerability.get("files", []):
            mobsf_path = vuln_file.get("file_path", "")

            for parsed_file in parsed_files:
                if paths_match(mobsf_path, parsed_file.path):
                    for java_class in parsed_file.classes:
                        for method in java_class.methods:
                            if is_position_within_method(
                                vuln_file.get("match_position", []),
                                vuln_file.get("match_lines", []),
                                method.position
                            ):
                                vulnerable_methods.append({
                                    "method": method,
                                    "class": java_class,
                                    "file": parsed_file,
                                    "vulnerability": result_key
                                })

    logger.info(f"Identified {len(vulnerable_methods)} vulnerable methods.")
    if len(vulnerable_methods) == 0:
        logger.warning("⚠️  No vulnerable methods found. Check path matching:")
        if scan_results.get("results"):
            sample_mobsf = list(scan_results["results"].values())[0]["files"][0]["file_path"]
            sample_parsed = parsed_files[0].path if parsed_files else "No parsed files"
            logger.warning(f"   MobSF path example: {sample_mobsf}")
            logger.warning(f"   Parsed path example: {sample_parsed}")

    return vulnerable_methods

# ============================
# 5. Generate summaries (LLM-BASED with per-file context)
# ============================
def generate_summaries_global(clusters, vulnerable_methods, parsed_files):
    logger.info("="*60)
    logger.info("Starting LLM-BASED summarization with global clustering...")
    logger.info("="*60)
    logger.info("⚠️  Loading CodeLlama model - this may take several minutes on first run...")
    llm_summarizer = EnhancedLlamaSummarizer()
    logger.info("✓ CodeLlama model loaded successfully!")

    summaries = {"clusters": {}, "classes": {}, "methods": {}}

    # Generate global cluster summaries using LLM
    for cluster_idx, cluster in enumerate(clusters, 1):
        cluster_id = f"cluster_{cluster_idx}"
        summaries["clusters"][cluster_id] = llm_summarizer.summarize_cluster(cluster)
        logger.info(f"Generated LLM summary for {cluster_id} ({len(cluster)} classes)")

    # Create class-to-cluster mapping for global clusters
    class_to_cluster = {}
    for cluster_idx, cluster in enumerate(clusters, 1):
        cluster_id = f"cluster_{cluster_idx}"
        for java_class in cluster:
            class_to_cluster[java_class.name] = cluster_id

    # Generate method and class summaries for vulnerable methods
    for vuln_info in vulnerable_methods:
        method = vuln_info["method"]
        java_class = vuln_info["class"]
        method_key = f"{java_class.name}.{method.name}"

        # LLM-based method summary
        if method_key not in summaries["methods"]:
            summaries["methods"][method_key] = llm_summarizer.summarize_code(method.code)
            logger.info(f"Generated LLM summary for method '{method_key}'")

        # LLM-based class summary
        class_key = java_class.name
        if class_key not in summaries["classes"]:
            summaries["classes"][class_key] = llm_summarizer.summarize_class_with_context(java_class)
            logger.info(f"Generated LLM summary for class '{class_key}'")

    logger.info("All LLM-based summaries generated with per-file clustering context.")
    return summaries

# ============================
# 6. Save outputs
# ============================
def save_outputs(scan_results, parsed_files, clusters, summaries):
    # 1. Scan results
    with open(os.path.join(OUTPUT_DIR, "mobsf_scan.json"), "w") as f:
        json.dump(scan_results, f, indent=2)
    logger.info("Saved scan results.")
    
    # 2. FULL Parsed files with all details
    def serialize_position(pos):
        return {
            "start_line": pos.start_line,
            "end_line": pos.end_line,
            "start_column": pos.start_column,
            "end_column": pos.end_column
        } if pos else None
    
    def serialize_method(method):
        return {
            "name": method.name,
            "return_type": method.return_type,
            "position": serialize_position(method.position),
            "code": method.code,
            "summary": method.summary,
            "cluster_summary": getattr(method, "cluster_summary", ""),
            "parent": None,  # avoid circular reference
            "parent_cluster": None,
            "is_false_positive": method.is_false_positive,
            "is_vulnerable": method.is_vulnerable,
            "vulnerability_metadata": method.vulnerability_meta,
            "vulnerability": method.vulnerability,
            "matched_string": method.matched_string,
            "parameters": [{"name": p.name, "type": p.type} for p in method.parameters]
        }
    
    def serialize_class(cls):
        return {
            "parent_file": None,  # avoid circular reference
            "name": cls.name,
            "position": serialize_position(cls.position),
            "code": cls.code,
            "summary": cls.summary,
            "methods": [serialize_method(m) for m in cls.methods]
        }
    
    def serialize_file(jfile):
        return {
            "path": jfile.path,
            "code": jfile.code,
            "classes": [serialize_class(c) for c in jfile.classes]
        }
    
    parsed_full = [serialize_file(pf) for pf in parsed_files]
    with open(os.path.join(OUTPUT_DIR, "parsed_files.json"), "w") as f:
        json.dump(parsed_full, f, indent=2)
    logger.info("Saved full parsed files.")
    
    # 3. GLOBAL Clusters - all classes clustered together
    clusters_data = []
    for cluster_idx, cluster in enumerate(clusters, 1):
        clusters_data.append({
            "cluster_id": cluster_idx,
            "size": len(cluster),
            "classes": [
                {"name": cls.name,
                 "num_methods": len(cls.methods)}
                for cls in cluster
            ]
        })

    with open(os.path.join(OUTPUT_DIR, "clusters.json"), "w") as f:
        json.dump(clusters_data, f, indent=2)
    logger.info("Saved global class clusters.")
    
    # 4. Summaries
    with open(os.path.join(OUTPUT_DIR, "summaries.json"), "w") as f:
        json.dump(summaries, f, indent=2)
    logger.info("Saved summaries.")

# ============================
# Main entry point
# ============================
def main():
    parser = argparse.ArgumentParser(description="Vulnerability analysis pipeline")
    parser.add_argument("--dir", type=str, required=True,
                        help="Android app source directory")
    parser.add_argument("--scan", action="store_true",
                        help="Run fresh MobSF scan (default: load existing)")
    parser.add_argument("--scan-only", action="store_true",
                        help="Only run MobSF scan and exit immediately")
    parser.add_argument("--mobsf-output", type=str,
                        help="Path to existing MobSF scan JSON (if not scanning)")
    parser.add_argument("--no-summarize", action="store_true",
                        help="Skip summarization")
    parser.add_argument("--evaluate", action="store_true",
                        help="Run LLM evaluation to predict true/false positives and assess summary quality")
    parser.add_argument("--output-name", type=str,
                        help="Custom output directory name (default: timestamped)")
    args = parser.parse_args()

    # Override output directory if custom name specified
    global OUTPUT_DIR
    if args.output_name:
        OUTPUT_DIR = os.path.join(os.getcwd(), f"out_{args.output_name}")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        logger.info(f"Output directory: {OUTPUT_DIR}")


    if args.scan or args.scan_only:
        scan_results = scan_with_mobsf(args.dir)

        # Save scan results
        with open(os.path.join(OUTPUT_DIR, "mobsf_scan.json"), "w") as f:
            json.dump(scan_results, f, indent=2)

        # If scan-only mode, exit now
        if args.scan_only:
            logger.info("="*60)
            logger.info("SCAN-ONLY mode: MobSF scan completed!")
            logger.info("="*60)
            logger.info(f"Scan results saved to: {OUTPUT_DIR}")
            logger.info("Exiting without parsing, clustering, or summarization.")
            return

    elif args.mobsf_output:
        logger.info(f"Loading existing MobSF scan from: {args.mobsf_output}")
        with open(args.mobsf_output, "r") as f:
            scan_results = json.load(f)
    else:
        # Update the error message to be accurate
        logger.error("Either --scan, --scan-only, or --mobsf-output must be provided")
        return

    parsed_files = parse_codebase(args.dir)
    if not parsed_files:
        logger.warning("No Java files found. Exiting.")
        return

    # GLOBAL clustering: Cluster all classes together across all files
    logger.info("="*60)
    logger.info("Starting GLOBAL semantic clustering...")
    logger.info("="*60)
    clusters, clusterer = cluster_classes_semantically(parsed_files)
    logger.info(f"Global clustering completed. Generated {len(clusters)} clusters across all files.")

    logger.info("="*60)
    logger.info("Identifying vulnerable methods from scan results...")
    logger.info("="*60)
    vulnerable_methods = identify_vulnerable_methods(scan_results, parsed_files)

    summaries = {"clusters": {}, "classes": {}, "methods": {}}
    if not args.no_summarize:
        summaries = generate_summaries_global(clusters, vulnerable_methods, parsed_files)


    save_outputs(scan_results, parsed_files, clusters, summaries)

    # Generate final results.json (same as results_final.ipynb)
    logger.info("Generating final results.json...")
    final_results = generate_final_results(OUTPUT_DIR)

    # Optional: LLM-based evaluation
    if args.evaluate:
        logger.info("")
        logger.info("="*60)
        logger.info("Running LLM-based vulnerability evaluation...")
        logger.info("="*60)
        evaluation_results = evaluate_all_vulnerabilities(OUTPUT_DIR)

    logger.info("")
    logger.info("="*60)
    logger.info("Pipeline completed successfully!")
    logger.info("="*60)
    logger.info(f"All outputs saved to: {OUTPUT_DIR}")
    logger.info("Output files:")
    logger.info(f"  - mobsf_raw_scan.json           (raw MobSF output)")
    logger.info(f"  - mobsf_scan.json               (filtered Java vulnerabilities)")
    logger.info(f"  - parsed_files.json             (parsed Java classes/methods)")
    logger.info(f"  - clusters.json                 (GLOBAL semantic clusters)")
    logger.info(f"  - summaries.json                (CodeLlama-generated summaries)")
    logger.info(f"  - results.json                  (final vulnerability mappings)")
    if args.evaluate:
        logger.info(f"  - evaluation.json               (CodeLlama true/false positive predictions + feedback)")
        logger.info(f"  - summary_quality_metrics.json  (objective summary quality scores)")
    logger.info("="*60)
    logger.info("Note: This version uses GLOBAL clustering to capture cross-file semantic relationships")
    logger.info("Note: Using CodeLlama-7b-Instruct for consistent code analysis across pipeline")
    if args.evaluate:
        logger.info("Note: Evaluation provides AI predictions - verify with manual security review")

if __name__ == "__main__":
    main()
