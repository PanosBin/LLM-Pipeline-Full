"""
Generate final results.json from pipeline outputs
This script replicates the logic from results_final.ipynb (cell 3)
"""
import json
import os
import logging

logger = logging.getLogger(__name__)


def normalize_path(path):
    """Normalize path for comparison"""
    return path.replace("\\", "/").lower()


def generate_final_results(output_dir: str) -> dict:
    """
    Generate final results.json with vulnerabilities mapped to methods
    including method, class, and cluster summaries.

    Args:
        output_dir: Directory containing pipeline outputs

    Returns:
        Dictionary with results
    """
    # File paths
    SUMMARIES_PATH = os.path.join(output_dir, "summaries.json")
    CLUSTERS_PATH = os.path.join(output_dir, "clusters.json")
    MOBSF_SCAN_PATH = os.path.join(output_dir, "mobsf_scan.json")
    PARSED_FILES_PATH = os.path.join(output_dir, "parsed_files.json")
    RESULTS_PATH = os.path.join(output_dir, "results.json")

    # Load data
    logger.info("Loading pipeline outputs...")
    with open(SUMMARIES_PATH, "r", encoding='utf-8') as f:
        summaries = json.load(f)

    # Load global clusters (or per-file if exists for backward compatibility)
    FILE_CLUSTERS_PATH = os.path.join(output_dir, "file_clusters.json")
    if os.path.exists(FILE_CLUSTERS_PATH):
        logger.info("Loading per-file clusters (legacy format)...")
        with open(FILE_CLUSTERS_PATH, "r", encoding='utf-8') as f:
            file_clusters_data = json.load(f)
        # Convert per-file format to flat list for compatibility
        clusters_data = []
        for file_path, file_cluster_list in file_clusters_data.items():
            clusters_data.extend(file_cluster_list)
    elif os.path.exists(CLUSTERS_PATH):
        logger.info("Loading global clusters...")
        with open(CLUSTERS_PATH, "r", encoding='utf-8') as f:
            clusters_data = json.load(f)
    else:
        logger.warning("No clusters file found!")
        clusters_data = []
    with open(MOBSF_SCAN_PATH, "r", encoding='utf-8') as f:
        mobsf_scan = json.load(f)
    with open(PARSED_FILES_PATH, "r", encoding='utf-8') as f:
        parsed_files = json.load(f)

    logger.info("✅ Files loaded!")

    # Create class -> cluster mapping (NEW: clusters now contain classes, not methods)
    logger.info("Creating class to cluster mapping...")
    class_to_cluster = {}
    for cluster_idx, cluster_info in enumerate(clusters_data):
        cluster_id = f"cluster_{cluster_idx + 1}"
        # NEW: clusters.json now has "classes" instead of "methods"
        for class_ref in cluster_info.get("classes", cluster_info.get("methods", [])):
            # Handle both new format (classes) and old format (methods) for backward compatibility
            if "name" in class_ref and "class" not in class_ref:
                # New format: class name directly
                class_name = class_ref["name"]
                class_to_cluster[class_name] = cluster_id
            elif "class" in class_ref:
                # Old format: method with parent class
                class_name = class_ref["class"]
                class_to_cluster[class_name] = cluster_id

    logger.info(f"✅ Mapped {len(class_to_cluster)} classes to clusters")

    # Build results from MobSF vulnerabilities
    logger.info("Building results from MobSF vulnerabilities...")
    results = []
    vulnerabilities_found = {}

    for vuln_name, vuln_detail in mobsf_scan.get("results", {}).items():
        vulnerabilities_found[vuln_name] = 0

        # Each file entry in MobSF is ONE vulnerability instance
        for filevul in vuln_detail.get("files", []):
            vuln_file_path = filevul.get("file_path", "")

            # Get EXACT line number from MobSF
            match_lines = filevul.get("match_lines", [0, 0])
            vuln_line = match_lines[0] if match_lines else 0

            # Get match string
            match_string = filevul.get("match_string", "")

            # Normalize paths for matching
            vuln_path_norm = normalize_path(vuln_file_path)

            # Find matching file in parsed_files
            method_found = False
            for parsed_file in parsed_files:
                pf_path = parsed_file.get("path", "")
                pf_path_norm = normalize_path(pf_path)

                # Check if paths match
                if pf_path_norm.endswith(vuln_path_norm.split("/")[-1]) or vuln_path_norm in pf_path_norm:
                    # Find which method contains this line
                    for cls in parsed_file.get("classes", []):
                        class_name = cls.get("name", "")

                        for meth in cls.get("methods", []):
                            method_name = meth.get("name", "")
                            method_key = f"{class_name}.{method_name}"

                            # Get method line range
                            method_start = meth.get("position", {}).get("start_line", 0)
                            method_end = meth.get("position", {}).get("end_line", 0)

                            # Check if vulnerability line is inside this method
                            if method_start <= vuln_line <= method_end:
                                # NEW: Get cluster ID from parent class (not method)
                                cluster_id = class_to_cluster.get(class_name, None)

                                # Build result entry
                                result_entry = {
                                    "file": pf_path,
                                    "line": vuln_line,  # EXACT line from MobSF
                                    "method": method_key,
                                    "vulnerability": vuln_name,
                                    "match": match_string.strip(),
                                    "summaries": {
                                        "method": summaries.get("methods", {}).get(method_key, ""),
                                        "class": summaries.get("classes", {}).get(class_name, ""),
                                        "cluster": summaries.get("clusters", {}).get(cluster_id, "") if cluster_id else ""
                                    }
                                }

                                results.append(result_entry)
                                vulnerabilities_found[vuln_name] += 1
                                method_found = True
                                break  # Found the method, stop searching

                        if method_found:
                            break

                    if method_found:
                        break

    logger.info(f"✅ Found {len(results)} vulnerability instances")
    logger.info("📊 Vulnerabilities breakdown:")
    for vuln_name, count in sorted(vulnerabilities_found.items()):
        if count > 0:
            logger.info(f"   {vuln_name}: {count} instances")

    # Remove exact duplicates (same file, line, vulnerability)
    logger.info("Removing exact duplicates...")
    unique_results = []
    seen = set()
    for r in results:
        key = (r["file"], r["line"], r["vulnerability"])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    logger.info(f"✅ {len(unique_results)} unique vulnerability instances")

    # Sort by file and line
    unique_results.sort(key=lambda x: (x["file"], x["line"]))

    # Save results
    output_data = {"results": unique_results}
    with open(RESULTS_PATH, "w", encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    logger.info(f"✅ Results written to {RESULTS_PATH}")
    logger.info("📈 Final statistics:")
    logger.info(f"   Total vulnerability instances: {len(unique_results)}")
    logger.info(f"   Unique methods affected: {len(set(r['method'] for r in unique_results))}")
    logger.info(f"   Unique files affected: {len(set(r['file'] for r in unique_results))}")
    logger.info(f"   Unique vulnerability types: {len(set(r['vulnerability'] for r in unique_results))}")
    logger.info(f"   Entries with all summaries: {len([r for r in unique_results if r['summaries']['method'] and r['summaries']['class'] and r['summaries']['cluster']])}")

    # Show sample results
    if unique_results:
        logger.info("📄 Sample results:")
        for i, r in enumerate(unique_results[:3]):
            logger.info(f"\n{i+1}. {r['vulnerability']} at line {r['line']}")
            logger.info(f"   Method: {r['method']}")
            match_preview = r['match'][:60] + "..." if len(r['match']) > 60 else r['match']
            logger.info(f"   Match: {match_preview}")

    return output_data
