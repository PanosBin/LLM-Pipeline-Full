# test_mobsf_scan.py
import json
import os
import subprocess

APP_ROOT = "/Users/panagiotisbinikos/Desktop/CB_Thesis/code/CB_N/data/apps/Damn-Vulnerable-Bank"
OUTPUT_JSON = "/Users/panagiotisbinikos/Desktop/CB_Thesis/code/CB_N/out/mobsf_test_scan.json"

def main():
    print("=" * 50)
    print("MobSF Full App Scan (Java Only)")
    print("=" * 50)
    print(f"Scanning app root: {APP_ROOT}")
    
    cmd = ["mobsfscan", "--json", "-o", OUTPUT_JSON, APP_ROOT]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
    
    # Load results
    with open(OUTPUT_JSON, "r") as f:
        results = json.load(f)
    
    # Filter: Keep only .java files
    filtered_results = {"results": {}, "errors": []}
    java_file_count = 0
    
    for vuln_name, vuln_data in results.get("results", {}).items():
        java_files = [
            f for f in vuln_data.get("files", [])
            if f.get("file_path", "").endswith(".java")
        ]
        
        if java_files:
            filtered_results["results"][vuln_name] = {
                "files": java_files,
                "metadata": vuln_data.get("metadata", {})
            }
            java_file_count += len(java_files)
    
    # Save filtered results
    with open(OUTPUT_JSON, "w") as f:
        json.dump(filtered_results, f, indent=2)
    
    print("\n✓ Scan complete!")
    print(f"Found {len(filtered_results['results'])} vulnerability types")
    
    for vuln_name, vuln_data in filtered_results["results"].items():
        print(f"  - {vuln_name}: {len(vuln_data['files'])} file(s)")
    
    print(f"\nTotal Java vulnerabilities: {java_file_count}")
    print(f"Results saved to: {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
