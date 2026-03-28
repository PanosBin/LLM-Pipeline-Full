# check_reference.py
import json

ref_path = "/Users/panagiotisbinikos/Desktop/CB_Thesis/code/LLM-main/out1/mobsf_scan.json"

with open(ref_path, "r") as f:
    ref_data = json.load(f)

print("="*60)
print("REFERENCE SCAN ANALYSIS")
print("="*60)

java_vulns = 0
xml_vulns = 0

for vuln_name, vuln_data in ref_data.get("results", {}).items():
    files = vuln_data.get("files", [])
    
    java_files = [f for f in files if ".java" in f.get("file_path", "")]
    xml_files = [f for f in files if ".xml" in f.get("file_path", "")]
    
    if java_files:
        java_vulns += len(java_files)
        print(f"\n✅ {vuln_name}: {len(java_files)} Java files")
        print(f"   Example: {java_files[0]['file_path']}")
    
    if xml_files:
        xml_vulns += len(xml_files)

print(f"\n{'='*60}")
print(f"TOTALS:")
print(f"  Java vulnerabilities: {java_vulns}")
print(f"  XML vulnerabilities: {xml_vulns}")
print(f"{'='*60}")

# Check if reference has Java vulnerabilities
if java_vulns > 0:
    print("\n✅ Reference DOES have Java source code vulnerabilities")
    print("   Your scan is missing these - MobSF config issue")
else:
    print("\n⚠️  Reference ALSO has only XML vulnerabilities")
    print("   This might be expected behavior")
