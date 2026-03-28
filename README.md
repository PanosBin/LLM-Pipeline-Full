# LLM-Pipeline-FILE

**Per-File Clustering Version**

This is a specialized fork of the LLM-Pipeline project that uses **per-file clustering** instead of global clustering.

## Key Differences from Original LLM-Pipeline

### Original Approach (Global Clustering)
- Clusters ALL classes from ALL files together
- Generates general summaries
- May group unrelated classes from different files

### This Approach (Per-File Clustering)
- Clusters classes WITHIN EACH FILE separately
- Generates **specific, context-aware summaries** showing:
  - How methods are used within their file
  - Which methods call each other in the same file
  - Relationships between classes in the same file
- More precise understanding of code organization

## Usage

```bash
# Run with per-file clustering
poetry run python main_file.py --dir /path/to/android/app --scan

# Run with LLM evaluation (predict true/false positives)
poetry run python main_file.py --dir /path/to/android/app --scan --evaluate

# Custom output name
poetry run python main_file.py --dir /path/to/app --scan --output-name MyApp_PerFile

# Scan only (no analysis or summaries)
poetry run python main_file.py --dir /path/to/app --scan-only

# Skip summarization (for testing)
poetry run python main_file.py --dir /path/to/app --scan --no-summarize
```

### LLM Evaluation Feature (NEW)

The `--evaluate` flag enables **automated vulnerability assessment** using LLaMA:

- **Predicts TRUE_POSITIVE or FALSE_POSITIVE** for each vulnerability
- **Evaluates summary quality** and suggests improvements
- **Provides confidence scores** and reasoning for each prediction

See [EVALUATION_GUIDE.md](EVALUATION_GUIDE.md) for detailed documentation.

## Output Files

- `mobsf_scan.json` - MobSF vulnerability scan results (filtered for Java)
- `parsed_files.json` - Parsed Java classes and methods with AST information
- `file_clusters.json` - Clusters organized by file (per-file semantic grouping)
- `summaries.json` - Context-aware summaries showing intra-file relationships
- `results.json` - Vulnerability mappings with file-specific context
- `evaluation.json` - LLM predictions and summary quality feedback (if `--evaluate` used)

## Installation

Same as original LLM-Pipeline:

```bash
./setup.sh
# OR
poetry install
```
