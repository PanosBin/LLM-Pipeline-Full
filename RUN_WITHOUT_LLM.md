# How to Run Without LLM Model

## Option 1: Skip Summarization (Recommended)

Use the `--no-summarize` flag to skip ALL LLM processing:

```bash
poetry run python main_file.py --dir ./data/apps/Damn-Vulnerable-Bank --scan --no-summarize
```

**What this skips:**
- ❌ LLM model loading
- ❌ Summary generation
- ❌ HuggingFace downloads

**What still runs:**
- ✅ MobSF scanning (finds vulnerabilities)
- ✅ Java parsing (Tree-sitter)
- ✅ Per-file clustering (CodeBERT embeddings)
- ✅ Vulnerability mapping to methods
- ✅ Final results.json generation

**Output files:**
- `mobsf_raw_scan.json` ✅
- `mobsf_scan.json` ✅
- `parsed_files.json` ✅
- `file_clusters.json` ✅
- `summaries.json` ⚠️ (empty: `{"clusters": {}, "classes": {}, "methods": {}}`)
- `results.json` ✅

---

## Option 2: Offline Mode (Use Cached Models)

If you've already downloaded CodeBERT once, set offline mode:

```bash
export HF_HUB_OFFLINE=1
poetry run python main_file.py --dir ./data/apps/Damn-Vulnerable-Bank --scan --no-summarize
```

This prevents HuggingFace from trying to download anything.

---

## Option 3: Run ONLY MobSF Scan

If you only want vulnerability scanning without any analysis:

```bash
# Just scan and save raw results
mobsfscan --type android --json -o my_scan.json ./data/apps/Damn-Vulnerable-Bank

# Check results
cat my_scan.json | jq '.results | keys'
```

---

## Full Example: Complete Pipeline Without LLM

```bash
cd LLM-Pipeline-FILE

# Set offline mode (optional - prevents HuggingFace downloads)
export HF_HUB_OFFLINE=1
export TOKENIZERS_PARALLELISM=false

# Run pipeline WITHOUT summarization
poetry run python main_file.py \
  --dir ./data/apps/Damn-Vulnerable-Bank \
  --scan \
  --no-summarize \
  --output-name DVB_NoLLM

# Results saved to: out_DVB_NoLLM/
```

**Estimated time:**
- With summarization: 10-30 minutes (first run downloads ~13GB LLM)
- Without summarization: 1-2 minutes ⚡

---

## What CodeBERT Is Used For

**CodeBERT** (microsoft/codebert-base, ~500MB) is used ONLY for clustering, not summarization.

It's downloaded automatically on first run and cached at:
```
~/.cache/huggingface/hub/models--microsoft--codebert-base/
```

If you can't download it:
1. Download manually from: https://huggingface.co/microsoft/codebert-base
2. Place in the cache directory
3. Run with `HF_HUB_OFFLINE=1`

---

## Why Use --no-summarize?

**Pros:**
- ⚡ Much faster (1-2 minutes vs 30 minutes)
- 💾 No 13GB LLaMA download
- 🔒 Works offline
- ✅ Still get vulnerability detection and clustering

**Cons:**
- ❌ No human-readable summaries
- ❌ Have to read raw code to understand vulnerabilities

**When to use:**
- Testing the pipeline
- Don't have GPU/lots of RAM
- Don't have internet access
- Just want vulnerability locations (not descriptions)
