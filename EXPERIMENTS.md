# Running Experiments

## Quick Start

### 1. Quick Test (Fast - ~2 minutes)
```bash
python run_experiment.py --quick
```

Tests:
- Scan-only mode
- Pipeline without summarization

### 2. Full Test (Slow - ~30-60 minutes)
```bash
python run_experiment.py --full
```

Tests:
- Scan-only
- No summarization
- With summaries
- With evaluation

### 3. Default Test (Medium - ~15 minutes)
```bash
python run_experiment.py
```

Tests:
- Scan-only
- Full pipeline with summaries

### 4. Test Specific App
```bash
python run_experiment.py --app ./path/to/your/app
```

## What Gets Tested

| Test | MobSF | Parse | Cluster | Summary | Evaluate | Time |
|------|-------|-------|---------|---------|----------|------|
| scan-only | ✓ | - | - | - | - | 30s |
| no-summarize | ✓ | ✓ | ✓ | - | - | 2min |
| with-summaries | ✓ | ✓ | ✓ | ✓ | - | 10min |
| with-evaluation | ✓ | ✓ | ✓ | ✓ | ✓ | 15min |

## Output

Results saved to:
```
experiments/
  experiment_results_TIMESTAMP.json
```

Example output:
```json
{
  "summary": {
    "total_experiments": 4,
    "successful": 4,
    "failed": 0,
    "total_time": 1234.5
  },
  "experiments": [
    {
      "experiment_name": "Damn-Vulnerable-Bank_scan_only",
      "success": true,
      "elapsed_time": 25.3,
      "outputs": {
        "mobsf_scan.json": {
          "exists": true,
          "vulnerability_types": 3,
          "size_kb": 7.2
        }
      }
    }
  ]
}
```

## Validation Checks

For each experiment, validates:
- ✓ All expected output files created
- ✓ File sizes reasonable
- ✓ JSON files parse correctly
- ✓ Counts (vulnerabilities, clusters, etc.)

## Add More Apps

Edit `run_experiment.py`:
```python
test_apps = [
    "./data/apps/Damn-Vulnerable-Bank",
    "./data/apps/YourApp",  # Add here
]
```

## Stress Test

Test on multiple apps at once:
```bash
python run_experiment.py --full
```

This will run all configurations on all apps sequentially.

## Tips

1. **Run on server with GPU** for faster LLM processing
2. **Use `--quick` first** to verify setup
3. **Monitor logs** for errors
4. **Check experiments/ folder** for results

## Troubleshooting

**Timeout errors:**
- Increase timeout in run_experiment.py (default: 1 hour)
- Use smaller app or `--quick` mode

**Out of memory:**
- Run experiments one at a time
- Use `--no-summarize` flag
- Close other applications

**Failed experiments:**
- Check `experiments/experiment_results_*.json` for error details
- Review pipeline logs in output directories
