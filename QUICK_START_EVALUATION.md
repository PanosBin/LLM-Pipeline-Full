# Quick Start: Testing LLM Evaluation

## What Was Implemented

The LLM evaluation feature has been added to the pipeline. It:

1. **Predicts TRUE_POSITIVE or FALSE_POSITIVE** for each vulnerability found by MobSF
2. **Assesses summary quality** and provides feedback on improvements
3. **Outputs detailed results** in `evaluation.json`

## Files Added/Modified

### New Files
- `src/evaluation/llm_evaluator.py` - Core evaluation logic
- `EVALUATION_GUIDE.md` - Detailed documentation
- `QUICK_START_EVALUATION.md` - This file

### Modified Files
- `main_file.py` - Added `--evaluate` flag and integration
- `README.md` - Updated with evaluation feature

## How to Test

### Prerequisites

1. **GPU recommended** (LLaMA-2-7b is ~13GB)
   - Minimum 16GB GPU memory
   - Will run on CPU but much slower

2. **HuggingFace access**
   - LLaMA-2 may require authentication
   - Set up token if needed: `huggingface-cli login`

3. **Dependencies installed**
   ```bash
   poetry install
   ```

### Test on Damn-Vulnerable-Bank

```bash
cd /Users/panagiotisbinikos/Desktop/CB_Thesis/code/LLM-Pipeline-FILE

# Run full pipeline with evaluation
poetry run python main_file.py \
  --dir ./data/apps/Damn-Vulnerable-Bank \
  --scan \
  --evaluate \
  --output-name DVB_Test_Eval

# Results will be in: out_DVB_Test_Eval/evaluation.json
```

### Quick View of Results

```bash
# Summary statistics
cat out_DVB_Test_Eval/evaluation.json | jq '.summary'

# See first vulnerability evaluation
cat out_DVB_Test_Eval/evaluation.json | jq '.evaluations[0]'

# Count TRUE_POSITIVE predictions
cat out_DVB_Test_Eval/evaluation.json | jq '.evaluations[] | select(.evaluation.prediction == "TRUE_POSITIVE") | .vulnerability' | wc -l

# High confidence TRUE_POSITIVES
cat out_DVB_Test_Eval/evaluation.json | jq '.evaluations[] | select(.evaluation.prediction == "TRUE_POSITIVE" and .evaluation.confidence > 0.8)'
```

## Expected Output

For Damn-Vulnerable-Bank (16 Java vulnerabilities expected):

```json
{
  "summary": {
    "total_vulnerabilities": 16,
    "predicted_true_positives": 10-14,  // Typical range
    "predicted_false_positives": 2-6,   // Typical range
    "summaries_helpful_count": 12-15,
    "summaries_helpful_percentage": 75-95
  },
  "evaluations": [
    {
      "vulnerability": "android_logging",
      "file": ".../BankLogin.java",
      "line": 45,
      "method": "BankLogin.bankLogin",
      "evaluation": {
        "prediction": "TRUE_POSITIVE",
        "confidence": 0.85,
        "reasoning": "...",
        "summary_feedback": {
          "helpful": true,
          "missing_info": "...",
          "suggestions": "..."
        }
      }
    }
    // ... 15 more
  ]
}
```

## Timing Expectations

- **MobSF Scan**: ~10-20 seconds
- **Parsing & Clustering**: ~30 seconds
- **LLM Summarization**: ~5-10 minutes (CodeLlama for 50+ methods)
- **LLM Evaluation**: ~2-3 minutes (LLaMA-2 for 16 vulnerabilities)

**Total: ~8-15 minutes** for full pipeline with evaluation

## Troubleshooting

### Issue: "Model not found" or "Access denied"

**LLaMA-2 is a gated model**. You need:

1. Accept terms at: https://huggingface.co/meta-llama/Llama-2-7b-chat-hf
2. Authenticate: `huggingface-cli login`
3. Use your token when prompted

Alternative: Modify `src/evaluation/llm_evaluator.py` line 24 to use a non-gated model:
```python
def __init__(self, model_name="mistralai/Mistral-7B-Instruct-v0.2"):
```

### Issue: CUDA out of memory

Reduce memory usage:
```python
# In src/evaluation/llm_evaluator.py, change load_in_8bit to load_in_4bit
self.model = AutoModelForCausalLM.from_pretrained(
    model_name,
    load_in_4bit=True,  # Changed from load_in_8bit
    device_map="auto",
    torch_dtype=torch.bfloat16
)
```

### Issue: Very slow on CPU

This is expected. Options:
1. Skip evaluation: Don't use `--evaluate` flag
2. Use smaller model (but less accurate)
3. Run on machine with GPU

### Issue: "results.json not found"

Make sure you're NOT using `--scan-only` or `--no-summarize` flags when testing evaluation.

The evaluation requires:
- ✅ `mobsf_scan.json`
- ✅ `summaries.json`
- ✅ `results.json`

## What to Look For

When reviewing evaluation results:

1. **Prediction Distribution**
   - Not all TRUE_POSITIVE or all FALSE_POSITIVE (that would be suspicious)
   - Confidence scores vary (shows LLM is actually reasoning)

2. **Summary Feedback**
   - Check what information is consistently missing
   - Use this to improve summarization prompts in future iterations

3. **Reasoning Quality**
   - Read a few reasoning explanations
   - Ensure they reference actual code patterns, not generic security advice

## Next Steps After Testing

1. **Validate a Sample**
   - Manually review 2-3 TRUE_POSITIVE predictions
   - Manually review 2-3 FALSE_POSITIVE predictions
   - Check if LLM assessments align with your security expertise

2. **Improve Summaries**
   - Use `summary_feedback.suggestions` to enhance prompts
   - Re-run pipeline and compare results

3. **Production Use**
   - Run on your actual Android apps
   - Use predictions to prioritize manual review
   - Track false positive rate over time

## Git Status

All changes committed:
- ✅ LLM evaluator implementation
- ✅ Integration into main_file.py
- ✅ Documentation (README, EVALUATION_GUIDE, this file)

Ready to push to repository if needed.

## Questions?

See [EVALUATION_GUIDE.md](EVALUATION_GUIDE.md) for comprehensive documentation.
