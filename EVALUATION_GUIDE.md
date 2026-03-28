# LLM Evaluation Feature Guide

## Overview

The LLM evaluation feature uses **CodeLlama-7b-Instruct** to automatically assess each vulnerability found by MobSF and provide feedback on summary quality.

**Why CodeLlama?** It's specialized for code understanding, making it more accurate than general-purpose LLMs for analyzing Java vulnerabilities.

## What It Does

For each vulnerability instance, the evaluator provides:

### 1. LLM-Based Assessment (Subjective)

**Predicts TRUE_POSITIVE or FALSE_POSITIVE**
   - Analyzes the vulnerability type, code, and context
   - Provides confidence score (0.0-1.0)
   - Explains the reasoning behind the prediction

**Evaluates Summary Quality (LLM Feedback)**
   - Determines if summaries (method/class/cluster) were helpful
   - Identifies missing information that would improve analysis
   - Suggests improvements for better vulnerability assessment

### 2. Objective Summary Quality Metrics (NEW)

Automatically measures summary quality using metrics:

- **Length**: Word count, adequate length (10-50 words ideal)
- **Code Coverage**: Does summary mention vulnerable code patterns?
- **Context Relevance**: Does summary mention called methods/classes?
- **Specificity**: Avoids generic phrases like "handles data"

**Overall Score**: 0.0-1.0 combining all metrics (≥0.6 = high quality)

## How to Use

### Run Full Pipeline with Evaluation

```bash
poetry run python main_file.py \
  --dir ./data/apps/Damn-Vulnerable-Bank \
  --scan \
  --evaluate
```

### Run Evaluation on Existing Results

If you've already run the pipeline and have results:

```bash
# Assuming results are in out_20260109_125041/
poetry run python main_file.py \
  --dir ./data/apps/Damn-Vulnerable-Bank \
  --mobsf-output out_20260109_125041/mobsf_scan.json \
  --evaluate
```

### Skip Evaluation (Default Behavior)

```bash
# Without --evaluate flag, no evaluation is performed
poetry run python main_file.py \
  --dir ./data/apps/Damn-Vulnerable-Bank \
  --scan
```

## Output Format

The evaluation generates **two files**:

### 1. evaluation.json (LLM predictions and feedback)

```json
{
  "summary": {
    "total_vulnerabilities": 16,
    "predicted_true_positives": 12,
    "predicted_false_positives": 4,
    "summaries_helpful_count": 14,
    "summaries_helpful_percentage": 87.5
  },
  "evaluations": [
    {
      "vulnerability": "android_logging",
      "file": "/path/to/BankLogin.java",
      "line": 45,
      "method": "BankLogin.bankLogin",
      "evaluation": {
        "prediction": "TRUE_POSITIVE",
        "confidence": 0.85,
        "reasoning": "The code uses Log.d() to output potentially sensitive authentication data...",
        "summary_feedback": {
          "helpful": true,
          "missing_info": "Data flow information showing what gets logged",
          "suggestions": "Include information about what data flows into logging statements"
        }
      }
    }
    // ... more evaluations
  ]
}
```

### 2. summary_quality_metrics.json (Objective metrics)

```json
{
  "aggregate": {
    "total_summaries_evaluated": 16,
    "average_overall_score": 0.723,
    "high_quality_count": 12,
    "high_quality_percentage": 75.0,
    "average_code_coverage": 0.65,
    "average_specificity": 0.78
  },
  "individual_metrics": [
    {
      "vulnerability": "android_logging",
      "file": "/path/to/BankLogin.java",
      "line": 45,
      "method": "BankLogin.bankLogin",
      "summary_type": "method",
      "summary": "Method 'bankLogin' handles user authentication and logs credentials using Log.d()",
      "metrics": {
        "overall_score": 0.825,
        "length": {
          "word_count": 12,
          "char_count": 85,
          "is_adequate_length": true
        },
        "code_coverage": {
          "mentions_vulnerability_keyword": true,
          "mentions_code_pattern": true,
          "keyword_found": "log.d",
          "pattern_coverage": 0.4
        },
        "context_relevance": {
          "mentions_class_name": true,
          "mentions_method_calls": true,
          "method_call_coverage": 0.33,
          "mentions_related_classes": false
        },
        "specificity": {
          "is_specific": true,
          "generic_phrase_count": 0,
          "specificity_score": 0.75
        },
        "is_high_quality": true
      }
    }
    // ... more metrics
  ]
}
```

**Key Metrics Explained:**
- **overall_score**: Weighted average of all metrics (0.0-1.0)
- **code_coverage**: Does summary mention the vulnerability pattern? (higher = better)
- **specificity_score**: Avoids generic phrases, uses specific names (higher = better)
- **is_high_quality**: True if overall_score ≥ 0.6

## Understanding the Results

### Prediction Types

- **TRUE_POSITIVE**: LLM believes this is a real security vulnerability
- **FALSE_POSITIVE**: LLM believes this is a false alarm
- **UNKNOWN**: LLM couldn't determine (should be rare)

### Confidence Scores

- `0.9-1.0`: Very confident
- `0.7-0.9`: Confident
- `0.5-0.7`: Somewhat confident
- `0.0-0.5`: Low confidence (review manually)

### Summary Feedback

The evaluation assesses whether the generated summaries helped understand the vulnerability:

- **helpful: true** - Summaries provided useful context
- **helpful: false** - Summaries lacked critical information
- **missing_info** - What information would have helped
- **suggestions** - How to improve summary generation

## Performance Considerations

### Resource Requirements

- **Model Size**: CodeLlama-7b-Instruct (~13GB)
- **Memory**: ~16GB GPU memory recommended
- **Time**: ~5-10 seconds per vulnerability (LLM evaluation) + ~1 second (objective metrics)

For 16 vulnerabilities: approximately **2-3 minutes** total

### Running Without GPU

If you don't have GPU available, the evaluation will run on CPU but will be significantly slower (~30-60 seconds per vulnerability).

To skip evaluation on resource-constrained systems:
```bash
# Don't use --evaluate flag
poetry run python main_file.py --dir ./data/apps/Damn-Vulnerable-Bank --scan
```

## Command Line Options Summary

```bash
poetry run python main_file.py \
  --dir <source_directory>          # Required: Android app source
  [--scan]                          # Run fresh MobSF scan
  [--scan-only]                     # Only scan, skip analysis
  [--mobsf-output <path>]           # Use existing scan results
  [--no-summarize]                  # Skip LLM summary generation
  [--evaluate]                      # Enable LLM evaluation (NEW)
  [--output-name <name>]            # Custom output directory name
```

## Example Workflows

### Full Analysis with Evaluation
```bash
# Complete pipeline: scan → parse → cluster → summarize → evaluate
poetry run python main_file.py \
  --dir ./data/apps/Damn-Vulnerable-Bank \
  --scan \
  --evaluate \
  --output-name DVB_Full
```

### Fast Scan Without LLM
```bash
# Quick scan without summarization or evaluation
poetry run python main_file.py \
  --dir ./data/apps/Damn-Vulnerable-Bank \
  --scan \
  --no-summarize
```

### Evaluation Only on Existing Results
```bash
# Re-run evaluation on previous results
poetry run python main_file.py \
  --dir ./data/apps/Damn-Vulnerable-Bank \
  --mobsf-output out_DVB_Full/mobsf_scan.json \
  --evaluate
```

## Interpreting Evaluation Results

### High-Value Results to Review

1. **TRUE_POSITIVE with high confidence (>0.8)**
   - Likely real vulnerabilities
   - Prioritize for manual review and fixing

2. **FALSE_POSITIVE with high confidence (>0.8)**
   - Can likely be dismissed
   - Still worth quick manual verification

3. **Low confidence (<0.6)**
   - Requires manual security review
   - LLM was uncertain

### Using Summary Feedback

The `summary_feedback` section tells you how to improve the pipeline:

- **Patterns in missing_info**: What types of information are consistently missing
- **Common suggestions**: What improvements would help most
- **helpful=false rate**: Overall summary quality metric

### Example Use Case

```bash
# 1. Run full pipeline
poetry run python main_file.py --dir ./myapp --scan --evaluate

# 2. Check evaluation.json
cat out_*/evaluation.json | jq '.summary'

# 3. Review high-confidence TRUE_POSITIVEs
cat out_*/evaluation.json | jq '.evaluations[] | select(.evaluation.prediction == "TRUE_POSITIVE" and .evaluation.confidence > 0.8)'

# 4. Check summary feedback
cat out_*/evaluation.json | jq '.evaluations[].evaluation.summary_feedback | select(.helpful == false)'
```

## Troubleshooting

### "Model not found" error
- Ensure CodeLlama-7b-Instruct-hf is accessible via HuggingFace
- CodeLlama is an open model (no gating), should download automatically
- Alternative: Use different model by modifying `src/evaluation/llm_evaluator.py` and `src/summarizing/enhanced_summarizer.py`

### Evaluation is very slow
- Check if CUDA/GPU is being used: `torch.cuda.is_available()`
- Consider using smaller model or skipping evaluation
- Run evaluation separately after initial analysis

### Out of memory
- Reduce batch processing (currently processes one at a time)
- Use smaller model variant
- Close other GPU applications
- Skip evaluation on this machine

## Next Steps

After evaluation:

1. **Review predictions** - Focus on high-confidence results
2. **Validate manually** - LLM predictions are guidance, not truth
3. **Improve summaries** - Use feedback to enhance summarization prompts
4. **Iterate** - Re-run evaluation after fixing false positives

## Important Notes

- **LLM predictions are not ground truth** - Always validate with manual security review
- **Model can make mistakes** - Especially for complex or novel vulnerability patterns
- **Summaries affect quality** - Better summaries → better predictions
- **Context matters** - File-level clustering provides better context than global clustering
