"""
Find optimal temperature for CodeLlama vulnerability triage.
Tests temperatures [0.1, 0.2, 0.3, 0.5, 0.7, 1.0] on all 10 cases (baseline only).
Picks the temperature with highest accuracy.

Usage:
  /root/.local/bin/poetry run python find_best_temperature.py
"""

import json
import os
import logging
from datetime import datetime

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

TEMPERATURES = [0.01, 0.1, 0.2, 0.3, 0.5, 0.7, 1.0]

CASES = [
    {"case_id": 1, "vuln_type": "Hidden UI Element (android_hidden_ui)", "cwe": "CWE-919", "severity": "ERROR", "owasp": "M1: Improper Platform Usage", "description": "Hidden elements in view can be used to hide data from user. But this data can be leaked.", "file": "GetTransactions.java | com.app.damnvulnerablebank", "flagged_line": "Line 96", "flagged_code": "recyclerView.setVisibility(View.GONE);", "ground_truth": "FALSE_POSITIVE"},
    {"case_id": 2, "vuln_type": "Sensitive Data in Log File (android_logging)", "cwe": "CWE-532", "severity": "INFO", "owasp": "M1: Improper Platform Usage", "description": "The App logs information. Please ensure that sensitive information is never logged.", "file": "SendMoney.java | com.app.damnvulnerablebank", "flagged_line": "Line 99", "flagged_code": 'Log.d("Send Money", decryptedResponse.toString());', "ground_truth": "TRUE_POSITIVE"},
    {"case_id": 3, "vuln_type": "Sensitive Data in Log File (android_logging)", "cwe": "CWE-532", "severity": "INFO", "owasp": "M1: Improper Platform Usage", "description": "The App logs information. Please ensure that sensitive information is never logged.", "file": "LogActivity.java | jakhar.aseem.diva", "flagged_line": "Line 56", "flagged_code": 'Log.e("diva-log", "Error while processing transaction with credit card: " + cctxt.getText().toString());', "ground_truth": "TRUE_POSITIVE"},
    {"case_id": 4, "vuln_type": "Hidden UI Element (android_hidden_ui)", "cwe": "CWE-919", "severity": "ERROR", "owasp": "M1: Improper Platform Usage", "description": "Hidden elements in view can be used to hide data from user. But this data can be leaked.", "file": "AccessControl3NotesActivity.java | jakhar.aseem.diva", "flagged_line": "Line 72", "flagged_code": "pinTxt.setVisibility(View.INVISIBLE);", "ground_truth": "FALSE_POSITIVE"},
    {"case_id": 5, "vuln_type": "SSL Certificate Validation Bypass (accept_self_signed_certificate)", "cwe": "CWE-295", "severity": "ERROR", "owasp": "M3: Insecure Communication", "description": "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole.", "file": "SecureURLOpen.java | org.cysecurity.example.dodobank.model", "flagged_line": "Lines 61-74", "flagged_code": "public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { }", "ground_truth": "FALSE_POSITIVE"},
    {"case_id": 6, "vuln_type": "SQLite Raw Query Injection (sqlite_injection)", "cwe": "CWE-78", "severity": "WARNING", "owasp": "M7: Client Code Quality", "description": "App uses SQLite Database and executes raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection.", "file": "TransactionTable.java | org.cysecurity.example.dodobank.controller", "flagged_line": "Lines 56-59", "flagged_code": 'db.rawQuery("select ... from ... where TRANSACTION_ID=" + id, null);', "ground_truth": "FALSE_POSITIVE"},
    {"case_id": 7, "vuln_type": "Weak Cryptographic Algorithm: AES ECB (aes_ecb_mode_default)", "cwe": "CWE-327", "severity": "ERROR", "owasp": "M5: Insufficient Cryptography", "description": 'Calling Cipher.getInstance("AES") will return AES ECB mode by default.', "file": "WeakCrypto.java | oversecured.ovaa.utils", "flagged_line": "Line 17", "flagged_code": 'Cipher instance = Cipher.getInstance("AES");', "ground_truth": "TRUE_POSITIVE"},
    {"case_id": 8, "vuln_type": "Static IV in AES-CBC Mode (cbc_static_iv)", "cwe": "CWE-329", "severity": "ERROR", "owasp": "M5: Insufficient Cryptography", "description": "The IV for AES CBC mode should be random. A static IV makes the ciphertext vulnerable to Chosen Plaintext Attack.", "file": "Encryption.java | com.htbridge.pivaa.handlers", "flagged_line": "Lines 114-124", "flagged_code": "byte[] IV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };", "ground_truth": "TRUE_POSITIVE"},
    {"case_id": 9, "vuln_type": "Sensitive Data in Log File (android_logging)", "cwe": "CWE-532", "severity": "INFO", "owasp": "M1: Improper Platform Usage", "description": "The App logs information. Please ensure that sensitive information is never logged.", "file": "Authentication.java | com.htbridge.pivaa.handlers", "flagged_line": "Line 35,55", "flagged_code": 'Log.i("info", "saveLoginInfo: username = " + username + " | password = " + password);', "ground_truth": "TRUE_POSITIVE"},
    {"case_id": 10, "vuln_type": "Sensitive Data in Log File (android_logging)", "cwe": "CWE-532", "severity": "INFO", "owasp": "M1: Improper Platform Usage", "description": "The App logs information. Please ensure that sensitive information is never logged.", "file": "Digest.java | org.apache.commons.codec.cli (Apache Commons Codec library)", "flagged_line": "Line 88", "flagged_code": 'System.out.println(prefix + Hex.encodeHexString(digest) + (fileName != null ? " " + fileName : ""));', "ground_truth": "FALSE_POSITIVE"},
]


def build_prompt(case):
    return f"""[INST] You are a senior Android security analyst performing manual triage of SAST tool findings. Your job is to determine whether each finding is a real vulnerability or a false positive.

IMPORTANT: SAST tools are known to have high false positive rates (often 40-60%). Many flagged patterns are actually normal, safe coding practices. You must critically evaluate whether the flagged code actually poses a security risk in context. Consider:
- Is the flagged pattern actually dangerous, or is it a common safe Android pattern?
- Does the code actually handle sensitive data, or is it benign?
- Is this a library/framework code vs application code?
- Could this be test/demo code rather than production code?

SAST TOOL FINDING:
- Vulnerability Type: {case['vuln_type']}
- CWE: {case['cwe']}
- Severity: {case['severity']}
- OWASP Mobile: {case['owasp']}
- Description: {case['description']}
- File: {case['file']}
- Flagged Line: {case['flagged_line']}
- Flagged Code: {case['flagged_code']}

Based on your expert analysis, classify this finding:

RESPOND IN THIS EXACT FORMAT:
CLASSIFICATION: [TRUE_POSITIVE or FALSE_POSITIVE]
CONFIDENCE: [1-5 where 1=Not at all confident, 2=Slightly confident, 3=Moderately confident, 4=Very confident, 5=Extremely confident]
REASONING: [2-3 sentences explaining why this is or is not a real vulnerability]
[/INST]"""


def parse(response):
    result = {"prediction": "UNKNOWN", "confidence": 3, "reasoning": ""}
    for line in response.split("\n"):
        line = line.strip()
        if line.startswith("CLASSIFICATION:"):
            val = line.upper()
            if "TRUE_POSITIVE" in val or "REAL" in val:
                result["prediction"] = "TRUE_POSITIVE"
            elif "FALSE_POSITIVE" in val or "FALSE" in val:
                result["prediction"] = "FALSE_POSITIVE"
        elif line.startswith("CONFIDENCE:"):
            for ch in line.split("CONFIDENCE:")[-1].strip():
                if ch.isdigit() and 1 <= int(ch) <= 5:
                    result["confidence"] = int(ch)
                    break
        elif line.startswith("REASONING:"):
            result["reasoning"] = line.split("REASONING:")[-1].strip()
    return result


def main():
    logger.info("Loading CodeLlama-7b-Instruct...")
    tokenizer = AutoTokenizer.from_pretrained("codellama/CodeLlama-7b-Instruct-hf")
    model = AutoModelForCausalLM.from_pretrained(
        "codellama/CodeLlama-7b-Instruct-hf",
        load_in_8bit=True, device_map="auto", torch_dtype=torch.bfloat16,
    )
    model.eval()
    logger.info("Model loaded.\n")

    results = {}

    for temp in TEMPERATURES:
        logger.info(f"{'='*50}")
        logger.info(f"TEMPERATURE: {temp}")
        logger.info(f"{'='*50}")

        correct = 0
        fp_correct = 0
        tp_correct = 0
        fp_total = 0
        tp_total = 0
        predictions = []

        for case in CASES:
            prompt = build_prompt(case)
            inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
            inputs = {k: v.to(model.device) for k, v in inputs.items()}

            with torch.no_grad():
                if temp < 0.05:
                    # Greedy decoding for very low temp
                    outputs = model.generate(**inputs, max_new_tokens=400, do_sample=False)
                else:
                    outputs = model.generate(
                        **inputs, max_new_tokens=400,
                        temperature=temp, do_sample=True, top_p=0.9,
                    )

            response = tokenizer.decode(outputs[0], skip_special_tokens=True)
            response = response.split("[/INST]")[-1].strip()
            pred = parse(response)

            is_correct = pred["prediction"] == case["ground_truth"]
            if is_correct:
                correct += 1
            if case["ground_truth"] == "FALSE_POSITIVE":
                fp_total += 1
                if is_correct:
                    fp_correct += 1
            else:
                tp_total += 1
                if is_correct:
                    tp_correct += 1

            predictions.append({
                "case_id": case["case_id"],
                "prediction": pred["prediction"],
                "ground_truth": case["ground_truth"],
                "correct": is_correct,
                "confidence": pred["confidence"],
                "reasoning": pred["reasoning"][:150],
            })

            symbol = "OK" if is_correct else "XX"
            logger.info(
                f"  [{symbol}] Case {case['case_id']}: {pred['prediction']:<15} "
                f"(GT: {case['ground_truth']:<15}) conf={pred['confidence']}/5"
            )

        accuracy = correct / len(CASES)
        fp_acc = fp_correct / fp_total if fp_total > 0 else 0
        tp_acc = tp_correct / tp_total if tp_total > 0 else 0

        results[temp] = {
            "accuracy": accuracy,
            "tp_accuracy": tp_acc,
            "fp_accuracy": fp_acc,
            "correct": correct,
            "predictions": predictions,
        }

        logger.info(f"\n  Accuracy:      {accuracy:.0%} ({correct}/10)")
        logger.info(f"  TP Detection:  {tp_acc:.0%} ({tp_correct}/{tp_total})")
        logger.info(f"  FP Detection:  {fp_acc:.0%} ({fp_correct}/{fp_total})")
        logger.info("")

    # ── Summary ──
    logger.info("\n" + "=" * 60)
    logger.info("TEMPERATURE COMPARISON SUMMARY")
    logger.info("=" * 60)
    logger.info(f"{'Temp':<8} {'Accuracy':<12} {'TP Det.':<12} {'FP Det.':<12}")
    logger.info("-" * 44)

    best_temp = None
    best_acc = -1

    for temp in TEMPERATURES:
        r = results[temp]
        marker = ""
        if r["accuracy"] > best_acc:
            best_acc = r["accuracy"]
            best_temp = temp
        logger.info(
            f"{temp:<8.2f} {r['accuracy']:<11.0%} {r['tp_accuracy']:<11.0%} {r['fp_accuracy']:<11.0%}"
        )

    logger.info("-" * 44)
    logger.info(f"\nBest temperature: {best_temp} (accuracy: {best_acc:.0%})")
    logger.info(f"\nUse this in experiment_survey_cases.py:")
    logger.info(f"  temperature={best_temp}")

    # Save results
    output_path = f"temperature_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_path, "w") as f:
        json.dump({"temperatures": {str(t): r for t, r in results.items()}, "best": best_temp}, f, indent=2)
    logger.info(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
