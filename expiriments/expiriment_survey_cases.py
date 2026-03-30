"""
Experiment: LLM Predictions on 10 Survey Vulnerability Cases
=============================================================
Mirrors the survey workflow exactly:
  1. BASELINE  (control)      – SAST tool info only → classify TP/FP + confidence 1-5
  2. ENHANCED  (experimental) – SAST info + LLM summaries → classify TP/FP + confidence 1-5
  3. SUMMARY EVALUATION       – assess quality of the generated summaries

Usage on server:
  /root/.local/bin/poetry run python experiment_survey_cases.py
"""

import json
import os
import logging
from datetime import datetime

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)-8s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# 10 SURVEY CASES (ground truth from manual expert review)
# ──────────────────────────────────────────────────────────────
CASES = [
    {
        "case_id": 1,
        "vuln_type": "Hidden UI Element (android_hidden_ui)",
        "cwe": "CWE-919: Weaknesses in Mobile Applications",
        "severity": "ERROR",
        "owasp": "M1: Improper Platform Usage",
        "description": "Hidden elements in view can be used to hide data from user. But this data can be leaked.",
        "file": "GetTransactions.java | com.app.damnvulnerablebank",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-01-DamnVulnerableBank-GetTransactions/GetTransactions.java",
        "flagged_line": "Line 96",
        "flagged_code": "recyclerView.setVisibility(View.GONE);",
        "ground_truth": "FALSE_POSITIVE",  # Hidden UI is just a normal Android pattern
    },
    {
        "case_id": 2,
        "vuln_type": "Sensitive Data in Log File (android_logging)",
        "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
        "severity": "INFO",
        "owasp": "M1: Improper Platform Usage",
        "description": "The App logs information. Please ensure that sensitive information is never logged.",
        "file": "SendMoney.java | com.app.damnvulnerablebank",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-02-DamnVulnerableBank-SendMoney/SendMoney.java",
        "flagged_line": "Line 99",
        "flagged_code": 'Log.d("Send Money", decryptedResponse.toString());',
        "ground_truth": "TRUE_POSITIVE",
    },
    {
        "case_id": 3,
        "vuln_type": "Sensitive Data in Log File (android_logging)",
        "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
        "severity": "INFO",
        "owasp": "M1: Improper Platform Usage",
        "description": "The App logs information. Please ensure that sensitive information is never logged.",
        "file": "LogActivity.java | jakhar.aseem.diva",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-03-DIVA-LogActivity/LogActivity.java",
        "flagged_line": "Line 56",
        "flagged_code": 'Log.e("diva-log", "Error while processing transaction with credit card: " + cctxt.getText().toString());',
        "ground_truth": "TRUE_POSITIVE",  # Actually logs sensitive data in DIVA
    },
    {
        "case_id": 4,
        "vuln_type": "Hidden UI Element (android_hidden_ui)",
        "cwe": "CWE-919: Weaknesses in Mobile Applications",
        "severity": "ERROR",
        "owasp": "M1: Improper Platform Usage",
        "description": "Hidden elements in view can be used to hide data from user. But this data can be leaked.",
        "file": "AccessControl3NotesActivity.java | jakhar.aseem.diva",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-04-DIVA-AccessControl3Notes/AccessControl3NotesActivity.java",
        "flagged_line": "Line 72",
        "flagged_code": "pinTxt.setVisibility(View.INVISIBLE);",
        "ground_truth": "FALSE_POSITIVE",  # Hidden UI is just a normal Android pattern
    },
    {
        "case_id": 5,
        "vuln_type": "SSL Certificate Validation Bypass (accept_self_signed_certificate)",
        "cwe": "CWE-295: Improper Certificate Validation",
        "severity": "ERROR",
        "owasp": "M3: Insecure Communication",
        "description": "Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole. This application is vulnerable to MITM attacks.",
        "file": "SecureURLOpen.java | org.cysecurity.example.dodobank.model",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-05-DodoBank-SecureURLOpen/SecureURLOpen.java",
        "flagged_line": "Lines 61-74",
        "flagged_code": "public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { }",
        "ground_truth": "FALSE_POSITIVE",  # Demo/test SSL code, not a real bypass
    },
    {
        "case_id": 6,
        "vuln_type": "SQLite Raw Query Injection (sqlite_injection)",
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "severity": "WARNING",
        "owasp": "M7: Client Code Quality",
        "description": "App uses SQLite Database and executes raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database.",
        "file": "TransactionTable.java | org.cysecurity.example.dodobank.controller",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-06-DodoBank-TransactionTable/TransactionTable.java",
        "flagged_line": "Lines 56-59",
        "flagged_code": 'db.rawQuery("select ... from ... where TRANSACTION_ID=" + id, null);',
        "ground_truth": "FALSE_POSITIVE",  # SQL uses internal data, no user input
    },
    {
        "case_id": 7,
        "vuln_type": "Weak Cryptographic Algorithm: AES ECB (aes_ecb_mode_default)",
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "severity": "ERROR",
        "owasp": "M5: Insufficient Cryptography",
        "description": 'Calling Cipher.getInstance("AES") will return AES ECB mode by default. ECB mode is known to be weak as it results in the same ciphertext for identical blocks of plaintext.',
        "file": "WeakCrypto.java | oversecured.ovaa.utils",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-07-OVAA-WeakCrypto/WeakCrypto.java",
        "flagged_line": "Line 17",
        "flagged_code": 'Cipher instance = Cipher.getInstance("AES");',
        "ground_truth": "TRUE_POSITIVE",
    },
    {
        "case_id": 8,
        "vuln_type": "Static IV in AES-CBC Mode (cbc_static_iv)",
        "cwe": "CWE-329: Not Using a Random IV with CBC Mode",
        "severity": "ERROR",
        "owasp": "M5: Insufficient Cryptography",
        "description": "The IV for AES CBC mode should be random. A static IV makes the ciphertext vulnerable to Chosen Plaintext Attack.",
        "file": "Encryption.java | com.htbridge.pivaa.handlers",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-08-PIVAA-Encryption/Encryption.java",
        "flagged_line": "Lines 114-124",
        "flagged_code": "byte[] IV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };",
        "ground_truth": "TRUE_POSITIVE",
    },
    {
        "case_id": 9,
        "vuln_type": "Sensitive Data in Log File (android_logging)",
        "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
        "severity": "INFO",
        "owasp": "M1: Improper Platform Usage",
        "description": "The App logs information. Please ensure that sensitive information is never logged.",
        "file": "Authentication.java | com.htbridge.pivaa.handlers",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-09-PIVAA-Authentication/Authentication.java",
        "flagged_line": "Line 35,55",
        "flagged_code": 'Log.i("info", "saveLoginInfo: username = " + username + " | password = " + password);',
        "ground_truth": "TRUE_POSITIVE",
    },
    {
        "case_id": 10,
        "vuln_type": "Sensitive Data in Log File (android_logging)",
        "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
        "severity": "INFO",
        "owasp": "M1: Improper Platform Usage",
        "description": "The App logs information. Please ensure that sensitive information is never logged.",
        "file": "Digest.java | org.apache.commons.codec.cli (Apache Commons Codec library)",
        "code_url": "https://github.com/PanosBin/android-vulnerability-cases/blob/main/case-10-PIVAA-Digest/Digest.java",
        "flagged_line": "Line 88",
        "flagged_code": 'System.out.println(prefix + Hex.encodeHexString(digest) + (fileName != null ? " " + fileName : ""));',
        "ground_truth": "FALSE_POSITIVE",  # Apache Commons library, not app logging
    },
]

NUM_RUNS = 1  # single run per condition, matching survey design


# ──────────────────────────────────────────────────────────────
# MODEL
# ──────────────────────────────────────────────────────────────
def load_model():
    model_name = "codellama/CodeLlama-7b-Instruct-hf"
    logger.info(f"Loading model: {model_name} ...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(
        model_name, load_in_8bit=True, device_map="auto", torch_dtype=torch.bfloat16,
    )
    model.eval()
    logger.info("Model loaded.")
    return tokenizer, model


def generate(tokenizer, model, prompt, max_new_tokens=500):
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
    inputs = {k: v.to(model.device) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = model.generate(
            **inputs, max_new_tokens=max_new_tokens,
            temperature=0.5, do_sample=True, top_p=0.9,
        )
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return response.split("[/INST]")[-1].strip()


# ──────────────────────────────────────────────────────────────
# PRE-GENERATED SUMMARIES (from pipeline, same as used in survey)
# ──────────────────────────────────────────────────────────────
SUMMARIES = {
    1: {
        "method": 'The method extractRecords() makes an HTTP POST request to the URL stored in the "apiurl" preference, with a JSON payload containing the encrypted data received from the previous screen.',
        "class": "This class GetTransactions extends AppCompatActivity and provides a user interface for viewing transaction records.",
        "cluster": "A user interface for adding, approving, and managing beneficiaries for a mobile banking application.",
    },
    2: {
        "method": "The code sends a POST request to an API endpoint with encrypted data, retrieves the response, decrypts it, and displays the result as a toast message or starts a new activity depending on the status of the response.",
        "class": "The SendMoney class is an Android app that allows users to transfer money from their account to another account using biometric authentication.",
        "cluster": "A user interface for adding, approving, and managing beneficiaries for a mobile banking application.",
    },
    3: {
        "method": "The checkout method takes an EditText object as input and attempts to process the credit card information entered by the user.",
        "class": "This class LogActivity is an Android activity that allows users to enter their credit card information and process it using a custom processCC() method.",
        "cluster": "A way for users to manage their API credentials and access control settings on an Android device.",
    },
    4: {
        "method": "The code retrieves a shared preference value for a PIN, compares it to the text entered by the user in an EditText field, and if they match, displays a list of notes from a database using a SimpleCursorAdapter.",
        "class": "This class AccessControl3NotesActivity extends AppCompatActivity and provides an interface for accessing and displaying private notes stored in a database.",
        "cluster": "A way for users to manage their API credentials and access control settings on an Android device.",
    },
    5: {
        "method": "The code creates an SSL socket factory that trusts all certificates and skips host name verification, which is useful for testing purposes but should not be used in production environments.",
        "class": "This class provides methods for making HTTPS requests with custom SSL socket factories, allowing the user to bypass host name verification in the Android emulator.",
        "cluster": "The classes collectively handle the transfer of funds between accounts using a shared preference file for storing user data and a background task for sending the transfer request.",
    },
    6: {
        "method": "The code inserts a new transaction into a database table with the given ID, sender, receiver, and amount, and logs the transaction details to the console.",
        "class": "This class provides an interface for managing transactions in a database.",
        "cluster": "The classes collectively handle the transfer of funds between accounts using a shared preference file for storing user data and a background task for sending the transfer request.",
    },
    7: {
        "method": "The provided code creates an AES encryption key using the SecretKeySpec class and initializes a Cipher object with the key to encrypt a string of data.",
        "class": "This class provides a weak encryption mechanism using the AES algorithm with a fixed key and returns the encrypted data as a base64-encoded string.",
        "cluster": "A way to interact with the Android platform and perform various tasks such as starting activities, making network requests, and handling user authentication.",
    },
    8: {
        "method": "The provided Java code uses the AES encryption algorithm with CBC mode and PKCS5 padding to encrypt a given string, using a hardcoded secret key and initialization vector, and then base64 encodes the resulting ciphertext before returning it as a string.",
        "class": "This class provides various encryption-related methods for encrypting and decrypting data using different algorithms such as AES with ECB and CBC modes, PKCS5 padding, and base64 encoding.",
        "cluster": "A database management system for storing and retrieving data in an Android application.",
    },
    9: {
        "method": "The code saves a login credential pair consisting of a username and password to a temporary file in the cache directory of an Android application, using MD5 encryption to hash the credentials before writing them to the file.",
        "class": "This class provides methods for saving and loading login information to and from an external storage device.",
        "cluster": "A framework for creating web-based applications using Android's WebView component.",
    },
    10: {
        "method": "This method takes a string prefix, a byte array digest, and a string fileName as input, and prints them to the console using the format specified by the shasum(1) command-line tool.",
        "class": "This class provides a command-line interface for computing message digests using the Apache Commons Codec library.",
        "cluster": "Various utilities for working with character encodings in Java.",
    },
}


# ──────────────────────────────────────────────────────────────
# STEP 1 — BASELINE PROMPT (Control Group: SAST info only)
# Mirrors the control group survey view exactly
# ──────────────────────────────────────────────────────────────
def build_baseline_prompt(case):
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


# ──────────────────────────────────────────────────────────────
# STEP 2 — ENHANCED PROMPT (Experimental Group: SAST + summaries)
# Mirrors the experimental group survey view exactly
# ──────────────────────────────────────────────────────────────
def build_enhanced_prompt(case, method_summary, class_summary, cluster_summary):
    return f"""[INST] You are a senior Android security analyst performing manual triage of SAST tool findings. Your job is to determine whether each finding is a real vulnerability or a false positive.

IMPORTANT: SAST tools are known to have high false positive rates (often 40-60%). Many flagged patterns are actually normal, safe coding practices. You must critically evaluate whether the flagged code actually poses a security risk in context. Use the LLM-generated summaries below to understand the code context and make a more informed decision. Consider:
- Is the flagged pattern actually dangerous, or is it a common safe Android pattern?
- Does the code actually handle sensitive data, or is it benign?
- Is this a library/framework code vs application code?
- Could this be test/demo code rather than production code?
- What does the method/class/cluster context tell you about whether this is truly exploitable?

SAST TOOL FINDING:
- Vulnerability Type: {case['vuln_type']}
- CWE: {case['cwe']}
- Severity: {case['severity']}
- OWASP Mobile: {case['owasp']}
- Description: {case['description']}
- File: {case['file']}
- Flagged Line: {case['flagged_line']}
- Flagged Code: {case['flagged_code']}

LLM-GENERATED CONTEXT SUMMARIES:
- Method Summary: {method_summary}
- Class Summary: {class_summary}
- Cluster Summary: {cluster_summary}

Based on your expert analysis of ALL the information above (SAST finding AND context summaries), classify this finding:

RESPOND IN THIS EXACT FORMAT:
CLASSIFICATION: [TRUE_POSITIVE or FALSE_POSITIVE]
CONFIDENCE: [1-5 where 1=Not at all confident, 2=Slightly confident, 3=Moderately confident, 4=Very confident, 5=Extremely confident]
REASONING: [2-3 sentences explaining why this is or is not a real vulnerability, referencing the summaries where relevant]
[/INST]"""


# ──────────────────────────────────────────────────────────────
# STEP 3 — SUMMARY EVALUATION PROMPT
# After both predictions, evaluate the summaries themselves
# ──────────────────────────────────────────────────────────────
def build_summary_evaluation_prompt(case, method_summary, class_summary, cluster_summary,
                                    baseline_pred, enhanced_pred):
    return f"""[INST] You are a security expert evaluating the quality of LLM-generated code summaries for vulnerability triage.

VULNERABILITY FINDING:
- Type: {case['vuln_type']}
- File: {case['file']}
- Flagged Code: {case['flagged_code']}

LLM-GENERATED SUMMARIES:
- Method Summary: {method_summary}
- Class Summary: {class_summary}
- Cluster Summary: {cluster_summary}

Evaluate the quality of these summaries for helping a security analyst triage this finding:

RESPOND IN THIS EXACT FORMAT:
HELPFUL: [YES or NO - did summaries provide useful context for triage?]
ACCURACY: [YES or NO - are the summaries factually accurate about the code?]
RELEVANCE: [YES or NO - do summaries focus on security-relevant aspects?]
COMPLETENESS: [1-5 where 1=Very incomplete, 5=Very complete]
MISSING_INFO: [What critical information is missing from the summaries?]
IMPROVEMENT: [How could the summaries be improved for better triage?]
[/INST]"""


# ──────────────────────────────────────────────────────────────
# PARSERS
# ──────────────────────────────────────────────────────────────
def parse_classification(response):
    result = {"prediction": "UNKNOWN", "confidence": 3, "reasoning": ""}
    for line in response.split("\n"):
        line = line.strip()
        if line.startswith("CLASSIFICATION:"):
            val = line.split("CLASSIFICATION:")[-1].strip().upper()
            if "TRUE_POSITIVE" in val or "REAL" in val:
                result["prediction"] = "TRUE_POSITIVE"
            elif "FALSE_POSITIVE" in val or "FALSE" in val:
                result["prediction"] = "FALSE_POSITIVE"
        elif line.startswith("CONFIDENCE:"):
            try:
                conf = line.split("CONFIDENCE:")[-1].strip()
                # Extract first number found
                for char in conf:
                    if char.isdigit():
                        c = int(char)
                        if 1 <= c <= 5:
                            result["confidence"] = c
                        break
            except ValueError:
                pass
        elif line.startswith("REASONING:"):
            result["reasoning"] = line.split("REASONING:")[-1].strip()
    # Fallback: grab reasoning after REASONING: tag
    if not result["reasoning"] and "REASONING:" in response:
        start = response.find("REASONING:") + len("REASONING:")
        end = len(response)
        result["reasoning"] = response[start:end].strip()[:500]
    return result


def parse_summary_evaluation(response):
    evaluation = {
        "helpful": False, "accuracy": False, "relevance": False,
        "completeness": 3, "missing_info": "", "improvement": "",
    }
    for line in response.split("\n"):
        line = line.strip()
        if line.startswith("HELPFUL:"):
            evaluation["helpful"] = "YES" in line.upper()
        elif line.startswith("ACCURACY:"):
            evaluation["accuracy"] = "YES" in line.upper()
        elif line.startswith("RELEVANCE:"):
            evaluation["relevance"] = "YES" in line.upper()
        elif line.startswith("COMPLETENESS:"):
            try:
                for ch in line.split("COMPLETENESS:")[-1].strip():
                    if ch.isdigit():
                        evaluation["completeness"] = int(ch)
                        break
            except ValueError:
                pass
        elif line.startswith("MISSING_INFO:"):
            evaluation["missing_info"] = line.split("MISSING_INFO:")[-1].strip()
        elif line.startswith("IMPROVEMENT:"):
            evaluation["improvement"] = line.split("IMPROVEMENT:")[-1].strip()
    return evaluation


# ──────────────────────────────────────────────────────────────
# MAIN EXPERIMENT
# ──────────────────────────────────────────────────────────────
def run_experiment():
    output_dir = f"experiment_survey_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir, exist_ok=True)

    tokenizer, model = load_model()

    # Use pre-generated summaries (same as used in the survey)
    case_summaries = SUMMARIES

    logger.info("Using pre-generated summaries from pipeline (same as survey)")
    with open(os.path.join(output_dir, "summaries_used.json"), "w") as f:
        json.dump({str(k): v for k, v in case_summaries.items()}, f, indent=2)

    # ══════════════════════════════════════════════════════════
    # PHASE 1: Baseline Predictions (SAST only — control group)
    # ══════════════════════════════════════════════════════════
    logger.info("\n" + "=" * 60)
    logger.info(f"PHASE 1: BASELINE predictions ({NUM_RUNS} runs)")
    logger.info("=" * 60)

    baseline_runs = []
    for run_idx in range(NUM_RUNS):
        logger.info(f"\n--- Baseline Run {run_idx + 1}/{NUM_RUNS} ---")
        run_results = []
        for case in CASES:
            prompt = build_baseline_prompt(case)
            response = generate(tokenizer, model, prompt)
            pred = parse_classification(response)
            pred["case_id"] = case["case_id"]
            pred["ground_truth"] = case["ground_truth"]
            pred["correct"] = pred["prediction"] == case["ground_truth"]
            pred["raw_response"] = response
            run_results.append(pred)
            logger.info(
                f"  Case {case['case_id']}: {pred['prediction']} "
                f"(GT: {case['ground_truth']}) "
                f"{'CORRECT' if pred['correct'] else 'WRONG'} "
                f"[confidence: {pred['confidence']}/5]"
            )
        baseline_runs.append(run_results)

    # ══════════════════════════════════════════════════════════
    # PHASE 2: Enhanced Predictions (SAST + summaries — experimental)
    # ══════════════════════════════════════════════════════════
    logger.info("\n" + "=" * 60)
    logger.info(f"PHASE 2: ENHANCED predictions ({NUM_RUNS} runs)")
    logger.info("=" * 60)

    enhanced_runs = []
    for run_idx in range(NUM_RUNS):
        logger.info(f"\n--- Enhanced Run {run_idx + 1}/{NUM_RUNS} ---")
        run_results = []
        for case in CASES:
            cid = case["case_id"]
            sums = case_summaries[cid]
            prompt = build_enhanced_prompt(case, sums["method"], sums["class"], sums["cluster"])
            response = generate(tokenizer, model, prompt)
            pred = parse_classification(response)
            pred["case_id"] = cid
            pred["ground_truth"] = case["ground_truth"]
            pred["correct"] = pred["prediction"] == case["ground_truth"]
            pred["summaries_used"] = {
                "method": sums["method"],
                "class": sums["class"],
                "cluster": sums["cluster"],
            }
            pred["raw_response"] = response
            run_results.append(pred)
            logger.info(
                f"  Case {cid}: {pred['prediction']} "
                f"(GT: {case['ground_truth']}) "
                f"{'CORRECT' if pred['correct'] else 'WRONG'} "
                f"[confidence: {pred['confidence']}/5]"
            )
        enhanced_runs.append(run_results)

    # ══════════════════════════════════════════════════════════
    # PHASE 3: Summary Quality Evaluation
    # ══════════════════════════════════════════════════════════
    logger.info("\n" + "=" * 60)
    logger.info("PHASE 3: Evaluating Summary Quality")
    logger.info("=" * 60)

    summary_evaluations = []
    # Use majority predictions from runs for the eval prompt
    for case in CASES:
        cid = case["case_id"]
        sums = case_summaries[cid]

        # Get majority baseline prediction
        baseline_preds = [r["prediction"] for run in baseline_runs for r in run if r["case_id"] == cid]
        baseline_majority = max(set(baseline_preds), key=baseline_preds.count) if baseline_preds else "UNKNOWN"

        # Get majority enhanced prediction
        enhanced_preds = [r["prediction"] for run in enhanced_runs for r in run if r["case_id"] == cid]
        enhanced_majority = max(set(enhanced_preds), key=enhanced_preds.count) if enhanced_preds else "UNKNOWN"

        prompt = build_summary_evaluation_prompt(
            case, sums["method"], sums["class"], sums["cluster"],
            baseline_majority, enhanced_majority,
        )
        response = generate(tokenizer, model, prompt)
        evaluation = parse_summary_evaluation(response)
        evaluation["case_id"] = cid
        evaluation["baseline_majority"] = baseline_majority
        evaluation["enhanced_majority"] = enhanced_majority
        evaluation["raw_response"] = response
        summary_evaluations.append(evaluation)

        logger.info(
            f"  Case {cid}: helpful={evaluation['helpful']}, "
            f"accurate={evaluation['accuracy']}, "
            f"relevant={evaluation['relevance']}, "
            f"completeness={evaluation['completeness']}/5"
        )

    # ══════════════════════════════════════════════════════════
    # SAVE ALL RAW RESULTS
    # ══════════════════════════════════════════════════════════
    all_results = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "model": "codellama/CodeLlama-7b-Instruct-hf",
            "num_cases": len(CASES),
            "num_runs": NUM_RUNS,
            "confidence_scale": "1-5 (1=Not at all, 2=Slightly, 3=Moderately, 4=Very, 5=Extremely)",
        },
        "cases": [{
            "case_id": c["case_id"],
            "vuln_type": c["vuln_type"],
            "cwe": c["cwe"],
            "severity": c["severity"],
            "file": c["file"],
            "flagged_code": c["flagged_code"],
            "ground_truth": c["ground_truth"],
            "summaries": case_summaries.get(c["case_id"], {}),
        } for c in CASES],
        "baseline_runs": baseline_runs,
        "enhanced_runs": enhanced_runs,
        "summary_evaluations": summary_evaluations,
    }

    with open(os.path.join(output_dir, "experiment_results.json"), "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    logger.info(f"\nRaw results saved to: {output_dir}/experiment_results.json")

    # ══════════════════════════════════════════════════════════
    # ANALYSIS & FIGURES
    # ══════════════════════════════════════════════════════════
    analyze_results(all_results, output_dir)

    logger.info(f"\nAll outputs saved to: {output_dir}/")


# ──────────────────────────────────────────────────────────────
# DATA ANALYSIS & PUBLICATION FIGURES
# ──────────────────────────────────────────────────────────────
def analyze_results(results, output_dir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        HAS_MPL = True
    except ImportError:
        logger.warning("matplotlib not available — saving JSON analysis only")
        HAS_MPL = False

    num_cases = len(CASES)
    num_runs = results["metadata"]["num_runs"]

    # ── Compute per-run metrics ──
    def compute_metrics(runs):
        all_metrics = []
        for run in runs:
            correct = sum(1 for r in run if r["correct"])
            tp_total = sum(1 for r in run if r["ground_truth"] == "TRUE_POSITIVE")
            fp_total = sum(1 for r in run if r["ground_truth"] == "FALSE_POSITIVE")
            tp_correct = sum(1 for r in run if r["ground_truth"] == "TRUE_POSITIVE" and r["correct"])
            fp_correct = sum(1 for r in run if r["ground_truth"] == "FALSE_POSITIVE" and r["correct"])
            pred_tp = sum(1 for r in run if r["prediction"] == "TRUE_POSITIVE")
            true_tp = sum(1 for r in run if r["prediction"] == "TRUE_POSITIVE" and r["ground_truth"] == "TRUE_POSITIVE")
            precision = true_tp / pred_tp if pred_tp > 0 else 0
            recall = true_tp / tp_total if tp_total > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            avg_conf = np.mean([r["confidence"] for r in run])
            all_metrics.append({
                "accuracy": correct / num_cases,
                "tp_accuracy": tp_correct / tp_total if tp_total > 0 else 0,
                "fp_accuracy": fp_correct / fp_total if fp_total > 0 else 0,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "avg_confidence": avg_conf,
            })
        return all_metrics

    baseline_metrics = compute_metrics(results["baseline_runs"])
    enhanced_metrics = compute_metrics(results["enhanced_runs"])

    def avg(m, k): return float(np.mean([x[k] for x in m]))
    def std(m, k): return float(np.std([x[k] for x in m]))

    # ── Per-case accuracy ──
    def per_case_acc(runs):
        acc = {}
        for case in CASES:
            cid = case["case_id"]
            correct_count = sum(1 for run in runs for r in run if r["case_id"] == cid and r["correct"])
            acc[cid] = correct_count / len(runs)
        return acc

    baseline_per_case = per_case_acc(results["baseline_runs"])
    enhanced_per_case = per_case_acc(results["enhanced_runs"])

    # ── Per-case average confidence ──
    def per_case_conf(runs):
        conf = {}
        for case in CASES:
            cid = case["case_id"]
            confs = [r["confidence"] for run in runs for r in run if r["case_id"] == cid]
            conf[cid] = float(np.mean(confs)) if confs else 0
        return conf

    baseline_per_case_conf = per_case_conf(results["baseline_runs"])
    enhanced_per_case_conf = per_case_conf(results["enhanced_runs"])

    # ── Summary evaluation aggregates ──
    evals = results["summary_evaluations"]
    eval_agg = {
        "helpful_pct": sum(1 for e in evals if e["helpful"]) / len(evals) * 100,
        "accurate_pct": sum(1 for e in evals if e["accuracy"]) / len(evals) * 100,
        "relevant_pct": sum(1 for e in evals if e["relevance"]) / len(evals) * 100,
        "avg_completeness": float(np.mean([e["completeness"] for e in evals])),
    }

    # ── Build analysis dict ──
    analysis = {
        "summary": {
            "num_cases": num_cases,
            "num_runs": num_runs,
            "ground_truth_distribution": {
                "true_positives": sum(1 for c in CASES if c["ground_truth"] == "TRUE_POSITIVE"),
                "false_positives": sum(1 for c in CASES if c["ground_truth"] == "FALSE_POSITIVE"),
            },
        },
        "baseline": {
            "accuracy_mean": round(avg(baseline_metrics, "accuracy"), 3),
            "accuracy_std": round(std(baseline_metrics, "accuracy"), 3),
            "tp_accuracy_mean": round(avg(baseline_metrics, "tp_accuracy"), 3),
            "fp_accuracy_mean": round(avg(baseline_metrics, "fp_accuracy"), 3),
            "precision_mean": round(avg(baseline_metrics, "precision"), 3),
            "recall_mean": round(avg(baseline_metrics, "recall"), 3),
            "f1_mean": round(avg(baseline_metrics, "f1"), 3),
            "confidence_mean": round(avg(baseline_metrics, "avg_confidence"), 2),
            "per_case_accuracy": {str(k): v for k, v in baseline_per_case.items()},
            "per_case_confidence": {str(k): round(v, 2) for k, v in baseline_per_case_conf.items()},
        },
        "enhanced": {
            "accuracy_mean": round(avg(enhanced_metrics, "accuracy"), 3),
            "accuracy_std": round(std(enhanced_metrics, "accuracy"), 3),
            "tp_accuracy_mean": round(avg(enhanced_metrics, "tp_accuracy"), 3),
            "fp_accuracy_mean": round(avg(enhanced_metrics, "fp_accuracy"), 3),
            "precision_mean": round(avg(enhanced_metrics, "precision"), 3),
            "recall_mean": round(avg(enhanced_metrics, "recall"), 3),
            "f1_mean": round(avg(enhanced_metrics, "f1"), 3),
            "confidence_mean": round(avg(enhanced_metrics, "avg_confidence"), 2),
            "per_case_accuracy": {str(k): v for k, v in enhanced_per_case.items()},
            "per_case_confidence": {str(k): round(v, 2) for k, v in enhanced_per_case_conf.items()},
        },
        "improvement": {
            "accuracy_delta": round(avg(enhanced_metrics, "accuracy") - avg(baseline_metrics, "accuracy"), 3),
            "f1_delta": round(avg(enhanced_metrics, "f1") - avg(baseline_metrics, "f1"), 3),
            "confidence_delta": round(avg(enhanced_metrics, "avg_confidence") - avg(baseline_metrics, "avg_confidence"), 2),
        },
        "summary_evaluation": eval_agg,
        "per_run_details": {
            "baseline": baseline_metrics,
            "enhanced": enhanced_metrics,
        },
    }

    with open(os.path.join(output_dir, "analysis.json"), "w") as f:
        json.dump(analysis, f, indent=2)

    # ── Print summary table ──
    logger.info("\n" + "=" * 70)
    logger.info("RESULTS SUMMARY")
    logger.info("=" * 70)
    logger.info(f"{'Metric':<25} {'Baseline':>12} {'Enhanced':>12} {'Delta':>10}")
    logger.info("-" * 70)
    for name, key in [("Accuracy", "accuracy_mean"), ("Precision", "precision_mean"),
                       ("Recall", "recall_mean"), ("F1 Score", "f1_mean"),
                       ("TP Detection", "tp_accuracy_mean"), ("FP Detection", "fp_accuracy_mean")]:
        b = analysis["baseline"][key]
        e = analysis["enhanced"][key]
        logger.info(f"{name:<25} {b:>11.1%} {e:>11.1%} {e-b:>+9.1%}")
    b_c = analysis["baseline"]["confidence_mean"]
    e_c = analysis["enhanced"]["confidence_mean"]
    logger.info(f"{'Avg Confidence (1-5)':<25} {b_c:>12.2f} {e_c:>12.2f} {e_c-b_c:>+10.2f}")
    logger.info("=" * 70)
    logger.info("\nSummary Quality Evaluation:")
    logger.info(f"  Helpful:       {eval_agg['helpful_pct']:.0f}%")
    logger.info(f"  Accurate:      {eval_agg['accurate_pct']:.0f}%")
    logger.info(f"  Relevant:      {eval_agg['relevant_pct']:.0f}%")
    logger.info(f"  Completeness:  {eval_agg['avg_completeness']:.1f}/5")
    logger.info("=" * 70)

    if not HAS_MPL:
        return analysis

    # ──────────────────────────────────────────────────────────
    # PUBLICATION FIGURES
    # ──────────────────────────────────────────────────────────
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 11,
        "axes.labelsize": 12,
        "axes.titlesize": 13,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "figure.dpi": 300,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
    })
    BL_COL = "#4A90D9"
    EN_COL = "#E8833A"

    def save_fig(fig, name):
        fig.savefig(os.path.join(output_dir, f"{name}.pdf"))
        fig.savefig(os.path.join(output_dir, f"{name}.png"))
        plt.close(fig)
        logger.info(f"  Saved {name}.pdf/png")

    # ── Fig 1: Overall Metrics Comparison ──
    fig, ax = plt.subplots(figsize=(8, 5))
    labels = ["Accuracy", "Precision", "Recall", "F1 Score"]
    b_vals = [analysis["baseline"][k] for k in ["accuracy_mean", "precision_mean", "recall_mean", "f1_mean"]]
    e_vals = [analysis["enhanced"][k] for k in ["accuracy_mean", "precision_mean", "recall_mean", "f1_mean"]]
    x = np.arange(len(labels))
    w = 0.32
    bars1 = ax.bar(x - w/2, b_vals, w, label="Baseline (SAST only)", color=BL_COL, edgecolor="white")
    bars2 = ax.bar(x + w/2, e_vals, w, label="Enhanced (SAST + Summaries)", color=EN_COL, edgecolor="white")
    for bars in [bars1, bars2]:
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                    f"{bar.get_height():.2f}", ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("Score")
    ax.set_title("LLM Triage Performance: Baseline vs. Enhanced")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.15)
    ax.legend(loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save_fig(fig, "fig1_metrics_comparison")

    # ── Fig 2: Per-Case Accuracy ──
    fig, ax = plt.subplots(figsize=(10, 4))
    case_ids = [c["case_id"] for c in CASES]
    gt_labels = ["FP" if c["ground_truth"] == "FALSE_POSITIVE" else "TP" for c in CASES]
    b_acc = [baseline_per_case[cid] for cid in case_ids]
    e_acc = [enhanced_per_case[cid] for cid in case_ids]
    x = np.arange(len(case_ids))
    w = 0.35
    ax.bar(x - w/2, b_acc, w, label="Baseline", color=BL_COL, edgecolor="white")
    ax.bar(x + w/2, e_acc, w, label="Enhanced", color=EN_COL, edgecolor="white")
    ax.set_ylabel("Accuracy (across runs)")
    ax.set_title("Per-Case Classification Accuracy")
    ax.set_xticks(x)
    ax.set_xticklabels([f"C{cid}\n({gt})" for cid, gt in zip(case_ids, gt_labels)], fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save_fig(fig, "fig2_per_case_accuracy")

    # ── Fig 3: Confidence Distribution (1-5 scale) ──
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    b_confs = [r["confidence"] for run in results["baseline_runs"] for r in run]
    e_confs = [r["confidence"] for run in results["enhanced_runs"] for r in run]
    bins = [0.5, 1.5, 2.5, 3.5, 4.5, 5.5]
    conf_labels = ["1\nNot at all", "2\nSlightly", "3\nModerately", "4\nVery", "5\nExtremely"]

    axes[0].hist(b_confs, bins=bins, color=BL_COL, edgecolor="white", alpha=0.85, rwidth=0.8)
    axes[0].set_title("Baseline Confidence")
    axes[0].set_xlabel("Confidence Level")
    axes[0].set_ylabel("Count")
    axes[0].set_xticks([1, 2, 3, 4, 5])
    axes[0].set_xticklabels(conf_labels, fontsize=8)
    axes[0].axvline(np.mean(b_confs), color="red", linestyle="--", label=f"Mean: {np.mean(b_confs):.1f}")
    axes[0].legend()

    axes[1].hist(e_confs, bins=bins, color=EN_COL, edgecolor="white", alpha=0.85, rwidth=0.8)
    axes[1].set_title("Enhanced Confidence")
    axes[1].set_xlabel("Confidence Level")
    axes[1].set_xticks([1, 2, 3, 4, 5])
    axes[1].set_xticklabels(conf_labels, fontsize=8)
    axes[1].axvline(np.mean(e_confs), color="red", linestyle="--", label=f"Mean: {np.mean(e_confs):.1f}")
    axes[1].legend()

    for ax in axes:
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    fig.suptitle("Confidence Score Distribution (1-5 Scale)", fontsize=13, y=1.02)
    fig.tight_layout()
    save_fig(fig, "fig3_confidence_distribution")

    # ── Fig 4: Confusion Matrices ──
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for idx, (title, runs, cmap) in enumerate([
        ("Baseline", results["baseline_runs"], "Blues"),
        ("Enhanced", results["enhanced_runs"], "Oranges"),
    ]):
        tp_tp = tp_fp = fp_tp = fp_fp = 0
        for run in runs:
            for r in run:
                gt_is_tp = r["ground_truth"] == "TRUE_POSITIVE"
                pred_is_tp = r["prediction"] == "TRUE_POSITIVE"
                if gt_is_tp and pred_is_tp: tp_tp += 1
                elif gt_is_tp and not pred_is_tp: tp_fp += 1
                elif not gt_is_tp and pred_is_tp: fp_tp += 1
                else: fp_fp += 1

        total = tp_tp + tp_fp + fp_tp + fp_fp
        cm = np.array([[tp_tp, tp_fp], [fp_tp, fp_fp]])
        cm_pct = cm / total * 100

        ax = axes[idx]
        ax.imshow(cm_pct, cmap=cmap, vmin=0, vmax=100)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{cm[i,j]}\n({cm_pct[i,j]:.1f}%)",
                        ha="center", va="center", fontsize=11,
                        color="white" if cm_pct[i,j] > 50 else "black")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Pred: TP", "Pred: FP"])
        ax.set_yticklabels(["Actual: TP", "Actual: FP"])
        ax.set_title(f"{title} (n={total})")

    fig.suptitle("Aggregated Confusion Matrices", fontsize=13, y=1.02)
    fig.tight_layout()
    save_fig(fig, "fig4_confusion_matrices")

    # ── Fig 5: Accuracy Across Runs (stability) ──
    fig, ax = plt.subplots(figsize=(7, 4))
    run_idx = list(range(1, num_runs + 1))
    ax.plot(run_idx, [m["accuracy"] for m in baseline_metrics], "o-",
            color=BL_COL, label="Baseline", linewidth=2, markersize=8)
    ax.plot(run_idx, [m["accuracy"] for m in enhanced_metrics], "s-",
            color=EN_COL, label="Enhanced", linewidth=2, markersize=8)
    ax.set_xlabel("Run")
    ax.set_ylabel("Accuracy")
    ax.set_title("Classification Accuracy Across Runs")
    ax.set_xticks(run_idx)
    ax.set_ylim(0, 1.05)
    ax.legend()
    ax.grid(alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save_fig(fig, "fig5_accuracy_stability")

    # ── Fig 6: Per-Case Confidence Comparison ──
    fig, ax = plt.subplots(figsize=(10, 4))
    x = np.arange(len(case_ids))
    w = 0.35
    ax.bar(x - w/2, [baseline_per_case_conf[cid] for cid in case_ids], w,
           label="Baseline", color=BL_COL, edgecolor="white")
    ax.bar(x + w/2, [enhanced_per_case_conf[cid] for cid in case_ids], w,
           label="Enhanced", color=EN_COL, edgecolor="white")
    ax.set_ylabel("Average Confidence (1-5)")
    ax.set_title("Per-Case Average Confidence")
    ax.set_xticks(x)
    ax.set_xticklabels([f"C{cid}\n({gt})" for cid, gt in zip(case_ids, gt_labels)], fontsize=9)
    ax.set_ylim(0, 5.5)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save_fig(fig, "fig6_per_case_confidence")

    # ── Fig 7: Summary Quality Evaluation ──
    fig, ax = plt.subplots(figsize=(7, 4))
    eval_labels = ["Helpful", "Accurate", "Relevant"]
    eval_vals = [eval_agg["helpful_pct"], eval_agg["accurate_pct"], eval_agg["relevant_pct"]]
    bars = ax.bar(eval_labels, eval_vals, color=["#2ecc71", "#3498db", "#9b59b6"],
                  edgecolor="white", width=0.5)
    for bar in bars:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{bar.get_height():.0f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax.set_ylabel("Percentage (%)")
    ax.set_title("LLM Summary Quality Assessment")
    ax.set_ylim(0, 110)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    save_fig(fig, "fig7_summary_quality")

    # ── LaTeX Table ──
    latex = r"""\begin{table}[htbp]
\centering
\caption{LLM Vulnerability Triage: Baseline vs.\ Enhanced (""" + str(num_runs) + r""" runs, 10 cases)}
\label{tab:llm-triage}
\begin{tabular}{lccc}
\toprule
\textbf{Metric} & \textbf{Baseline} & \textbf{Enhanced} & \textbf{$\Delta$} \\
\midrule
"""
    rows = [
        ("Accuracy", "accuracy_mean", "accuracy_std"),
        ("Precision", "precision_mean", None),
        ("Recall", "recall_mean", None),
        ("F1 Score", "f1_mean", None),
        ("TP Detection", "tp_accuracy_mean", None),
        ("FP Detection", "fp_accuracy_mean", None),
    ]
    for label, key, std_key in rows:
        b = analysis["baseline"][key]
        e = analysis["enhanced"][key]
        d = e - b
        if std_key:
            b_std = analysis["baseline"][std_key]
            e_std = analysis["enhanced"][std_key]
            latex += f"{label} & {b:.3f} $\\pm$ {b_std:.3f} & {e:.3f} $\\pm$ {e_std:.3f} & {d:+.3f} \\\\\n"
        else:
            latex += f"{label} & {b:.3f} & {e:.3f} & {d:+.3f} \\\\\n"

    b_c = analysis["baseline"]["confidence_mean"]
    e_c = analysis["enhanced"]["confidence_mean"]
    latex += f"Confidence (1--5) & {b_c:.2f} & {e_c:.2f} & {e_c-b_c:+.2f} \\\\\n"

    latex += r"""\bottomrule
\end{tabular}
\end{table}

\begin{table}[htbp]
\centering
\caption{LLM-Generated Summary Quality Assessment}
\label{tab:summary-quality}
\begin{tabular}{lc}
\toprule
\textbf{Metric} & \textbf{Score} \\
\midrule
"""
    latex += f"Helpful & {eval_agg['helpful_pct']:.0f}\\% \\\\\n"
    latex += f"Accurate & {eval_agg['accurate_pct']:.0f}\\% \\\\\n"
    latex += f"Relevant & {eval_agg['relevant_pct']:.0f}\\% \\\\\n"
    latex += f"Completeness (1--5) & {eval_agg['avg_completeness']:.1f} \\\\\n"
    latex += r"""\bottomrule
\end{tabular}
\end{table}
"""

    with open(os.path.join(output_dir, "tables.tex"), "w") as f:
        f.write(latex)
    logger.info("  Saved tables.tex")

    return analysis


if __name__ == "__main__":
    run_experiment()
