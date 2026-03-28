"""
Enhanced summarizer with method call analysis.
Supervisor requirement: Analyze what methods a class uses to create more specific summaries.
"""

import re
import logging
from typing import Set, Optional
from transformers import AutoTokenizer, AutoModelForCausalLM
import warnings
import torch

logger = logging.getLogger(__name__)


def strip_imports_and_boilerplate(code: str) -> str:
    """
    Remove package/import lines and keep from first class/interface/enum onward.
    """
    lines = code.splitlines()
    kept = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("package "):
            continue
        kept.append(line)
    code_no_imports = "\n".join(kept)

    match = re.search(r"\b(class|interface|enum)\b", code_no_imports)
    return code_no_imports[match.start():] if match else code_no_imports


class EnhancedLlamaSummarizer:
    """
    Enhanced summarizer that analyzes method calls within classes
    to generate more specific and contextual summaries.
    """

    def __init__(self, model_name="codellama/CodeLlama-7b-Instruct-hf", device="cuda"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name, device_map="auto", load_in_8bit=True, torch_dtype=torch.bfloat16
        )
        self.device = device
        self.context_size = 4096  # Model max context size

    # -------------------------
    # Prompt formatting (CodeLlama Instruct)
    # -------------------------
    def _format_codellama_inst(self, system: str, user: str) -> str:
        return (
            "<s>[INST] <<SYS>>\n"
            f"{system.strip()}\n"
            "<</SYS>>\n\n"
            f"{user.strip()} [/INST]"
        )

    # -------------------------
    # Extraction helpers
    # -------------------------
    def extract_method_calls(self, code: str) -> Set[str]:
        pattern = r"\b(?!if|for|while|switch|catch)([a-zA-Z_][a-zA-Z0-9_]*)\s*\("
        matches = re.findall(pattern, code)

        filtered = set()
        for match in matches:
            if match[0].isupper():  # constructor/type
                continue
            if match in ["new", "return", "throw", "assert", "synchronized"]:
                continue
            filtered.add(match)
        return filtered

    def extract_class_dependencies(self, code: str) -> Set[str]:
        pattern = r"\b([A-Z][a-zA-Z0-9_]*)\b"
        matches = re.findall(pattern, code)

        common_types = {
            "String", "Integer", "Boolean", "Long", "Double", "Float",
            "List", "Map", "Set", "ArrayList", "HashMap", "HashSet",
            "Object", "Class", "System", "Exception", "Override",
            "View", "Context", "Bundle", "Intent",
        }
        return set(m for m in matches if m not in common_types)

    # -------------------------
    # Output cleaning (remove ONLY bad openers)
    # -------------------------
    def _capitalize_first_char(self, s: str) -> str:
        s = (s or "").strip()
        return (s[0].upper() + s[1:]) if s else s  # keeps rest unchanged [web:153]

    def _strip_bad_openers(self, text: str) -> str:
        """
        Remove repetitive starting phrases, but do not destroy content.
        After stripping, capitalize first char to keep it grammatical.
        """
        t = (text or "").strip()

        if "```" in t:
            t = t.split("```")[-1].strip()

        t = re.sub(r"^\s*(Answer|Summary)\s*:\s*", "", t, flags=re.IGNORECASE).strip()

        opener_patterns = [
            r"^\s*This\s+code\s+snippet\s+is\s+(a\s+part\s+of\s+)?(an\s+)?Android\s+app\s+that\s+",
            r"^\s*This\s+code\s+snippet\s+",
            r"^\s*This\s+class\s+is\s+",
            r"^\s*The\s+purpose\s+of\s+this\s+class\s+is\s+to\s+",
            r"^\s*The\s+purpose\s+is\s+to\s+",
            r"^\s*The\s+classes?\s+share\s+common\s+functionality\s+(related\s+to|for)\s+",
            r"^\s*The\s+\w+\s+classes?\s+share\s+common\s+functionality\s+(related\s+to|for)\s+",
            r"^\s*The\s+classes?\s+represent\s+(a\s+)?common\s+purpose\s+of\s+",

            # NEW: remove "collectively provide" style openers too
            r"^\s*The\s+classes\s+collectively\s+(provide|implement|represent|offer)\s+",
            r"^\s*These\s+classes\s+(provide|implement|represent|offer)\s+",
            r"^\s*The\s+classes?\s+share\s+(a\s+)?common\s+purpose\s+of\s+",
            r"^\s*The\s+classes\s+in\s+the\s+cluster\s+(provide|implement|represent|offer)\s+",
        ]
        for pat in opener_patterns:
            t = re.sub(pat, "", t, flags=re.IGNORECASE).strip()

        t = re.sub(r"\s{2,}", " ", t).strip()
        return self._capitalize_first_char(t)

    def _first_sentence(self, text: str) -> str:
        t = (text or "").strip()
        if not t:
            return ""
        parts = re.split(r"(?<=[.!?])\s+", t)
        return (parts[0] if parts else t).strip()

    def _looks_bad_or_generic(self, s: str) -> bool:
        t = (s or "").strip().lower()
        if len(t) < 10:
            return True
        generic_markers = [
            "no summary produced",
            "performs the main operation",
            "implements a related feature",
            "manages ",
            "coordinates ",
        ]
        return any(m in t for m in generic_markers)

    def _keyword_fallback(self, code: str, kind: str = "code") -> str:
        c = (code or "").lower()

        if "biometricprompt" in c or "fingerprint" in c:
            return "Authenticates the user with biometrics before allowing a sensitive action."
        if "encrypt" in c and "decrypt" in c:
            return "Encrypts and decrypts data as part of the app’s secure data handling."
        if "decrypt" in c:
            return "Decrypts received data and prepares it for use in the app."
        if "encrypt" in c:
            return "Encrypts data before it is stored or sent."
        if "recyclerview" in c or "viewholder" in c or "adapter" in c:
            return "Builds and displays list-based UI data for the user."
        if "webview" in c:
            return "Loads and controls web content inside a WebView."
        if "login" in c or "authenticate" in c:
            return "Handles user authentication and session setup."
        if kind == "cluster":
            return "Implements one coherent feature across multiple related classes."
        if kind == "class":
            return "Implements the main workflow of this class."
        return "Implements the main workflow of this code."

    def _clean_summary(self, raw: str, code_for_fallback: str, kind: str) -> str:
        t = self._strip_bad_openers(raw)
        t = self._first_sentence(t)
        t = t.strip()

        if self._looks_bad_or_generic(t):
            t = self._keyword_fallback(code_for_fallback, kind=kind)

        t = self._first_sentence(t).strip()
        if not t:
            t = self._keyword_fallback(code_for_fallback, kind=kind)
        return t

    # -------------------------
    # Generation helper (token-based truncation + retry)
    # -------------------------
    def _generate_one_sentence(self, system_message: str, user_message: str, code_for_fallback: str,
                              max_new_tokens: int, kind: str) -> str:
        prompt = self._format_codellama_inst(system_message, user_message)

        max_input = self.context_size - max_new_tokens
        if max_input < 512:
            max_input = max(256, self.context_size // 2)

        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=max_input,
        ).to(self.device)

        gen_kwargs = dict(
            max_new_tokens=max_new_tokens,
            do_sample=False,
            eos_token_id=self.tokenizer.eos_token_id,
            pad_token_id=self.tokenizer.pad_token_id or self.tokenizer.eos_token_id,
            repetition_penalty=1.1,
        )
        output_ids = self.model.generate(**inputs, **gen_kwargs)

        new_tokens = output_ids[0, inputs["input_ids"].shape[1]:]
        raw = self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

        if not raw:
            full = self.tokenizer.decode(output_ids[0], skip_special_tokens=True)
            raw = full.replace(prompt, "").strip()

        cleaned = self._clean_summary(raw, code_for_fallback=code_for_fallback, kind=kind)

        if self._looks_bad_or_generic(cleaned):
            retry_user = (
                "Rewrite the summary to be specific.\n"
                "Constraints:\n"
                "- ONE sentence.\n"
                "- Describe concrete actions and the main data being handled.\n"
                "- Do NOT start with: 'This class', 'This code snippet', 'The classes share', 'The classes collectively'.\n\n"
                + user_message
            )
            prompt2 = self._format_codellama_inst(system_message, retry_user)
            inputs2 = self.tokenizer(
                prompt2,
                return_tensors="pt",
                truncation=True,
                max_length=max_input,
            ).to(self.device)
            output_ids2 = self.model.generate(**inputs2, **gen_kwargs)
            new_tokens2 = output_ids2[0, inputs2["input_ids"].shape[1]:]
            raw2 = self.tokenizer.decode(new_tokens2, skip_special_tokens=True).strip()
            if not raw2:
                full2 = self.tokenizer.decode(output_ids2[0], skip_special_tokens=True)
                raw2 = full2.replace(prompt2, "").strip()
            cleaned2 = self._clean_summary(raw2, code_for_fallback=code_for_fallback, kind=kind)
            return cleaned2

        return cleaned

    # -------------------------
    # Public API
    # -------------------------
    def summarize_code(self, code: str, max_length=100):
        code_clean = strip_imports_and_boilerplate(code)

        system_message = (
            "You are a professional Java code interpreter.\n"
            "Return ONE sentence describing the code’s purpose and behavior.\n"
            "Avoid boilerplate openers (e.g., 'This code snippet...', 'This class...', 'The purpose is...').\n"
            "Be concise and direct."
        )

        user_message = (
            "Summarize what the code does in ONE sentence.\n"
            "Code:\n```java\n"
            f"{code_clean}\n"
            "```"
        )

        return self._generate_one_sentence(
            system_message=system_message,
            user_message=user_message,
            code_for_fallback=code_clean,
            max_new_tokens=max_length,
            kind="code",
        )

    def summarize_class_with_context(self, java_class, max_length=150):
        code = java_class.code
        class_name = java_class.name
        code_clean = strip_imports_and_boilerplate(code)

        method_calls = self.extract_method_calls(code_clean)
        dependencies = self.extract_class_dependencies(code_clean)
        method_names = [m.name for m in java_class.methods]

        context_info = []
        if method_calls:
            context_info.append(f"Calls: {', '.join(list(method_calls)[:10])}")
        if dependencies:
            context_info.append(f"Uses: {', '.join(list(dependencies)[:10])}")
        if method_names:
            context_info.append(f"Defines: {', '.join(method_names[:5])}")
        context_str = "; ".join(context_info) if context_info else "No additional context"

        system_message = (
            "You are a professional Java code interpreter.\n"
            "Return ONE sentence describing the class’s purpose and behavior.\n"
            "Avoid boilerplate openers (e.g., 'This class...', 'The purpose is...').\n"
            "Do not output method lists; describe what the class does."
        )

        user_message = (
            f"Class name: {class_name}\n"
            f"Context: {context_str}\n"
            "Summarize what this class does in ONE sentence.\n"
            "Code:\n```java\n"
            f"{code_clean}\n"
            "```"
        )

        return self._generate_one_sentence(
            system_message=system_message,
            user_message=user_message,
            code_for_fallback=code_clean,
            max_new_tokens=max_length,
            kind="class",
        )

    def summarize_cluster(self, cluster, max_length=200):
        if not cluster:
            return "Empty cluster."

        class_names = [cls.name for cls in cluster]

        all_method_calls = set()
        all_dependencies = set()
        for cls in cluster:
            code_clean = strip_imports_and_boilerplate(cls.code)
            all_method_calls.update(self.extract_method_calls(code_clean))
            all_dependencies.update(self.extract_class_dependencies(code_clean))

        context_info = []
        context_info.append(f"Classes in cluster (do not list in answer): {', '.join(class_names[:8])}")
        if all_method_calls:
            context_info.append(f"Common calls: {', '.join(list(all_method_calls)[:12])}")
        if all_dependencies:
            context_info.append(f"Common types: {', '.join(list(all_dependencies)[:12])}")
        context_str = "; ".join(context_info)

        system_message = (
            "You are a professional Java code interpreter.\n"
            "Return ONE sentence describing what this group of classes collectively does.\n"
            "Avoid: 'The classes share common functionality...' and 'The classes collectively...'.\n"
            "Do not list class names; describe the shared feature."
        )

        combined_code = "\n\n".join(
            [f"// Class: {cls.name}\n{strip_imports_and_boilerplate(cls.code)[:700]}" for cls in cluster[:3]]
        )

        user_message = (
            f"Context: {context_str}\n"
            "Summarize the shared purpose in ONE sentence.\n"
            "Code sample:\n```java\n"
            f"{combined_code}\n"
            "```"
        )

        return self._generate_one_sentence(
            system_message=system_message,
            user_message=user_message,
            code_for_fallback=combined_code,
            max_new_tokens=max_length,
            kind="cluster",
        )