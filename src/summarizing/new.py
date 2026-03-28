from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import warnings
import torch

class LlamaSummarizer:
    def __init__(
        self,
        model_name="meta-llama/CodeLlama-7b-Instruct-hf",  # Changed to CodeLlama
        use_8bit=False,                # set False if you prefer full precision
        use_bf16=True,                # Hopper (H100) supports bfloat16 well
        max_new_tokens=64
    ):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)

        torch_dtype = torch.bfloat16 if use_bf16 else torch.float16
        
        if use_8bit:
            quant_config = BitsAndBytesConfig(
                load_in_8bit=True,
                llm_int8_threshold=6.0,
                llm_int8_has_fp16_weight=False
            )
            
            print("Loading quantized model on CPU first...")
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                quantization_config=quant_config,
                device_map="cpu",  # Load on CPU first
                torch_dtype=torch_dtype,
                low_cpu_mem_usage=True
            )
            
            print("Moving quantized model to GPU...")
            try:
                self.model = self.model.to("cuda:0")
                print("Quantized model successfully moved to GPU!")
            except Exception as e:
                print(f"Warning: Could not move quantized model to GPU: {e}")
                print("Continuing with CPU inference (will be slower)")
        else:
            # Load on CPU first to avoid CUDA context issues
            print("Loading model on CPU first...")
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch_dtype,
                device_map="cpu"  # Load on CPU
            )
            
            # Then move to GPU
            print("Moving model to GPU...")
            try:
                self.model = self.model.to("cuda:0")
                print("Model successfully moved to GPU!")
            except Exception as e:
                print(f"Warning: Could not move model to GPU: {e}")
                print("Continuing with CPU inference (will be slower)")
        
        # Ensure pad token for chat/instruction models
        if self.tokenizer.pad_token_id is None and self.tokenizer.eos_token_id is not None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        self.context_size = getattr(self.model.config, "max_position_embeddings", 4096)
        self.max_new_tokens = max_new_tokens

    def _build_prompt(self, code: str) -> str:
        system_message = (
            "You are a professional Java code interpreter. "
            "Summarize the following code in ONE precise and concise sentence describing its overall functionality."
        )
        # Plain-text prompt; no backticks that could confuse token count
        return f"{system_message}\n\nCode:\n{code}\n\nSummary:"

    def _truncate_if_needed(self, prompt: str) -> str:
        # Ensure total tokens <= context_size - max_new_tokens
        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=False)
        max_input_tokens = max(self.context_size - self.max_new_tokens, 1)
        if inputs.input_ids.shape[-1] > max_input_tokens:
            warnings.warn("Input too long for model context. Truncating input for summarization.")
            # Re-tokenize with truncation
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=max_input_tokens)
            return self.tokenizer.decode(inputs.input_ids[0], skip_special_tokens=True)
        return prompt

    def summarize_code(self, code: str) -> str:
        prompt = self._build_prompt(code)
        prompt = self._truncate_if_needed(prompt)

        inputs = self.tokenizer(prompt, return_tensors="pt", padding=True)
        # Move tensors to same device as model
        device = next(self.model.parameters()).device
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.inference_mode():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=False,
                eos_token_id=self.tokenizer.eos_token_id,
                pad_token_id=self.tokenizer.pad_token_id
            )

        text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        # Extract content after "Summary:" if present
        return text.split("Summary:")[-1].strip() if "Summary:" in text else text.strip()

    def summarize_cluster(self, cluster):
        # Handle either:
        # - cluster is a list of JavaMethod objects (with .code)
        # - cluster is an object exposing .get_elements() -> list[JavaMethod]
        if hasattr(cluster, "get_elements"):
            methods = cluster.get_elements()
        else:
            methods = cluster

        # Concatenate top-N methods to fit context
        MAX_METHODS = 8
        code_snippets = []
        for m in methods[:MAX_METHODS]:
            try:
                code_snippets.append(m.code)
            except Exception:
                continue
        code = "\n\n".join(code_snippets)
        return self.summarize_code(code)
