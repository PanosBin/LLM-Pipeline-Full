#!/bin/bash
# ==========================================================
# Setup script for macOS (Apple Silicon & Intel)
# ==========================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "LLM-Pipeline Setup - macOS"
echo "=========================================="

# ----------------------------------------------------------
# 1. Check / install Homebrew
# ----------------------------------------------------------
echo "[1/7] Checking Homebrew..."
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add brew to PATH for Apple Silicon
    if [ -f /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
else
    echo "Homebrew found."
fi

# ----------------------------------------------------------
# 2. Install Python 3.11 via Homebrew (if needed)
# ----------------------------------------------------------
echo "[2/7] Checking Python 3.11..."
if ! command -v python3.11 &> /dev/null; then
    echo "Installing Python 3.11..."
    brew install python@3.11
fi
PYTHON_BIN=$(command -v python3.11)
echo "Using Python: $PYTHON_BIN ($($PYTHON_BIN --version))"

# ----------------------------------------------------------
# 3. Install Poetry (if needed)
# ----------------------------------------------------------
echo "[3/7] Checking Poetry..."
if ! command -v poetry &> /dev/null; then
    echo "Installing Poetry..."
    curl -sSL https://install.python-poetry.org | "$PYTHON_BIN" -
    export PATH="$HOME/.local/bin:$PATH"
fi
echo "Poetry version: $(poetry --version)"

# ----------------------------------------------------------
# 4. Create Poetry environment with Python 3.11
# ----------------------------------------------------------
echo "[4/7] Setting up Poetry environment..."
poetry env use "$PYTHON_BIN"
poetry install
echo "Environment ready."

# ----------------------------------------------------------
# 5. Build Tree-sitter Java library
# ----------------------------------------------------------
echo "[5/7] Building Tree-sitter Java library..."
if [ ! -d "tree-sitter-java" ]; then
    echo "ERROR: tree-sitter-java directory not found!"
    echo "Make sure the repo was cloned with all files."
    exit 1
fi

rm -f build/languages.so
mkdir -p build
poetry run python -c "
from tree_sitter import Language
Language.build_library('build/languages.so', ['tree-sitter-java'])
print('Tree-sitter Java compiled successfully.')
"

# ----------------------------------------------------------
# 6. Hugging Face login (optional - needed for LLM mode)
# ----------------------------------------------------------
echo "[6/7] Hugging Face login..."
if [ -n "$HF_TOKEN" ]; then
    poetry run huggingface-cli login --token "$HF_TOKEN" --add-to-git-credential
    echo "Logged in to Hugging Face."
else
    echo "SKIPPED - set HF_TOKEN env variable to enable."
    echo "  export HF_TOKEN=\"hf_your_token_here\""
    echo "  (only needed for LLM summarization mode)"
fi

# ----------------------------------------------------------
# 7. Verify installation
# ----------------------------------------------------------
echo "[7/7] Verifying installation..."
poetry run python -c "
import torch
import transformers
from tree_sitter import Language
print(f'  torch:        {torch.__version__}')
print(f'  transformers: {transformers.__version__}')
print(f'  GPU (MPS):    {torch.backends.mps.is_available()}')
print('All imports OK.')
"

echo ""
echo "=========================================="
echo "Setup completed successfully!"
echo "=========================================="
echo ""
echo "Usage:"
echo "  # Without LLM (debugging/fast):"
echo "  poetry run python main.py --dir ./data/apps/Damn-Vulnerable-Bank --scan --no-summarize"
echo ""
echo "  # With LLM (full pipeline):"
echo "  export HF_TOKEN=\"hf_your_token_here\"  # first time only"
echo "  poetry run python main.py --dir ./data/apps/Damn-Vulnerable-Bank --scan"
echo ""
