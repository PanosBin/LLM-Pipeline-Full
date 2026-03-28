#!/bin/bash
# ==========================================================
# Setup script for Linux (Ubuntu/Debian) and WSL on Windows
# Run as root or with sudo
# ==========================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "LLM-Pipeline Setup - Linux / WSL"
echo "=========================================="

# ----------------------------------------------------------
# 1. Install system dependencies
# ----------------------------------------------------------
echo "[1/8] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    libffi-dev \
    zlib1g-dev \
    libssl-dev \
    libbz2-dev \
    libsqlite3-dev \
    libncurses5-dev \
    libncursesw5-dev \
    libreadline-dev \
    libgdbm-dev \
    libgdbm-compat-dev \
    liblzma-dev \
    uuid-dev \
    tk-dev \
    git \
    curl \
    > /dev/null
echo "System dependencies installed."

# ----------------------------------------------------------
# 2. Install pyenv (if needed)
# ----------------------------------------------------------
echo "[2/8] Setting up pyenv..."
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"

if ! command -v pyenv &> /dev/null; then
    curl -s https://pyenv.run | bash
fi

eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# Persist pyenv to shell config (only if not already there)
SHELL_RC="$HOME/.bashrc"
if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
fi
if ! grep -q 'pyenv init' "$SHELL_RC" 2>/dev/null; then
    echo '' >> "$SHELL_RC"
    echo '# pyenv' >> "$SHELL_RC"
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> "$SHELL_RC"
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> "$SHELL_RC"
    echo 'eval "$(pyenv init -)"' >> "$SHELL_RC"
    echo 'eval "$(pyenv virtualenv-init -)"' >> "$SHELL_RC"
    echo "Added pyenv to $SHELL_RC"
fi

# ----------------------------------------------------------
# 3. Install Python 3.11.9 via pyenv
# ----------------------------------------------------------
echo "[3/8] Checking Python 3.11.9..."
NEED_INSTALL=false

if pyenv versions --bare | grep -q "^3.11.9$"; then
    if ! "$PYENV_ROOT/versions/3.11.9/bin/python3.11" -c "import _ctypes" 2>/dev/null; then
        echo "Python 3.11.9 is broken (missing _ctypes). Reinstalling..."
        NEED_INSTALL=true
    else
        echo "Python 3.11.9 is healthy."
    fi
else
    echo "Python 3.11.9 not found. Installing..."
    NEED_INSTALL=true
fi

if [ "$NEED_INSTALL" = true ]; then
    pyenv uninstall -f 3.11.9 2>/dev/null || true
    pyenv install 3.11.9
fi

pyenv local 3.11.9
PYTHON_BIN="$PYENV_ROOT/versions/3.11.9/bin/python3.11"
echo "Using Python: $PYTHON_BIN ($($PYTHON_BIN --version))"

# ----------------------------------------------------------
# 4. Install Poetry (if needed)
# ----------------------------------------------------------
echo "[4/8] Checking Poetry..."
export PATH="$HOME/.local/bin:$PATH"
if ! command -v poetry &> /dev/null; then
    echo "Installing Poetry..."
    curl -sSL https://install.python-poetry.org | "$PYTHON_BIN" -
fi
echo "Poetry version: $(poetry --version)"

# ----------------------------------------------------------
# 5. Create Poetry environment
# ----------------------------------------------------------
echo "[5/8] Setting up Poetry environment..."
poetry env remove python3.11 2>/dev/null || true
poetry env use "$PYTHON_BIN"
poetry install
echo "Environment ready."

# ----------------------------------------------------------
# 6. Build Tree-sitter Java library
# ----------------------------------------------------------
echo "[6/8] Building Tree-sitter Java library..."
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
# 7. Hugging Face login (optional - needed for LLM mode)
# ----------------------------------------------------------
echo "[7/8] Hugging Face login..."
if [ -n "$HF_TOKEN" ]; then
    poetry run huggingface-cli login --token "$HF_TOKEN" --add-to-git-credential
    echo "Logged in to Hugging Face."
else
    echo "SKIPPED - set HF_TOKEN env variable to enable."
    echo "  export HF_TOKEN=\"hf_your_token_here\""
    echo "  (only needed for LLM summarization mode)"
fi

# ----------------------------------------------------------
# 8. Verify installation
# ----------------------------------------------------------
echo "[8/8] Verifying installation..."
poetry run python -c "
import torch
import transformers
from tree_sitter import Language
print(f'  torch:        {torch.__version__}')
print(f'  transformers: {transformers.__version__}')
print(f'  CUDA:         {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'  GPU:          {torch.cuda.get_device_name(0)}')
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
