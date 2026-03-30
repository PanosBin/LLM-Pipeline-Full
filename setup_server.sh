#!/bin/bash
# ==========================================================
# Setup script for Server (no sudo needed - runs as root)
# Fixes broken repos and installs everything from scratch
# ==========================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "LLM-Pipeline Setup - Server"
echo "=========================================="

# ----------------------------------------------------------
# 1. Fix broken repos and install system dependencies
# ----------------------------------------------------------
echo "[1/8] Fixing repos and installing system dependencies..."

# Remove broken nodesource repo if it exists
rm -f /etc/apt/sources.list.d/nodesource.list 2>/dev/null || true
rm -f /etc/apt/sources.list.d/nodesource.list.save 2>/dev/null || true

apt-get update -qq || true
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
    liblzma-dev \
    uuid-dev \
    tk-dev \
    git \
    curl \
    > /dev/null 2>&1 || echo "WARNING: Some system deps may have failed. Continuing..."
echo "System dependencies done."

# ----------------------------------------------------------
# 2. Install pyenv (if needed)
# ----------------------------------------------------------
echo "[2/8] Setting up pyenv..."
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"

if ! command -v pyenv &> /dev/null; then
    curl -s https://pyenv.run | bash
fi

eval "$(pyenv init -)" 2>/dev/null || true
eval "$(pyenv virtualenv-init -)" 2>/dev/null || true

SHELL_RCS="" 
[ -f "$HOME/.bashrc" ] && SHELL_RCS="$HOME/.bashrc" 
[ -f "$HOME/.zshrc" ] && SHELL_RCS="$SHELL_RCS $HOME/.zshrc" 
# If neither exists, create .zshrc (server uses zsh) 
if [ -z "$SHELL_RCS" ]; then 
    touch "$HOME/.zshrc" 
    SHELL_RCS="$HOME/.zshrc" 
fi

for SHELL_RC in $SHELL_RCS; do 
if ! grep -q 'pyenv init' "$SHELL_RC" 2>/dev/null; then
    echo '' >> "$SHELL_RC"
    echo '# pyenv' >> "$SHELL_RC"
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> "$SHELL_RC"
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> "$SHELL_RC"
    echo 'eval "$(pyenv init -)"' >> "$SHELL_RC"
    echo 'eval "$(pyenv virtualenv-init -)"' >> "$SHELL_RC"
    echo "Added pyenv to $SHELL_RC"
fi
# Also add Poetry to shell config so it works in new shells                
if ! grep -q '.local/bin' "$SHELL_RC" 2>/dev/null; then                    
    echo '' >> "$SHELL_RC"                                                 
    echo '# Poetry' >> "$SHELL_RC"                                         
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"             
    echo "Added Poetry path to $SHELL_RC" 
fi 
done


# ----------------------------------------------------------
# 3. Install Python 3.11.9 via pyenv
# ----------------------------------------------------------
echo "[3/8] Installing Python 3.11.9 (this may take a few minutes)..."
NEED_INSTALL=false

if pyenv versions --bare 2>/dev/null | grep -q "^3.11.9$"; then
    if ! "$PYENV_ROOT/versions/3.11.9/bin/python3.11" -c "import _ctypes" 2>/dev/null; then
        echo "Python 3.11.9 is broken. Reinstalling..."
        NEED_INSTALL=true
    else
        echo "Python 3.11.9 already installed and healthy."
    fi
else
    NEED_INSTALL=true
fi

if [ "$NEED_INSTALL" = true ]; then
    pyenv uninstall -f 3.11.9 2>/dev/null || true
    pyenv install 3.11.9
fi

pyenv local 3.11.9
PYTHON_BIN="$PYENV_ROOT/versions/3.11.9/bin/python3.11"
echo "Using Python: $($PYTHON_BIN --version)"

# ----------------------------------------------------------
# 4. Install Poetry
# ----------------------------------------------------------
echo "[4/8] Setting up Poetry..."
export PATH="$HOME/.local/bin:$PATH"
if ! command -v poetry &> /dev/null; then
    curl -sSL https://install.python-poetry.org | "$PYTHON_BIN" -
fi
echo "Poetry version: $(poetry --version)"

# ----------------------------------------------------------
# 5. Install Python dependencies
# ----------------------------------------------------------
echo "[5/8] Installing Python dependencies..."
poetry env remove python3.11 2>/dev/null || true
poetry env use "$PYTHON_BIN"
poetry install
echo "Dependencies installed."

# ----------------------------------------------------------
# 6. Build Tree-sitter Java library
# ----------------------------------------------------------
echo "[6/8] Building Tree-sitter Java library..."
if [ ! -f "tree-sitter-java/src/parser.c" ]; then
    echo "tree-sitter-java source not found. Fetching..."
    rm -rf tree-sitter-java
    git clone https://github.com/tree-sitter/tree-sitter-java.git


fi

rm -f build/languages.so
mkdir -p build
poetry run python -c "
from tree_sitter import Language
Language.build_library('build/languages.so', ['tree-sitter-java'])
print('Tree-sitter Java compiled successfully.')
"

# ----------------------------------------------------------
# 7. Hugging Face login
# ----------------------------------------------------------
echo "[7/8] Hugging Face login..."
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs) 2>/dev/null || true
fi

if [ -n "$HF_TOKEN" ]; then
    poetry run huggingface-cli login --token "$HF_TOKEN" --add-to-git-credential 2>/dev/null || true
    echo "Logged in to Hugging Face."
else
    echo "SKIPPED - create .env file with HF_TOKEN first:"
    echo "  echo 'HF_TOKEN=\"hf_your_token\"' > .env"
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
echo "To run the pipeline:"
echo ""
echo "  # Quick test (no LLM):"
echo "  poetry run python main_file.py --dir ./data/apps/Damn-Vulnerable-Bank --scan --no-summarize --output-name quick_test"
echo ""
echo "  # Full pipeline with evaluation:"
echo "  poetry run python main_file.py --dir ./data/apps/Damn-Vulnerable-Bank --scan --evaluate --output-name test_run"
echo ""
