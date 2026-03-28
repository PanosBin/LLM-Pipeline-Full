#!/bin/bash
# Setup script for LLM-Pipeline

set -e

echo "=========================================="
echo "LLM-Pipeline Setup Script"
echo "=========================================="

# Check if Python 3.11+ is available
echo "Checking Python version..."
python_version=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
if [[ $(echo "$python_version < 3.11" | bc) -eq 1 ]]; then
    echo "ERROR: Python 3.11 or higher is required. Current version: $python_version"
    exit 1
fi
echo "✓ Python version: $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
if [ -f "pyproject.toml" ]; then
    echo "Using Poetry..."
    pip install poetry
    poetry install
elif [ -f "requirements.txt" ]; then
    echo "Using requirements.txt..."
    pip install -r requirements.txt
else
    echo "ERROR: No pyproject.toml or requirements.txt found!"
    exit 1
fi

# Compile Tree-sitter language
echo "Compiling Tree-sitter Java language..."
if [ ! -d "tree-sitter-java" ]; then
    echo "ERROR: tree-sitter-java directory not found!"
    echo "Please ensure the tree-sitter-java submodule is initialized:"
    echo "  git submodule update --init --recursive"
    exit 1
fi

# Create build directory
mkdir -p build

# Compile the language
python3 -c "
from tree_sitter import Language
Language.build_library('build/languages.so', ['tree-sitter-java'])
print('✓ Tree-sitter Java language compiled successfully')
"

echo ""
echo "=========================================="
echo "Setup completed successfully!"
echo "=========================================="
echo ""
echo "To use the pipeline:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Run the pipeline: python main.py --dir /path/to/android/app --scan"
echo ""
echo "For help: python main.py --help"
