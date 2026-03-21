#!/bin/bash
# Virtual Environment Setup Script for ROP Tools Suite

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

echo "========================================="
echo "ROP Tools Suite - Virtual Environment Setup"
echo "========================================="
echo ""

# Check if venv already exists
if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment already exists at: $VENV_DIR"
    read -p "Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing virtual environment..."
        rm -rf "$VENV_DIR"
    else
        echo "Using existing virtual environment."
        echo "To activate manually: source venv/bin/activate"
        exit 0
    fi
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv "$VENV_DIR"

# Activate virtual environment
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies from requirements.txt..."
pip install -r "$SCRIPT_DIR/requirements.txt"

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Virtual environment created at: $VENV_DIR"
echo ""
echo "To activate manually:"
echo "  source venv/bin/activate"
echo ""
echo "To install tools system-wide with virtualenv:"
echo "  ./install_with_venv.sh"
echo ""