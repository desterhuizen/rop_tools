#!/bin/bash
# Installation script for ROP Tools Suite using virtual environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
INSTALL_DIR="$HOME/.local/bin"
BIN_DIR="$SCRIPT_DIR/bin"

echo "========================================="
echo "ROP Tools Suite - Installation with venv"
echo "========================================="
echo ""

# Check if venv exists
if [ ! -d "$VENV_DIR" ]; then
    echo "Error: Virtual environment not found!"
    echo "Please run ./setup_venv.sh first"
    exit 1
fi

# Check if venv Python exists
if [ ! -f "$VENV_DIR/bin/python3" ]; then
    echo "Error: Virtual environment Python not found!"
    echo "Please run ./setup_venv.sh to create the virtual environment"
    exit 1
fi

# Create ~/.local/bin if it doesn't exist
mkdir -p "$INSTALL_DIR"

# Create bin directory for wrapper scripts
mkdir -p "$BIN_DIR"

echo "Creating wrapper scripts..."

# Create wrapper script for shellgen
cat > "$BIN_DIR/shellgen" << EOF
#!/bin/bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
"\$SCRIPT_DIR/venv/bin/python3" "\$SCRIPT_DIR/shellgen/shellgen_cli.py" "\$@"
EOF

# Create wrapper script for hash_generator
cat > "$BIN_DIR/hash_generator" << EOF
#!/bin/bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
"\$SCRIPT_DIR/venv/bin/python3" "\$SCRIPT_DIR/shellgen/hash_generator.py" "\$@"
EOF

# Create wrapper script for get_rop_gadgets
cat > "$BIN_DIR/get_rop_gadgets" << EOF
#!/bin/bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
"\$SCRIPT_DIR/venv/bin/python3" "\$SCRIPT_DIR/rop/get_rop_gadgets.py" "\$@"
EOF

# Create wrapper script for get_base_address
cat > "$BIN_DIR/get_base_address" << EOF
#!/bin/bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
"\$SCRIPT_DIR/venv/bin/python3" "\$SCRIPT_DIR/rop/get_base_address.py" "\$@"
EOF

# Create wrapper script for rop_worksheet
cat > "$BIN_DIR/rop_worksheet" << EOF
#!/bin/bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
"\$SCRIPT_DIR/venv/bin/python3" "\$SCRIPT_DIR/rop/rop_worksheet.py" "\$@"
EOF

# Make wrapper scripts executable
chmod +x "$BIN_DIR"/*

echo "Creating symbolic links in ~/.local/bin/..."

# Create symbolic links
ln -sf "$BIN_DIR/shellgen" "$INSTALL_DIR/shellgen"
ln -sf "$BIN_DIR/hash_generator" "$INSTALL_DIR/hash_generator"
ln -sf "$BIN_DIR/get_rop_gadgets" "$INSTALL_DIR/get_rop_gadgets"
ln -sf "$BIN_DIR/get_base_address" "$INSTALL_DIR/get_base_address"
ln -sf "$BIN_DIR/rop_worksheet" "$INSTALL_DIR/rop_worksheet"

echo ""
echo "========================================="
echo "Installation Complete!"
echo "========================================="
echo ""
echo "Wrapper scripts created in: $BIN_DIR"
echo "Symbolic links created in: $INSTALL_DIR"
echo ""
echo "Verify installation:"
echo "  which shellgen"
echo "  shellgen --help"
echo ""
echo "Installed commands:"
echo "  - shellgen"
echo "  - hash_generator"
echo "  - get_rop_gadgets"
echo "  - get_base_address"
echo "  - rop_worksheet"
echo ""
echo "Note: All commands will use the Python interpreter from:"
echo "  $VENV_DIR/bin/python3"
echo ""