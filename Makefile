.PHONY: help test test-rop test-shellgen test-lib test-verbose coverage lint lint-fix install install-venv install-direct uninstall deps deps-test deps-lint clean

PYTHON ?= python3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ==============================================================================
# Testing
# ==============================================================================

test: ## Run all tests
	@total=0; \
	for suite in rop/tests shellgen/tests lib/tests target_builder/tests; do \
		output=$$($(PYTHON) -m unittest discover -s $$suite -q 2>&1); \
		echo "$$output"; \
		count=$$(echo "$$output" | grep -oE 'Ran ([0-9]+)' | grep -oE '[0-9]+'); \
		total=$$((total + count)); \
	done; \
	echo ""; \
	echo "========================================"; \
	echo "Total: $$total tests across all suites"; \
	echo "========================================"

test-rop: ## Run ROP tools tests
	$(PYTHON) -m unittest discover -s rop/tests -q

test-shellgen: ## Run shellgen tests
	$(PYTHON) -m unittest discover -s shellgen/tests -q

test-lib: ## Run shared library tests
	$(PYTHON) -m unittest discover -s lib/tests -q

test-target-builder: ## Run target builder tests
	$(PYTHON) -m unittest discover -s target_builder/tests -q

test-verbose: ## Run all tests with verbose output
	$(PYTHON) -m unittest discover -s rop/tests -v
	$(PYTHON) -m unittest discover -s shellgen/tests -v
	$(PYTHON) -m unittest discover -s lib/tests -v
	$(PYTHON) -m unittest discover -s target_builder/tests -v

coverage: ## Run tests with coverage report
	coverage run -m unittest discover -s rop/tests -q
	coverage run -a -m unittest discover -s shellgen/tests -q
	coverage run -a -m unittest discover -s lib/tests -q
	coverage run -a -m unittest discover -s target_builder/tests -q
	coverage report
	@echo ""
	@echo "Run 'make coverage-html' for an HTML report"

coverage-html: coverage ## Generate HTML coverage report
	coverage html
	@echo "Open htmlcov/index.html to view the report"

# ==============================================================================
# Linting
# ==============================================================================

lint: ## Run all linters
	flake8 lib/ rop/ shellgen/ code_snippets/ target_builder/
	black --check lib/ rop/ shellgen/ code_snippets/ target_builder/
	isort --check-only lib/ rop/ shellgen/ code_snippets/ target_builder/

lint-fix: ## Auto-format code with black and isort
	black lib/ rop/ shellgen/ code_snippets/ target_builder/
	isort lib/ rop/ shellgen/ code_snippets/ target_builder/

# ==============================================================================
# Installation
# ==============================================================================

install: install-venv ## Install tools (venv method, default)

install-venv: ## Install using virtual environment (recommended)
	@./setup_venv.sh
	@./install_with_venv.sh

install-direct: ## Install using direct symlinks (no venv)
	@mkdir -p ~/.local/bin
	@chmod +x shellgen/shellgen_cli.py shellgen/hash_generator.py \
		rop/get_rop_gadgets.py rop/get_base_address.py rop/rop_worksheet.py \
		target_builder/target_builder_cli.py
	@ln -sf "$(CURDIR)/shellgen/shellgen_cli.py" ~/.local/bin/shellgen
	@ln -sf "$(CURDIR)/shellgen/hash_generator.py" ~/.local/bin/hash_generator
	@ln -sf "$(CURDIR)/rop/get_rop_gadgets.py" ~/.local/bin/get_rop_gadgets
	@ln -sf "$(CURDIR)/rop/get_base_address.py" ~/.local/bin/get_base_address
	@ln -sf "$(CURDIR)/rop/rop_worksheet.py" ~/.local/bin/rop_worksheet
	@ln -sf "$(CURDIR)/target_builder/target_builder_cli.py" ~/.local/bin/target_builder
	@echo "Installed to ~/.local/bin/"
	@echo "Ensure ~/.local/bin is in your PATH"

uninstall: ## Remove installed symlinks
	@rm -f ~/.local/bin/shellgen ~/.local/bin/hash_generator \
		~/.local/bin/get_rop_gadgets ~/.local/bin/get_base_address \
		~/.local/bin/rop_worksheet ~/.local/bin/target_builder
	@echo "Removed symlinks from ~/.local/bin/"

# ==============================================================================
# Dependencies
# ==============================================================================

deps: ## Install core dependencies
	$(PYTHON) -m pip install -r requirements.txt

deps-test: ## Install test dependencies
	$(PYTHON) -m pip install -r requirements-test.txt

deps-lint: ## Install linting dependencies
	$(PYTHON) -m pip install -r requirements-lint.txt

deps-all: deps deps-test deps-lint ## Install all dependencies

# ==============================================================================
# Cleanup
# ==============================================================================

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf htmlcov/ .coverage