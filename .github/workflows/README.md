# GitHub Actions Workflows

This directory contains CI/CD workflows for automated testing and quality assurance.

## Available Workflows

### 1. `tests.yml` - Test Suite
**Triggers:** Push/PR to main or develop branches, manual dispatch

Runs the complete test suite across multiple Python versions (3.7-3.11) to ensure compatibility.

**What it tests:**
- `lib/` - Shared library tests (ColorPrinter)
- `rop/` - ROP tools tests (21 test files)
- `shellgen/` - Shellcode generator tests (4 test files)

**Test command:**
```bash
python -m unittest discover -s <module>/tests -p "test_*.py" -v
```

### 2. `coverage.yml` - Test Coverage
**Triggers:** Push/PR to main branch, manual dispatch

Generates test coverage reports using Python 3.10 on Ubuntu.

**Features:**
- Runs all tests with coverage tracking
- Generates coverage report
- Uploads HTML coverage report as artifact (retained for 30 days)
- Displays coverage summary in workflow summary

**Manual coverage check:**
```bash
pip install coverage
coverage run -m unittest discover -s lib/tests -p "test_*.py"
coverage run -a -m unittest discover -s rop/tests -p "test_*.py"
coverage run -a -m unittest discover -s shellgen/tests -p "test_*.py"
coverage report -m
coverage html
```

## Badges

The following badges are displayed in the main README.md:

- **Tests**: ![Tests](https://github.com/YOUR_USERNAME/rop_tools/actions/workflows/tests.yml/badge.svg)
- **Coverage**: ![Coverage](https://github.com/YOUR_USERNAME/rop_tools/actions/workflows/coverage.yml/badge.svg)

**Note:** Replace `YOUR_USERNAME` with your actual GitHub username in both the badges and workflow files.

## Running Tests Locally

### Run all tests
```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
python -m unittest discover -s lib/tests -p "test_*.py" -v
python -m unittest discover -s rop/tests -p "test_*.py" -v
python -m unittest discover -s shellgen/tests -p "test_*.py" -v
```

### Run specific test file
```bash
python -m unittest lib/tests/test_color_printer.py -v
python -m unittest rop/tests/test_repl_completer.py -v
python -m unittest shellgen/tests/test_encoders.py -v
```

### Run with coverage
```bash
pip install coverage
coverage run -m unittest discover -s lib/tests -p "test_*.py"
coverage run -a -m unittest discover -s rop/tests -p "test_*.py"
coverage run -a -m unittest discover -s shellgen/tests -p "test_*.py"
coverage report -m
coverage html  # Generate HTML report in htmlcov/
```

## Test Statistics

- **Total Test Files**: 26
  - `lib/tests/`: 1 file (40 test cases)
  - `rop/tests/`: 21 files (extensive coverage)
  - `shellgen/tests/`: 4 files (127 test cases)

- **Test Framework**: Python `unittest` (standard library)
- **Mocking**: `unittest.mock`
- **Coverage Tool**: `coverage.py`

## Workflow Configuration

### Python Versions Tested
- Python 3.7
- Python 3.8
- Python 3.9
- Python 3.10
- Python 3.11

### Operating Systems
- **tests.yml**: Ubuntu (Linux)
- **coverage.yml**: Ubuntu (Linux)

To test on additional platforms, add to the matrix in `tests.yml`:
```yaml
matrix:
  os: [ubuntu-latest, windows-latest, macos-latest]
  python-version: ['3.7', '3.8', '3.9', '3.10', '3.11']
```

## Troubleshooting

### Workflow not triggering
- Ensure you've pushed to `main` or `develop` branch
- Check that workflow files are in `.github/workflows/`
- Verify YAML syntax with `yamllint`

### Tests failing in CI but passing locally
- Check Python version differences
- Verify all dependencies are in `requirements.txt`
- Check for platform-specific issues (Windows vs Linux)
- Review workflow logs in GitHub Actions tab

### Coverage artifacts not appearing
- Artifacts are only available after workflow completes
- Check the "Artifacts" section at the bottom of the workflow run
- Artifacts expire after 30 days

## Manual Workflow Dispatch

Both workflows can be triggered manually:

1. Go to the "Actions" tab in GitHub
2. Select the workflow (Tests or Coverage)
3. Click "Run workflow"
4. Select the branch
5. Click "Run workflow" button

## Adding New Tests

When adding new test files:

1. **Create test file**: `<module>/tests/test_*.py`
2. **Use unittest framework**:
   ```python
   import unittest

   class TestMyFeature(unittest.TestCase):
       def test_something(self):
           self.assertEqual(1, 1)

   if __name__ == "__main__":
       unittest.main()
   ```
3. **Verify locally**: `python -m unittest <module>/tests/test_*.py -v`
4. **Commit and push**: Workflows will run automatically

## Future Enhancements

Potential workflow additions:

- **Linting**: Add `flake8`, `pylint`, or `black` for code quality
- **Security**: Add `bandit` for security vulnerability scanning
- **Documentation**: Auto-generate documentation with `sphinx`
- **Release**: Auto-publish to PyPI on version tags
- **Pre-commit**: Add pre-commit hooks for local validation

---

**Note**: These workflows are designed for authorized security testing tools. All tests verify defensive security functionality only.