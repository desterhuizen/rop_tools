# GitHub Actions Workflows

This directory contains a single unified CI workflow for automated testing, linting, and coverage.

## Workflow: `ci.yml`

**Triggers:** Push/PR to main or develop branches, manual dispatch

Three parallel jobs run under one workflow:

### Lint
Runs flake8, black, isort, and mypy (optional) on Python 3.12.

### Test (matrix)
Runs the full test suite across Python 3.8-3.12:
- `lib/` - Shared library tests (ColorPrinter)
- `rop/` - ROP tools tests (21 test files)
- `shellgen/` - Shellcode generator tests (4 test files)

### Coverage
Runs after tests pass (main branch and PRs only). Generates coverage reports, uploads to Codecov, and saves HTML artifact (retained 30 days).

**Codecov**: Coverage badge and history at [codecov.io/gh/desterhuizen/rop_tools](https://codecov.io/gh/desterhuizen/rop_tools). Requires `CODECOV_TOKEN` repo secret.

## Running Locally

```bash
# Using Makefile (recommended)
make test          # Run all tests
make test-verbose  # Verbose output
make lint          # Check flake8, black, isort
make lint-fix      # Auto-format with black and isort
make coverage      # Run tests with coverage report

# Or manually
python -m unittest discover -s lib/tests -p "test_*.py" -t . -v
python -m unittest discover -s rop/tests -p "test_*.py" -t . -v
python -m unittest discover -s shellgen/tests -p "test_*.py" -t . -v
```

## Test Statistics

- **Total Test Files**: 26
  - `lib/tests/`: 1 file (40 test cases)
  - `rop/tests/`: 21 files
  - `shellgen/tests/`: 4 files (127 test cases)
- **Test Framework**: Python `unittest` (standard library)
- **Mocking**: `unittest.mock`
- **Coverage Tool**: `coverage.py`

## Configuration

- **Actions versions**: checkout@v6, setup-python@v6, upload-artifact@v6
- **Python versions**: 3.8, 3.9, 3.10, 3.11, 3.12
- **OS**: Ubuntu (ubuntu-latest)

## Troubleshooting

### ImportError: Start directory is not importable
Add the `-t .` flag to specify the top-level directory:
```bash
python -m unittest discover -s lib/tests -p "test_*.py" -t . -v
```

### Tests failing in CI but passing locally
- Check Python version differences
- Verify all dependencies are in `requirements.txt`
- Check for platform-specific issues
- Ensure you're using `-t .` flag in test discovery commands

### Coverage artifacts not appearing
- Artifacts are only available after workflow completes
- Check the "Artifacts" section at the bottom of the workflow run
- Artifacts expire after 30 days

## Adding New Tests

1. Create test file: `<module>/tests/test_*.py`
2. Use unittest framework:
   ```python
   import unittest

   class TestMyFeature(unittest.TestCase):
       def test_something(self):
           self.assertEqual(1, 1)
   ```
3. Verify locally: `make test`
4. Commit and push — workflow runs automatically

---

**Note**: These workflows are designed for authorized security testing tools. All tests verify defensive security functionality only.