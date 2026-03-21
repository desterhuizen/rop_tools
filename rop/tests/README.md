# ROP Tools Test Suite

This directory contains comprehensive unit and integration tests for the ROP
tools suite.

## Structure

```
tests/
├── README.md                              # This file
│
├── ROP Worksheet Tests
│   ├── test_core_data.py                  # Tests for worksheet.core.data
│   ├── test_core_resolver.py              # Tests for worksheet.core.resolver
│   ├── test_operations_asm.py             # Tests for worksheet.operations.asm_ops
│   ├── test_operations_stack.py           # Tests for worksheet.operations.stack_ops
│   ├── test_operations_quick.py           # Tests for worksheet.operations.quick_ops
│   ├── test_gadgets_library.py            # Tests for worksheet.gadgets.library
│   ├── test_gadgets_processor.py          # Tests for worksheet.gadgets.processor
│   ├── test_chain_manager.py              # Tests for worksheet.chain.manager
│   ├── test_io_windbg.py                  # Tests for worksheet.io.windbg
│   ├── test_ui_display.py                 # Tests for worksheet.ui.display
│   └── test_integration.py                # Integration tests for worksheet
│
├── get_rop_gadgets Tests
│   ├── test_ropgadgets_core_categories.py # Tests for core.categories
│   ├── test_ropgadgets_core_gadget.py     # Tests for core.gadget
│   ├── test_ropgadgets_core_parser.py     # Tests for core.parser
│   ├── test_ropgadgets_display_formatters.py # Tests for display.formatters
│   └── test_ropgadgets_integration.py     # Integration tests for get_rop_gadgets CLI
│
└── PE Analysis Tests
    ├── test_core_pe_info.py               # Tests for core.pe_info (PEAnalyzer, IAT)
    └── test_get_base_address_integration.py # Integration tests for get_base_address CLI
```

## Running Tests

### Prerequisites

Install test dependencies:

```bash
pip install -r requirements-test.txt
```

### Run All Tests

```bash
# From the rop/ directory
python -m pytest tests/

# With verbose output
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_core_data.py -v

# Run specific test class
python -m pytest tests/test_core_data.py::TestBlankWorksheet -v

# Run specific test
python -m pytest tests/test_core_data.py::TestBlankWorksheet::test_blank_worksheet_structure -v
```

### Run Tests with Coverage

```bash
# Generate coverage report
python -m pytest tests/ --cov=worksheet --cov-report=term-missing

# Generate HTML coverage report
python -m pytest tests/ --cov=worksheet --cov-report=html
# Then open htmlcov/index.html
```

## Test Coverage

### ROP Worksheet Tests

- **Core modules** (data.py, resolver.py): 100% coverage
    - Worksheet structure creation
    - Value resolution (hex, registers, stack, named values, arithmetic)
    - Target parsing (registers, stack offsets, dereferenced registers, named
      values)

- **Operations modules** (asm_ops.py, stack_ops.py, quick_ops.py): 100% coverage
    - ASM operations: mov, add, xor, xchg, inc, dec, neg
    - Stack operations: push, pop, direct stack manipulation
    - Quick operations: set, clear
    - Logging functionality

- **Gadgets modules** (processor.py, library.py): 100% coverage
    - Gadget library management (add, delete, clear)
    - Gadget auto-execution
    - Instruction parsing and validation

- **Chain module** (manager.py): 100% coverage
    - Chain building (add by address, gadget ID, or literal)
    - Chain deletion by index
    - Chain clearing

- **I/O module** (windbg.py): 100% coverage
    - WinDbg register import
    - WinDbg stack dump import
    - Offset calculation

- **UI module** (display.py): 100% coverage
    - Worksheet view building
    - Rich object rendering
    - Named value matching display

### get_rop_gadgets Tests

- **Core modules**: `test_ropgadgets_core_*.py`
    - Gadget parsing and categorization
    - Register analysis (affected vs modified)
    - Pattern matching and filtering
    - Bad character filtering

- **Integration tests**: `test_ropgadgets_integration.py` (25 tests)
    - CLI argument parsing
    - Instruction filtering (first/last/any position)
    - Category filtering
    - Register filtering
    - Bad instruction filtering (9 new tests):
        - Default filtering of call, jmp, int, leave, conditional jumps
        - `--keep-bad-instructions` flag behavior
        - Case-insensitive matching
        - Filter count output validation
    - Grouping (by instruction, category, register)
    - Sorting and limiting
    - Offset calculation
    - Regex highlighting
    - Error handling

### PE Analysis Tests

- **PE Info tests**: `test_core_pe_info.py` (20 tests)
    - PEAnalyzer class methods (base address extraction, file analysis)
    - IAT (Import Address Table) extraction
    - Section parsing and characteristics
    - Dataclass functionality (PEInfo, PESection, IATEntry)
    - Error handling for invalid PE files
    - **Note**: Most tests skip on non-Windows platforms (14 tests)

- **get_base_address integration**: `test_get_base_address_integration.py` (14
  tests)
    - CLI argument parsing
    - Verbose mode (`-v` flag)
    - Quiet mode (`-q` flag)
    - IAT display (`--iat` flag)
    - DLL filtering (`--dll` flag)
    - Color output control (`--no-color`)
    - Error handling (missing files, invalid PE files)
    - Address format display (hex and decimal)
    - **Note**: Most tests skip on non-Windows platforms (12 tests)

## Test Statistics

- **Total tests**: ~185 (including new tests)
- **Test files**: 13
- **Test classes**: ~55
- **Coverage**: ~95% of production code
- **Platform notes**: PE-related tests (26 tests) skip on non-Windows platforms

## Writing New Tests

When adding new functionality, follow these guidelines:

1. **Create a new test file** for new modules:
   ```python
   """
   Unit tests for worksheet.module.name module.
   """
   import pytest
   from worksheet.core.data import blank_worksheet
   from worksheet.module.name import function_to_test

   class TestFunctionName:
       """Test the function_name function."""

       def test_basic_functionality(self):
           """Test basic case."""
           ws = blank_worksheet()
           # Test code here
           assert expected == actual
   ```

2. **Use descriptive test names** that explain what is being tested

3. **Follow AAA pattern**: Arrange, Act, Assert
   ```python
   def test_example(self):
       # Arrange
       ws = blank_worksheet()
       ws["registers"]["EAX"] = "0xdeadbeef"

       # Act
       result = some_function(ws, "EAX")

       # Assert
       assert result == expected_value
   ```

4. **Test edge cases**:
    - Empty inputs
    - Invalid inputs
    - Boundary conditions
    - Error conditions

5. **Use fixtures** for common setup (if needed):
   ```python
   @pytest.fixture
   def populated_worksheet():
       ws = blank_worksheet()
       ws["registers"]["EAX"] = "0xdeadbeef"
       return ws
   ```

## Continuous Integration

To integrate with CI/CD:

```yaml
# Example .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.12'
      - run: pip install -r requirements-test.txt
      - run: python -m pytest tests/ -v --cov=worksheet
```

## Known Issues

None currently. All 140 tests passing.

## Contact

For issues or questions about tests, please refer to the main project
documentation.