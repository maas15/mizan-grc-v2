# Mizan GRC v2 - Test Version

**Governance, Risk, and Compliance Management System**

Version: 2.0.0-test

## Overview

Mizan GRC v2 is a Governance, Risk, and Compliance (GRC) management system designed to help organizations manage risks, implement controls, and maintain compliance with various regulatory frameworks.

## Features

### Test Version Capabilities

- **Risk Management**: Track and assess organizational risks with severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- **Control Management**: Implement and monitor control measures with status tracking
- **Compliance Management**: Track compliance requirements across multiple frameworks (ISO27001, SOC2, GDPR, etc.)
- **GRC Dashboard**: Visual summary of risks, controls, and compliance status

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/maas15/mizan-grc-v2.git
cd mizan-grc-v2
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Application

Run the main application to see a demo of the GRC system:

```bash
python main.py
```

This will display:
- Sample risks with severity levels
- Control measures and their status
- Compliance requirements and overall compliance rate

### Running Tests

Execute the test suite:

```bash
pytest tests/ -v
```

Run tests with coverage:

```bash
pytest tests/ -v --cov=mizan_grc
```

## Project Structure

```
mizan-grc-v2/
├── mizan_grc/          # Main application package
│   ├── __init__.py     # Package initialization
│   ├── models.py       # Domain models (Risk, Control, ComplianceRequirement)
│   └── grc_manager.py  # Business logic for GRC operations
├── tests/              # Test suite
│   ├── __init__.py
│   ├── test_models.py
│   └── test_grc_manager.py
├── main.py             # Application entry point
├── version.py          # Version information
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Core Components

### Models

- **Risk**: Represents organizational risks with severity levels
- **Control**: Represents control measures to mitigate risks
- **ComplianceRequirement**: Represents compliance obligations

### GRCManager

Central management class that handles:
- Risk tracking and filtering
- Control implementation
- Compliance status reporting

## Development

### Adding New Features

1. Create new models in `mizan_grc/models.py`
2. Extend `GRCManager` in `mizan_grc/grc_manager.py`
3. Add tests in `tests/`
4. Update documentation

### Testing

All new features should include comprehensive tests. The test suite covers:
- Model creation and behavior
- GRC Manager operations
- Business logic validation

## License

This is a test version for demonstration purposes.

## Version History

- **2.0.0-test** (2026-02-01): Initial test version with core GRC features