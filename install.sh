#!/bin/bash

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if (( $(echo "$python_version < 3.8" | bc -l) )); then
    echo "Error: Python 3.8 or higher is required"
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install the package
echo "Installing ORADAD Extractor..."
pip install -e .

# Create test directories
mkdir -p test_data
mkdir -p reports

echo "Installation complete!"
echo "To activate the environment: source venv/bin/activate"
echo "To run the tool: oradad-extract --help" 