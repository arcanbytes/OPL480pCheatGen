# Development Guide

This document explains how to prepare an environment to collaborate with **OPL480pCheatGen**.

## Prerequisites
- Python 3.11 or higher
- Git

## Environment Setup
1. Clone the repository:
```bash
git clone https://github.com/arcanbytes/OPL480pCheatGen.git
cd OPL480pCheatGen
```
2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate # On Windows: .venv\Scripts\activate
```
3. Install the development dependencies:
```bash
pip install -r requirements.txt
pip install -r requirements-tests.txt
```

## Running Tests
- Run all tests with:
```bash
pytest
```
- Run a specific test file:
```bash
pytest tests/test_cli.py
```
- Testing Files
The tests use ELFs extracted from PS2 game ISOs and are therefore not included. These ELF files are packaged in 7z files, and within each 7z there should be the original ELF and the ELF patched by OPL480pCheatGen. Make sure that the patching settings match those specified in each specific test. That said, you can easily create your own tests using any ISO; you just need to adapt the code a bit.

## Build/Packaging Process
- Build the executable with PyInstaller:
```bash
python build.py
```
- The binaries will be generated in the `release/` folder.

## Contribution Guidelines
1. Create a branch from `main`:
```bash
git checkout -b branch-name
```
2. Use descriptive commit messages.
3. Open a Pull Request on GitHub explaining your changes.

