# API Reference Overview

This section contains automatically generated documentation for the internal
modules of the MCH project.

## Project Structure

- **mch**: The core package.
- **mch.scanners**: Specialized scanner implementations (ACAO, Fuzz, Ports).
- **mch.config**: Configuration management.
- **mch.state**: Persistence logic.
- **mch.utils**: Shared helpers.

## Test-Driven Documentation
This project uses "Live Documentation," where usage examples in the API reference are pulled directly from our test suite. This ensures that:
- Examples are always up-to-date with the codebase.
- Documentation reflects actual, verified usage patterns.
- Any breaking change in the code that breaks a test will also alert the documentation engine.

::: mch
