# Contributing to ICOokForms

First off, thank you for considering contributing to ICOokForms! It's people like you that make ICOokForms such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps which reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed after following the steps**
* **Explain which behavior you expected to see instead and why**
* **Include screenshots if relevant**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a step-by-step description of the suggested enhancement**
* **Provide specific examples to demonstrate the steps**
* **Describe the current behavior** and **explain which behavior you expected to see instead**
* **Explain why this enhancement would be useful**

### Pull Requests

* Fill in the required template
* Follow the Rust style guide
* Include tests for new functionality
* Update documentation as needed
* Ensure all tests pass
* Maintain code coverage above 90%

## Development Process

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/guillaume-piron-dev/icookforms.git
cd icookforms

# Build the project
cargo build

# Run tests
cargo test

# Run lints
cargo clippy -- -D warnings

# Format code
cargo fmt
```

### Coding Standards

#### Rust Style

* Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
* Use `cargo fmt` before committing
* Fix all `cargo clippy` warnings
* Write idiomatic Rust code

#### Documentation

* Document all public APIs with rustdoc
* Include examples in documentation
* Update README.md for significant changes
* Keep CHANGELOG.md up to date

#### Testing

* Write unit tests for new functions
* Write integration tests for new features
* Aim for 90%+ code coverage
* Use property-based testing with `proptest` where appropriate

#### Commits

* Use clear and meaningful commit messages
* Follow [Conventional Commits](https://www.conventionalcommits.org/)
* Keep commits atomic and focused
* Reference issues in commits when applicable

Example commit messages:
```
feat: add GDPR compliance checker
fix: correct cookie expiration parsing
docs: update API documentation for Scanner
test: add integration tests for compliance module
refactor: simplify error handling in parser
```

### Testing

```bash
# Run all tests
cargo test

# Run tests with coverage
cargo tarpaulin --out Html

# Run benchmarks
cargo bench

# Run specific test
cargo test test_cookie_parsing

# Run tests with logging
RUST_LOG=debug cargo test
```

### Code Review Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and lints
5. Commit your changes (`git commit -m 'feat: add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Pull Request Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass
- [ ] Code is formatted with `cargo fmt`
- [ ] No `cargo clippy` warnings
- [ ] Documentation is updated
- [ ] Tests are added for new functionality
- [ ] CHANGELOG.md is updated (for significant changes)
- [ ] Commit messages follow conventions

## Project Structure

```
icookforms/
├── src/               # Source code
│   ├── cli/          # Command-line interface
│   ├── scanner/      # Cookie scanning
│   ├── parser/       # Cookie parsing
│   ├── analyzer/     # Security & compliance analysis
│   ├── compliance/   # Regulation checking
│   ├── reporter/     # Report generation
│   ├── storage/      # Data storage
│   ├── types/        # Core types
│   └── utils/        # Utilities
├── tests/            # Integration tests
├── benches/          # Benchmarks
├── docs/             # Documentation
└── examples/         # Usage examples
```

## Questions?

Feel free to:
* Open an issue
* Start a discussion on GitHub Discussions
* Contact the maintainers

## License

By contributing to ICOokForms, you agree that your contributions will be licensed under the Apache License 2.0.

Thank you for contributing! 🎉
