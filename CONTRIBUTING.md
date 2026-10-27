# Contributing to Stratagem

Thank you for your interest in contributing to Stratagem! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to [the project maintainers](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Docker (recommended for testing)
- C compiler (gcc or clang) and make
- Git

### Setting Up the Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/stratagem.git
   cd stratagem
   ```

3. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

4. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

5. Build the harness:
   ```bash
   cd harness
   ./build.sh
   cd ..
   ```

## Development Workflow

### Branching Strategy

- `main`: The production branch
- `develop`: Development branch for upcoming releases
- `feature/*`: Feature branches
- `bugfix/*`: Bug fix branches
- `docs/*`: Documentation updates

### Creating a Branch

For a new feature:
```bash
git checkout -b feature/your-feature-name
```

For a bug fix:
```bash
git checkout -b bugfix/your-bugfix-name
```

### Making Changes

1. Write clear, descriptive commit messages
2. Keep changes focused and atomic
3. Test your changes thoroughly
4. Update documentation as needed

### Commit Message Format

Follow conventional commit format:
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Example:
```
feat(agent): add ensemble model voting

Implement weighted voting mechanism for multi-model ensemble
strategies to improve strategy selection quality.

Closes #123
```

## Pull Request Process

### Before Submitting

1. Update documentation if your changes affect functionality
2. Add tests for new functionality
3. Ensure all existing tests pass
4. Run code formatting tools
5. Update the CHANGELOG if applicable

### Submitting a PR

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a pull request on GitHub with:
   - Clear title and description
   - Reference related issues
   - Screenshots or examples if applicable
   - Testing instructions

3. Wait for code review and address feedback

### PR Review Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated and passing
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] No merge conflicts
- [ ] Changes are backward compatible (unless breaking change is documented)

## Coding Standards

### Python Code Style

- Follow PEP 8 style guide
- Use type hints where appropriate
- Maximum line length: 100 characters
- Use meaningful variable and function names
- Add docstrings to functions and classes

Example:
```python
def generate_strategy(grammar: Grammar, target: str) -> Strategy:
    """
    Generate a fuzzing strategy for the given grammar and target.

    Args:
        grammar: The ANTLR grammar to use for generation
        target: The target parser name

    Returns:
        A Strategy object for the target
    """
    pass
```

### C Code Style

- Follow kernel coding style where applicable
- Use 4-space indentation
- Include comments for complex logic
- Use meaningful variable names

### Code Organization

- Keep functions focused and single-purpose
- Avoid deep nesting (max 4 levels)
- Prefer composition over inheritance
- Separate interface from implementation

## Testing

### Running Tests

Run the hermetic agent suite (no harness, network or credentials needed):
```bash
python -m pytest agent -q
```

Run the same checks the CI pipeline runs:
```bash
python scripts/ci.py --unit --cov
```

Run with coverage:
```bash
python -m pytest agent -q --cov=agent --cov-report=term-missing
```

Run the measurement-layer self-checks:
```bash
python -m agent.selftest
python -m fuzzer.selftest
```

Run a single test module without pytest:
```bash
python -m agent.test_loop
python -m agent.test_dx
```

### Writing Tests

- Write tests for new features
- Test edge cases and error conditions
- Use descriptive test names
- Keep tests independent
- Keep agent-loop tests hermetic: patch `agent.loop.Campaign` and point
  `agent.loop.REPO_ROOT` at a temporary directory instead of running the harness

Example:
```python
def test_strategy_validation_valid_strategy():
    """Test that a valid strategy passes validation."""
    strategy = create_test_strategy()
    result = validate_strategy(strategy)
    assert result.is_valid is True
```

### Integration Testing

Build the harness, then verify that a recorded transcript replays to
byte-identical strategies:
```bash
cd harness && ./build.sh asan && cd ..
python scripts/ci.py --replay --run-id loop --iterations 5 --examples 10
```

On Windows, run the replay check inside WSL2 or Docker; the sanitizer binary is
a POSIX executable.

### Debugging a Failing Test or Run

```bash
# Artifact-level report for a run
python -m agent.debug --run-id loop --diagnose

# The exact prompt and response for one call
python -m agent.debug --run-id loop --call 3 --full

# Structured events from a loop run with --debug
python -m agent.loop --backend replay --run-id demo --debug
python -m agent.debug --run-id demo --events
```

See [docs/developer-experience.md](docs/developer-experience.md) for details.

## Documentation

### Types of Documentation

1. **Code Documentation**: Docstrings and comments
2. **User Documentation**: README, guides, tutorials
3. **API Documentation**: Function and class references
4. **Architecture Documentation**: Design decisions, architecture

### Updating Documentation

- Keep documentation in sync with code changes
- Use clear, concise language
- Include examples where helpful
- Update CHANGELOG for user-facing changes

### Documentation Format

- Use Markdown for documentation files
- Follow existing style and structure
- Include code blocks with syntax highlighting
- Use relative links for internal references

## Reporting Issues

### Bug Reports

When reporting a bug, include:

1. Clear description of the issue
2. Steps to reproduce
3. Expected behavior
4. Actual behavior
5. Environment details (OS, Python version, etc.)
6. Relevant logs or error messages
7. Screenshots if applicable

### Feature Requests

When requesting a feature:

1. Clear description of the feature
2. Use case or motivation
3. Proposed implementation (if known)
4. Alternative approaches considered

### Issue Template

```markdown
## Issue Type
- [ ] Bug
- [ ] Feature Request
- [ ] Documentation

## Description
[Brief description]

## Steps to Reproduce (if bug)
1.
2.
3.

## Expected Behavior
[What you expected to happen]

## Actual Behavior
[What actually happened]

## Environment
- OS:
- Python version:
- Stratagem version:

## Additional Context
[Any other relevant information]
```

## Development Guidelines

### Performance Considerations

- Profile code before optimizing
- Consider impact on fuzzing loop performance
- Cache expensive operations
- Use efficient data structures

### Security Considerations

- Never commit API keys or secrets
- Use environment variables for sensitive data
- Validate all external inputs
- Follow security best practices for C code

### Reproducibility

- Ensure fuzzing campaigns are reproducible
- Document random seeds and configurations
- Save transcripts for replay
- Use deterministic tests where possible

## Questions?

- Check existing documentation and issues
- Open a discussion for general questions
- Contact maintainers for specific concerns

## Recognition

Contributors will be acknowledged in the project's CONTRIBUTORS file and release notes.

Thank you for contributing to Stratagem!
