# Contributing to PALACO

**Version:** 1.0  
**Status:** ACTIVE  
**Last Updated:** 2026-07-19

---

## Welcome!

Thank you for your interest in contributing to PALACO! This document outlines the process for contributing code, documentation, and improvements.

---

## Code of Conduct

All contributors must follow the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Conduct.

**Summary:**
- Be respectful and inclusive
- No harassment or discrimination
- Report violations to the maintainers

---

## How to Contribute

### 1. Reporting Issues

**Bug Reports:**
- Use [GitHub Issues](https://github.com/Maurits-pixe/palaco-genesis/issues)
- Include reproduction steps
- Specify Rust version and environment
- Include relevant logs or stack traces

**Feature Requests:**
- Use [GitHub Discussions](https://github.com/Maurits-pixe/palaco-genesis/discussions)
- Explain use case and motivation
- Suggest implementation approach if possible

### 2. Development Setup

**Prerequisites:**
- Rust 1.70+ (via [rustup](https://rustup.rs/))
- Git
- A text editor or IDE

**Clone and Setup:**
```bash
git clone https://github.com/Maurits-pixe/palaco-genesis.git
cd palaco-genesis
cargo build
cargo test
```

### 3. Making Changes

**Branch Naming:**
```
feature/description      # New feature
fix/description          # Bug fix
docs/description         # Documentation
refactor/description     # Code refactoring
test/description         # Test additions
```

**Before Committing:**
```bash
# Format code
cargo fmt --all

# Lint check
cargo clippy --all

# Run tests
cargo test --all

# Check docs
cargo doc --no-deps
```

### 4. Commit Messages

**Format:**
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Example:**
```
feat(kernel): add compile-time invariant validation

Added validation macros that enforce invariants at compile time.
This reduces runtime checks and improves type safety.

Closes #42
Related: ADR-003
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation
- `style` — Code style (formatting, etc.)
- `refactor` — Code refactoring
- `test` — Test additions
- `chore` — Build, CI, dependencies

### 5. Pull Request Process

**Before Opening PR:**
1. Ensure branch is up to date: `git pull origin main`
2. All tests passing: `cargo test --all`
3. Formatting correct: `cargo fmt --check`
4. No Clippy warnings: `cargo clippy --all`
5. Documentation updated: `cargo doc --no-deps`

**PR Title and Description:**
```markdown
## Description

[What does this PR do?]

## Related Issues

Closes #NNN

## Changes

- [ ] Code changes
- [ ] Documentation updates
- [ ] Tests added
- [ ] CHANGELOG updated

## Testing

[How was this tested?]

## Checklist

- [ ] Code formatted (`cargo fmt --check`)
- [ ] Tests pass (`cargo test --all`)
- [ ] No Clippy warnings (`cargo clippy --all`)
- [ ] Documentation complete
- [ ] CHANGELOG updated
```

### 6. Code Review

**What We Look For:**
- ✅ Follows platform architecture (PAS-001)
- ✅ No `unsafe` code without justification
- ✅ All warnings resolved (Clippy, fmt)
- ✅ Tests for new functionality
- ✅ Documentation updated
- ✅ ADR referenced if architectural
- ✅ Validation gates pass (Gate 0-6 minimum)

**Review Feedback:**
- We'll leave comments on code
- Respond to feedback with code changes or discussion
- Push new commits to same branch
- Do not rebase/force-push (we track conversation)

---

## Development Guidelines

### Architecture Compliance

1. **Understand Your Crate's Role** — Read PAS-001
2. **Respect Layering** — Only depend on lower layers
3. **Minimize Dependencies** — Use standard library when possible
4. **Document Public API** — Every `pub` item needs docs
5. **Link to ADRs** — Reference relevant decisions in code

### Code Style

**Rust:**
- Format with `cargo fmt`
- Follow Rust naming conventions
- Use meaningful variable names
- Keep functions focused and small

**Documentation:**
- Use triple-slash `///` for public docs
- Include examples for complex types
- Link to related items
- Explain the "why", not just the "what"

### Testing

**Unit Tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
```

**Integration Tests:**
- Locate in `tests/` directory
- Test cross-crate interactions
- Name descriptively: `tests/service_orchestration.rs`

**Coverage:**
- Aim for 80%+ coverage
- Test both success and error paths
- Include edge cases

### Documentation

**Required:**
- Module-level docs (explain purpose)
- Public type docs (what is it?)
- Public function docs (what does it do?)
- Complex algorithms (explain rationale)

**Examples:**
```rust
/// Initiates a service with the given configuration.
///
/// # Arguments
///
/// * `config` - Service configuration
///
/// # Returns
///
/// Returns `Ok(())` if service started successfully.
/// Returns `Err` if initialization failed.
///
/// # Example
///
/// ```ignore
/// let config = ServiceConfig::default();
/// init_service(&config)?;
/// ```
pub fn init_service(config: &ServiceConfig) -> Result<()> {
    // Implementation
}
```

---

## Validation Gates

Your PR must pass these gates (automatically via CI):

| Gate | Check | Required |
|------|-------|----------|
| G0 | Foundation documents present | ✅ |
| G1 | Repository structure correct | ✅ |
| G2 | Build passes, tests pass | ✅ |
| G3-5 | Crate-specific tests | ✅ |
| G6 | Integration tests | ✅ |
| G7 | Architecture compliance | ✅ |

All gates must pass before merge.

---

## Maintenance

### Issue Triage

- **bug** — Functionality that doesn't work as intended
- **enhancement** — Request for new feature
- **documentation** — Missing or unclear docs
- **good first issue** — Good for new contributors
- **help wanted** — Contributor input needed

### Release Process

1. **Feature Complete** — All planned features done
2. **Testing** — Full test suite passes
3. **Review** — Code review complete
4. **Documentation** — All docs updated
5. **Version Bump** — Update version in Cargo.toml
6. **Changelog** — Document changes
7. **Tag** — Create git tag
8. **Release** — Publish to crates.io

---

## Questions?

- **Technical Questions:** [GitHub Discussions](https://github.com/Maurits-pixe/palaco-genesis/discussions)
- **Bug Reports:** [GitHub Issues](https://github.com/Maurits-pixe/palaco-genesis/issues)
- **Security Issues:** Email security@palaco.dev (private disclosure)

---

## Thank You!

Contributions make PALACO better. We appreciate your time and effort!

---

**Document Authority:** PALACO Maintainers  
**Classification:** Public
