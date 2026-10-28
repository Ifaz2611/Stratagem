# TODO: Future Expansion

This document outlines potential improvements and new features for Stratagem, the agentic grammar fuzzer.

## High Priority

### Target Expansion
- [x] Add support for additional XML parsers (libxml2, expat, tinyxml2)
- [x] Implement target abstraction layer to make switching between targets easier
- [x] Add JSON parser target as a proof-of-concept for non-XML grammars
- [x] Consider supporting protocol parsers (HTTP, DNS, SMTP)

### Fuzzer Improvements
- [x] Implement parallel fuzzing (multiple campaigns running simultaneously)
- [x] Add support for adaptive batch sizes based on strategy performance
- [x] Implement intelligent corpus management (deduplication, coverage-guided selection)
- [x] Add timeout detection and handling for slow inputs
- [x] Implement incremental campaign persistence for long-running tests

### Agent Enhancements
- [x] Add support for multi-model ensembles (vote on best strategy)
- [x] Implement strategy caching and reuse across similar targets
- [x] Add automatic hyperparameter tuning for the agentic loop
- [x] Implement few-shot learning with successful past strategies as examples
- [x] Add capability to generate target-specific harness code

## Medium Priority

### Coverage & Analysis
- [x] Add support for additional sanitizers (ThreadSanitizer, MemorySanitizer)
- [x] Implement more sophisticated crash triage (bug clustering, deduplication)
- [x] Add automatic minimal reproducer generation
- [x] Implement statistical significance testing for coverage improvements
- [x] Add visual coverage reports (HTML/interactive dashboards)

### Grammar Support
- [x] Add support for additional grammar formats (EBNF, Yacc/Bison)
- [x] Implement automatic grammar extraction from existing code
- [x] Add grammar mutation capabilities
- [x] Implement support for context-sensitive grammars

### LLM Backend
- [x] Implement streaming response handling for faster feedback
- [x] Add prompt versioning and A/B testing
- [x] Implement fallback mechanisms for LLM failures

## Low Priority

### Developer Experience
- [x] Add comprehensive test suite for the agent loop
- [x] Implement better error messages and debugging tools
- [x] Implement progress bars and real-time status updates
- [x] Add integration with CI/CD pipelines

### Documentation
- [x] Add tutorial for adding new targets
- [x] Create architecture diagrams
- [x] Add contribution guidelines
- [x] Write API documentation for key modules
- [x] Add case studies from past findings

### Performance
- [x] Implement strategy compilation to bytecode
- [x] Add result caching for deterministic strategies
- [x] Optimize memory usage for large corpora
- [x] Implement distributed fuzzing support

## Research & Experimentation

### Novel Strategies
- [ ] Explore combining agentic generation with traditional mutation fuzzing
- [ ] Experiment with reinforcement learning for strategy refinement
- [ ] Investigate symbolic execution integration
- [ ] Explore cross-target strategy transfer learning
- [ ] Experiment with adversarial input generation

### Evaluation
- [ ] Run comparative studies against traditional fuzzers (AFL, libFuzzer)
- [ ] Measure effectiveness on real-world vulnerabilities
- [ ] Evaluate cost-effectiveness vs traditional approaches
- [ ] Study reproducibility across different LLM providers/models
- [ ] Analyze the impact of prompt engineering on results

## Backlog

### Bug Fixes
- [x] Investigate rare encoding issues in byte serialization
- [x] Fix potential memory leaks in long-running campaigns
- [x] Address edge cases in diagnostic normalization
- [x] Fix timezone handling in timestamped reports
- [x] Resolve Windows compatibility issues

### Technical Debt
- [ ] Refactor large functions in loop.py
- [ ] Improve type hints across codebase
- [ ] Reduce code duplication in strategy modules
- [ ] Standardize error handling patterns
- [ ] Improve logging consistency

---