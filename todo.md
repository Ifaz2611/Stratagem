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

## Backlog

### Bug Fixes
- [x] Investigate rare encoding issues in byte serialization
- [x] Fix potential memory leaks in long-running campaigns
- [x] Address edge cases in diagnostic normalization
- [x] Fix timezone handling in timestamped reports
- [x] Resolve Windows compatibility issues

### Technical Debt
- [x] Refactor large functions in loop.py
- [x] Improve type hints across codebase
- [x] Reduce code duplication in strategy modules
- [x] Standardize error handling patterns
- [x] Improve logging consistency


====================================

PONYTAILS-- survey 

  ### Must fix
  1. Non-XML targets receive XML prompts and fail validation (agent/loop.py:L681-690, agent/validate.py:L54-58)
      • What this is: Prompt construction in the agent loop for the initial seed strategy and subsequent refinements.
      • Problem: _seed_prompt and _refine_prompt hardcode XMLParser.g4, XMLLexer.g4, and XML grammar productions. Running with --target json or --target http asks the model to write an XML
      generator, which the JSON or HTTP parser rejects on 100% of inputs, failing smoke validation and halting the run.
      • Fix: Inject self.target_obj.grammar_file and self.target_obj.productions instead of hardcoded XML files, and pass target-specific bounds to validation.
      • If we skip it: Multi-target support advertised in the documentation fails completely when using the agent loop.
  2. Resumed runs report zero new diagnostics to the model (agent/loop.py:L452-468)
      • What this is: State restoration logic when resuming an interrupted run via --resume-from N.
      • Problem: _restore_feedback_unions iterates through range(self.resume_from) and adds all diagnostics from iteration N - 1 into self.union_diagnostics. When iteration N starts and computes
      new_diags = this_diags - self.union_diagnostics, the difference is empty, falsely prompting the model that nothing new was found.
      • Fix: Populate self.union_diagnostics only up to self.resume_from - 1, excluding the immediate predecessor iteration being refined.
      • If we skip it: Resuming an interrupted run degrades prompt quality and steers the model away from productive paths.
  3. Stale lease reclamation unlinks active claims of other workers (fuzzer/distributed.py:L425-430, fuzzer/distributed.py:L518-519)
      • What this is: Shard lease cleanup in filesystem-distributed fuzzing campaigns.
      • Problem: If worker A pauses past its lease timeout, worker B reclaims the task and writes its own claim file. When worker A eventually finishes, its finally block unconditionally calls
      claim_path.unlink(), wiping worker B's active claim and causing worker C to start a duplicate third run on the same directory.
      • Fix: Check that the claim file on disk matches the current worker's ID and PID before deleting it.
      • If we skip it: Distributed nodes run redundant campaigns and overwrite each other's shard output files.
  4. Smoke gate writes to a fixed path, clobbering concurrent validations (agent/validate.py:L270-274)
      • What this is: Gate 4 smoke test execution that runs 50 examples through the harness before accepting code.
      • Problem: The campaign output directory is hardcoded to runs/.validate. When running multi-model ensembles or concurrent local campaigns, simultaneous validation calls write results and
      checkpoints to the exact same directory at the same time.
      • Fix: Use a unique temporary directory via tempfile.TemporaryDirectory for each validation execution.
      • If we skip it: Multi-candidate ensemble runs suffer filesystem write races and corrupted validation results.
  5. Validation writes unverified code to the permanent strategy destination (agent/validate.py:L262-264)
      • What this is: Disk persistence of candidate strategy code during validation checks.
      • Problem: dest.write_text(code) writes the candidate file to fuzzer/strategies/ before check_interface and smoke testing run. If the candidate fails interface inspection or smoke tests and
      repairs fail, the broken code remains in fuzzer/strategies/ as the named iteration file.
      • Fix: Write to a scratch file during validation and copy to dest only after Validation.ok is confirmed.
      • If we skip it: Failed generation attempts leave invalid modules on disk that get picked up by loaders and tests.
  6. fuzzer/grammar.py shadows the top-level grammar package (fuzzer/grammar.py:L1-10)
      • What this is: A re-export module inside fuzzer/ intended to mirror the top-level grammar package.
      • Problem: When any script is executed with fuzzer on sys.path (such as python fuzzer/test_grammar_support.py), import grammar resolves to fuzzer/grammar.py instead of the root grammar/
      directory, importing itself recursively and crashing with AttributeError: module 'grammar' has no attribute '__all__'.
      • Fix: Delete fuzzer/grammar.py and have callers import directly from grammar.
      • If we skip it: Direct command-line execution of fuzzer scripts fails on module import.
  ──────
  ### Should fix
  7. Five test suites use a non-asserting check() helper that hides test failures under pytest (fuzzer/test_performance.py:L46-52, fuzzer/test_improvements.py:L38-44,
  fuzzer/test_grammar_support.py:L37-43)
      • What this is: Integration test suites for fuzzer performance, grammar support, and improvements.
      • Problem: Individual test functions call check(name, cond) which only appends to an internal list without asserting. When run under pytest, the test functions exit normally, and pytest
      reports all tests as passing even when checks fail.
      • Fix: Assert assert not _failed at the end of each test function, or use standard assert statements.
      • If we skip it: Broken features in the fuzzer package report 100% green test runs in pytest.
  8. CI pipeline and default pytest configuration omit all fuzzer tests (pyproject.toml:L6, .github/workflows/ci.yml:L44, scripts/ci.py:L116-125)
      • What this is: Test discovery configuration in pyproject.toml and CI runner scripts.
      • Problem: pyproject.toml sets testpaths = ["agent"], and scripts/ci.py only invokes pytest agent. Over 400 test assertions across fuzzer/test_*.py are never run on commits, pull requests,
      or CI builds.
      • Fix: Include the fuzzer test suite in scripts/ci.py:run_unit and pyproject.toml.
      • If we skip it: Regressions in core fuzzer components pass through CI undetected.
  9. The --prompt-ab CLI flag instantiates PromptABTester but is never executed (agent/loop.py:L291-296)
      • What this is: A/B testing infrastructure for comparing prompt template versions across iterations.
      • Problem: self.ab_tester is created in _init_prompts(), but is never referenced again in Loop. Every iteration continues using self.prompt_set directly; variants are never rotated or
      evaluated.
      • Fix: Call self.ab_tester.choose_variant() and self.ab_tester.observe() in Loop._run(), or remove the unused flag.
      • If we skip it: Users passing --prompt-ab get standard single-prompt runs without any A/B routing.
  10. PromptVersion rendering helpers are bypassed by raw file replacement in Loop (agent/loop.py:L681-697, agent/prompt_manager.py:L106-150)
      • What this is: Prompt template rendering in the agent loop.
      • Problem: PromptVersion provides render_seed() and render_refine(), but Loop re-implements raw disk reads and chained string .replace() calls.
      • Fix: Delegate rendering to self.prompt_version.render_seed(...) and self.prompt_version.render_refine(...).
      • If we skip it: Two diverging implementations of template substitution must be maintained.
  11. Non-XML crash payloads are saved with .xml file extensions (fuzzer/campaign.py:L398)
      • What this is: Crash artifact writing in Campaign._process_one.
      • Problem: Line 398 hardcodes (crash_dir / f"{sha[:16]}.xml").write_bytes(payload), saving binary DNS packets, JSON payloads, or HTTP requests as .xml files.
      • Fix: Save payloads as .bin or use an extension attribute from target_obj.
      • If we skip it: Triaged crash files have misleading file extensions that confuse inspection tools and editors.
  12. OpenAICompatBackend documentation hint directs Anthropic users to a 404 endpoint (agent/llm.py:L458-459)
      • What this is: Error message guidance for configuring API credentials and endpoints.
      • Problem: The hint suggests setting OPENAI_BASE_URL=https://api.anthropic.com/v1, but Anthropic's API does not expose OpenAI-compatible /chat/completions endpoints, returning a 404 error.
      • Fix: Point Anthropic users to the Claude CLI backend (--backend cli) or an OpenAI-compatible proxy gateway like LiteLLM.
      • If we skip it: New users following the printed error message encounter unexpected connection failures.
  13. Result cache opens and closes SQLite connection for every individual input (fuzzer/result_cache.py:L100-110, fuzzer/campaign.py:L648-662)
      • What this is: Deterministic harness result caching in SQLite.
      • Problem: _session() connects, sets WAL PRAGMAs, commits, and closes the database on every single payload execution, creating heavy filesystem lock overhead in high-throughput campaigns.
      • Fix: Keep one open SQLite connection per worker thread and close it when the campaign completes.
      • If we skip it: Result caching slows down fast in-process campaigns rather than accelerating them.

  ──────
  ### Nice to have

  14. Duplicate minimization algorithms across two modules (minimize.py, fuzzer/reproducer.py:L34-138)
      • What this is: Input minimization logic for crashing inputs.
      • Problem: minimize.py implements Hypothesis shrinker hunting, while reproducer.py implements an independent custom Delta Debugger.
      • Fix: Consolidate payload reduction under reproducer.py or share the reduction passes.
      • If we skip it: Two separate code paths perform input minimization with differing guarantees.
  15. Delta debugger simplification pass hardcodes XML characters (fuzzer/reproducer.py:L130)
      • What this is: Stage 4 simplification pass in DeltaDebugger.
      • Problem: The byte simplifier preserves < > / = " because it assumes XML structure, which is unnecessary when reducing JSON, DNS, or HTTP inputs.
      • Fix: Retrieve delimiter characters from the target object if available.
      • If we skip it: Minimization for non-XML payloads retains irrelevant angle brackets.
  16. Monolithic Loop class mixes orchestration, reporting, and CLI handling (agent/loop.py:L137-1410)
      • What this is: Central orchestrator for the agentic refinement loop.
      • Problem: agent/loop.py is over 1,500 lines long, combining prompt compilation, budgeting, validation retries, markdown table formatting, and resume accounting in one class.
      • Fix: Extract markdown report generation and prompt construction into separate helper functions.
      • If we skip it: The loop file remains dense and difficult to review or test in isolation.

---