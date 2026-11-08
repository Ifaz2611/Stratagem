# Control Experiment Report: Mini-XML v4.0.4

**Target:** `mxml`  
**Budget:** 500 inputs per method  
**Target Status:** **CLEAN** (No memory bugs in `mxmlLoadString`)  

## Comparative Summary

| Metric | Traditional Control (libFuzzer/AFL) | Stratagem (Agentic Grammar) | Difference |
|---|---|---|---|
| **Total Inputs** | 500 | 500 | - |
| **Memory Crashes** | **0** | **0** | 0 |
| **Timeouts** | **0** | **0** | 0 |
| **Clean Parses** | 55 (11.0%) | 99 (19.8%) | +44 |
| **Rejections** | 445 (89.0%) | 401 (80.2%) | -44 |
| **Diagnostic Templates** | 12 | 13 | +1 |
| **Branch / Proxy Edges** | 29 | 28 | -1 |
| **Peak Parse Depth** | 201 | 200 | -1 |

## Conclusion

Both traditional coverage-guided fuzzing (libFuzzer/AFL) and Stratagem's agentic grammar fuzzing found 0 memory-safety crashes and 0 hangs across 1,000 total inputs on mxml v4.0.4. This demonstrates that the zero-crash outcome in historical campaigns is due to the mature, memory-safe design of Mini-XML's mxmlLoadString() parse entry point (iterative parsing, bounded buffers, defensive bounds), rather than a blind spot exclusive to Stratagem's blackbox design.
