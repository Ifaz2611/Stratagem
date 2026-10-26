# Task

Write a target-specific fuzzing harness for the parser below.

## Target

- **name:** {target_name}
- **category:** {target_category}
- **description:** {target_description}
- **language:** {language}
- **required headers:** {headers}
- **link flags:** {link_flags}

## Grammar or protocol specification

The specification below describes the input language. It is context, not a
complete parser recipe: the real target may accept more or less than it says.

```
{grammar_text}
```

## Output contract

The harness will be fed one input on stdin and measured by the campaign layer.
It must follow this exact contract:

| exit | meaning |
|---|---|
| 0 | parsed without diagnostics |
| 1 | rejected as malformed (not a crash) |
| 2 | harness error (allocation or setup failure) |
| 3 | parsed, but the parser emitted diagnostics |

Diagnostics are lines on stdout beginning with `DIAG` and a TAB:

```
DIAG<TAB>Missing close tag </a> on line 4
```

Do not print diagnostics on stderr; the campaign reads them from stdout. The
sanitizers are configured to abort on error, so a real bug will terminate the
process before any exit code is written.

## Constraints

- Read all of stdin, including embedded NULs and invalid UTF-8.
- The input is untrusted and may be empty, enormous, truncated or adversarial.
- Do not install signal handlers for SIGSEGV/SIGABRT/SIGBUS; they would hide
  the crashes the fuzzer is trying to find.
- Do not use `system`, `popen`, `exec*`, `fork`, sockets or file I/O.
- Allocate with `malloc`/`calloc`/`new` and check every result.
- Keep the harness under 300 lines.
- Define `int main(void)` (or `int main(int argc, char **argv)` if needed).
- For C++ targets, `extern "C"` is only needed where the library is C.

## Existing protocol harness (style reference only)

Use this only as a model for the stdin loop and the exit-status shape. Do not
copy target logic from it.

```c
{protocol_example}
```

Write the harness now. Output exactly one fenced code block.
