# Findings

The historical campaigns tested 10,000 documents from 19 generated strategies
and one random-text baseline. They found no memory-safety crash and no timeout.
The work produced one upstream fix, reproduced one known leak, and identified a
smaller diagnostic limitation.

## F1. Non-ASCII characters damaged error messages

**Status: fixed upstream.** I reported the problem in
[PR #357](https://github.com/michaelrsweet/mxml/pull/357) and explained that it
was found through fuzzing. The maintainer fixed it in commit
[`d986100`](https://github.com/michaelrsweet/mxml/commit/d9861001da). The fix
prints bad characters in `U+XXXX` form.

Four messages in `mxml-file.c` formatted a decoded Unicode code point with
`%c`. The value came from `mxml_getc()`, so it was a code point rather than a
single byte.

This caused two visible problems:

- Values with a low byte of `0x00`, such as U+0100, inserted a NUL and cut the
  message short.
- Values from U+0080 to U+00FF inserted one high byte. That byte was not a valid
  UTF-8 encoding of the character.

Both problems reached applications through the public
`mxmlOptionsSetErrorCallback()` callback.

```text
input          message before the fix
U+0041 'A'     XML does not start with '<' (saw 'A').
U+00E9         XML does not start with '<' (saw '\xe9').     invalid UTF-8
U+0100         XML does not start with '<' (saw '            truncated
U+1F600        XML does not start with '<' (saw '            truncated
```

A short reproducer is:

```sh
python3 -c "import sys; sys.stdout.buffer.write('Ā<r/>'.encode())" > t.xml
./build/asan/harness t.xml
```

The random-text baseline found this before the agentic loop started. The same
parser error appeared as several diagnostic templates because its text changed
with the rejected character. I followed that difference to the `%c` call
sites.

The diagnostic normalizer still counts a truncated message as a separate
observable template. This can make the distinct-message total slightly higher
than the number of parser error sites.

## F2. Known index bug used as a control

**Status: known and already fixed upstream.** This is upstream issue #350, not a
finding from this project. It is included to test crash detection.

`templ` and `tempr` are `size_t`. When `tempr` is zero, `tempr - 1`
wraps to `SIZE_MAX`:

```c
size_t templ, tempr;
if (left < (tempr - 1))
  index_sort(ind, left, tempr - 1);
```

Several inputs reach the same bug:

| document | root order | result |
|---|---|---|
| `<a><b/></a>` | smallest first | crash |
| `<b><aa/><a/></b>` | largest first | crash |
| `<a><a/><a/></a>` | equal names | no crash |

The bug is in `mxmlIndexNew`, not in the parse entry point used by the
campaigns. The harness reaches it only with `--index`. The smoke test checks
the crashing input and the similar non-crashing input.

## F3. Leak on an attribute error

**Status: independently reproduced.** The problem matches upstream issue
[#354](https://github.com/michaelrsweet/mxml/issues/354). It was open in mxml
v4.0.4 and on the upstream branch when I tested it.

LeakSanitizer found the same stack signature in 820 of the 10,000 historical
documents, or 8.2%:

```text
mxml_new -> mxmlNewElement -> mxml_load_data -> mxmlLoadString
```

The rate depends on how often a strategy produces an attribute without a value.
It ranged from 1.9% to 18.3% across runs. The complete replay result is in
`runs/analysis/leak_pass.json`.

The smallest reproducer used here is five bytes:

```sh
printf '<a a>' | ASAN_OPTIONS=detect_leaks=1 ./build/asan/harness
# LeakSanitizer: detected memory leaks, 90 bytes
```

Nearby inputs show that the leak belongs to this error path:

| input | parser result | leaked |
|---|---|---:|
| `<a a>` | missing attribute value | 90 bytes |
| `<a></b>` | mismatched close tag | 0 bytes |
| `<a a="1">` | parsed | 0 bytes |

The element is allocated before the pointer used by the cleanup path is
assigned. Two errors can jump to cleanup during that interval. My crash
signature grouped `<a a>` with the reproducer from issue #354, which supports
the match.

## F4. Long diagnostics lose their useful ending

**Status: not reported upstream.** This is bounded and memory-safe. I recorded
it as a diagnostic limitation rather than a security bug.

`_mxml_error` uses a fixed 1,024-byte buffer:

```c
char s[1024];
vsnprintf(s, sizeof(s), format, ap);
```

Some messages put a long element name before the explanation. When the name is
long enough, the callback receives 1,023 bytes of the name and none of the text
that explains the error.

```sh
python3 -c "print('<a/><' + 'b'*1100 + '/>', end='')" | ./build/asan/harness
```

Run D reached this case after generating names up to 389 characters and as many
as 257 attributes on one element. The diagnostic normalizer groups messages at
the buffer limit into one template, so several truncations from one site do not
look like separate parser branches.

## Upstream issue #355 did not apply

Issue #355 reports a heap over-read from a UTF-16 byte-order mark followed by an
odd number of bytes. It affects an older function named `mxml_string_getc`.
mxml 4.x no longer contains that function, so the reported bug does not apply to
the pinned target.

The check was still useful because it pointed to a gap in my byte-oriented
tests. The fixed byte probe now includes truncated UTF-16.

## Crash triage check

The campaigns found no memory-safety crash, so I tested the triage path with the
known issue #350 control.

Three different inputs produced the same normalized signature:

```text
<a><b/></a>                  -> d8ee1ccd656a
<b><aa/><a/></b>             -> d8ee1ccd656a
<!DOCTYPE a SYSTEM ""><a/>   -> d8ee1ccd656a
```

The normalizer removes repeated recursive frames and address or line-number
changes. This prevents recursion depth from creating several signatures for one
bug.

Hypothesis reduced a crashing generated case to:

```text
examples before shrinking : 15
shrunk input              : '<!DOCTYPE a SYSTEM ""><a/>'   (26 bytes)
label                     : heap-buffer-overflow READ index_sort@mxml-index.c
```

Hypothesis minimizes the generator's draw sequence, not the final byte length.
The hand-written `<a><b/></a>` input is shorter at 11 bytes. The shrunk input
was run five times and reproduced the crash each time.

Stack-based signatures are only an estimate of root cause. Klees et al. found
that common stack-hash methods can merge different bugs or split one bug. The
normalization rules are kept in `fuzzer/triage.py`.

## Remaining gaps

`mxml_getc` handles encoding detection and multi-byte decoding. In the first
coverage review, only 31.7% of its 82 lines were reached. The main cause was the
serializer error described in `docs/design-decisions.md` D13.

After the serializer fix, the five saved run C strategies plus the fixed byte
probe reached 73.17% of `mxml_getc` and 47.06% of `mxml-file.c`. This is
corrected evaluation, not a replay of the historical corpora.

Across the five historical run C corpora, no raw UTF-16 byte-order mark reached
the parser. The final saved strategy also produced none in 1,500 corrected draws
at seeds 11, 22, and 33. The raw-byte branch was valid but too rare in the
strategy's larger `st.one_of`.

`fuzzer/strategies/byte_probe.py` removes that sampling problem. It always runs
eight fixed cases: UTF-16LE and UTF-16BE marks, truncated UTF-16, a UTF-8 mark,
malformed UTF-8, an embedded NUL, and a contradictory encoding declaration.
All eight cases replay with the same classifications, and none causes a crash.
