// Fuzzing harness for Mini-XML (mxml) v4.0.4.
//
// Reads one XML document and calls the library's parse entry point,
// mxmlLoadString(). Reports what happened via exit code and a machine-readable
// line protocol on stdout.
//
// Three design points, each following from how mxml actually behaves
// (see grammar/ADAPTATIONS.md):
//
//   1. Input comes from a file or stdin, never argv. A single argv entry is
//      capped at MAX_ARG_STRLEN, 128 KiB on Linux, which silently truncates
//      large documents such as deep-nesting tests.
//
//   2. Accept/reject is decided by mxmlLoadString()'s return value, not by
//      whether the error callback fired. mxml emits a diagnostic and still
//      returns a tree for some inputs, such as a raw control character in
//      character data, so classifying on "did an error appear" would misreport
//      those as rejections and corrupt the acceptance-rate signal.
//
//   3. Diagnostics go to stdout, leaving stderr reserved for sanitizer output.
//      The Python runner scans stderr for AddressSanitizer and
//      UndefinedBehaviorSanitizer reports, and parser messages in that stream
//      would make crash detection ambiguous.
//
// Exit codes:
//   0  parsed, no diagnostics        ("valid parse")
//   3  parsed, with diagnostics      (parsed-but-complained; a real 4th state)
//   1  rejected                      ("well-formed rejection", not a crash)
//   2  harness error                 (our fault: cannot read input, OOM)
//   killed by signal / sanitizer abort  -> crash, detected by the runner
//
// stdout line protocol (tab-separated; mxml messages contain no tabs):
//   DIAG\t<message>
//   RESULT\tparsed|rejected\t<ndiags>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mxml.h"

#define EXIT_PARSED_CLEAN 0
#define EXIT_REJECTED     1
#define EXIT_HARNESS_ERR  2
#define EXIT_PARSED_DIAG  3

static int n_diags = 0;

// Called by mxml for every diagnostic. Note this fires for recoverable
// complaints too, not only fatal ones -- see design point 2 above.
static void on_error(void *cbdata, const char *message)
{
  (void)cbdata;
  n_diags++;
  fputs("DIAG\t", stdout);

  // Escape control bytes rather than emitting the message raw.
  //
  // mxml interpolates the offending character into some messages, e.g.
  // "XML does not start with '<' (saw 'X')". When X is a newline or tab, a raw
  // write splits one DIAG record across two lines or injects a field separator,
  // and the reader sees a truncated message, corrupting the diagnostic
  // histogram the loop steers by.
  for (const char *p = message ? message : "(null)"; *p; p++) {
    unsigned char c = (unsigned char)*p;
    switch (c) {
      case '\n': fputs("\\n", stdout); break;
      case '\r': fputs("\\r", stdout); break;
      case '\t': fputs("\\t", stdout); break;
      case '\\': fputs("\\\\", stdout); break;
      default:
        if (c < 0x20 || c == 0x7f)
          printf("\\x%02x", c);
        else
          fputc((int)c, stdout);
    }
  }
  fputc('\n', stdout);
}

// Slurp an entire stream into a NUL-terminated heap buffer.
// mxmlLoadString needs a NUL-terminated string, and the document may contain
// embedded NULs from the generator; those simply truncate the document as far
// as mxml is concerned, which is itself worth exercising.
static char *slurp(FILE *f, size_t *out_len)
{
  size_t cap = 65536, len = 0;
  char *buf = malloc(cap);
  if (!buf)
    return NULL;

  for (;;) {
    if (len + 1 >= cap) {
      size_t ncap = cap * 2;
      char *nbuf = realloc(buf, ncap);
      if (!nbuf) {
        free(buf);
        return NULL;
      }
      buf = nbuf;
      cap = ncap;
    }
    size_t n = fread(buf + len, 1, cap - len - 1, f);
    if (n == 0)
      break;
    len += n;
  }

  buf[len] = '\0';
  *out_len = len;
  return buf;
}

int main(int argc, char **argv)
{
  const char *path = NULL;
  int build_index = 0;

  for (int i = 1; i < argc; i++) {
    // Opt-in, and not used during fuzzing runs. Reproduces the known heap
    // under-read in index_sort (upstream issue #350), present in v4.0.4 and
    // fixed after it, as a positive control confirming the crash-detection and
    // triage pipeline catches a real bug rather than merely never crashing.
    if (!strcmp(argv[i], "--index"))
      build_index = 1;
    else
      path = argv[i];
  }

  FILE *f = path ? fopen(path, "rb") : stdin;
  if (!f) {
    fprintf(stderr, "harness: cannot open %s\n", path);
    return EXIT_HARNESS_ERR;
  }

  size_t len = 0;
  char *doc = slurp(f, &len);
  if (path)
    fclose(f);
  if (!doc) {
    fprintf(stderr, "harness: out of memory reading input\n");
    return EXIT_HARNESS_ERR;
  }

  mxml_options_t *opts = mxmlOptionsNew();
  if (!opts) {
    free(doc);
    fprintf(stderr, "harness: mxmlOptionsNew failed\n");
    return EXIT_HARNESS_ERR;
  }
  mxmlOptionsSetErrorCallback(opts, on_error, NULL);

  // The parse entry point under test.
  mxml_node_t *tree = mxmlLoadString(NULL, opts, doc);

  if (tree && build_index) {
    mxml_index_t *ind = mxmlIndexNew(tree, NULL, NULL);
    if (ind)
      mxmlIndexDelete(ind);
  }

  printf("RESULT\t%s\t%d\n", tree ? "parsed" : "rejected", n_diags);
  fflush(stdout);

  int rc;
  if (tree) {
    rc = n_diags ? EXIT_PARSED_DIAG : EXIT_PARSED_CLEAN;
    // Freeing walks the whole tree and is part of what is under test: a
    // malformed document can produce a tree that is safe to build and unsafe
    // to tear down.
    mxmlDelete(tree);
  } else {
    rc = EXIT_REJECTED;
  }

  mxmlOptionsDelete(opts);
  free(doc);
  return rc;
}
