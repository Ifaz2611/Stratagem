// libFuzzer / AFL++ control harness for Mini-XML (mxml) v4.0.4.
//
// Serves as a traditional coverage-guided fuzzing control against the same
// parse entry point (mxmlLoadString) used by Stratagem.
//
// Compile with libFuzzer:
//   clang -g -O1 -fsanitize=fuzzer,address,undefined -Ithird_party/mxml \
//     harness/fuzz_control.c third_party/mxml/libmxml4.a -o build/fuzz_control
//
// Usage:
//   ./build/fuzz_control -max_total_time=60 -max_len=65536

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "mxml.h"

// Discard diagnostics to avoid polluting fuzzer output
static void null_error_cb(void *cbdata, const char *message)
{
  (void)cbdata;
  (void)message;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  // Mini-XML requires NUL-terminated strings for mxmlLoadString
  char *doc = (char *)malloc(size + 1);
  if (!doc)
    return 0;

  memcpy(doc, data, size);
  doc[size] = '\0';

  mxml_options_t *opts = mxmlOptionsNew();
  if (!opts) {
    free(doc);
    return 0;
  }

  mxmlOptionsSetErrorCallback(opts, null_error_cb, NULL);

  mxml_node_t *tree = mxmlLoadString(NULL, opts, doc);
  if (tree) {
    mxmlDelete(tree);
  }

  mxmlOptionsDelete(opts);
  free(doc);

  return 0;
}
