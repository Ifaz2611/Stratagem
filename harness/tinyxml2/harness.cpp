// Fuzzing harness for TinyXML-2.
//
// Reads one XML document from stdin or argv[1] and calls XMLDocument::Parse().
// Reports what happened via exit code and the standard Stratagem stdout protocol.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "tinyxml2.h"

#define EXIT_PARSED_CLEAN 0
#define EXIT_REJECTED     1
#define EXIT_HARNESS_ERR  2
#define EXIT_PARSED_DIAG  3

static int n_diags = 0;

static char *slurp(FILE *f, size_t *out_len)
{
  size_t cap = 65536, len = 0;
  char *buf = (char *)malloc(cap);
  if (!buf) return NULL;

  for (;;) {
    if (len + 1 >= cap) {
      size_t ncap = cap * 2;
      char *nbuf = (char *)realloc(buf, ncap);
      if (!nbuf) {
        free(buf);
        return NULL;
      }
      buf = nbuf;
      cap = ncap;
    }
    size_t n = fread(buf + len, 1, cap - len - 1, f);
    if (n == 0) break;
    len += n;
  }
  buf[len] = '\0';
  *out_len = len;
  return buf;
}

int main(int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : NULL;
  FILE *f = path ? fopen(path, "rb") : stdin;
  if (!f) {
    fprintf(stderr, "harness: cannot open %s\n", path ? path : "stdin");
    return EXIT_HARNESS_ERR;
  }

  size_t len = 0;
  char *doc = slurp(f, &len);
  if (path) fclose(f);
  if (!doc) {
    fprintf(stderr, "harness: out of memory reading input\n");
    return EXIT_HARNESS_ERR;
  }

  tinyxml2::XMLDocument xmlDoc;
  tinyxml2::XMLError err = xmlDoc.Parse(doc, len);

  int rc;
  if (err != tinyxml2::XML_SUCCESS) {
    n_diags++;
    printf("DIAG\t%s: %s on line %d\n", xmlDoc.ErrorName(), xmlDoc.ErrorStr(), xmlDoc.ErrorLineNum());
    printf("RESULT\trejected\t%d\n", n_diags);
    rc = EXIT_REJECTED;
  } else {
    printf("RESULT\tparsed\t%d\n", n_diags);
    rc = EXIT_PARSED_CLEAN;
  }

  fflush(stdout);
  free(doc);
  return rc;
}
