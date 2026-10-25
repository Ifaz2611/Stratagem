// Fuzzing harness for libexpat.
//
// Reads one XML document from stdin or argv[1] and calls XML_Parse().
// Reports what happened via exit code and the standard Stratagem stdout protocol.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <expat.h>

#define EXIT_PARSED_CLEAN 0
#define EXIT_REJECTED     1
#define EXIT_HARNESS_ERR  2
#define EXIT_PARSED_DIAG  3

static int n_diags = 0;

static char *slurp(FILE *f, size_t *out_len)
{
  size_t cap = 65536, len = 0;
  char *buf = malloc(cap);
  if (!buf) return NULL;

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

  XML_Parser parser = XML_ParserCreate(NULL);
  if (!parser) {
    free(doc);
    fprintf(stderr, "harness: XML_ParserCreate failed\n");
    return EXIT_HARNESS_ERR;
  }

  enum XML_Status status = XML_Parse(parser, doc, (int)len, 1);
  int rc;

  if (status == XML_STATUS_ERROR) {
    enum XML_Error err_code = XML_GetErrorCode(parser);
    const char *err_msg = XML_ErrorString(err_code);
    long line = XML_GetCurrentLineNumber(parser);
    long col = XML_GetCurrentColumnNumber(parser);

    n_diags++;
    printf("DIAG\t%s on line %ld, column %ld\n", err_msg ? err_msg : "unknown error", line, col);
    printf("RESULT\trejected\t%d\n", n_diags);
    rc = EXIT_REJECTED;
  } else {
    printf("RESULT\tparsed\t%d\n", n_diags);
    rc = EXIT_PARSED_CLEAN;
  }

  fflush(stdout);
  XML_ParserFree(parser);
  free(doc);
  return rc;
}
