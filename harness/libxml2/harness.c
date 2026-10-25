// Fuzzing harness for libxml2.
//
// Reads one XML document from stdin or argv[1] and calls xmlReadMemory().
// Reports what happened via exit code and the standard Stratagem stdout protocol.
//
// Exit codes:
//   0  parsed, clean (no diagnostics)
//   3  parsed, with diagnostics
//   1  rejected (parse error / tree NULL)
//   2  harness error (file read error, OOM)
//   signal / sanitizer abort -> crash
//
// stdout line protocol:
//   DIAG\t<message>
//   RESULT\tparsed|rejected\t<ndiags>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>

#define EXIT_PARSED_CLEAN 0
#define EXIT_REJECTED     1
#define EXIT_HARNESS_ERR  2
#define EXIT_PARSED_DIAG  3

static int n_diags = 0;

static void on_error(void *ctx, const char *msg, ...)
{
  (void)ctx;
  char buf[1024];
  va_list args;
  va_start(args, msg);
  vsnprintf(buf, sizeof(buf), msg, args);
  va_end(args);

  n_diags++;
  fputs("DIAG\t", stdout);
  for (const char *p = buf; *p; p++) {
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

  xmlSetGenericErrorFunc(NULL, (xmlGenericErrorFunc)on_error);

  // Parse entry point under test: xmlReadMemory
  xmlDocPtr tree = xmlReadMemory(doc, (int)len, "noname.xml", NULL,
                                 XML_PARSE_NOBLANKS | XML_PARSE_NONET);

  printf("RESULT\t%s\t%d\n", tree ? "parsed" : "rejected", n_diags);
  fflush(stdout);

  int rc;
  if (tree) {
    rc = n_diags ? EXIT_PARSED_DIAG : EXIT_PARSED_CLEAN;
    xmlFreeDoc(tree);
  } else {
    rc = EXIT_REJECTED;
  }

  xmlCleanupParser();
  free(doc);
  return rc;
}
