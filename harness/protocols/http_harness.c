// Fuzzing harness for HTTP protocol parser.
//
// Reads an HTTP request from stdin or argv[1] and parses method, URI, version, and headers.
// Reports outcome via exit code and the standard Stratagem line protocol.
//
// Exit codes:
//   0  parsed cleanly
//   1  rejected (syntax error)
//   2  harness error
//   3  parsed with diagnostics (e.g. ambiguity / smuggling warning)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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
      if (!nbuf) { free(buf); return NULL; }
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
  if (!f) return EXIT_HARNESS_ERR;

  size_t len = 0;
  char *doc = slurp(f, &len);
  if (path) fclose(f);
  if (!doc) return EXIT_HARNESS_ERR;

  if (len == 0) {
    n_diags++;
    printf("DIAG\tEmpty HTTP request on line 1\n");
    printf("RESULT\trejected\t%d\n", n_diags);
    free(doc);
    return EXIT_REJECTED;
  }

  // Find request line
  char *eol = strstr(doc, "\r\n");
  if (!eol) eol = strchr(doc, '\n');
  if (!eol) {
    n_diags++;
    printf("DIAG\tMissing newline in request line on line 1\n");
    printf("RESULT\trejected\t%d\n", n_diags);
    free(doc);
    return EXIT_REJECTED;
  }

  // Parse method, uri, version
  char method[64] = {0}, uri[1024] = {0}, version[64] = {0};
  int scanned = sscanf(doc, "%63s %1023s %63s", method, uri, version);
  if (scanned < 3) {
    n_diags++;
    printf("DIAG\tMalformed HTTP request line on line 1\n");
    printf("RESULT\trejected\t%d\n", n_diags);
    free(doc);
    return EXIT_REJECTED;
  }

  if (strncmp(version, "HTTP/", 5) != 0) {
    n_diags++;
    printf("DIAG\tInvalid HTTP version '%s' on line 1\n", version);
    printf("RESULT\trejected\t%d\n", n_diags);
    free(doc);
    return EXIT_REJECTED;
  }

  int has_cl = 0, has_te = 0;
  char *p = eol + (*eol == '\r' ? 2 : 1);
  int line_num = 2;

  while (*p && p < doc + len) {
    if (*p == '\r' && *(p+1) == '\n') break;
    if (*p == '\n') break;

    char *next_eol = strstr(p, "\r\n");
    if (!next_eol) next_eol = strchr(p, '\n');
    if (!next_eol) next_eol = doc + len;

    char *colon = memchr(p, ':', next_eol - p);
    if (!colon) {
      n_diags++;
      printf("DIAG\tMissing ':' in header on line %d\n", line_num);
      printf("RESULT\trejected\t%d\n", n_diags);
      free(doc);
      return EXIT_REJECTED;
    }

    size_t hname_len = colon - p;
    if (hname_len == 0 || isspace((unsigned char)*(colon - 1))) {
      n_diags++;
      printf("DIAG\tInvalid header name formatting on line %d\n", line_num);
      printf("RESULT\trejected\t%d\n", n_diags);
      free(doc);
      return EXIT_REJECTED;
    }

    if (hname_len == 14 && strncasecmp(p, "Content-Length", 14) == 0) has_cl = 1;
    if (hname_len == 17 && strncasecmp(p, "Transfer-Encoding", 17) == 0) has_te = 1;

    p = next_eol + (*next_eol == '\r' ? 2 : 1);
    line_num++;
  }

  int rc = EXIT_PARSED_CLEAN;
  if (has_cl && has_te) {
    n_diags++;
    printf("DIAG\tAmbiguous framing: both Content-Length and Transfer-Encoding on line 2\n");
    rc = EXIT_PARSED_DIAG;
  }

  printf("RESULT\t%s\t%d\n", "parsed", n_diags);
  fflush(stdout);
  free(doc);
  return rc;
}
