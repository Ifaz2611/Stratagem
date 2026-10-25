// Fuzzing harness for SMTP protocol parser.
//
// Reads SMTP session commands from stdin or argv[1] and parses commands and parameters.
// Reports outcome via exit code and standard Stratagem stdout protocol.

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
    printf("DIAG\tEmpty SMTP stream\n");
    printf("RESULT\trejected\t%d\n", n_diags);
    free(doc);
    return EXIT_REJECTED;
  }

  char *p = doc;
  int line_num = 1;
  int in_data = 0;

  while (*p && p < doc + len) {
    char *eol = strstr(p, "\r\n");
    if (!eol) eol = strchr(p, '\n');
    if (!eol) eol = doc + len;

    size_t line_len = eol - p;
    if (line_len > 1000) {
      n_diags++;
      printf("DIAG\t500 Line too long (%zu > 1000) on line %d\n", line_len, line_num);
      printf("RESULT\trejected\t%d\n", n_diags);
      free(doc);
      return EXIT_REJECTED;
    }

    if (in_data) {
      if (line_len == 1 && *p == '.') in_data = 0;
    } else if (line_len > 0) {
      char verb[32] = {0};
      sscanf(p, "%31s", verb);
      for (int i = 0; verb[i]; i++) verb[i] = (char)toupper((unsigned char)verb[i]);

      if (strcmp(verb, "DATA") == 0) {
        in_data = 1;
      } else if (strcmp(verb, "HELO") == 0 || strcmp(verb, "EHLO") == 0) {
        if (line_len <= 5) {
          n_diags++;
          printf("DIAG\t501 Syntax error in %s parameters on line %d\n", verb, line_num);
          printf("RESULT\trejected\t%d\n", n_diags);
          free(doc);
          return EXIT_REJECTED;
        }
      } else if (strcmp(verb, "MAIL") == 0) {
        if (!strstr(p, "FROM:") && !strstr(p, "from:")) {
          n_diags++;
          printf("DIAG\t501 Syntax error in MAIL command on line %d\n", line_num);
          printf("RESULT\trejected\t%d\n", n_diags);
          free(doc);
          return EXIT_REJECTED;
        }
      } else if (strcmp(verb, "RCPT") == 0) {
        if (!strstr(p, "TO:") && !strstr(p, "to:")) {
          n_diags++;
          printf("DIAG\t501 Syntax error in RCPT command on line %d\n", line_num);
          printf("RESULT\trejected\t%d\n", n_diags);
          free(doc);
          return EXIT_REJECTED;
        }
      } else if (strcmp(verb, "QUIT") == 0 || strcmp(verb, "RSET") == 0 || strcmp(verb, "NOOP") == 0) {
        // OK
      } else {
        n_diags++;
        printf("DIAG\t500 Command unrecognized: '%s' on line %d\n", verb, line_num);
        printf("RESULT\trejected\t%d\n", n_diags);
        free(doc);
        return EXIT_REJECTED;
      }
    }

    p = eol + (*eol == '\r' ? 2 : 1);
    line_num++;
  }

  printf("RESULT\tparsed\t%d\n", n_diags);
  fflush(stdout);
  free(doc);
  return EXIT_PARSED_CLEAN;
}
