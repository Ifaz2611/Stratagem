// Fuzzing harness for JSON parser.
//
// Reads a JSON document from stdin or argv[1] and parses it.
// Reports outcome via exit code and the standard Stratagem stdout protocol.
//
// Exit codes:
//   0  parsed cleanly
//   1  rejected (syntax error)
//   2  harness error (file read failure, OOM)
//   signal / sanitizer abort -> crash

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define EXIT_PARSED_CLEAN 0
#define EXIT_REJECTED     1
#define EXIT_HARNESS_ERR  2
#define EXIT_PARSED_DIAG  3

static int n_diags = 0;

static void report_diag(const char *msg, int line, int col)
{
  n_diags++;
  printf("DIAG\t%s at line %d, column %d\n", msg, line, col);
}

// Minimal C JSON validator
typedef struct {
  const char *src;
  size_t len;
  size_t pos;
  int line;
  int col;
} Parser;

static void advance(Parser *p)
{
  if (p->pos < p->len) {
    if (p->src[p->pos] == '\n') {
      p->line++;
      p->col = 1;
    } else {
      p->col++;
    }
    p->pos++;
  }
}

static char peek(Parser *p)
{
  return p->pos < p->len ? p->src[p->pos] : '\0';
}

static void skip_ws(Parser *p)
{
  while (p->pos < p->len && (p->src[p->pos] == ' ' || p->src[p->pos] == '\t' ||
                             p->src[p->pos] == '\r' || p->src[p->pos] == '\n')) {
    advance(p);
  }
}

static int parse_value(Parser *p, int depth);

static int parse_string(Parser *p)
{
  if (peek(p) != '"') return 0;
  advance(p);
  while (p->pos < p->len) {
    char c = peek(p);
    if ((unsigned char)c < 0x20) {
      report_diag("Unescaped control character in string", p->line, p->col);
      return 0;
    }
    if (c == '"') {
      advance(p);
      return 1;
    }
    if (c == '\\') {
      advance(p);
      if (p->pos >= p->len) break;
      char esc = peek(p);
      if (esc == '"' || esc == '\\' || esc == '/' || esc == 'b' ||
          esc == 'f' || esc == 'n' || esc == 'r' || esc == 't') {
        advance(p);
      } else if (esc == 'u') {
        advance(p);
        for (int i = 0; i < 4; i++) {
          if (!isxdigit((unsigned char)peek(p))) {
            report_diag("Invalid unicode escape sequence", p->line, p->col);
            return 0;
          }
          advance(p);
        }
      } else {
        report_diag("Invalid escape sequence", p->line, p->col);
        return 0;
      }
    } else {
      advance(p);
    }
  }
  report_diag("Unterminated string", p->line, p->col);
  return 0;
}

static int parse_number(Parser *p)
{
  if (peek(p) == '-') advance(p);
  if (!isdigit((unsigned char)peek(p))) {
    report_diag("Expected digit in number", p->line, p->col);
    return 0;
  }
  while (isdigit((unsigned char)peek(p))) advance(p);
  if (peek(p) == '.') {
    advance(p);
    if (!isdigit((unsigned char)peek(p))) {
      report_diag("Expected digit after decimal point", p->line, p->col);
      return 0;
    }
    while (isdigit((unsigned char)peek(p))) advance(p);
  }
  if (peek(p) == 'e' || peek(p) == 'E') {
    advance(p);
    if (peek(p) == '+' || peek(p) == '-') advance(p);
    if (!isdigit((unsigned char)peek(p))) {
      report_diag("Expected digit in exponent", p->line, p->col);
      return 0;
    }
    while (isdigit((unsigned char)peek(p))) advance(p);
  }
  return 1;
}

static int parse_object(Parser *p, int depth)
{
  if (depth > 512) {
    report_diag("Maximum JSON nesting depth exceeded", p->line, p->col);
    return 0;
  }
  advance(p); // skip '{'
  skip_ws(p);
  if (peek(p) == '}') {
    advance(p);
    return 1;
  }
  for (;;) {
    skip_ws(p);
    if (peek(p) != '"') {
      report_diag("Expected string key in object", p->line, p->col);
      return 0;
    }
    if (!parse_string(p)) return 0;
    skip_ws(p);
    if (peek(p) != ':') {
      report_diag("Expected ':' after key", p->line, p->col);
      return 0;
    }
    advance(p);
    skip_ws(p);
    if (!parse_value(p, depth + 1)) return 0;
    skip_ws(p);
    if (peek(p) == '}') {
      advance(p);
      return 1;
    }
    if (peek(p) == ',') {
      advance(p);
    } else {
      report_diag("Expected ',' or '}' in object", p->line, p->col);
      return 0;
    }
  }
}

static int parse_array(Parser *p, int depth)
{
  if (depth > 512) {
    report_diag("Maximum JSON nesting depth exceeded", p->line, p->col);
    return 0;
  }
  advance(p); // skip '['
  skip_ws(p);
  if (peek(p) == ']') {
    advance(p);
    return 1;
  }
  for (;;) {
    skip_ws(p);
    if (!parse_value(p, depth + 1)) return 0;
    skip_ws(p);
    if (peek(p) == ']') {
      advance(p);
      return 1;
    }
    if (peek(p) == ',') {
      advance(p);
    } else {
      report_diag("Expected ',' or ']' in array", p->line, p->col);
      return 0;
    }
  }
}

static int parse_value(Parser *p, int depth)
{
  skip_ws(p);
  char c = peek(p);
  if (c == '"') return parse_string(p);
  if (c == '{') return parse_object(p, depth);
  if (c == '[') return parse_array(p, depth);
  if (c == '-' || isdigit((unsigned char)c)) return parse_number(p);
  if (p->pos + 4 <= p->len && strncmp(p->src + p->pos, "true", 4) == 0) {
    p->pos += 4; p->col += 4; return 1;
  }
  if (p->pos + 5 <= p->len && strncmp(p->src + p->pos, "false", 5) == 0) {
    p->pos += 5; p->col += 5; return 1;
  }
  if (p->pos + 4 <= p->len && strncmp(p->src + p->pos, "null", 4) == 0) {
    p->pos += 4; p->col += 4; return 1;
  }
  report_diag("Unexpected character parsing value", p->line, p->col);
  return 0;
}

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

  Parser p = {doc, len, 0, 1, 1};
  skip_ws(&p);
  int ok = 0;
  if (p.pos < p.len) {
    ok = parse_value(&p, 0);
    skip_ws(&p);
    if (ok && p.pos < p.len) {
      report_diag("Extra content after JSON document", p.line, p.col);
      ok = 0;
    }
  } else {
    report_diag("Empty JSON document", 1, 1);
  }

  printf("RESULT\t%s\t%d\n", ok ? "parsed" : "rejected", n_diags);
  fflush(stdout);
  free(doc);
  return ok ? EXIT_PARSED_CLEAN : EXIT_REJECTED;
}
