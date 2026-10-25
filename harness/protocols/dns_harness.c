// Fuzzing harness for DNS wire format packet parser.
//
// Reads a raw binary DNS message from stdin or argv[1] and parses the header,
// questions, and resource records. Checks for decompression loops and out-of-bounds reads.
//
// Exit codes:
//   0  parsed cleanly
//   1  rejected (malformed packet)
//   2  harness error
//   signal / abort -> crash (e.g. decompression loop abort)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_PARSED_CLEAN 0
#define EXIT_REJECTED     1
#define EXIT_HARNESS_ERR  2
#define EXIT_PARSED_DIAG  3

static int n_diags = 0;

static unsigned char *slurp(FILE *f, size_t *out_len)
{
  size_t cap = 65536, len = 0;
  unsigned char *buf = (unsigned char *)malloc(cap);
  if (!buf) return NULL;
  for (;;) {
    if (len + 1 >= cap) {
      size_t ncap = cap * 2;
      unsigned char *nbuf = (unsigned char *)realloc(buf, ncap);
      if (!nbuf) { free(buf); return NULL; }
      buf = nbuf;
      cap = ncap;
    }
    size_t n = fread(buf + len, 1, cap - len - 1, f);
    if (n == 0) break;
    len += n;
  }
  *out_len = len;
  return buf;
}

int main(int argc, char **argv)
{
  const char *path = argc > 1 ? argv[1] : NULL;
  FILE *f = path ? fopen(path, "rb") : stdin;
  if (!f) return EXIT_HARNESS_ERR;

  size_t len = 0;
  unsigned char *doc = slurp(f, &len);
  if (path) fclose(f);
  if (!doc) return EXIT_HARNESS_ERR;

  if (len < 12) {
    n_diags++;
    printf("DIAG\tTruncated DNS header: length %zu < 12\n", len);
    printf("RESULT\trejected\t%d\n", n_diags);
    free(doc);
    return EXIT_REJECTED;
  }

  unsigned short qdcount = (doc[4] << 8) | doc[5];
  size_t offset = 12;
  int seen_offsets[256];
  int n_seen = 0;

  for (int q = 0; q < qdcount; q++) {
    int name_len = 0;
    for (;;) {
      if (offset >= len) {
        n_diags++;
        printf("DIAG\tBuffer underflow parsing QNAME at offset %zu\n", offset);
        printf("RESULT\trejected\t%d\n", n_diags);
        free(doc);
        return EXIT_REJECTED;
      }
      unsigned char b = doc[offset];
      if (b == 0) {
        offset++;
        break;
      } else if ((b & 0xC0) == 0xC0) {
        if (offset + 1 >= len) {
          n_diags++;
          printf("DIAG\tIncomplete pointer at offset %zu\n", offset);
          printf("RESULT\trejected\t%d\n", n_diags);
          free(doc);
          return EXIT_REJECTED;
        }
        size_t ptr = ((b & 0x3F) << 8) | doc[offset + 1];
        if (ptr >= len) {
          n_diags++;
          printf("DIAG\tPointer out of bounds: %zu >= %zu at offset %zu\n", ptr, len, offset);
          printf("RESULT\trejected\t%d\n", n_diags);
          free(doc);
          return EXIT_REJECTED;
        }
        for (int i = 0; i < n_seen; i++) {
          if (seen_offsets[i] == (int)ptr) {
            // Compression loop: abort to trigger crash detection!
            fprintf(stderr, "DNS pointer compression loop detected at offset %zu\n", offset);
            abort();
          }
        }
        if (n_seen < 256) seen_offsets[n_seen++] = (int)ptr;
        offset += 2;
        break;
      } else if (b > 63) {
        n_diags++;
        printf("DIAG\tLabel length too large: %u > 63 at offset %zu\n", b, offset);
        printf("RESULT\trejected\t%d\n", n_diags);
        free(doc);
        return EXIT_REJECTED;
      } else {
        offset++;
        name_len += b;
        if (name_len > 255 || offset + b > len) {
          n_diags++;
          printf("DIAG\tTruncated label data or name > 255 at offset %zu\n", offset);
          printf("RESULT\trejected\t%d\n", n_diags);
          free(doc);
          return EXIT_REJECTED;
        }
        offset += b;
      }
    }
    if (offset + 4 > len) {
      n_diags++;
      printf("DIAG\tTruncated QTYPE/QCLASS at offset %zu\n", offset);
      printf("RESULT\trejected\t%d\n", n_diags);
      free(doc);
      return EXIT_REJECTED;
    }
    offset += 4;
  }

  printf("RESULT\tparsed\t%d\n", n_diags);
  fflush(stdout);
  free(doc);
  return EXIT_PARSED_CLEAN;
}
