#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "base64_url.h"

size_t base64_urldecode(unsigned char *decoded, const char *string)
{
  char *data;
  size_t i, n;

  n = strlen(string);
  data = malloc(n * sizeof(char) + 5);
  if (!data) {
    return 0;
  }

  for (i = 0; i < n; i++) {
    switch (string[i]) {
      case '-':
        data[i] = '+';
        break;
      case '_':
        data[i] = '/';
        break;
      default:
        data[i] = string[i];
    }
  }
  n = 4 - (i % 4);
  if (n < 4) {
    while (n--) {
      data[i++] = '=';
    }
  }
  data[i] = '\0';

  n = base64_decode(decoded, data);

  free(data);

  return n;
}

size_t base64_urlencode(char *encoded, const unsigned char *string, size_t len)
{
  size_t i, n, t;

  n = base64_encode(encoded, string, len);

  for (i = t = 0; i < n; i++) {
    switch (encoded[i]) {
      case '+':
        encoded[t++] = '-';
        break;
      case '/':
        encoded[t++] = '_';
        break;
      case '=':
        break;
      default:
        encoded[t++] = encoded[i];
    }
  }

  encoded[t] = '\0';

  return t;
}
