#ifndef BASE64_URL_H
#define BASE64_URL_H

size_t base64_urldecode(unsigned char *decoded, const char *string);
size_t base64_urlencode(char *encoded, const unsigned char *string, size_t len);

#endif /* BASE64_URL_H */
