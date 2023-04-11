#ifndef THUMBHASH_H
#define THUMBHASH_H

typedef struct thumbhash thumbhash_t;

thumbhash_t *thumbhash_load_image(const char *filename);
thumbhash_t *thumbhash_load_image_base64(const char *data);
thumbhash_t *thumbhash_import_message_digest(const char *data, const int url);
void thumbhash_free(thumbhash_t *thumbhash);

char *thumbhash_to_message_digest(thumbhash_t *thumbhash, const int url);

int thumbhash_to_image(thumbhash_t *thumbhash, const int width, const int height, const double saturation);

int thumbhash_export_image(thumbhash_t *thumbhash, const char *filename);
char *thumbhash_export_image_base64(thumbhash_t *thumbhash);

#endif /* THUMBHASH_H */
