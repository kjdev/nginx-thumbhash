#include <alloca.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_LINEAR
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include "base64.h"
#include "base64_url.h"
#include "thumbhash.h"

struct thumbhash {
  int width;
  int height;
  int channels;
  unsigned char *pixels;
  struct {
    unsigned char data[25];
    size_t len;
  } hash;
};

static thumbhash_t *thumbhash_new(void)
{
  thumbhash_t *thumbhash = NULL;

  thumbhash = malloc(sizeof(thumbhash_t));
  if (!thumbhash) {
    return NULL;
  }
  memset(thumbhash, 0, sizeof(thumbhash_t));

  thumbhash->pixels = NULL;

  return thumbhash;
}

typedef struct {
  double dc;
  double scale;
  struct {
    double *data;
    size_t len;
    size_t size;
  } ac;
} thumbhash_channel_t;

typedef struct {
  thumbhash_channel_t l;
  thumbhash_channel_t p;
  thumbhash_channel_t q;
  thumbhash_channel_t a;
  uint8_t has_alpha;
  uint8_t is_landscape;
} thumbhash_hash_t;

static void thumbhash_hash_deinit(thumbhash_hash_t *hash)
{
  if (!hash) {
    return;
  }

  if (hash->l.ac.data) {
    free(hash->l.ac.data);
    hash->l.ac.data = NULL;
  }
  if (hash->p.ac.data) {
    free(hash->p.ac.data);
    hash->p.ac.data = NULL;
  }
  if (hash->q.ac.data) {
    free(hash->q.ac.data);
    hash->q.ac.data = NULL;
  }
  if (hash->a.ac.data) {
    free(hash->a.ac.data);
    hash->a.ac.data = NULL;
  }
}

static int thumbhash_encode_channel(thumbhash_channel_t *channel,
                                    const double *data,
                                    const int nx, const int ny,
                                    const int width, const int height)
{
  double *fx;
  int cx, cy;

  if (!channel || !data) {
    return EINVAL;
  }

  channel->ac.size = nx * ny;
  channel->ac.data = calloc(channel->ac.size, sizeof(double));
  if (!channel->ac.data) {
    return ENOMEM;
  }
  channel->ac.len = 0;
  channel->dc = 0.0;
  channel->scale = 0.0;

  fx = alloca(width * sizeof(double));
  if (!fx) {
    return ENOMEM;
  }
  memset(fx, 0, width * sizeof(double));

  for (cy = 0; cy < ny; cy++) {
    for (cx = 0; cx * ny < nx * (ny - cy); cx++) {
      double f = 0.0;
      int x, y;

      for (x = 0; x < width; x++) {
        fx[x] = cos(M_PI /(double) width * (double) cx * ((double) x + 0.5));
      }

      for (y = 0; y < height; y++) {
        double fy;
        fy = cos(M_PI / (double) height * (double) cy * ((double) y + 0.5));

        for (x = 0; x < width; x++) {
          f += data[x+y*width] * fx[x] * fy;
        }
      }

      f /= (double) (width * height);

      if (cx > 0 || cy > 0) {
        if (channel->ac.len >= channel->ac.size) {
          return EPERM;
        }
        channel->ac.data[channel->ac.len++] = f;
        channel->scale = fmax(channel->scale, fabs(f));
      }
      else {
        channel->dc = f;
      }
    }
  }

  if (channel->scale > 0.0) {
    size_t i;
    for (i = 0; i < channel->ac.len; i++) {
      channel->ac.data[i] = 0.5 + 0.5 / channel->scale * channel->ac.data[i];
    }
  }

  return 0;
}

static int thumbhash_encode(thumbhash_t *thumbhash,
                            unsigned char *pixels, int width, int height)
{
  double avg_r = 0, avg_g = 0, avg_b = 0, avg_a = 0;
  double lm, l_limit;
  double *l, *p, *q, *a;
  int lx, ly,idx, x;
  int header16 = 0, header24 = 0;
  size_t i, size;
  thumbhash_hash_t hash = {0};

  if (!thumbhash || !pixels) {
    return EINVAL;
  }

  size = width * height;

  for (i = 0; i < size; i++) {
    double alpha;

    alpha = pixels[i*4+3] / 255.0;

    avg_r += alpha / 255.0 * pixels[i*4];
    avg_g += alpha / 255.0 * pixels[i*4+1];
    avg_b += alpha / 255.0 * pixels[i*4+2];
    avg_a += alpha;
  }

  if (avg_a > 0.0) {
    avg_r /= avg_a;
    avg_g /= avg_a;
    avg_b /= avg_a;
  }

  l_limit = 7.0;
  if (avg_a < size) {
    hash.has_alpha = 1;
    l_limit = 5.0;
  }

  lm = fmax(width, height);
  lx = (int) fmax(1, round(l_limit * width / lm));
  ly = (int) fmax(1, round(l_limit * height / lm));

  l = malloc(size * sizeof(double));
  if (!l) {
    return ENOMEM;
  }
  p = malloc(size * sizeof(double));
  if (!p) {
    free(l);
    return ENOMEM;
  }
  q = malloc(size * sizeof(double));
  if (!q) {
    free(l);
    free(p);
    return ENOMEM;
  }
  a = malloc(size * sizeof(double));
  if (!q) {
    free(l);
    free(p);
    free(q);
    return ENOMEM;
  }

  /* Convert the image from RGBA to LPQA (composite atop the average color) */
  for (i = 0; i < size; i++) {
    double r, g, b, alpha;

    alpha = pixels[i*4+3] / 255.0;

    r = avg_r * (1.0 - alpha) + alpha / 255.0 * pixels[i*4];
    g = avg_g * (1.0 - alpha) + alpha / 255.0 * pixels[i*4+1];
    b = avg_b * (1.0 - alpha) + alpha / 255.0 * pixels[i*4+2];

    l[i] = (r + g + b) / 3.0;
    p[i] = (r + g) / 2.0 - b;
    q[i] = r - g;
    a[i] = alpha;
  }

  /* Encode using the DCT into DC and normalized AC terms */
  if (thumbhash_encode_channel(&hash.l, l, MAX(lx, 3), MAX(ly, 3),
                               width, height) != 0) {
    thumbhash_hash_deinit(&hash);
    return EPERM;
  }
  if (thumbhash_encode_channel(&hash.p, p, 3, 3, width, height) != 0) {
    thumbhash_hash_deinit(&hash);
    return EPERM;
  }
  if (thumbhash_encode_channel(&hash.q, q, 3, 3, width, height) != 0) {
    thumbhash_hash_deinit(&hash);
    return EPERM;
  }
  if (hash.has_alpha
      && thumbhash_encode_channel(&hash.a, a, 5, 5, width, height) != 0) {
    thumbhash_hash_deinit(&hash);
    return EPERM;
  }

  free(l);
  free(p);
  free(q);
  free(a);

  if (width > height) {
    hash.is_landscape = 1;
  }

  header24 = (int) round(63.0 * hash.l.dc);
  header24 |= (int) round(31.5 + 31.5 * hash.p.dc) << 6;
  header24 |= (int) round(31.5 + 31.5 * hash.q.dc) << 12;
  header24 |= (int) round(31.0 * hash.l.scale) << 18;
  if (hash.has_alpha) {
    header24 |= 1 << 23;
  }

  if (hash.is_landscape) {
    header16 = ly;
  }
  else {
    header16 = lx;
  }
  header16 |= (int) round(63.0 * hash.p.scale) << 3;
  header16 |= (int) round(63.0 * hash.q.scale) << 9;
  if (hash.is_landscape) {
    header16 |= 1 << 15;
  }

  /* Write the constants */
  thumbhash->hash.data[thumbhash->hash.len++] = header24 & 255;
  thumbhash->hash.data[thumbhash->hash.len++] = (header24 >> 8) & 255;
  thumbhash->hash.data[thumbhash->hash.len++] = header24 >> 16;
  thumbhash->hash.data[thumbhash->hash.len++] = header16 & 255;
  thumbhash->hash.data[thumbhash->hash.len++] = header16 >> 8;
  if (hash.has_alpha) {
    thumbhash->hash.data[thumbhash->hash.len++] =
      ((int) round(15.0 * hash.a.dc)) | ((int) round(15.0 * hash.a.scale) << 4);
  }

  /* Write the varying factors */
  idx = 0;
  for (x = 0; x < 4; x++) {
    thumbhash_channel_t *channel = NULL;

    switch (x) {
      case 0:
        channel = &hash.l;
        break;
      case 1:
        channel = &hash.p;
        break;
      case 2:
        channel = &hash.q;
        break;
      case 3:
        if (hash.has_alpha) {
          channel = &hash.a;
        }
        break;
    }

    if (!channel) {
      break;
    }

    for (i = 0; i < channel->ac.len; i++) {
      unsigned char u;

      u = round(15.0 * channel->ac.data[i]);
      if (idx & 1) {
        thumbhash->hash.data[thumbhash->hash.len++] |= u << 4;
      }
      else {
        thumbhash->hash.data[thumbhash->hash.len] = u;
      }
      idx += 1;
    }
  }

  thumbhash_hash_deinit(&hash);

  return 0;
}

typedef struct {
  thumbhash_t *thumbhash;
  int has_alpha;
  int idx;
} thumbhash_decode_channel_t;

static void thumbhash_decode_channel_init(thumbhash_decode_channel_t *decode,
                                          thumbhash_t *thumbhash,
                                          int has_alpha)
{
  decode->thumbhash = thumbhash;
  decode->has_alpha = has_alpha;
  decode->idx = 0;
}

static int thumbhash_decode_channel(thumbhash_decode_channel_t *decode,
                                    thumbhash_channel_t *channel,
                                    const int nx, const int ny,
                                    const double saturation)
{
  int cx, cy, offset;
  double scale;

  channel->ac.size = ny * ny * 2;
  channel->ac.data = calloc(channel->ac.size, sizeof(double));
  if (!channel->ac.data) {
    return ENOMEM;
  }
  channel->ac.len = 0;

  offset = decode->has_alpha ? 6 : 5;

  scale = channel->scale * saturation;

  for (cy = 0; cy < ny; cy++) {
    for (cx = cy ? 0 : 1; cx * ny < nx * (ny - cy); cx++) {
      size_t hidx;
      double f;

      hidx = offset + (decode->idx/2);
      if (hidx >= decode->thumbhash->hash.len) {
        free(channel->ac.data);
        channel->ac.data = NULL;
        return EPERM;
      }

      f = ((double) ((decode->thumbhash->hash.data[hidx]
                      >> ((decode->idx & 1) * 4)) & 15)
           / 7.5 - 1.0) * scale;
      channel->ac.data[channel->ac.len++] = f;

      decode->idx++;
    }
  }

  return 0;
}

static int thumbhash_decode(thumbhash_t *thumbhash,
                            int width, int height, double saturation)
{
  int base_size = 32;
  int header16 = 0, header24 = 0;
  int lx, ly;
  int i, x, y;
  double fx[7] = {0}, fy[7] = {0};
  double ratio;
  size_t size;
  thumbhash_hash_t hash = {0};
  thumbhash_decode_channel_t decode;

  if (!thumbhash || thumbhash->hash.len == 0) {
    return EINVAL;
  }

  /* the factor applied to increase image saturation */
  if (saturation <= 0.0) {
    saturation = 1.25;
  }

  /* Read the constants */
  header24 = thumbhash->hash.data[0];
  header24 |= thumbhash->hash.data[1] << 8;
  header24 |= thumbhash->hash.data[2] << 16;
  header16 = thumbhash->hash.data[3];
  header16 |= thumbhash->hash.data[4] << 8;

  hash.l.dc = (double) (header24 & 63) / 63.0;
  hash.p.dc = (double) ((header24 >> 6) & 63) / 31.5 - 1.0;
  hash.q.dc = (double) ((header24 >> 12) & 63) / 31.5 - 1.0;
  hash.l.scale = (double) ((header24 >> 18) & 31) / 31.0;
  if (header24 >> 23) {
    hash.has_alpha = 1;
  }
  hash.p.scale = (double) ((header16 >> 3) & 63) / 63.0;
  hash.q.scale = (double) ((header16 >> 9) & 63) / 63.0;
  hash.is_landscape = 0;
  if (header16 >> 15) {
    hash.is_landscape = 1;
  }
  lx = MAX(3, (hash.is_landscape ? (hash.has_alpha ? 5 : 7) : header16 & 7));
  ly = MAX(3, (hash.is_landscape ? (header16 & 7) : (hash.has_alpha ? 5 : 7)));
  hash.a.dc = 1.0;
  hash.a.scale = 0.0;
  if (hash.has_alpha) {
    if (thumbhash->hash.len < 6) {
      return EINVAL;
    }
    hash.a.dc = (thumbhash->hash.data[5] & 15) / 15.0;
    hash.a.scale = (thumbhash->hash.data[5] >> 4) / 15.0;
  }

  /* Read the varying factors */
  thumbhash_decode_channel_init(&decode, thumbhash, hash.has_alpha);
  if (thumbhash_decode_channel(&decode, &hash.l, lx, ly, 1.0) != 0) {
    thumbhash_hash_deinit(&hash);
    return EPERM;
  }
  if (thumbhash_decode_channel(&decode, &hash.p, 3, 3, saturation) != 0) {
    thumbhash_hash_deinit(&hash);
    return EPERM;
  }
  if (thumbhash_decode_channel(&decode, &hash.q, 3, 3, saturation) != 0) {
    thumbhash_hash_deinit(&hash);
    return EPERM;
  }
  if (hash.has_alpha) {
    if (thumbhash_decode_channel(&decode, &hash.a, 5, 5, 1.0) != 0) {
      thumbhash_hash_deinit(&hash);
      return EPERM;
    }
  }

  /* Decode size */
  if (width < 0) {
    width = 0;
  }
  if (height < 0) {
    height = 0;
  }
  if (!(width == 0 && height == 0) && (width == 0 || height == 0)) {
    base_size = MAX(width, height);
    width = 0;
    height = 0;
  }

  ratio = (double) lx / (double) ly;
  if (ratio > 1.0) {
    if (width > 0) {
      thumbhash->width = width;
    }
    else {
      thumbhash->width = base_size;
    }
    if (height > 0) {
      thumbhash->height = height;
    }
    else {
      thumbhash->height = (int) round((double) base_size / ratio);
    }
  }
  else {
    if (height > 0) {
      thumbhash->height = height;
    }
    else {
      thumbhash->height = base_size;
    }
    if (width > 0) {
      thumbhash->width = width;
    }
    else {
      thumbhash->width = (int) round((double) base_size * ratio);
    }
  }

  /* Decode using the DCT into RGB */
  if (thumbhash->pixels) {
    stbi_image_free(thumbhash->pixels);
  }
  size = thumbhash->width * thumbhash->height * 4 * sizeof(unsigned char);
  thumbhash->pixels = stbi__malloc(size);
  if (!thumbhash->pixels) {
    thumbhash_hash_deinit(&hash);
    return ENOMEM;
  }
  memset(thumbhash->pixels, 0, size);

  for (y = 0, i = 0; y < thumbhash->height; y++) {
    for (x = 0; x < thumbhash->width; x++, i += 4) {
      int j, cx, cy;
      double l = hash.l.dc, p = hash.p.dc, q = hash.q.dc, a = hash.a.dc;
      double f, fy2;
      double r, g, b;

      /* Precompute the coefficients */
      for (cx = 0; cx < MAX(lx, hash.has_alpha ? 5 : 3); cx++) {
        fx[cx] = cos(M_PI / (double) thumbhash->width
                     * ((double) x + 0.5) * (double) cx);
      }
      for (cy = 0; cy < MAX(ly, hash.has_alpha ? 5 : 3); cy++) {
        fy[cy] = cos(M_PI / (double) thumbhash->height
                     * ((double) y + 0.5) * (double) cy);
      }

      /* Decode L */
      for (cy = 0, j = 0; cy < ly; cy++) {
        fy2 = fy[cy] * 2.0;
        for (cx = cy ? 0 : 1; cx * ly < lx * (ly - cy); cx++, j++) {
          l += hash.l.ac.data[j] * fx[cx] * fy2;
        }
      }

      /* Decode P and Q */
      for (cy = 0, j = 0; cy < 3; cy++) {
        fy2 = fy[cy] * 2.0;
        for (cx = cy ? 0 : 1; cx < 3 - cy; cx++, j++) {
          f = fx[cx] * fy2;
          p += hash.p.ac.data[j] * f;
          q += hash.q.ac.data[j] * f;
        }
      }

      /* Decode A */
      if (hash.has_alpha) {
        for (cy = 0, j = 0; cy < 5; cy++) {
          fy2 = fy[cy] * 2.0;
          for (cx = cy ? 0 : 1; cx < 5 - cy; cx++, j++) {
            a += (double) hash.a.ac.data[j] * fx[cx] * fy2;
          }
        }
      }

      /* Convert to RGB */
      b = l - 2.0 / 3.0 * p;
      r = (3.0 * l - b + q) / 2.0;
      g = r - q;

      thumbhash->pixels[i] = (unsigned char) fmax(0, 255.0 * fmin(1.0, r));
      thumbhash->pixels[i+1] = (unsigned char) fmax(0, 255.0 * fmin(1.0, g));
      thumbhash->pixels[i+2] = (unsigned char) fmax(0, 255.0 * fmin(1.0, b));
      thumbhash->pixels[i+3] = (unsigned char) fmax(0, 255.0 * fmin(1.0, a));
    }
  }

  thumbhash_hash_deinit(&hash);

  return 0;
}

typedef struct {
  unsigned char *data;
  size_t len;
} thumbhash_image_t;

static void thumbhash_image_deinit(thumbhash_image_t *image)
{
  if (image && image->data) {
    free(image->data);
  }
}

static void thumbhash_image_write(void *context, void *data, int len)
{
  thumbhash_image_t *image;

  if (!context || !data || len <= 0) {
    return;
  }

  image = (thumbhash_image_t *) context;

  image->data = malloc(len * sizeof(unsigned char) + 1);
  if (!image->data) {
    return;
  }

  memcpy(image->data, data, len);
  image->data[len] = '\0';
  image->len = len;
}


thumbhash_t *thumbhash_load_image(const char *filename)
{
  int channels, height, width;
  unsigned char *pixels;
  thumbhash_t *thumbhash = NULL;

  if (!filename) {
    return NULL;
  }

  thumbhash = thumbhash_new();
  if (!thumbhash) {
    return NULL;
  }

  pixels = stbi_load(filename, &width, &height, &channels, STBI_rgb_alpha);
  if (!pixels) {
    thumbhash_free(thumbhash);
    return NULL;
  }

  if (thumbhash_encode(thumbhash, pixels, width, height) != 0) {
    free(pixels);
    thumbhash_free(thumbhash);
    return NULL;
  }

  free(pixels);

  return thumbhash;
}

thumbhash_t *thumbhash_load_image_base64(const char *data)
{
  int channels, height, width;
  unsigned char *buf, *pixels;
  size_t len;
  thumbhash_t *thumbhash = NULL;

  if (!data) {
    return NULL;
  }

  buf = malloc(3 * (strlen(data) / 4));
  if (!buf) {
    return NULL;
  }

  len = base64_decode(buf, data);
  if (!buf || !len) {
    free(buf);
    return NULL;
  }

  thumbhash = thumbhash_new();
  if (!thumbhash) {
    free(buf);
    return NULL;
  }

  pixels = stbi_load_from_memory(buf, len,
                                 &width, &height, &channels, STBI_rgb_alpha);
  if (!pixels) {
    free(buf);
    thumbhash_free(thumbhash);
    return NULL;
  }

  free(buf);

  if (thumbhash_encode(thumbhash, pixels, width, height) != 0) {
    free(pixels);
    thumbhash_free(thumbhash);
    return NULL;
  }

  free(pixels);

  return thumbhash;
}

thumbhash_t *thumbhash_import_message_digest(const char *data, const int url)
{
  thumbhash_t *thumbhash = NULL;

  if (!data) {
    return NULL;
  }

  thumbhash = thumbhash_new();
  if (!thumbhash) {
    return NULL;
  }

  if (url) {
    thumbhash->hash.len = base64_urldecode(thumbhash->hash.data, data);
  }
  else {
    thumbhash->hash.len = base64_decode(thumbhash->hash.data, data);
  }

  if (thumbhash->hash.len == 0) {
    thumbhash_free(thumbhash);
    return NULL;
  }

  return thumbhash;
}

void thumbhash_free(thumbhash_t *thumbhash)
{
  if (!thumbhash) {
    return;
  }

  if (thumbhash->pixels) {
    stbi_image_free(thumbhash->pixels);
  }

  free(thumbhash);
}

char *thumbhash_to_message_digest(thumbhash_t *thumbhash, const int url)
{
  char *var = NULL;

  if (!thumbhash || thumbhash->hash.len == 0) {
    return NULL;
  }

  var = calloc(thumbhash->hash.len * 2 + 1, sizeof(char));
  if (!var) {
    return NULL;
  }

  if (url) {
    base64_urlencode(var, thumbhash->hash.data, thumbhash->hash.len);
  }
  else {
    base64_encode(var, thumbhash->hash.data, thumbhash->hash.len);
  }

  return var;
}

int thumbhash_to_image(thumbhash_t *thumbhash,
                       const int width, const int height,
                       const double saturation)
{
  if (!thumbhash) {
    return EINVAL;
  }

  if (thumbhash_decode(thumbhash, width, height, saturation) != 0) {
    return EINVAL;
  }

  return 0;
}

int thumbhash_export_image(thumbhash_t *thumbhash, const char *filename)
{
  if (!thumbhash || !thumbhash->pixels || !filename) {
    return EINVAL;
  }

  if (stbi_write_png(filename,
                     thumbhash->width, thumbhash->height,
                     STBI_rgb_alpha, thumbhash->pixels,
                     thumbhash->width * STBI_rgb_alpha) == 0) {
    return EPERM;
  }

  return 0;
}

char *thumbhash_export_image_base64(thumbhash_t *thumbhash)
{
  char *var = NULL;
  thumbhash_image_t image = {0};

  if (!thumbhash || !thumbhash->pixels) {
    return NULL;
  }

  if (stbi_write_png_to_func(thumbhash_image_write, (void *) &image,
                             thumbhash->width, thumbhash->height,
                             STBI_rgb_alpha, thumbhash->pixels,
                             thumbhash->width * STBI_rgb_alpha) == 0) {
    return NULL;
  }

  if (image.data) {
    char *prefix = "data:image/png;base64,";
    size_t prefix_len = 22;

    var = calloc(image.len * 2 + prefix_len + 1, sizeof(char));
    if (!var) {
      return NULL;
    }

    memcpy(var, prefix, prefix_len);

    base64_encode(var + prefix_len, (unsigned char *) image.data, image.len);
  }

  thumbhash_image_deinit(&image);

  return var;
}
