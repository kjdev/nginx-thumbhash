#include <math.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include "thumbhash.h"

static char *ngx_http_thumbhash_conf_set_render(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_thumbhash_conf_set_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_thumbhash_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_thumbhash_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_thumbhash_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_thumbhash_filter_handler(ngx_http_request_t *r);

typedef struct {
  ngx_flag_t enabled;
  ngx_http_complex_value_t *width;
  ngx_http_complex_value_t *height;
  ngx_http_complex_value_t *message_digest;
  ngx_flag_t base64url;
  ngx_http_complex_value_t *query;
  ngx_str_t temp_path;
} ngx_http_thumbhash_loc_conf_t;

static ngx_command_t ngx_http_thumbhash_commands[] = {
  { ngx_string("thumbhash_render"),
    NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    ngx_http_thumbhash_conf_set_render,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("thumbhash_filter"),
    NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE12,
    ngx_http_thumbhash_conf_set_filter,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("thumbhash_temp_path"),
    NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_thumbhash_loc_conf_t, temp_path),
    NULL },
  ngx_null_command
};

static ngx_http_module_t ngx_http_thumbhash_module_ctx = {
  NULL,                               /* preconfiguration */
  NULL,                               /* postconfiguration */
  NULL,                               /* create main configuration */
  NULL,                               /* init main configuration */
  NULL,                               /* create server configuration */
  NULL,                               /* merge server configuration */
  ngx_http_thumbhash_create_loc_conf, /* create location configuration */
  ngx_http_thumbhash_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_thumbhash_module = {
  NGX_MODULE_V1,
  &ngx_http_thumbhash_module_ctx, /* module context */
  ngx_http_thumbhash_commands,    /* module directives */
  NGX_HTTP_MODULE,                /* module type */
  NULL,                           /* init master */
  NULL,                           /* init module */
  NULL,                           /* init process */
  NULL,                           /* init thread */
  NULL,                           /* exit thread */
  NULL,                           /* exit process */
  NULL,                           /* exit master */
  NGX_MODULE_V1_PADDING
};

static char *
ngx_http_thumbhash_set_complex_value_slot(ngx_conf_t *cf,
                                          ngx_command_t *cmd, void *conf,
                                          ngx_str_t *value)
{
  ngx_http_compile_complex_value_t ccv;
  ngx_http_complex_value_t **cv;
  char *p = conf;

  cv = (ngx_http_complex_value_t **) (p + cmd->offset);

  if (*cv != NGX_CONF_UNSET_PTR && *cv != NULL) {
    return NGX_CONF_ERROR;
  }

  *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
  if (*cv == NULL) {
    return NGX_CONF_ERROR;
  }

  ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

  ccv.cf = cf;
  ccv.value = value;
  ccv.complex_value = *cv;

  if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *
ngx_http_thumbhash_conf_set_size(ngx_conf_t *cf, ngx_command_t *cmd,
                                 ngx_http_thumbhash_loc_conf_t *conf,
                                 ngx_str_t *value)
{
  ngx_str_t var;

  if (ngx_strncmp(value->data, "width=", 6) == 0 && value->len > 6) {
    var.data = value->data + 6;
    var.len = value->len - 6;
    return ngx_http_thumbhash_set_complex_value_slot(cf, cmd,
                                                     &conf->width, &var);
  }

  if (ngx_strncmp(value->data, "height=", 7) == 0 && value->len > 7) {
    var.data = value->data + 7;
    var.len = value->len - 7;
    return ngx_http_thumbhash_set_complex_value_slot(cf, cmd,
                                                     &conf->height, &var);
  }

  return NGX_CONF_ERROR;
}

static char *
ngx_http_thumbhash_conf_set_render(ngx_conf_t *cf,
                                   ngx_command_t *cmd, void *conf)
{
  ngx_http_core_loc_conf_t *clcf;
  ngx_str_t *value;
  ngx_uint_t i;
  ngx_http_thumbhash_loc_conf_t *lcf = conf;

  if (lcf->enabled == 1) {
    return "is duplicate";
  }

  value = cf->args->elts;

  if (ngx_http_thumbhash_set_complex_value_slot(cf, cmd,
                                                &lcf->message_digest,
                                                &value[1]) != NGX_CONF_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" invalid parameter \"%V\"",
                       &cmd->name, &value[1]);
    return NGX_CONF_ERROR;
  }

  for (i = 2; i < cf->args->nelts; i++) {
    if (ngx_http_thumbhash_conf_set_size(cf, cmd, lcf,
                                         &value[i]) == NGX_CONF_OK) {
      continue;
    }

    if (ngx_strncmp(value[i].data, "base64=", 7) == 0 && value[i].len > 7) {
      ngx_str_t var;

      var.data = value[i].data + 7;
      var.len = value[i].len - 7;

      if (ngx_strncmp(var.data, "url", 3) == 0) {
        lcf->base64url = 1;
      }
      else if (ngx_strncmp(var.data, "standard", 8) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" invalid parameter \"%V\"",
                           &cmd->name, &value[i]);
        return NGX_CONF_ERROR;
      }

      continue;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" invalid parameter \"%V\"",
                       &cmd->name, &value[i]);
    return NGX_CONF_ERROR;
  }

  lcf->enabled = 1;

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_thumbhash_handler;

  return NGX_CONF_OK;
}

static char *
ngx_http_thumbhash_conf_set_filter(ngx_conf_t *cf,
                                   ngx_command_t *cmd, void *conf)
{
  ngx_http_core_loc_conf_t *clcf;
  ngx_str_t *value;
  ngx_uint_t i;
  ngx_http_thumbhash_loc_conf_t *lcf = conf;

  if (lcf->enabled == 1) {
    return "is duplicate";
  }

  value = cf->args->elts;

  for (i = 1; i < cf->args->nelts; i++) {
    if (ngx_http_thumbhash_conf_set_size(cf, cmd, lcf,
                                         &value[i]) == NGX_CONF_OK) {
      continue;
    }

    if (ngx_strncmp(value[i].data, "query=", 6) == 0 && value[i].len > 6) {
      ngx_str_t var;

      var.data = value[i].data + 6;
      var.len = value[i].len - 6;

      if (ngx_http_thumbhash_set_complex_value_slot(cf, cmd, &lcf->query,
                                                    &var) == NGX_CONF_OK) {
        continue;
      }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"%V\" invalid parameter \"%V\"",
                       &cmd->name, &value[i]);
    return NGX_CONF_ERROR;
  }

  lcf->enabled = 1;

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_thumbhash_filter_handler;

  return NGX_CONF_OK;
}

static void *
ngx_http_thumbhash_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_thumbhash_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_thumbhash_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->enabled = NGX_CONF_UNSET;
  conf->width = NGX_CONF_UNSET_PTR;
  conf->height = NGX_CONF_UNSET_PTR;
  conf->message_digest = NGX_CONF_UNSET_PTR;
  conf->base64url = NGX_CONF_UNSET;
  conf->query = NGX_CONF_UNSET_PTR;

  return conf;
}

static char *
ngx_http_thumbhash_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_thumbhash_loc_conf_t *prev = parent;
  ngx_http_thumbhash_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
  ngx_conf_merge_ptr_value(conf->width, prev->width, NULL);
  ngx_conf_merge_ptr_value(conf->height, prev->height, NULL);
  ngx_conf_merge_ptr_value(conf->message_digest, prev->message_digest, NULL);
  ngx_conf_merge_value(conf->base64url, prev->base64url, 0);
  ngx_conf_merge_ptr_value(conf->query, prev->query, NULL);

  ngx_conf_merge_str_value(conf->temp_path, prev->temp_path, "");
  if (conf->temp_path.len > 0) {
    if (conf->temp_path.data[conf->temp_path.len-1] == '/') {
      conf->temp_path.len--;
    }
  }

  return NGX_CONF_OK;
}

static u_char *
ngx_http_thumbhash_strdup(ngx_pool_t *pool, u_char *data, size_t len)
{
  u_char *dst;

  dst = ngx_pnalloc(pool, len + 1);
  if (dst == NULL) {
    return NULL;
  }

  ngx_memcpy(dst, data, len);
  dst[len] = '\0';

  return dst;
}

static void
ngx_http_thumbhash_conf_get_size(ngx_http_request_t *r,
                                 ngx_http_thumbhash_loc_conf_t *cf,
                                 ngx_int_t *width, ngx_int_t *height)
{
  ngx_str_t w, h;

  *width = 0;
  if (cf->width
      && ngx_http_complex_value(r, cf->width, &w) == NGX_OK && w.len > 0) {
    *width = ngx_atoi(w.data, w.len);
    if (*width < 0) {
      *width = 0;
    }
  }

  *height = 0;
  if (cf->height
      && ngx_http_complex_value(r, cf->height, &h) == NGX_OK && h.len > 0) {
    *height = ngx_atoi(h.data, h.len);
    if (*height < 0) {
      *height = 0;
    }
  }
}

static ngx_int_t
ngx_http_thumbhash_to_temp_path(u_char *path,
                                ngx_http_thumbhash_loc_conf_t *cf,
                                ngx_flag_t create)
{
  ngx_int_t i, j;

  if (cf->temp_path.len <= 0) {
    return NGX_OK;
  }

  for (i = 0, j = 0; i < NGX_MAX_PATH_LEVEL; i++, j += 3) {
    if (i > 0 && create) {
      path[cf->temp_path.len+j] = '\0';
      if (ngx_create_dir(path, 0700) == NGX_FILE_ERROR) {
        return NGX_ERROR;
      }
    }

    path[cf->temp_path.len+j] = '/';
  }

  return NGX_OK;
}

static ngx_int_t
ngx_http_thumbhash_output_path(ngx_http_request_t *r,
                               ngx_http_thumbhash_loc_conf_t *cf,
                               ngx_int_t width, ngx_int_t height, char *ext,
                               ngx_str_t *path)
{
  size_t size, root;
  u_char *p;
  ngx_str_t suffix = ngx_null_string;

  if (!ext) {
    return NGX_ERROR;
  }

  size = ((unsigned int) log10(width)) + 1;
  size += ((unsigned int) log10(height)) + 1;
  size += ngx_strlen(ext) + 3;

  suffix.data = ngx_pnalloc(r->pool, size);
  if (suffix.data == NULL) {
    return NGX_ERROR;
  }

  if (width == 0 && height == 0) {
    p = ngx_sprintf(suffix.data, "%s", ext);
  }
  else if (width == 0 || height == 0) {
    p = ngx_sprintf(suffix.data, "_%d%s", ngx_max(width, height), ext);
  }
  else {
    p = ngx_sprintf(suffix.data, "_%dx%d%s", width, height, ext);
  }
  suffix.len = p - suffix.data;

  if (cf->temp_path.len) {
    u_char hash[16];
    ngx_md5_t md5;
    ngx_str_t key = ngx_null_string;

    key.len = r->uri.len + suffix.len;
    key.data = ngx_pnalloc(r->pool, key.len);
    if (key.data == NULL) {
      return NGX_ERROR;
    }
    ngx_memcpy(key.data, r->uri.data, r->uri.len);
    ngx_memcpy(key.data + r->uri.len, suffix.data, suffix.len);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, key.data, key.len);
    ngx_md5_final(hash, &md5);

    path->len = cf->temp_path.len + 2 * sizeof(hash);
    path->data = ngx_pnalloc(r->pool, path->len + 1);
    if (path->data == NULL) {
      return NGX_ERROR;
    }

    ngx_memcpy(path->data, cf->temp_path.data, cf->temp_path.len);
    p = ngx_hex_dump(path->data + cf->temp_path.len, hash, sizeof(hash));
    *p = '\0';

    if (ngx_http_thumbhash_to_temp_path(path->data, cf, 0) != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "thumbhash: failed to cache directory: %s", path->data);
      return NGX_ERROR;
    }

    return NGX_OK;
  }

  p = ngx_http_map_uri_to_path(r, path, &root, suffix.len);
  if (p == NULL) {
    return NGX_ERROR;
  }
  ngx_memcpy(p, suffix.data, suffix.len);
  p += suffix.len;
  *p = '\0';
  path->len = p - path->data;

  return NGX_OK;
}

static ngx_int_t
ngx_http_thumbhash_image_create(ngx_http_request_t *r,
                                ngx_http_thumbhash_loc_conf_t *cf,
                                ngx_str_t *message_digest, ngx_int_t base64url,
                                ngx_int_t width, ngx_int_t height,
                                ngx_str_t *path)
{
  char *input, *output;
  thumbhash_t *thumbhash;

  ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "thumbhash: create image: \"%V\","
                 " path: \"%V\", base64: %s, size: %dx%d",
                 message_digest, path, base64url ? "url" : "standard",
                 width, height);

  input = (char *) ngx_http_thumbhash_strdup(r->pool,
                                             message_digest->data,
                                             message_digest->len);
  if (!input) {
    return NGX_ERROR;
  }

  if (cf->temp_path.len) {
    if (ngx_http_thumbhash_to_temp_path(path->data, cf, 1) != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "thumbhash: failed to cache directory: %s", path->data);
      return NGX_ERROR;
    }
  }

  output = (char *) path->data;

  thumbhash = thumbhash_import_message_digest(input, base64url);
  if (!thumbhash) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "thumbhash: failed to thumbhash import: %s: base64: %s",
                  input, base64url ? "url" : "standard");
    return NGX_ERROR;
  }

  if (thumbhash_to_image(thumbhash, width, height, 0.0) != 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "thumbhash: failed to thumbhash image: %s", input);
    thumbhash_free(thumbhash);
    return NGX_ERROR;
  }

  if (thumbhash_export_image(thumbhash, output) != 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "thumbhash: failed to thumbhash export: %s", output);
    thumbhash_free(thumbhash);
    return NGX_ERROR;
  }

  thumbhash_free(thumbhash);

  return NGX_OK;
}

static ngx_int_t
ngx_http_thumbhash_image_convert(ngx_http_request_t *r,
                                 ngx_http_thumbhash_loc_conf_t *cf,
                                 ngx_str_t *src,
                                 ngx_int_t width, ngx_int_t height,
                                 ngx_str_t *dst)
{
  char *input, *output;
  thumbhash_t *thumbhash;

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "thumbhash: convert image: \"%V\", src: \"%V\"",
                 dst, src);

  input = (char *) ngx_http_thumbhash_strdup(r->pool, src->data, src->len);
  if (!input) {
    return NGX_ERROR;
  }

  if (cf->temp_path.len) {
    if (ngx_http_thumbhash_to_temp_path(dst->data, cf, 1) != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "thumbhash: failed to cache directory: %s", dst->data);
      return NGX_ERROR;
    }
  }

  output = (char *) dst->data;

  thumbhash = thumbhash_load_image(input);
  if (!thumbhash) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "thumbhash: failed to thumbhash load image: %s", input);
    return NGX_ERROR;
  }

  if (thumbhash_to_image(thumbhash, width, height, 0.0) != 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "thumbhash: failed to thumbhash image: %s", input);
    thumbhash_free(thumbhash);
    return NGX_ERROR;
  }

  if (thumbhash_export_image(thumbhash, output) != 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "thumbhash: failed to thumbhash export: %s", output);
    thumbhash_free(thumbhash);
    return NGX_ERROR;
  }

  thumbhash_free(thumbhash);

  return NGX_OK;
}

static ngx_int_t ngx_http_thumbhash_image_render(ngx_http_request_t *r,
                                                 ngx_str_t *path,
                                                 ngx_flag_t content_type)
{
  ngx_buf_t *buf;
  ngx_chain_t out;
  ngx_http_core_loc_conf_t *cf;
  ngx_int_t rc;
  ngx_log_t *log;
  ngx_open_file_info_t of;

  cf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

  log = r->connection->log;

  ngx_memzero(&of, sizeof(ngx_open_file_info_t));

  of.read_ahead = cf->read_ahead;
  of.directio = cf->directio;
  of.valid = cf->open_file_cache_valid;
  of.min_uses = cf->open_file_cache_min_uses;
  of.errors = cf->open_file_cache_errors;
  of.events = cf->open_file_cache_events;

  if (ngx_http_set_disable_symlinks(r, cf, path, &of) != NGX_OK) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (ngx_open_cached_file(cf->open_file_cache,
                           path, &of, r->pool) != NGX_OK) {
    ngx_uint_t level;

    switch (of.err) {
      case 0:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

      case NGX_ENOENT: // 404
      case NGX_ENOTDIR:
      case NGX_ENAMETOOLONG:
        return NGX_DECLINED;

      case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
      case NGX_EMLINK:
      case NGX_ELOOP:
#endif
        level = NGX_LOG_ERR;
        break;
      default:
        level = NGX_LOG_CRIT;
        break;
    }

    ngx_log_error(level, r->connection->log, of.err,
                  "thumbhash: %s \"%s\" failed", of.failed, path->data);

    return NGX_DECLINED;
  }

  r->root_tested = !r->error_page;

  rc = ngx_http_discard_request_body(r);
  if (rc != NGX_OK) {
    return rc;
  }

  log->action = "sending thumbhash to client";

  r->headers_out.status = NGX_HTTP_OK;
  r->headers_out.content_length_n = of.size;
  r->headers_out.last_modified_time = of.mtime;

  if (ngx_http_set_etag(r) != NGX_OK) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (content_type) {
    if (ngx_http_set_content_type(r) != NGX_OK) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
  }
  else {
    r->headers_out.content_type_len = sizeof("image/png") - 1;
    ngx_str_set(&r->headers_out.content_type, "image/png");
    r->headers_out.content_type_lowcase = NULL;
  }

  buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
  if (buf == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  buf->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
  if (buf->file == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
    return rc;
  }

  buf->file_pos = 0;
  buf->file_last = of.size;

  buf->in_file = buf->file_last ? 1 : 0;
  buf->last_buf = (r == r->main) ? 1 : 0;
  buf->last_in_chain = 1;

  buf->file->fd = of.fd;
  buf->file->name = *path;
  buf->file->log = log;
  buf->file->directio = of.is_directio;

  out.buf = buf;
  out.next = NULL;

  return ngx_http_output_filter(r, &out);
}

static ngx_int_t ngx_http_thumbhash_handler(ngx_http_request_t *r)
{
  ngx_file_info_t fi;
  ngx_http_thumbhash_loc_conf_t *cf;
  ngx_str_t path;
  ngx_int_t width = 0, height = 0;
  ngx_str_t message_digest = ngx_null_string;

  cf = ngx_http_get_module_loc_conf(r, ngx_http_thumbhash_module);

  if (!cf->message_digest
      || ngx_http_complex_value(r, cf->message_digest,
                                &message_digest) != NGX_OK
      || message_digest.len <= 0) {
    return NGX_HTTP_BAD_REQUEST;
  }

  ngx_http_thumbhash_conf_get_size(r, cf, &width, &height);

  if (ngx_http_thumbhash_output_path(r, cf, width, height, ".png",
                                     &path) != NGX_OK) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "thumbhash: destination filename: \"%V\"", &path);

  if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
    if (ngx_http_thumbhash_image_create(r, cf, &message_digest, cf->base64url,
                                        width, height, &path) != NGX_OK) {
      return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
  }

  return ngx_http_thumbhash_image_render(r, &path, 0);
}

static ngx_int_t ngx_http_thumbhash_filter_handler(ngx_http_request_t *r)
{
  size_t root;
  u_char *p;
  ngx_file_info_t fi;
  ngx_str_t src, dst;
  ngx_http_thumbhash_loc_conf_t *cf;
  ngx_int_t width = 0, height = 0;
  ngx_str_t query = ngx_null_string;

  cf = ngx_http_get_module_loc_conf(r, ngx_http_thumbhash_module);

  p = ngx_http_map_uri_to_path(r, &src, &root, 0);
  if (p == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  src.len--;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "thumbhash: source filename: \"%V\"", &src);

  if (!cf->query
      || ngx_http_complex_value(r, cf->query, &query) != NGX_OK
      || query.len <= 0) {
    query.data = (unsigned char *) "thumbhash";
    query.len = 9;
  }

  if (r->args.len < query.len || !ngx_strstr(r->args.data, query.data)) {
    return ngx_http_thumbhash_image_render(r, &src, 1);
  }

  ngx_http_thumbhash_conf_get_size(r, cf, &width, &height);

  if (ngx_http_thumbhash_output_path(r, cf, width, height, "_thumbhash.png",
                                     &dst) != NGX_OK) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "thumbhash: destination filename: \"%V\"", &dst);

  if (ngx_file_info(dst.data, &fi) == NGX_FILE_ERROR) {
    if (ngx_http_thumbhash_image_convert(r, cf, &src,
                                         width, height, &dst) != NGX_OK) {
      return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
  }

  return ngx_http_thumbhash_image_render(r, &dst, 0);
}
