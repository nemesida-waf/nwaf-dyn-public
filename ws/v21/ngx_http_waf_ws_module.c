
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Pentestit, LLC
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_upstream.h>

#include "ngx_http_waf_ws_module.h"
#include "request_parser.h"
#include "event_description.h"

#include "nwaf_parse.h"
#include "nwaf_process.h"

static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_body_output_filter(void *data, ngx_chain_t *in);
static ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_input_filter_init(void *data);
static ngx_int_t ngx_http_proxy_copy_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_chunked_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_non_buffered_copy_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_proxy_non_buffered_chunked_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_proxy_process_trailer(ngx_http_request_t *r,
    ngx_buf_t *buf);
static void ngx_http_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_proxy_rewrite(ngx_http_request_t *r,
    ngx_str_t *value, size_t prefix, size_t len, ngx_str_t *replacement);

static void *ngx_http_waf_ws_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_waf_ws_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_waf_ws_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_proxy_init_headers(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *conf, ngx_http_proxy_headers_t *headers,
    ngx_keyval_t *default_headers);
#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_proxy_preserve_ssl_passwords(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev);
#endif

static ngx_int_t ngx_http_nwaf_ws_init_process(ngx_cycle_t *cycle);
static void ngx_http_nwaf_ws_exit_process(ngx_cycle_t *cycle);

static char *ngx_http_nwaf_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

//static char *ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data);
#if (NGX_HTTP_SSL)
/*static char *ngx_http_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post,
    void *data);*/
#endif

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_proxy_merge_ssl(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *conf, ngx_http_proxy_loc_conf_t *prev);
static ngx_int_t ngx_http_proxy_set_ssl(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *plcf);
#if (NGX_HTTP_PROXY_MULTICERT)
static ngx_int_t ngx_http_proxy_compile_certificates(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *plcf);
#endif
#endif
static void ngx_http_proxy_set_vars(ngx_url_t *u, ngx_http_proxy_vars_t *v);


#if (NGX_HTTP_V3)

static ngx_int_t ngx_http_v3_proxy_merge_quic(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *conf, ngx_http_proxy_loc_conf_t *prev);

static ngx_int_t ngx_http_v3_proxy_create_request(ngx_http_request_t *r);

static ngx_chain_t *ngx_http_v3_create_headers_frame(ngx_http_request_t *r,
    ngx_buf_t *hbuf);
static ngx_chain_t *ngx_http_v3_create_data_frame(ngx_http_request_t *r,
    ngx_chain_t *body, size_t size);
static ngx_inline ngx_uint_t ngx_http_v3_map_method(ngx_uint_t method);
static ngx_int_t ngx_http_v3_proxy_encode_method(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b);
static ngx_int_t ngx_http_v3_proxy_encode_authority(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b);
static ngx_int_t ngx_http_v3_proxy_encode_path(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b);
static ngx_int_t ngx_http_v3_proxy_encode_headers(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b);
static ngx_int_t ngx_http_v3_proxy_body_length(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c);
static ngx_chain_t *ngx_http_v3_proxy_encode_body(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c);
static ngx_int_t ngx_http_v3_proxy_body_output_filter(void *data,
    ngx_chain_t *in);

static ngx_int_t ngx_http_v3_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_proxy_process_status_line(ngx_http_request_t *r);
static void ngx_http_v3_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http_v3_proxy_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);
static ngx_int_t ngx_http_v3_proxy_process_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);

static ngx_int_t ngx_http_v3_proxy_headers_done(ngx_http_request_t *r);
static ngx_int_t ngx_http_v3_proxy_process_pseudo_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value);
static ngx_int_t ngx_http_v3_proxy_input_filter_init(void *data);
static ngx_int_t ngx_http_v3_proxy_copy_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_v3_proxy_non_buffered_copy_filter(void *data,
    ssize_t bytes);
static ngx_int_t ngx_http_v3_proxy_construct_cookie_header(
    ngx_http_request_t *r);

static ngx_str_t  ngx_http_v3_proxy_quic_salt = ngx_string("ngx_quic");
#endif

#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_upstream_no_cache(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache_get(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_http_file_cache_t **cache);
static ngx_int_t ngx_http_upstream_cache_send(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache_background_update(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache_check_range(ngx_http_request_t *r, ngx_http_upstream_t *u);
#endif

static void ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r);
static void ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_set_local(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_http_upstream_local_t *local);
//static void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc);
static ngx_int_t ngx_http_upstream_need_connection_drop(ngx_http_upstream_t *u);
static void ngx_http_upstream_cleanup(void *data);
static void ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_configure(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c);
static void ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);

static ngx_int_t ngx_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c);
static void ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t ft_type);
static void ngx_http_upstream_free_peer(ngx_http_upstream_t *u, ngx_uint_t ft_type);
static void ngx_http_upstream_close_peer_connection(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t no_send);
static void ngx_http_upstream_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t do_write);
static ngx_int_t ngx_http_upstream_send_request_body(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t do_write);
static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_block_reading(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_process_header(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_process_early_hints(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_early_hints_writer(ngx_http_request_t *r);
static void ngx_http_upstream_handler(ngx_event_t *ev);
static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_test_next(ngx_http_request_t *r, ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_intercept_errors(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_read_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static void ngx_http_upstream_upgrade(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_upgraded_read_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_upgraded_write_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_upgraded_read_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_upgraded_write_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_process_upgraded(ngx_http_request_t *r, ngx_uint_t from_upstream, ngx_uint_t do_write);
static void ngx_http_upstream_process_non_buffered_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r);
static ngx_int_t ngx_http_upstream_output_filter(void *data, ngx_chain_t *chain);
static void ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r, ngx_uint_t do_write);
static void ngx_http_upstream_process_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_process_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_process_request(ngx_http_request_t *r, ngx_http_upstream_t *u);
static void ngx_http_upstream_store(ngx_http_request_t *r, ngx_http_upstream_t *u);

#if (NGX_THREADS)
static ngx_int_t ngx_http_upstream_thread_handler(ngx_thread_task_t *task, ngx_file_t *file);
static void ngx_http_upstream_thread_event_handler(ngx_event_t *ev);
#endif

u_char nwaf_ws_close[2] = {0x88, 0x00};

extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_upstream_module;

#if (NGX_HTTP_SSL)

static void ngx_http_upstream_ssl_init_connection(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c);
static void ngx_http_upstream_ssl_handshake_handler(ngx_connection_t *c);
static void ngx_http_upstream_ssl_handshake(ngx_http_request_t *, ngx_http_upstream_t *u, ngx_connection_t *c);
static void ngx_http_upstream_ssl_save_session(ngx_connection_t *c);
static ngx_int_t ngx_http_upstream_ssl_name(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c);
static ngx_int_t ngx_http_upstream_ssl_certificate(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c);


#if (NGX_HTTP_PROXY_MULTICERT)
static ngx_int_t ngx_http_upstream_ssl_certificates(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c);
#endif
#endif

#if (NGX_HTTP_V3)
static ngx_int_t ngx_http_v3_upstream_init_connection(ngx_http_request_t *,
    ngx_http_upstream_t *u, ngx_connection_t *c);
static ngx_int_t ngx_http_v3_upstream_init_ssl(ngx_connection_t *c, void *data);
static ngx_int_t ngx_http_v3_upstream_reuse_connection(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c);
static ngx_int_t ngx_http_v3_upstream_init_h3(ngx_connection_t *c,
    ngx_http_request_t *r);
static void ngx_http_v3_upstream_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_v3_upstream_connected(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *sc);
static ngx_int_t ngx_http_v3_upstream_send_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *sc);
static void ngx_http_quic_upstream_dummy_handler(ngx_event_t *ev);
static void ngx_http_quic_stream_close_handler(ngx_event_t *ev);
#endif

ngx_module_t  ngx_http_waf_ws_module;


static ngx_command_t  ngx_http_waf_ws_commands[] = {

    { ngx_string("nwaf_ws_proxy_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_nwaf_proxy_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_waf_ws_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_waf_ws_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_waf_ws_create_loc_conf,       /* create location configuration */
    ngx_http_waf_ws_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_waf_ws_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_ws_module_ctx,            /* module context */
    ngx_http_waf_ws_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_nwaf_ws_init_process,         /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_nwaf_ws_exit_process,         /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char  ngx_http_proxy_version[] = " HTTP/1.0" CRLF;
static char  ngx_http_proxy_version_11[] = " HTTP/1.1" CRLF;


static ngx_keyval_t  ngx_http_proxy_headers[] = {
    { ngx_string("Host"), ngx_string("$proxy_internal_host") },
    { ngx_string("Connection"), ngx_string("") },
    { ngx_string("Proxy-Connection"), ngx_string("") },
    { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
    { ngx_string("Transfer-Encoding"), ngx_string("$proxy_internal_chunked") },
    { ngx_string("TE"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};


#if (NGX_HTTP_V3)

/*
 * RFC 9114  4.2 HTTP Fields
 *
 * An intermediary transforming an HTTP/1.x message to HTTP/3 MUST remove
 * connection-specific header fields as discussed in Section 7.6.1 of [HTTP],
 * or their messages will be treated by other HTTP/3 endpoints as malformed.
 */
static ngx_keyval_t  ngx_http_v3_proxy_headers[] = {
    { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
#if 0
    /* TODO: trailers */
    { ngx_string("TE"), ngx_string("$v3_proxy_internal_trailers") },
#endif
    { ngx_string("Host"), ngx_string("") },
    { ngx_string("Connection"), ngx_string("") },
    { ngx_string("Transfer-Encoding"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};

#if (NGX_HTTP_CACHE)

static ngx_keyval_t  ngx_http_v3_proxy_cache_headers[] = {
    { ngx_string("Host"), ngx_string("") },
    { ngx_string("Connection"), ngx_string("") },
    { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
    { ngx_string("Transfer-Encoding"), ngx_string("") },
    { ngx_string("TE"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_string("If-Modified-Since"),
      ngx_string("$upstream_cache_last_modified") },
    { ngx_string("If-Unmodified-Since"), ngx_string("") },
    { ngx_string("If-None-Match"), ngx_string("$upstream_cache_etag") },
    { ngx_string("If-Match"), ngx_string("") },
    { ngx_string("Range"), ngx_string("") },
    { ngx_string("If-Range"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};

#endif

#endif

static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};


#if (NGX_HTTP_CACHE)

static ngx_keyval_t  ngx_http_proxy_cache_headers[] = {
    { ngx_string("Host"), ngx_string("$proxy_internal_host") },
    { ngx_string("Connection"), ngx_string("") },
    { ngx_string("Proxy-Connection"), ngx_string("") },
    { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
    { ngx_string("Transfer-Encoding"), ngx_string("$proxy_internal_chunked") },
    { ngx_string("TE"), ngx_string("") },
    { ngx_string("Keep-Alive"), ngx_string("") },
    { ngx_string("Expect"), ngx_string("") },
    { ngx_string("Upgrade"), ngx_string("") },
    { ngx_string("If-Modified-Since"),
      ngx_string("$upstream_cache_last_modified") },
    { ngx_string("If-Unmodified-Since"), ngx_string("") },
    { ngx_string("If-None-Match"), ngx_string("$upstream_cache_etag") },
    { ngx_string("If-Match"), ngx_string("") },
    { ngx_string("Range"), ngx_string("") },
    { ngx_string("If-Range"), ngx_string("") },
    { ngx_null_string, ngx_null_string }
};

#endif


static ngx_path_init_t  ngx_http_proxy_temp_path = {
    ngx_string(NGX_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
};


/*
static ngx_conf_bitmask_t  ngx_http_proxy_cookie_flags_masks[] = {

    { ngx_string("secure"),
      NGX_HTTP_PROXY_COOKIE_SECURE|NGX_HTTP_PROXY_COOKIE_SECURE_ON },

    { ngx_string("nosecure"),
      NGX_HTTP_PROXY_COOKIE_SECURE|NGX_HTTP_PROXY_COOKIE_SECURE_OFF },

    { ngx_string("httponly"),
      NGX_HTTP_PROXY_COOKIE_HTTPONLY|NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON },

    { ngx_string("nohttponly"),
      NGX_HTTP_PROXY_COOKIE_HTTPONLY|NGX_HTTP_PROXY_COOKIE_HTTPONLY_OFF },

    { ngx_string("samesite=strict"),
      NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT },

    { ngx_string("samesite=lax"),
      NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX },

    { ngx_string("samesite=none"),
      NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE },

    { ngx_string("nosamesite"),
      NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_OFF },

    { ngx_null_string, 0 }
};
*/



static ngx_http_upstream_next_t  ngx_http_upstream_next_errors[] = {
    { 500, NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { 502, NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { 503, NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { 504, NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { 403, NGX_HTTP_UPSTREAM_FT_HTTP_403 },
    { 404, NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { 429, NGX_HTTP_UPSTREAM_FT_HTTP_429 },
    { 0, 0 }
};

static ngx_int_t ngx_http_nwaf_ws_init_process(ngx_cycle_t *cycle){
  ngx_http_waf_ws_main_conf_t	*wwsmc;

  wwsmc = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_ws_module);

  nwaf_memc_connect(wwsmc);

  return NGX_OK;
}

static void ngx_http_nwaf_ws_exit_process(ngx_cycle_t *cycle){
  ngx_http_waf_ws_main_conf_t	*wwsmc;

  wwsmc = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_waf_ws_module);

  nwaf_memc_close(wwsmc);
}

static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream dummy handler");
}

static ngx_int_t ngx_http_upstream_output_filter(void *data, ngx_chain_t *chain)
{
    ngx_int_t            rc;
    ngx_event_pipe_t    *p;
    ngx_http_request_t  *r;

    r = data;
    p = r->upstream->pipe;

    rc = ngx_http_output_filter(r, chain);

    p->aio = r->aio;

    return rc;
}

static ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "upstream test connect");

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r, ngx_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_int_t                  rc;
    ngx_uint_t                 flags;
    ngx_connection_t          *downstream, *upstream;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;

    u = r->upstream;
    downstream = r->connection;
    upstream = u->peer.connection;

    b = &u->buffer;

    do_write = do_write || u->length == 0;

    for ( ;; ) {

        if (do_write) {

            if (u->out_bufs || u->busy_bufs || downstream->buffered) {
                rc = ngx_http_output_filter(r, u->out_bufs);

                if (rc == NGX_ERROR) {
                    ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                    return;
                }

                ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
                                        &u->out_bufs, u->output.tag);
            }

            if (u->busy_bufs == NULL) {

                if (u->length == 0
                    || (upstream->read->eof && u->length == -1))
                {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }

                if (upstream->read->eof) {
                    ngx_log_error(NGX_LOG_ERR, upstream->log, 0,
                                  "upstream prematurely closed connection");

                    ngx_http_upstream_finalize_request(r, u,
                                                       NGX_HTTP_BAD_GATEWAY);
                    return;
                }

                if (upstream->read->error || u->error) {
                    ngx_http_upstream_finalize_request(r, u,
                                                       NGX_HTTP_BAD_GATEWAY);
                    return;
                }

                b->pos = b->start;
                b->last = b->start;
            }
        }

        size = b->end - b->last;

        if (size && upstream->read->ready) {

            n = upstream->recv(upstream, b->last, size);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n > 0) {
                u->state->bytes_received += n;
                u->state->response_length += n;

                if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
                    ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                    return;
                }
            }

            do_write = 1;

            continue;
        }

        break;
    }

    if (ngx_http_upstream_need_connection_drop(u)) {
        ngx_log_error(NGX_LOG_INFO, upstream->log, 0, "drop connection");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (downstream->data == r) {
        if (ngx_handle_write_event(downstream->write, clcf->send_lowat)
            != NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
    }

    if (downstream->write->active && !downstream->write->ready) {
        ngx_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        ngx_del_timer(downstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = NGX_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (ngx_handle_read_event(upstream->read, flags) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        ngx_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        ngx_del_timer(upstream->read);
    }
}

static void ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r)
{
    ngx_event_t          *wev;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    wev = c->write;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered downstream");

    c->log->action = "sending to client";

    if (wev->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    ngx_http_upstream_process_non_buffered_request(r, 1);
}

static void ngx_http_upstream_process_non_buffered_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered upstream");

    c->log->action = "reading upstream";

    if (c->read->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    ngx_http_upstream_process_non_buffered_request(r, 0);
}

#if (NGX_THREADS)

static ngx_int_t ngx_http_upstream_thread_handler(ngx_thread_task_t *task, ngx_file_t *file)
{
    ngx_str_t                  name;
    ngx_event_pipe_t          *p;
    ngx_connection_t          *c;
    ngx_thread_pool_t         *tp;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;
    p = r->upstream->pipe;

    if (r->aio) {
        c = r->connection;

#if (NGX_HTTP_V2)
        if (r->stream) {
            c = r->stream->connection->connection;
        }
#endif

        if (task == c->sendfile_task) {
            return NGX_OK;
        }
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (ngx_http_complex_value(r, clcf->thread_pool_value, &name)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name);

        if (tp == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return NGX_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = ngx_http_upstream_thread_event_handler;

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        return NGX_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;
    p->aio = 1;

    ngx_add_timer(&task->event, 60000);

    return NGX_OK;
}


static void
ngx_http_upstream_thread_event_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream thread: \"%V?%V\"", &r->uri, &r->args);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "thread operation took too long");
        ev->timedout = 0;
        return;
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    r->main->blocked--;
    r->aio = 0;

#if (NGX_HTTP_V2)

    if (r->stream) {
        c->write->ready = 1;
        c->write->active = 0;
    }

#endif

    if (r->done || r->main->terminated) {
        c->write->handler(c->write);
    } else {
        r->write_event_handler(r);
        ngx_http_run_posted_requests(c);
    }
}

#endif

#if (NGX_HTTP_SSL)

static void ngx_http_upstream_ssl_init_connection(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_int_t                  rc;
    ngx_http_core_loc_conf_t  *clcf;

    if (ngx_http_upstream_test_connect(c) != NGX_OK) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

#if (NGX_HAVE_NTLS)
    if (u->conf->ssl_ntls) {

        SSL_CTX_set_ssl_version(u->conf->ssl->ctx, NTLS_method());
        SSL_CTX_set_cipher_list(u->conf->ssl->ctx,
                                (char *) u->conf->ssl_ciphers.data);
        SSL_CTX_enable_ntls(u->conf->ssl->ctx);
    }
#endif

    if (ngx_ssl_create_connection(u->conf->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->ssl_server_name || u->conf->ssl_verify) {
        if (ngx_http_upstream_ssl_name(r, u, c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#if (NGX_HTTP_PROXY_MULTICERT)

    if (u->conf->ssl_certificate_values) {
        if (ngx_http_upstream_ssl_certificates(r, u, c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

    } else

#endif

    if (u->conf->ssl_certificate
        && u->conf->ssl_certificate->value.len
        && (u->conf->ssl_certificate->lengths
            || u->conf->ssl_certificate_key->lengths))
    {
        if (ngx_http_upstream_ssl_certificate(r, u, c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    if (u->ssl_alpn_protocol.len) {
        if (SSL_set_alpn_protos(c->ssl->connection, u->ssl_alpn_protocol.data,
                                u->ssl_alpn_protocol.len)
            != 0)
        {
            ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
                          "SSL_set_alpn_protos() failed");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#endif

    if (u->conf->ssl_session_reuse) {
        c->ssl->save_session = ngx_http_upstream_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        /* abbreviated SSL handshake may interact badly with Nagle */

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    r->connection->log->action = "SSL handshaking to upstream";

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {

        if (!c->write->timer_set) {
            ngx_add_timer(c->write, u->conf->connect_timeout);
        }

        c->ssl->handler = ngx_http_upstream_ssl_handshake_handler;
        return;
    }

    ngx_http_upstream_ssl_handshake(r, u, c);
}

static void ngx_http_upstream_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    r = c->data;

    u = r->upstream;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl handshake: \"%V?%V\"",
                   &r->uri, &r->args);

    ngx_http_upstream_ssl_handshake(r, u, u->peer.connection);

    ngx_http_run_posted_requests(c);
}


static void ngx_http_upstream_ssl_handshake(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c)
{
    long  rc;

    if (c->ssl->handshaked) {

        if (u->conf->ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            if (ngx_ssl_check_host(c, &u->ssl_name) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (!c->ssl->sendfile) {
            c->sendfile = 0;
            u->output.sendfile = 0;
        }

        c->write->handler = ngx_http_upstream_handler;
        c->read->handler = ngx_http_upstream_handler;

        ngx_http_upstream_send_request(r, u, 1);

        return;
    }

    if (c->write->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

failed:

    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
}


static void ngx_http_upstream_ssl_save_session(ngx_connection_t *c)
{
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

#if (NGX_HTTP_V3)
    if (c->udp) {
        /* SSL callback is called on main quic connection */
        c = ngx_quic_client_get_ssl_data(c);
        if (c == NULL) {
            /* stream already closed */
            return;
        }
    }
#endif

    if (c->idle) {
        return;
    }

    r = c->data;

    u = r->upstream;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    u->peer.save_session(&u->peer, u->peer.data);
}


static ngx_int_t ngx_http_upstream_ssl_name(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c)
{
    u_char     *p, *last;
    ngx_str_t   name;

    if (u->conf->ssl_name) {
        if (ngx_http_complex_value(r, u->conf->ssl_name, &name) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, notably if derived from $proxy_host
     * or $http_host; we have to strip it
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = ngx_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = ngx_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!u->conf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = ngx_pnalloc(r->pool, name.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(c->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NGX_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return NGX_OK;
}

static ngx_int_t ngx_http_upstream_ssl_certificate(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_str_t  cert, key;

    if (ngx_http_complex_value(r, u->conf->ssl_certificate, &cert)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl cert: \"%s\"", cert.data);

    if (*cert.data == '\0') {
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, u->conf->ssl_certificate_key, &key)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl key: \"%s\"", key.data);

    if (ngx_ssl_connection_certificate(c, r->pool, &cert, &key,
                                       u->conf->ssl_certificate_cache,
                                       u->conf->ssl_passwords)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}



#if (NGX_HTTP_PROXY_MULTICERT)

static ngx_int_t
ngx_http_upstream_ssl_certificates(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_str_t                 *certp, *keyp, cert, key;
    ngx_uint_t                 i, nelts;
    ngx_http_complex_value_t  *certs, *keys;
#if (NGX_HAVE_NTLS)
    ngx_str_t                  tcert, tkey;
#endif

    nelts = u->conf->ssl_certificate_values->nelts;
    certs = u->conf->ssl_certificate_values->elts;
    keys = u->conf->ssl_certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {
        certp = &cert;
        keyp = &key;

        if (ngx_http_complex_value(r, &certs[i], certp) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_HAVE_NTLS)
        tcert = *certp;
        ngx_ssl_ntls_prefix_strip(&tcert);
        certp = &cert;
#endif

        if (*certp->data == 0) {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream ssl cert: \"%s\"", certp->data);

        if (ngx_http_complex_value(r, &keys[i], keyp) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_HAVE_NTLS)
        tkey = *keyp;
        ngx_ssl_ntls_prefix_strip(&tkey);
        keyp = &key;
#endif

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream ssl key: \"%s\"", keyp->data);

        if (ngx_ssl_connection_certificate(c, r->pool, certp, keyp,
                                           u->conf->ssl_certificate_cache,
                                           u->conf->ssl_passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

#endif

#endif

static ngx_int_t ngx_http_upstream_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    off_t         file_pos;
    ngx_chain_t  *cl;

    if (u->reinit_request(r) != NGX_OK) {
        return NGX_ERROR;
    }

    u->early_hints_length = 0;
    u->keepalive = 0;
    u->upgrade = 0;
    u->error = 0;

    ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* reinit the request chain */

    file_pos = 0;

    for (cl = u->request_bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;

        /* there is at most one file */

        if (cl->buf->in_file) {
            cl->buf->file_pos = file_pos;
            file_pos = cl->buf->file_last;
        }
    }

    /* reinit the subrequest's ngx_output_chain() context */

    if (r->request_body && r->request_body->temp_file
        && r != r->main && u->output.buf)
    {
        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            return NGX_ERROR;
        }

        u->output.free->buf = u->output.buf;
        u->output.free->next = NULL;

        u->output.buf->pos = u->output.buf->start;
        u->output.buf->last = u->output.buf->start;
    }

    u->output.buf = NULL;
    u->output.in = NULL;
    u->output.busy = NULL;

    /* reinit u->buffer */

    u->buffer.pos = u->buffer.start;

#if (NGX_HTTP_CACHE)

    if (r->cache) {
        u->buffer.pos += r->cache->header_start;
    }

#endif

    u->buffer.last = u->buffer.pos;

    return NGX_OK;
}

static void
ngx_http_upstream_upgrade(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (r != r->main) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "connection upgrade in subrequest");
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    r->keepalive = 0;
    c->log->action = "proxying upgraded connection";

    u->read_event_handler = ngx_http_upstream_upgraded_read_upstream;
    u->write_event_handler = ngx_http_upstream_upgraded_write_upstream;
    r->read_event_handler = ngx_http_upstream_upgraded_read_downstream;
    r->write_event_handler = ngx_http_upstream_upgraded_write_downstream;

    if (clcf->tcp_nodelay) {

        if (ngx_tcp_nodelay(c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        if (ngx_tcp_nodelay(u->peer.connection) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
    }

    if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (u->peer.connection->read->ready
        || u->buffer.pos != u->buffer.last)
    {
        ngx_post_event(c->read, &ngx_posted_events);
        ngx_http_upstream_process_upgraded(r, 1, 1);
        return;
    }

    ngx_http_upstream_process_upgraded(r, 0, 1);
}


static void ngx_http_upstream_upgraded_read_downstream(ngx_http_request_t *r)
{
    ngx_http_upstream_process_upgraded(r, 0, 0);
}


static void ngx_http_upstream_upgraded_write_downstream(ngx_http_request_t *r)
{
    ngx_http_upstream_process_upgraded(r, 1, 1);
}


static void ngx_http_upstream_upgraded_read_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_http_upstream_process_upgraded(r, 1, 0);
}


static void ngx_http_upstream_upgraded_write_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_http_upstream_process_upgraded(r, 0, 1);
}


static void
ngx_http_upstream_process_upgraded(ngx_http_request_t *r,
    ngx_uint_t from_upstream, ngx_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_uint_t                 flags;
    ngx_connection_t          *c, *downstream, *upstream, *dst, *src;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_http_waf_ws_ctx_t     *ws_rctx;
	ngx_http_waf_main_conf_t  *wmc;

    c = r->connection;
    u = r->upstream;

	wmc = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    ws_rctx = ngx_http_get_module_ctx(r, ngx_http_waf_ws_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upgraded, fu:%ui", from_upstream);

    downstream = c;
    upstream = u->peer.connection;

    if (downstream->write->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (upstream->read->timedout || upstream->write->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (ngx_http_upstream_need_connection_drop(u)) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "drop connection");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (from_upstream) {
        src = upstream;
        dst = downstream;
        b = &u->buffer;

    } else {
        src = downstream;
        dst = upstream;
        b = &u->from_client;

        if (r->header_in->last > r->header_in->pos) {
            b = r->header_in;
            b->end = b->last;
            do_write = 1;
        }

        if (b->start == NULL) {
            b->start = ngx_palloc(r->pool, u->conf->buffer_size);
            if (b->start == NULL) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return;
            }

            b->pos = b->start;
            b->last = b->start;
            b->end = b->start + u->conf->buffer_size;
            b->temporary = 1;
            b->tag = u->output.tag;
        }
    }

    for ( ;; ) {

        if (do_write) {
            size = b->last - b->pos;

            if (size && dst->write->ready) {

                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR) {
                    ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                    return;
                }

                if (n > 0) {
                    b->pos += n;
                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                if (from_upstream) {
                    u->state->bytes_received += n;
                }
// Process buffer
                if (ws_rctx->ws_request == 1) {
                  if (nwaf_check_flags(ws_rctx->rctx, r, wmc) == NGX_OK) {
                    if (!from_upstream){
                      nwaf_process_request(b, r);
                    } else {
                      nwaf_process_response(b, ws_rctx, r);
                      nwaf_process_upstream(b, ws_rctx, r);
                      if ((ws_rctx->con_closing) && (ws_rctx->wait_for_close == 0)) {
                        break;
                      }
                    }
                  }
                }
//
                continue;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

// Process exit
    if ((ws_rctx->ws_request == 1) && (ws_rctx->con_closing) && (ws_rctx->wait_for_close == 0)) {
      return;
    }
//

    if ((upstream->read->eof && u->buffer.pos == u->buffer.last)
        || (downstream->read->eof && u->from_client.pos == u->from_client.last)
        || (downstream->read->eof && upstream->read->eof))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream upgraded done");
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (ngx_handle_write_event(upstream->write, u->conf->send_lowat)
        != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (upstream->write->active && !upstream->write->ready) {
        ngx_add_timer(upstream->write, u->conf->send_timeout);

    } else if (upstream->write->timer_set) {
        ngx_del_timer(upstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = NGX_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (ngx_handle_read_event(upstream->read, flags) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        ngx_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        ngx_del_timer(upstream->read);
    }

    if (ngx_handle_write_event(downstream->write, clcf->send_lowat)
        != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (downstream->read->eof || downstream->read->error) {
        flags = NGX_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (ngx_handle_read_event(downstream->read, flags) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (downstream->write->active && !downstream->write->ready) {
        ngx_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        ngx_del_timer(downstream->write);
    }
}

static void
ngx_http_upstream_block_reading(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream block reading");

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}


static void
ngx_http_upstream_process_header(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ssize_t            n;
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process header");

    c->log->action = "reading response header from upstream";

    if (c->read->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (u->buffer.start == NULL) {
        u->buffer.start = ngx_palloc(r->pool, u->conf->buffer_size);
        if (u->buffer.start == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
        u->buffer.end = u->buffer.start + u->conf->buffer_size;
        u->buffer.temporary = 1;

        u->buffer.tag = u->output.tag;

        if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                          sizeof(ngx_table_elt_t))
            != NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
                          sizeof(ngx_table_elt_t))
            != NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

#if (NGX_HTTP_CACHE)

        if (r->cache) {
            u->buffer.pos += r->cache->header_start;
            u->buffer.last = u->buffer.pos;
        }
#endif
    }

    if (u->conf->ignore_input) {
        rc = u->process_header(r);
        goto done;
    }

    for ( ;; ) {

        if (c->read->ready) {
            n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);

        } else {
            n = NGX_AGAIN;
        }

        if (n == NGX_AGAIN) {
#if 0
            ngx_add_timer(rev, u->read_timeout);
#endif

            if (ngx_http_upstream_need_connection_drop(u)) {
                ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_HTTP_502);
                return;
            }

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            return;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "upstream prematurely closed connection");
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
            return;
        }

        u->state->bytes_received += n;

        u->buffer.last += n;

#if 0
        u->valid_header_in = 0;

        u->peer.cached = 0;
#endif

        u->response_received = 1;

again:

        rc = u->process_header(r);

        if (rc == NGX_AGAIN) {

            if (u->buffer.last == u->buffer.end) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "upstream sent too big header");

                ngx_http_upstream_next(r, u,
                                       NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
                return;
            }

            continue;
        }

        if (rc == NGX_HTTP_UPSTREAM_EARLY_HINTS) {
            rc = ngx_http_upstream_process_early_hints(r, u);

            if (rc == NGX_OK) {
                goto again;
            }
        }

        break;
    }

done:

    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return;
    }

    if (rc == NGX_HTTP_UPSTREAM_RECONNECT) {
        /*
         * Reconnect to the same peer: close the connection but keep the
         * peer selection intact (sockaddr, name, round-robin reference).
         * The next ngx_http_upstream_connect() will reuse the same peer
         * without calling pc->get().  Do not call free_peer() — there is
         * no matching get() to balance, and the peer must stay selected
         * for reconnect.  Per-peer stats are recorded via stat() with
         * the status previously set by the module in u->state->status.
         */

        u->state->bytes_sent = u->peer.connection->sent;

#if (NGX_API && NGX_HTTP_UPSTREAM_ZONE)
        if (u->upstream != NULL && u->upstream->shm_zone != NULL) {
            ngx_http_upstream_stat(&u->peer, 0);
        }
#endif

        ngx_http_upstream_close_peer_connection(r, u, 1);

        ngx_http_upstream_connect(r, u);
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* rc == NGX_OK */

    u->state->header_time = ngx_current_msec - u->start_time;

    if (u->headers_in.status_n >= NGX_HTTP_SPECIAL_RESPONSE) {

        if (ngx_http_upstream_test_next(r, u) == NGX_OK) {
            return;
        }

        if (ngx_http_upstream_intercept_errors(r, u) == NGX_OK) {
            return;
        }
    }

    if (u->peer.notify_mask & NGX_HTTP_UPSTREAM_NOTIFY_HEADER) {
        u->peer.notify(&u->peer, u->peer.data, NGX_HTTP_UPSTREAM_NOTIFY_HEADER);
    }

    rc = ngx_http_upstream_process_headers(r, u);

    if (rc == NGX_DONE) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (ngx_http_upstream_need_connection_drop(u)) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_HTTP_502);
        return;
    }

    ngx_http_upstream_send_response(r, u);
}


static ngx_int_t
ngx_http_upstream_process_early_hints(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    u_char            *p;
    ngx_uint_t         i;
    ngx_list_part_t   *part;
    ngx_table_elt_t   *h, *ho;
    ngx_connection_t  *c;

    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http upstream early hints");

    if (u->conf->pass_early_hints) {

        u->early_hints_length += u->buffer.pos - u->buffer.start;

        if (u->early_hints_length <= (off_t) u->conf->buffer_size) {

            part = &u->headers_in.headers.part;
            h = part->elts;

            for (i = 0; /* void */; i++) {

                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    h = part->elts;
                    i = 0;
                }

                if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                                  h[i].lowcase_key, h[i].key.len))
                {
                    continue;
                }

                ho = ngx_list_push(&r->headers_out.headers);
                if (ho == NULL) {
                    return NGX_ERROR;
                }

                *ho = h[i];
            }

            if (ngx_http_send_early_hints(r) == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (c->buffered) {
                if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                    return NGX_ERROR;
                }

                r->write_event_handler = ngx_http_upstream_early_hints_writer;
            }

        } else {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "upstream sent too big early hints");
        }
    }

    ngx_http_clean_header(r);

    ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    p = u->buffer.pos;

    u->buffer.pos = u->buffer.start;

#if (NGX_HTTP_CACHE)

    if (r->cache) {
        u->buffer.pos += r->cache->header_start;
    }

#endif

    u->buffer.last = ngx_movemem(u->buffer.pos, p, u->buffer.last - p);

    return NGX_OK;
}


static void
ngx_http_upstream_early_hints_writer(ngx_http_request_t *r)
{
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream early hints writer");

    c->log->action = "sending early hints to client";

    if (ngx_http_write_filter(r, NULL) == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!c->buffered) {
        if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
            r->write_event_handler =
                                  ngx_http_upstream_wr_check_broken_connection;

        } else {
            r->write_event_handler = ngx_http_request_empty_handler;
        }
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}

static ngx_int_t ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho, **ph;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
        ho->next = NULL;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_upstream_intercept_errors(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_int_t                  status;
    ngx_uint_t                 i;
    ngx_table_elt_t           *h, *ho, **ph;
    ngx_http_err_page_t       *err_page;
    ngx_http_core_loc_conf_t  *clcf;

    status = u->headers_in.status_n;

    if (status == NGX_HTTP_NOT_FOUND && u->conf->intercept_404) {
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_NOT_FOUND);
        return NGX_OK;
    }

    if (!u->conf->intercept_errors) {
        return NGX_DECLINED;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->error_pages == NULL) {
        return NGX_DECLINED;
    }

    err_page = clcf->error_pages->elts;
    for (i = 0; i < clcf->error_pages->nelts; i++) {

        if (err_page[i].status == status) {

            if (status == NGX_HTTP_UNAUTHORIZED
                && u->headers_in.www_authenticate)
            {
                h = u->headers_in.www_authenticate;
                ph = &r->headers_out.www_authenticate;

                while (h) {
                    ho = ngx_list_push(&r->headers_out.headers);

                    if (ho == NULL) {
                        ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                        return NGX_OK;
                    }

                    *ho = *h;
                    ho->next = NULL;

                    *ph = ho;
                    ph = &ho->next;

                    h = h->next;
                }
            }

#if (NGX_HTTP_CACHE)

            if (r->cache) {

                if (ngx_http_upstream_no_cache(r, u) != NGX_OK) {
                    ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return NGX_OK;
                }

                if (u->cacheable) {
                    time_t  valid;

                    valid = r->cache->valid_sec;

                    if (valid == 0) {
                        valid = ngx_http_file_cache_valid(u->conf->cache_valid,
                                                          status);
                        if (valid) {
                            r->cache->valid_sec = ngx_time() + valid;
                        }
                    }

                    if (valid) {
                        r->cache->error = status;
                    }
                }

                ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
            }
#endif
            ngx_http_upstream_finalize_request(r, u, status);

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

static void ngx_http_upstream_process_downstream(ngx_http_request_t *r)
{
    ngx_event_t          *wev;
    ngx_connection_t     *c;
    ngx_event_pipe_t     *p;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    p = u->pipe;
    wev = c->write;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process downstream");

    c->log->action = "sending to client";

#if (NGX_THREADS)
    p->aio = r->aio;
#endif

    if (wev->timedout) {

        p->downstream_error = 1;
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");

    } else {

        if (wev->delayed) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http downstream delayed");

            if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            }

            return;
        }

        if (ngx_event_pipe(p, 1) == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
    }

    ngx_http_upstream_process_request(r, u);
}


static void ngx_http_upstream_process_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_event_t       *rev;
    ngx_event_pipe_t  *p;
    ngx_connection_t  *c;

    c = u->peer.connection;
    p = u->pipe;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upstream");

    c->log->action = "reading upstream";

    if (rev->timedout) {

        p->upstream_error = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");

    } else {

        if (rev->delayed) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http upstream delayed");

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            }

            return;
        }

        if (ngx_event_pipe(p, 0) == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
    }

    ngx_http_upstream_process_request(r, u);
}

static void ngx_http_upstream_store(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    size_t                  root;
    time_t                  lm;
    ngx_str_t               path;
    ngx_temp_file_t        *tf;
    ngx_ext_rename_file_t   ext;

    tf = u->pipe->temp_file;

    if (tf->file.fd == NGX_INVALID_FILE) {

        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return;
        }

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = u->conf->temp_path;
        tf->pool = r->pool;
        tf->persistent = 1;

        if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                 tf->persistent, tf->clean, tf->access)
            != NGX_OK)
        {
            return;
        }

        u->pipe->temp_file = tf;
    }

    ext.access = u->conf->store_access;
    ext.path_access = u->conf->store_access;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (u->headers_in.last_modified) {

        lm = ngx_parse_http_time(u->headers_in.last_modified->value.data,
                                 u->headers_in.last_modified->value.len);

        if (lm != NGX_ERROR) {
            ext.time = lm;
            ext.fd = tf->file.fd;
        }
    }

    if (u->conf->store_lengths == NULL) {

        if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            return;
        }

    } else {
        if (ngx_http_script_run(r, &path, u->conf->store_lengths->elts, 0,
                                u->conf->store_values->elts)
            == NULL)
        {
            return;
        }
    }

    path.len--;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream stores \"%s\" to \"%s\"",
                   tf->file.name.data, path.data);

    if (path.len == 0) {
        return;
    }

    (void) ngx_ext_rename_file(&tf->file.name, &path, &ext);

    u->store = 0;
}

static void ngx_http_upstream_process_request(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_temp_file_t   *tf;
    ngx_event_pipe_t  *p;

    p = u->pipe;

#if (NGX_THREADS)

    if (p->writing && !p->aio) {

        if (ngx_event_pipe(p, 1) == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
    }

    if (p->writing) {

        if (ngx_http_upstream_need_connection_drop(u)) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "drop connection");
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return;
        }

        return;
    }

#endif

    if (u->peer.connection) {

        if (u->store) {

            if (p->upstream_eof || p->upstream_done) {

                tf = p->temp_file;

                if (u->headers_in.status_n == NGX_HTTP_OK
                    && (p->upstream_done || p->length == -1)
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n == tf->offset))
                {
                    ngx_http_upstream_store(r, u);
                }
            }
        }

#if (NGX_HTTP_CACHE)

        if (u->cacheable) {

            if (p->upstream_done) {
                ngx_http_file_cache_update(r, p->temp_file);

            } else if (p->upstream_eof) {

                tf = p->temp_file;

                if (p->length == -1
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n
                           == tf->offset - (off_t) r->cache->body_start))
                {
                    ngx_http_file_cache_update(r, tf);

                } else {
                    ngx_http_file_cache_free(r->cache, tf);
                }

            } else if (p->upstream_error) {
                ngx_http_file_cache_free(r->cache, p->temp_file);
            }
        }

#endif

        if (p->upstream_done || p->upstream_eof || p->upstream_error) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http upstream exit: %p", p->out);

            if (p->upstream_done
                || (p->upstream_eof && p->length == -1))
            {
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

            if (p->upstream_eof) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed connection");
            }

            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return;
        }
    }

    if (p->downstream_error) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream downstream error");

        if (!u->cacheable && !u->store && u->peer.connection) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
    }

    if (ngx_http_upstream_need_connection_drop(u)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "drop connection");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        return;
    }
}

static void ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_event_pipe_t          *p;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->post_action) {
        ngx_http_upstream_finalize_request(r, u, rc);
        return;
    }

    u->header_sent = 1;

    if (u->upgrade) {

#if (NGX_HTTP_CACHE)

        if (r->cache) {
            ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        ngx_http_upstream_upgrade(r, u);
        return;
    }

    c = r->connection;

    if (r->header_only) {

        if (!u->buffering) {
            ngx_http_upstream_finalize_request(r, u, rc);
            return;
        }

        if (!u->cacheable && !u->store) {
            ngx_http_upstream_finalize_request(r, u, rc);
            return;
        }

        u->pipe->downstream_error = 1;
    }

    if (r->request_body && r->request_body->temp_file
        && r == r->main && !r->preserve_body
        && !u->conf->preserve_output)
    {
        ngx_pool_run_cleanup_file(r->pool, r->request_body->temp_file->file.fd);
        r->request_body->temp_file->file.fd = NGX_INVALID_FILE;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!u->buffering) {

#if (NGX_HTTP_CACHE)

        if (r->cache) {
            ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        if (u->input_filter == NULL) {
            u->input_filter_init = ngx_http_upstream_non_buffered_filter_init;
            u->input_filter = ngx_http_upstream_non_buffered_filter;
            u->input_filter_ctx = r;
        }

        u->read_event_handler = ngx_http_upstream_process_non_buffered_upstream;
        r->write_event_handler =
                             ngx_http_upstream_process_non_buffered_downstream;

        r->limit_rate = 0;
        r->limit_rate_set = 1;

        if (u->input_filter_init(u->input_filter_ctx) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        n = u->buffer.last - u->buffer.pos;

        if (n) {
            u->buffer.last = u->buffer.pos;

            u->state->response_length += n;

            if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return;
            }

            ngx_http_upstream_process_non_buffered_downstream(r);

        } else {
            u->buffer.pos = u->buffer.start;
            u->buffer.last = u->buffer.start;

            if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return;
            }

            ngx_http_upstream_process_non_buffered_upstream(r, u);
        }

        return;
    }

#if (NGX_HTTP_CACHE)

    if (r->cache && r->cache->file.fd != NGX_INVALID_FILE) {
        ngx_pool_run_cleanup_file(r->pool, r->cache->file.fd);
        r->cache->file.fd = NGX_INVALID_FILE;
    }

    if (ngx_http_upstream_no_cache(r, u) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    if (u->cacheable) {
        time_t  now, valid;

        now = ngx_time();

        valid = r->cache->valid_sec;

        if (valid == 0) {
            valid = ngx_http_file_cache_valid(u->conf->cache_valid,
                                              u->headers_in.status_n);
            if (valid) {
                r->cache->valid_sec = now + valid;
            }
        }

        if (valid) {
            r->cache->date = now;
            r->cache->body_start = (u_short) (u->buffer.pos - u->buffer.start);

            if (u->headers_in.status_n == NGX_HTTP_OK
                || u->headers_in.status_n == NGX_HTTP_PARTIAL_CONTENT)
            {
                r->cache->last_modified = u->headers_in.last_modified_time;

                if (u->headers_in.etag) {
                    r->cache->etag = u->headers_in.etag->value;

                } else {
                    ngx_str_null(&r->cache->etag);
                }

            } else {
                r->cache->last_modified = -1;
                ngx_str_null(&r->cache->etag);
            }

            if (ngx_http_file_cache_set_header(r, u->buffer.start) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
                return;
            }

        } else {
            u->cacheable = 0;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http cacheable: %d", u->cacheable);

    if (u->cacheable == 0 && r->cache) {
        ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

    if (r->header_only && !u->cacheable && !u->store) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

#endif

    p = u->pipe;

    p->output_filter = ngx_http_upstream_output_filter;
    p->output_ctx = r;
    p->tag = u->output.tag;
    p->bufs = u->conf->bufs;
    p->busy_size = u->conf->busy_buffers_size;
    p->upstream = u->peer.connection;
    p->downstream = c;
    p->pool = r->pool;
    p->log = c->log;
    p->limit_rate = ngx_http_complex_value_size(r, u->conf->limit_rate, 0);
    p->start_sec = ngx_time();

    p->cacheable = u->cacheable || u->store;

    p->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (p->temp_file == NULL) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    p->temp_file->file.fd = NGX_INVALID_FILE;
    p->temp_file->file.log = c->log;
    p->temp_file->path = u->conf->temp_path;
    p->temp_file->pool = r->pool;

    if (p->cacheable) {
        p->temp_file->persistent = 1;

#if (NGX_HTTP_CACHE)
        if (r->cache && !r->cache->file_cache->use_temp_path) {
            p->temp_file->path = r->cache->file_cache->path;
            p->temp_file->file.name = r->cache->file.name;
        }
#endif

    } else {
        p->temp_file->log_level = NGX_LOG_WARN;
        p->temp_file->warn = "an upstream response is buffered "
                             "to a temporary file";
    }

    p->max_temp_file_size = u->conf->max_temp_file_size;
    p->temp_file_write_size = u->conf->temp_file_write_size;

#if (NGX_THREADS)
    if (clcf->aio == NGX_HTTP_AIO_THREADS && clcf->aio_write) {
        p->thread_handler = ngx_http_upstream_thread_handler;
        p->thread_ctx = r;
    }
#endif

    p->preread_bufs = ngx_alloc_chain_link(r->pool);
    if (p->preread_bufs == NULL) {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    p->preread_bufs->buf = &u->buffer;
    p->preread_bufs->next = NULL;
    u->buffer.recycled = 1;

    p->preread_size = u->buffer.last - u->buffer.pos;

    if (u->cacheable) {

        p->buf_to_file = ngx_calloc_buf(r->pool);
        if (p->buf_to_file == NULL) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }

        p->buf_to_file->start = u->buffer.start;
        p->buf_to_file->pos = u->buffer.start;
        p->buf_to_file->last = u->buffer.pos;
        p->buf_to_file->temporary = 1;
    }

    if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
        p->single_buf = 1;
    }

    p->free_bufs = 1;

    u->buffer.last = u->buffer.pos;

    if (u->conf->cyclic_temp_file) {

        p->cyclic_temp_file = 1;
        c->sendfile = 0;

    } else {
        p->cyclic_temp_file = 0;
    }

    p->read_timeout = u->conf->read_timeout;
    p->send_timeout = clcf->send_timeout;
    p->send_lowat = clcf->send_lowat;

    p->length = -1;

    if (u->input_filter_init
        && u->input_filter_init(p->input_ctx) != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }

    u->read_event_handler = ngx_http_upstream_process_upstream;
    r->write_event_handler = ngx_http_upstream_process_downstream;

    ngx_http_upstream_process_upstream(r, u);
}

#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_upstream_cache_background_update(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_http_request_t  *sr;

    if (r == r->main) {
        r->preserve_body = 1;
    }

    if (ngx_http_subrequest(r, &r->uri, &r->args, &sr, NULL,
                            NGX_HTTP_SUBREQUEST_CLONE
                            |NGX_HTTP_SUBREQUEST_BACKGROUND)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sr->header_only = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_cache_check_range(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    off_t             offset;
    u_char           *p, *start;
    ngx_table_elt_t  *h;

    h = r->headers_in.range;

    if (h == NULL
        || !u->cacheable
        || u->conf->cache_max_range_offset == NGX_MAX_OFF_T_VALUE)
    {
        return NGX_OK;
    }

    if (u->conf->cache_max_range_offset == 0) {
        return NGX_DECLINED;
    }

    if (h->value.len < 7
        || ngx_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return NGX_OK;
    }

    p = h->value.data + 6;

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return NGX_DECLINED;
    }

    start = p;

    while (*p >= '0' && *p <= '9') { p++; }

    offset = ngx_atoof(start, p - start);

    if (offset >= u->conf->cache_max_range_offset) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

#endif

static ngx_int_t ngx_http_upstream_test_next(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_msec_t                 timeout;
    ngx_uint_t                 status;
    ngx_http_upstream_next_t  *un;

    status = u->headers_in.status_n;

    for (un = ngx_http_upstream_next_errors; un->status; un++) {

        if (status != un->status) {
            continue;
        }

        timeout = u->conf->next_upstream_timeout;

        if ((u->conf->next_upstream & un->mask)
            && !(u->request_sent && r->request_body_no_buffering)
            && !(timeout && ngx_current_msec - u->peer.start_time >= timeout))
        {

            if (u->request_sent
                && (r->method & (NGX_HTTP_POST|NGX_HTTP_LOCK|NGX_HTTP_PATCH))
                && !(u->conf->next_upstream
                     & NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT))
            {
                return NGX_OK;
            }

            ngx_http_upstream_next(r, u, un->mask);
            return NGX_OK;
        }

#if (NGX_HTTP_CACHE)

        if (u->cache_status == NGX_HTTP_CACHE_EXPIRED
            && (u->conf->cache_use_stale & un->mask))
        {
            ngx_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, rc);
                return NGX_OK;
            }

            u->cache_status = NGX_HTTP_CACHE_STALE;
            rc = ngx_http_upstream_cache_send(r, u);

            if (rc == NGX_DONE) {
                return NGX_OK;
            }

            if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_http_upstream_finalize_request(r, u, rc);
            return NGX_OK;
        }

#endif

        break;
    }

#if (NGX_HTTP_CACHE)

    if (status == NGX_HTTP_NOT_MODIFIED
        && u->cache_status == NGX_HTTP_CACHE_EXPIRED
        && u->conf->cache_revalidate)
    {
        time_t     now, valid, updating, error;
        ngx_int_t  rc;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream not modified");

        now = ngx_time();

        valid = r->cache->valid_sec;
        updating = r->cache->updating_sec;
        error = r->cache->error_sec;

        if (ngx_http_upstream_no_cache(r, u) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_OK;
        }

        rc = u->reinit_request(r);

        if (rc != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, rc);
            return NGX_OK;
        }

        u->cache_status = NGX_HTTP_CACHE_REVALIDATED;
        rc = ngx_http_upstream_cache_send(r, u);

        if (rc == NGX_DONE) {
            return NGX_OK;
        }

        if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (u->cacheable) {

            if (valid == 0) {
                valid = r->cache->valid_sec;
                updating = r->cache->updating_sec;
                error = r->cache->error_sec;
            }

            if (valid == 0) {
                valid = ngx_http_file_cache_valid(u->conf->cache_valid,
                                                  u->headers_in.status_n);
                if (valid) {
                    valid = now + valid;
                }
            }

            if (valid) {
                r->cache->valid_sec = valid;
                r->cache->updating_sec = updating;
                r->cache->error_sec = error;

                r->cache->date = now;

                ngx_http_file_cache_update_header(r);
            }
        }

        ngx_http_upstream_finalize_request(r, u, rc);
        return NGX_OK;
    }

#endif

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_upstream_set_local(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_http_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NGX_OK;
    }

#if (NGX_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, local->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        u->peer.local = NULL;
        return NGX_OK;
    }

    addr = ngx_palloc(r->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_parse_addr_port(r->pool, addr, val.data, val.len);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        u->peer.local = NULL;
        return NGX_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NGX_OK;
}

static void
ngx_http_upstream_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup http upstream request: \"%V\"", &r->uri);

    ngx_http_upstream_finalize_request(r, r->upstream, NGX_DONE);
}

static ngx_int_t
ngx_http_upstream_process_trailers(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h, *ho;

    if (!u->conf->pass_trailers) {
        return NGX_OK;
    }

    part = &u->headers_in.trailers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        ho = ngx_list_push(&r->headers_out.trailers);
        if (ho == NULL) {
            return NGX_ERROR;
        }

        *ho = h[i];
    }

    return NGX_OK;
}

void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc)
{
    ngx_uint_t  flush;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

    if (u->cleanup == NULL) {
        /* the request was already finalized */
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    *u->cleanup = NULL;
    u->cleanup = NULL;

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->state && u->state->response_time == (ngx_msec_t) -1) {
        u->state->response_time = ngx_current_msec - u->start_time;

        if (u->pipe && u->pipe->read_length) {
            u->state->bytes_received += u->pipe->read_length
                                        - u->pipe->preread_size;
            u->state->response_length = u->pipe->read_length;
        }

        if (u->peer.connection) {
            u->state->bytes_sent = u->peer.connection->sent;
        }
    }

    u->finalize_request(r, rc);

    if (u->peer.sockaddr) {
        ngx_http_upstream_free_peer(u, 0);
    }

    if (u->peer.connection) {

        /*
         * We send the "close notify" shutdown alert to the upstream only
         * and do not wait its "close notify" shutdown alert.
         * It is acceptable according to the TLS standard.
         */
        ngx_http_upstream_close_peer_connection(r, u, 0);
    }

    if (u->pipe) {
        u->pipe->upstream = NULL;
    }

    if (u->pipe && u->pipe->temp_file) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

    if (u->store && u->pipe && u->pipe->temp_file
        && u->pipe->temp_file->file.fd != NGX_INVALID_FILE)
    {
        if (ngx_delete_file(u->pipe->temp_file->file.name.data)
            == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_delete_file_n " \"%s\" failed",
                          u->pipe->temp_file->file.name.data);
        }
    }

#if (NGX_HTTP_CACHE)

    if (r->cache) {

        if (u->cacheable) {

            if (rc == NGX_HTTP_BAD_GATEWAY || rc == NGX_HTTP_GATEWAY_TIME_OUT) {
                time_t  valid;

                valid = ngx_http_file_cache_valid(u->conf->cache_valid, rc);

                if (valid) {
                    r->cache->valid_sec = ngx_time() + valid;
                    r->cache->error = rc;
                }
            }
        }

        ngx_http_file_cache_free(r->cache, u->pipe->temp_file);

#if (NGX_API)

        if (u->cache_status == NGX_HTTP_CACHE_MISS
            || u->cache_status == NGX_HTTP_CACHE_EXPIRED
            || u->cache_status == NGX_HTTP_CACHE_BYPASS)
        {
            ngx_http_file_cache_t   *cache;
            ngx_http_cache_stats_t  *stats;

            cache = r->cache->file_cache;
            stats = &cache->sh->stats[u->cache_status - 1];

            ngx_shmtx_lock(&cache->shpool->mutex);

            stats->responses++;

            if (u->state) {
                stats->bytes += u->state->response_length;
            }

            ngx_shmtx_unlock(&cache->shpool->mutex);
        }

#endif

    }

#endif

    r->read_event_handler = ngx_http_block_reading;

    if (rc == NGX_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (!u->header_sent
        || rc == NGX_HTTP_REQUEST_TIME_OUT
        || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST)
    {
        ngx_http_finalize_request(r, rc);
        return;
    }

    flush = 0;

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        rc = NGX_ERROR;
        flush = 1;
    }

    if (r->header_only
        || (u->pipe && u->pipe->downstream_error))
    {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (rc == 0) {

        if (ngx_http_upstream_process_trailers(r, u) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        rc = ngx_http_send_special(r, NGX_HTTP_LAST);

    } else if (flush) {
        r->keepalive = 0;
        rc = ngx_http_send_special(r, NGX_HTTP_FLUSH);
    }

    ngx_http_finalize_request(r, rc);
}

static void ngx_http_upstream_read_request_handler(ngx_http_request_t *r)
{
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream read request handler");

    if (c->read->timedout) {
        c->timedout = 1;
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    ngx_http_upstream_send_request(r, u, 0);
}

static ngx_int_t ngx_http_upstream_send_request_body(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_uint_t do_write)
{
    ngx_int_t                  rc;
    ngx_chain_t               *out, *cl, *ln;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request body");

    if (!r->request_body_no_buffering) {

        /* buffered request body */

        if (!u->request_sent) {
            u->request_sent = 1;
            out = u->request_bufs;

        } else {
            out = NULL;
        }

        rc = ngx_output_chain(&u->output, out);

        if (rc == NGX_AGAIN) {
            u->request_body_blocked = 1;

        } else {
            u->request_body_blocked = 0;
        }

        return rc;
    }

    if (!u->request_sent) {
        u->request_sent = 1;
        out = u->request_bufs;

        if (r->request_body->bufs) {
            for (cl = out; cl->next; cl = cl->next) { /* void */ }
            cl->next = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        c = u->peer.connection;
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
            return NGX_ERROR;
        }

        r->read_event_handler = ngx_http_upstream_read_request_handler;

    } else {
        out = NULL;
    }

    for ( ;; ) {

        if (do_write) {
            rc = ngx_output_chain(&u->output, out);

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            while (out) {
                ln = out;
                out = out->next;
                ngx_free_chain(r->pool, ln);
            }

            if (rc == NGX_AGAIN) {
                u->request_body_blocked = 1;

            } else {
                u->request_body_blocked = 0;
            }

            if (rc == NGX_OK && !r->reading_body) {
                break;
            }
        }

        if (r->reading_body) {
            /* read client request body */

            rc = ngx_http_read_unbuffered_request_body(r);

            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            out = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        /* stop if there is nothing to send */

        if (out == NULL) {
            rc = NGX_AGAIN;
            break;
        }

        do_write = 1;
    }

    if (!r->reading_body) {
        if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
            r->read_event_handler =
                                  ngx_http_upstream_rd_check_broken_connection;
        }
    }

    return rc;
}

#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_upstream_no_cache(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t  rc;

    if (!u->cacheable) {
        return NGX_OK;
    }

    if (u->headers_in.no_cache || u->headers_in.expired) {
        u->cacheable = 0;
        return NGX_OK;
    }

    rc = ngx_http_test_predicates(r, u->conf->no_cache);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        u->cacheable = 0;
        return NGX_OK;
    }

    /* rc == NGX_OK */

    if (u->cache_status == NGX_HTTP_CACHE_BYPASS) {

        /* create cache if previously bypassed */

        if (ngx_http_file_cache_create(r) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t               rc;
    ngx_http_cache_t       *c;
    ngx_http_file_cache_t  *cache;

    c = r->cache;

    if (c == NULL) {

        if (!(r->method & u->conf->cache_methods)) {
            return NGX_DECLINED;
        }

        rc = ngx_http_upstream_cache_get(r, u, &cache);

        if (rc != NGX_OK) {
            return rc;
        }

        if (r->method == NGX_HTTP_HEAD && u->conf->cache_convert_head) {
            u->method = ngx_http_core_get_method;
        }

        if (ngx_http_file_cache_new(r) != NGX_OK) {
            return NGX_ERROR;
        }

        if (u->create_key(r) != NGX_OK) {
            return NGX_ERROR;
        }

        /* TODO: add keys */

        ngx_http_file_cache_create_key(r);

        if (r->cache->header_start + 256 > u->conf->buffer_size) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%V_buffer_size %uz is not enough for cache key, "
                          "it should be increased to at least %uz",
                          &u->conf->module, u->conf->buffer_size,
                          ngx_align(r->cache->header_start + 256, 1024));

            r->cache = NULL;
            return NGX_DECLINED;
        }

        u->cacheable = 1;

        c = r->cache;

        c->body_start = u->conf->buffer_size;
        c->min_uses = u->conf->cache_min_uses;
        c->file_cache = cache;

        switch (ngx_http_test_predicates(r, u->conf->cache_bypass)) {

        case NGX_ERROR:
            return NGX_ERROR;

        case NGX_DECLINED:
            u->cache_status = NGX_HTTP_CACHE_BYPASS;
            return NGX_DECLINED;

        default: /* NGX_OK */
            break;
        }

        c->lock = u->conf->cache_lock;
        c->lock_timeout = u->conf->cache_lock_timeout;
        c->lock_age = u->conf->cache_lock_age;

        u->cache_status = NGX_HTTP_CACHE_MISS;
    }

    rc = ngx_http_file_cache_open(r);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream cache: %i", rc);

    switch (rc) {

    case NGX_HTTP_CACHE_STALE:

        if (((u->conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background
            && u->conf->cache_background_update)
        {
            if (ngx_http_upstream_cache_background_update(r, u) == NGX_OK) {
                r->cache->background = 1;
                u->cache_status = rc;
                rc = NGX_OK;

            } else {
                rc = NGX_ERROR;
            }
        }

        break;

    case NGX_HTTP_CACHE_UPDATING:

        if (((u->conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background)
        {
            u->cache_status = rc;
            rc = NGX_OK;

        } else {
            rc = NGX_HTTP_CACHE_STALE;
        }

        break;

    case NGX_OK:
        u->cache_status = NGX_HTTP_CACHE_HIT;
    }

    switch (rc) {

    case NGX_OK:

        return NGX_OK;

    case NGX_HTTP_CACHE_STALE:

        c->valid_sec = 0;
        c->updating_sec = 0;
        c->error_sec = 0;

        u->buffer.start = NULL;
        u->cache_status = NGX_HTTP_CACHE_EXPIRED;

        break;

    case NGX_DECLINED:

        if ((size_t) (u->buffer.end - u->buffer.start) < u->conf->buffer_size) {
            u->buffer.start = NULL;

        } else {
            u->buffer.pos = u->buffer.start + c->header_start;
            u->buffer.last = u->buffer.pos;
        }

        break;

    case NGX_HTTP_CACHE_SCARCE:

        u->cacheable = 0;

        break;

    case NGX_AGAIN:

        return NGX_BUSY;

    case NGX_ERROR:

        return NGX_ERROR;

    default:

        /* cached NGX_HTTP_BAD_GATEWAY, NGX_HTTP_GATEWAY_TIME_OUT, etc. */

        u->cache_status = NGX_HTTP_CACHE_HIT;

        return rc;
    }

    if (ngx_http_upstream_cache_check_range(r, u) == NGX_DECLINED) {
        u->cacheable = 0;
    }

    r->cached = 0;

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_upstream_cache_get(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_http_file_cache_t **cache)
{
    ngx_str_t               *name, val;
    ngx_uint_t               i;
    ngx_http_file_cache_t  **caches;

    if (u->conf->cache_zone) {
        *cache = u->conf->cache_zone->data;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, u->conf->cache_value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0
        || (val.len == 3 && ngx_strncmp(val.data, "off", 3) == 0))
    {
        return NGX_DECLINED;
    }

    caches = u->caches->elts;

    for (i = 0; i < u->caches->nelts; i++) {
        name = &caches[i]->shm_zone->shm.name;

        if (name->len == val.len
            && ngx_strncmp(name->data, val.data, val.len) == 0)
        {
            *cache = caches[i];
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "cache \"%V\" not found", &val);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_upstream_cache_send(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_http_cache_t  *c;

    r->cached = 1;
    c = r->cache;

    if (c->header_start == c->body_start) {
        r->http_version = NGX_HTTP_VERSION_9;
        return ngx_http_cache_send(r);
    }

    /* TODO: cache stack */

    u->buffer = *c->buf;
    u->buffer.pos += c->header_start;

    ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = u->process_header(r);

    if (rc == NGX_OK) {

        rc = ngx_http_upstream_process_headers(r, u);

        if (rc != NGX_OK) {
            return rc;
        }

        return ngx_http_cache_send(r);
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN || rc == NGX_HTTP_UPSTREAM_EARLY_HINTS) {
        rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* rc == NGX_HTTP_UPSTREAM_INVALID_HEADER */

    ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                  "cache file \"%s\" contains invalid header",
                  c->file.name.data);

    /* TODO: delete file */

    return rc;
}

#endif

static ngx_int_t
ngx_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_str_t                       uri, args;
    ngx_uint_t                      i, flags;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    if (u->headers_in.no_cache || u->headers_in.expired) {
        u->cacheable = 0;
    }

    if (u->headers_in.x_accel_redirect
        && !(u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT))
    {
        if (u->cleanup) {
            ngx_http_upstream_finalize_request(r, u, NGX_DECLINED);
        }

        part = &u->headers_in.headers.part;
        h = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                h = part->elts;
                i = 0;
            }

            if (h[i].hash == 0) {
                continue;
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash,
                               h[i].lowcase_key, h[i].key.len);

            if (hh && hh->redirect) {
                if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
                    ngx_http_finalize_request(r,
                                              NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return NGX_DONE;
                }
            }
        }

        uri = u->headers_in.x_accel_redirect->value;

        if (uri.data[0] == '@') {
            ngx_http_named_location(r, &uri);

        } else {
            ngx_str_null(&args);
            flags = NGX_HTTP_LOG_UNSAFE;

            if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) {
                ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
                return NGX_DONE;
            }

            if (r->method != NGX_HTTP_HEAD) {
                r->method = NGX_HTTP_GET;
                r->method_name = ngx_http_core_get_method;
            }

            ngx_http_internal_redirect(r, &uri, &args);
        }

        ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DONE;
    }

    part = &u->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        nwaf_process_header(h[i], r); // Process headers for extensions

        if (h[i].hash == 0) {
            continue;
        }

        if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash,
                           h[i].lowcase_key, h[i].key.len);

        if (hh) {
            if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_http_upstream_copy_header_line(r, &h[i], 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
        r->headers_out.server->hash = 0;
    }

    if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
        r->headers_out.date->hash = 0;
    }

    r->headers_out.status = u->headers_in.status_n;
    r->headers_out.status_line = u->headers_in.status_line;

    r->headers_out.content_length_n = u->headers_in.content_length_n;

    r->disable_not_modified = !u->cacheable;

    if (u->conf->force_ranges) {
        r->allow_ranges = 1;
        r->single_range = 1;

#if (NGX_HTTP_CACHE)
        if (r->cached) {
            r->single_range = 0;
        }
#endif
    }

    u->length = -1;

    return NGX_OK;
}

static void
ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,
    ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_int_t            event;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http upstream check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

            if (ngx_del_event(ev, event, 0) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        if (!u->cacheable) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        return;
    }
#endif

#if (NGX_HTTP_V3)

    if (c->quic) {
        if (c->write->error) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client prematurely closed "
                          "connection, so upstream connection is closed too");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
        socklen_t  len;

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, err,
                        "epoll_wait() reported that client prematurely closed "
                        "connection, so upstream connection is closed too");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "epoll_wait() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, err,
                   "http upstream recv(): %d", n);

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

        if (ngx_del_event(ev, event, 0) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cacheable && u->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "client prematurely closed connection, "
                      "so upstream connection is closed too");
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    if (u->peer.connection == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
    }
}

static void
ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_uint_t ft_type)
{
    ngx_msec_t  timeout;
    ngx_uint_t  status;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http next upstream, %xi", ft_type);

    if (u->peer.connection) {
        u->state->bytes_sent = u->peer.connection->sent;
    }

    if (u->peer.sockaddr) {
        ngx_http_upstream_free_peer(u, ft_type);
    }

    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == NGX_HTTP_UPSTREAM_FT_ERROR) {
        /* TODO: inform balancer instead */
        u->peer.tries++;
    }

    switch (ft_type) {

    case NGX_HTTP_UPSTREAM_FT_TIMEOUT:
    case NGX_HTTP_UPSTREAM_FT_HTTP_504:
        status = NGX_HTTP_GATEWAY_TIME_OUT;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_500:
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_503:
        status = NGX_HTTP_SERVICE_UNAVAILABLE;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_403:
        status = NGX_HTTP_FORBIDDEN;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_404:
        status = NGX_HTTP_NOT_FOUND;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_429:
        status = NGX_HTTP_TOO_MANY_REQUESTS;
        break;

    /*
     * NGX_HTTP_UPSTREAM_FT_BUSY_LOCK and NGX_HTTP_UPSTREAM_FT_MAX_WAITING
     * never reach here
     */

    default:
        status = NGX_HTTP_BAD_GATEWAY;
    }

    if (r->connection->error) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    u->state->status = status;

    timeout = u->conf->next_upstream_timeout;

    if (u->request_sent
        && (r->method & (NGX_HTTP_POST|NGX_HTTP_LOCK|NGX_HTTP_PATCH)))
    {
        ft_type |= NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
    }

    if (u->peer.tries == 0
        || ((u->conf->next_upstream & ft_type) != ft_type)
        || (u->request_sent && r->request_body_no_buffering)
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
#if (NGX_HTTP_CACHE)

        if (u->cache_status == NGX_HTTP_CACHE_EXPIRED
            && ((u->conf->cache_use_stale & ft_type) || r->cache->stale_error))
        {
            ngx_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, rc);
                return;
            }

            u->cache_status = NGX_HTTP_CACHE_STALE;
            rc = ngx_http_upstream_cache_send(r, u);

            if (rc == NGX_DONE) {
                return;
            }

            if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_http_upstream_finalize_request(r, u, rc);
            return;
        }
#endif

        ngx_http_upstream_finalize_request(r, u, status);
        return;
    }

    if (u->peer.connection) {
        ngx_http_upstream_close_peer_connection(r, u, 1);
    }

    ngx_http_upstream_connect(r, u);
}


static void
ngx_http_upstream_close_peer_connection(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_uint_t no_send)
{
    ngx_pool_t        *pool;
    ngx_connection_t  *c;
#if (NGX_HTTP_V3)
    ngx_connection_t  *sc;
#endif

    c = u->peer.connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "close http upstream connection: %d", c->fd);

#if (NGX_HTTP_V3)

    if (c->quic) {
        /* a quic stream */

        sc = c;
        c = c->quic->parent;

        ngx_http_v3_upstream_close_request_stream(sc, 1);

        if (u->h3_started && !u->hq) {
            /* HTTP/3 was initialized on this stream, close gracefully */
            ngx_http_v3_shutdown(c);
        }
    }

    if (c->udp) {
        /* main QUIC udp connection */
        ngx_quic_finalize_connection(c, 0 /* NGX_QUIC_ERR_NO_ERROR */, "");

        u->peer.cached = 0;
        u->peer.connection = NULL;

        return;
    }

#endif

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = no_send;

        (void) ngx_ssl_shutdown(c);
    }
#endif

    pool = c->pool;

    ngx_close_connection(c);

    if (pool) {
        ngx_destroy_pool(pool);
    }

    u->peer.cached = 0;
    u->peer.connection = NULL;
}

static void
ngx_http_upstream_free_peer(ngx_http_upstream_t *u, ngx_uint_t ft_type)
{
    ngx_uint_t              state;
    ngx_peer_connection_t  *pc;

    pc = &u->peer;

    switch (ft_type) {
    case 0:
        state = 0;
        break;

    case NGX_HTTP_UPSTREAM_FT_HTTP_403:
    case NGX_HTTP_UPSTREAM_FT_HTTP_404:
        state = NGX_PEER_NEXT;
        break;

    default:
        state = NGX_PEER_FAILED;
        break;
    }

    if (pc->free) {
        pc->free(pc, pc->data, state);
    }

    if (pc->close) {
        pc->close(pc, pc->data, state);
    }

    pc->sockaddr = NULL;
#if (NGX_HTTP_UPSTREAM_SID)
    pc->sid.len = 0;
#endif
}

static void ngx_http_upstream_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_uint_t do_write)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream send request");

    if (u->state->connect_time == (ngx_msec_t) -1) {
        u->state->connect_time = ngx_current_msec - u->start_time;

        if (!u->peer.cached
#if (NGX_HTTP_SSL)
            && !u->ssl
#endif
            && ngx_http_upstream_test_connect(c) != NGX_OK)
        {
            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
            return;
        }
    }

    if (ngx_http_upstream_need_connection_drop(u)) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_HTTP_502);
        return;
    }

    if (!u->request_sent) {
        u->read_event_handler = ngx_http_upstream_process_header;
    }

    c->log->action = "sending request to upstream";

    rc = ngx_http_upstream_send_request_body(r, u, do_write);

    if (rc == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_upstream_finalize_request(r, u, rc);
        return;
    }

    if (rc == NGX_AGAIN) {
        if (!c->write->ready || u->request_body_blocked) {
            ngx_add_timer(c->write, u->conf->send_timeout);

        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (c->write->ready && c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
            if (ngx_tcp_push(c->fd) == -1) {
                ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                              ngx_tcp_push_n " failed");
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        }

        if (c->read->ready) {
            ngx_post_event(c->read, &ngx_posted_events);
        }

        return;
    }

    /* rc == NGX_OK */

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                          ngx_tcp_push_n " failed");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

    if (!u->conf->preserve_output) {
        u->write_event_handler = ngx_http_upstream_dummy_handler;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!u->request_body_sent) {
        u->request_body_sent = 1;

#if (NGX_HTTP_V3)

        /*
         * need to finalize QUIC stream, to notify that no more data expected
         * otherwise, server expecting more data (although C-L is present!)
         */

        if (c->quic && !u->hq) {
            if (ngx_quic_shutdown_stream(c, NGX_WRITE_SHUTDOWN) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
#endif

        if (u->header_sent) {
            return;
        }

        if (u->conf->ignore_input) {
            ngx_http_upstream_process_header(r, u);
            return;
        }

        ngx_add_timer(c->read, u->conf->read_timeout);

        if (c->read->ready) {
            ngx_http_upstream_process_header(r, u);
            return;
        }
    }
}

static void ngx_http_upstream_handler(ngx_event_t *ev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    if (ev->write) {
        u->write_event_handler(r, u);

    } else {
        u->read_event_handler(r, u);
    }

    ngx_http_run_posted_requests(c);
}

static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
#if (NGX_HTTP_V3)
    ngx_int_t          rc;
#endif
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request handler");

    if (c->write->timedout) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

#if (NGX_HTTP_V3)

    if (u->h3) {
        if (!u->h3_started) {

            rc = ngx_http_v3_upstream_connected(r, u, c);

            if (rc == NGX_DECLINED) {
                ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
                return;
            }

            if (rc != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

        } else {

            if (u->header_sent && !u->conf->preserve_output) {
                u->write_event_handler = ngx_http_upstream_dummy_handler;

                (void) ngx_handle_write_event(c->write, 0);

                return;
            }

            ngx_http_upstream_send_request(r, u, 1);
        }

        return;
    }

#endif

#if (NGX_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    if (u->header_sent && !u->conf->preserve_output) {
        u->write_event_handler = ngx_http_upstream_dummy_handler;

        (void) ngx_handle_write_event(c->write, 0);

        return;
    }

    ngx_http_upstream_send_request(r, u, 1);
}

static void
ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    r->connection->log->action = "connecting to upstream";

    if (u->state && u->state->response_time == (ngx_msec_t) -1) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    u->state = ngx_array_push(r->upstream_states);
    if (u->state == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));

    u->start_time = ngx_current_msec;

    u->state->transport = u->peer.type;
    u->state->response_time = (ngx_msec_t) -1;
    u->state->connect_time = (ngx_msec_t) -1;
    u->state->header_time = (ngx_msec_t) -1;

    rc = u->peer.sockaddr ? NGX_OK : u->peer.get(&u->peer, u->peer.data);

    if (rc == NGX_OK) {
        rc = u->peer.connect ? u->peer.connect(&u->peer, u->peer.data)
                             : ngx_event_connect(&u->peer, u->peer.data);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (u->upstream && u->upstream->shm_zone
        && (u->upstream->flags & NGX_HTTP_UPSTREAM_CONF)
    ) {
        u->state->peer = ngx_palloc(r->pool,
                                    sizeof(ngx_str_t) + u->peer.name->len);
        if (u->state->peer == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->state->peer->len = u->peer.name->len;
        u->state->peer->data = (u_char *) (u->state->peer + 1);
        ngx_memcpy(u->state->peer->data, u->peer.name->data, u->peer.name->len);

        u->peer.name = u->state->peer;
    }
#endif

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no live upstreams");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN */

    c = u->peer.connection;

    /* cached connection may have different type */
    u->state->transport = c->type;

#if (NGX_HTTP_CLIENT)
    if (r->connection->stub) {
        c->idle = r->connection->idle;
    }
#endif

    c->requests++;

#if (NGX_HTTP_V3)

    /* this is cached main quic connection with completed handshake */
    if (u->peer.cached && c->type == SOCK_DGRAM) {
        if (ngx_http_v3_upstream_reuse_connection(r, u, c) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

#endif

    c->data = r;

    c->write->handler = ngx_http_upstream_handler;
    c->read->handler = ngx_http_upstream_handler;

    if (c->pool == NULL) {

        /* we need separate pool here to be able to cache SSL connections */

        c->pool = ngx_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    c->sendfile &= r->connection->sendfile;

    if (r->connection->tcp_nopush == NGX_TCP_NOPUSH_DISABLED) {
        c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    }

    if (ngx_http_upstream_configure(r, u, c) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

#if (NGX_HTTP_V3)

    if (u->h3) {
        rc = ngx_http_v3_upstream_init_connection(r, u, c);

        if (rc == NGX_DECLINED) {
            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
            return;
        }

        if (rc != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

#endif

#if (NGX_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    ngx_http_upstream_send_request(r, u, 1);
}


static ngx_int_t
ngx_http_upstream_configure(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_connection_t *c)
{
    ngx_http_core_loc_conf_t  *clcf;

    u->write_event_handler = ngx_http_upstream_send_request_handler;
    u->read_event_handler = ngx_http_upstream_block_reading;

    u->output.sendfile = c->sendfile;

    /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = clcf->sendfile_max_chunk;

    if (u->request_sent || u->response_received
        || (u->peer.cached && c->type != u->peer.type))
    {
        /*
         * Reinitialize the request when:
         * 1) A previous attempt was made (request_sent or response_received),
         *    requiring the request buffer and upstream state to be reset; or
         * 2) The keepalive cache returned a connection whose socket type
         *    differs from u->peer.type (e.g., a cached TCP connection
         *    returned for a UDP peer in auto-transport mode).  The module's
         *    reinit_request callback can then rebuild the request buffer
         *    with the correct wire format for the actual connection type.
         */

        if (ngx_http_upstream_reinit(r, u) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (r->request_body
        && r->request_body->buf
        && r->request_body->temp_file
        && r == r->main)
    {
        /*
         * the r->request_body->buf can be reused for one request only,
         * the subrequests should allocate their own temporary bufs
         */

        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            return NGX_ERROR;
        }

        u->output.free->buf = r->request_body->buf;
        u->output.free->next = NULL;
        u->output.allocated = 1;

        r->request_body->buf->pos = r->request_body->buf->start;
        r->request_body->buf->last = r->request_body->buf->start;
        r->request_body->buf->tag = u->output.tag;
    }

    u->request_sent = 0;
    u->request_body_sent = 0;
    u->request_body_blocked = 0;
    u->response_received = 0;

    return NGX_OK;
}

static void
ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_uint_t                     run_posted;
    ngx_connection_t              *c;
    ngx_http_request_t            *r;
    ngx_http_upstream_t           *u;
    ngx_http_upstream_resolved_t  *ur;

    run_posted = ctx->async;

    r = ctx->data;
    c = r->connection;

    u = r->upstream;
    ur = u->resolved;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream resolve: \"%V?%V\"", &r->uri, &r->args);

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        goto failed;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
    u_char      text[NGX_SOCKADDR_STRLEN];
    ngx_str_t   addr;
    ngx_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, NGX_SOCKADDR_STRLEN, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (ngx_http_upstream_create_round_robin_peer(r, ur) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        goto failed;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = ngx_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    ngx_http_upstream_connect(r, u);

failed:

    if (run_posted) {
        ngx_http_run_posted_requests(c);
    }
}

static ngx_int_t
ngx_http_upstream_need_connection_drop(ngx_http_upstream_t *u)
{

#if (NGX_HTTP_CLIENT)
    if (u->peer.connection && u->peer.connection->close) {
        return 1;
    }
#endif

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_http_upstream_rr_peer_t       *peer;
    ngx_http_upstream_rr_peer_data_t  *rrp;

    if (u->upstream == NULL || u->upstream->shm_zone == NULL) {
        return 0;
    }

    rrp = u->peer.data;

    if (rrp == NULL) {
        return 0;
    }

    peer = rrp->current;

    if (!peer->zombie) {
        return 0;
    }

    if (u->conf->connection_drop == NGX_HTTP_UPSTREAM_CONNECTION_DROP_OFF) {
        return 0;
    }

    if (ngx_current_msec - peer->zombie >= u->conf->connection_drop) {
        return 1;
    }
#endif

    return 0;
}

static void
ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r)
{
#if (NGX_HTTP_CLIENT)
    if (r->connection->stub) {
        return;
    }
#endif

    ngx_http_upstream_check_broken_connection(r, r->connection->read);
}


static void
ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r)
{
#if (NGX_HTTP_CLIENT)
    if (r->connection->stub) {
        return;
    }
#endif

    ngx_http_upstream_check_broken_connection(r, r->connection->write);
}

static void
ngx_http_nwaf_upstream_init_request(ngx_http_request_t *r)
{
    ngx_str_t                      *host;
    ngx_uint_t                      i;
    ngx_resolver_ctx_t             *ctx, temp;
    ngx_http_cleanup_t             *cln;
    ngx_http_upstream_t            *u;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    if (r->aio) {
        return;
    }

    u = r->upstream;

    u->method = r->method_name;

#if (NGX_HTTP_CACHE)

    if (u->conf->cache) {
        ngx_int_t  rc;

        rc = ngx_http_upstream_cache(r, u);

        if (rc == NGX_BUSY) {
            r->write_event_handler = ngx_http_nwaf_upstream_init_request;
            return;
        }

        r->write_event_handler = ngx_http_request_empty_handler;

        if (rc == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rc == NGX_OK) {
            rc = ngx_http_upstream_cache_send(r, u);

            if (rc == NGX_DONE) {
                return;
            }

            if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NGX_DECLINED;
                r->cached = 0;
                u->buffer.start = NULL;
                u->cache_status = NGX_HTTP_CACHE_MISS;
                u->request_sent = 1;
            }
        }

        if (rc != NGX_DECLINED) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

#endif

    u->store = u->conf->store;

    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {

        if (r->connection->read->ready) {
            ngx_post_event(r->connection->read, &ngx_posted_events);

        } else {
            if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        r->read_event_handler = ngx_http_upstream_rd_check_broken_connection;
        r->write_event_handler = ngx_http_upstream_wr_check_broken_connection;
    }

    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }

    if (u->create_request(r) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_upstream_set_local(r, u, u->conf->local) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;

    if (u->output.output_filter == NULL) {
        u->output.output_filter = ngx_chain_writer;
        u->output.filter_ctx = &u->writer;
    }

    u->writer.pool = r->pool;

    if (r->upstream_states == NULL) {

        r->upstream_states = ngx_array_create(r->pool, 1,
                                            sizeof(ngx_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {

        u->state = ngx_array_push(r->upstream_states);
        if (u->state == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_http_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {
        uscf = u->conf->upstream;
    } else {

#if (NGX_HTTP_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "no port in upstream \"%V\"", host);
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_http_upstream_create_round_robin_peer(r, u->resolved)
                != NGX_OK)
            {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_http_upstream_connect(r, u);

            return;
        }

        if (u->resolved->port == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no port in upstream \"%V\"", host);
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        ctx = ngx_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "no resolver defined to resolve %V", host);

            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return;
        }

        ctx->name = *host;
        ctx->handler = ngx_http_upstream_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "no upstream configuration");
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NGX_HTTP_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(r, uscf) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

// Create request context
    nwaf_create_ws_rctx(r);
//
    ngx_http_upstream_connect(r, u);
}

void ngx_http_nwaf_upstream_init(ngx_http_request_t *r)
{
    ngx_connection_t     *c;

    c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http init upstream, client timer: %d", c->read->timer_set);

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_nwaf_upstream_init_request(r);
        return;
    }
#endif

#if (NGX_HTTP_V3)
    if (c->quic) {
        ngx_http_nwaf_upstream_init_request(r);
        return;
    }
#endif

    if (c->stub) {
        ngx_http_nwaf_upstream_init_request(r);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
                == NGX_ERROR)
            {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    ngx_http_nwaf_upstream_init_request(r);
}

static ngx_int_t ngx_http_nwaf_proxy_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_upstream_t         *u;
    ngx_http_proxy_ctx_t        *ctx;
    ngx_http_proxy_loc_conf_t   *plcf;
#if (NGX_HTTP_CACHE)
    ngx_http_proxy_main_conf_t  *pmcf;
#endif

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->legacy = 1;

    ngx_http_set_ctx(r, ctx, ngx_http_proxy_module);

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    u = r->upstream;

    if (plcf->proxy_lengths == NULL) {
#if (NGX_HTTP_V3)
        ctx->host = plcf->host;
#endif
        ctx->vars = plcf->vars;
        u->schema = plcf->vars.schema;

#if (NGX_HTTP_SSL)
        u->ssl = plcf->ssl;
#endif

    } else {
        if (ngx_http_proxy_eval(r, ctx, plcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_module;

    u->conf = &plcf->upstream;

#if (NGX_HTTP_CACHE)
    pmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = ngx_http_proxy_create_key;
#endif

    u->create_request = ngx_http_proxy_create_request;
    u->reinit_request = ngx_http_proxy_reinit_request;
    u->process_header = ngx_http_proxy_process_status_line;
    u->abort_request = ngx_http_proxy_abort_request;
    u->finalize_request = ngx_http_proxy_finalize_request;

#if (NGX_HTTP_V3)
    if (plcf->http_version == NGX_HTTP_VERSION_30) {

        u->h3 = 1;
        u->peer.type = SOCK_DGRAM;

        if (plcf->enable_hq) {
            u->hq = 1;

        } else {
            u->create_request = ngx_http_v3_proxy_create_request;
            u->reinit_request = ngx_http_v3_proxy_reinit_request;
            u->process_header = ngx_http_v3_proxy_process_status_line;
            u->abort_request = ngx_http_v3_proxy_abort_request;
            u->finalize_request = ngx_http_v3_proxy_finalize_request;
        }

        ctx->v3_parse = ngx_pcalloc(r->pool, sizeof(ngx_http_v3_parse_t));
        if (ctx->v3_parse == NULL) {
            return NGX_ERROR;
        }
    }
#endif

    r->state = 0;

    if (plcf->redirects) {
        u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
    }

    if (plcf->cookie_domains || plcf->cookie_paths || plcf->cookie_flags) {
        u->rewrite_cookie = ngx_http_proxy_rewrite_cookie;
    }

    u->buffering = plcf->upstream.buffering;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_proxy_copy_filter;

    u->input_filter_init = ngx_http_proxy_input_filter_init;
    u->input_filter = ngx_http_proxy_non_buffered_copy_filter;

#if (NGX_HTTP_V3)
    if (plcf->http_version == NGX_HTTP_VERSION_30 && !plcf->enable_hq) {
        u->pipe->input_filter = ngx_http_v3_proxy_copy_filter;

        u->input_filter_init = ngx_http_v3_proxy_input_filter_init;
        u->input_filter = ngx_http_v3_proxy_non_buffered_copy_filter;
    }
#endif

    u->pipe->input_ctx = r;
    u->input_filter_ctx = r;

    u->accel = 1;

    if (!plcf->upstream.request_buffering
        && plcf->body_values == NULL && plcf->upstream.pass_request_body
        && (!r->headers_in.chunked
            || (plcf->http_version == NGX_HTTP_VERSION_11
#if (NGX_HTTP_V3)
                || plcf->http_version == NGX_HTTP_VERSION_30
#endif
           )))
    {
        r->request_body_no_buffering = 1;
    }

//    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
    rc = ngx_http_read_client_request_body(r, ngx_http_nwaf_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


#if (NGX_HTTP_CACHE)


#endif


static ngx_int_t
ngx_http_proxy_create_request(ngx_http_request_t *r)
{
    size_t                        len, uri_len, loc_len, body_len,
                                  key_len, val_len;
    uintptr_t                     escape;
    ngx_buf_t                    *b;
    ngx_str_t                     method;
    ngx_uint_t                    i, unparsed_uri;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_ctx_t         *ctx;
    ngx_http_script_code_pt       code;
    ngx_http_proxy_headers_t     *headers;
    ngx_http_script_engine_t      e, le;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

#if (NGX_HTTP_CACHE)
    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif

    if (plcf->method) {
        if (ngx_http_complex_value(r, plcf->method, &method) != NGX_OK) {
            return NGX_ERROR;
        }

        u->method = method;

    } else {
        method = u->method;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (method.len == 4
        && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
    {
        ctx->head = 1;
    }

    len = method.len + 1 + sizeof(ngx_http_proxy_version) - 1
          + sizeof(CRLF) - 1;

    escape = 0;
    loc_len = 0;
    unparsed_uri = 0;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        uri_len = ctx->vars.uri.len;

    } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
        unparsed_uri = 1;
        uri_len = r->unparsed_uri.len;

    } else {
        loc_len = (r->valid_location && ctx->vars.uri.len)
                  ? ngx_min(plcf->location.len, r->uri.len) : 0;

        if (r->quoted_uri || r->internal) {
            escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                        r->uri.len - loc_len, NGX_ESCAPE_URI);
        }

        uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
                  + sizeof("?") - 1 + r->args.len;
    }

    if (uri_len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "zero length URI to proxy");
        return NGX_ERROR;
    }

    len += uri_len;

    ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

    ngx_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);

    if (plcf->body_lengths) {
        le.ip = plcf->body_lengths->elts;
        le.request = r;
        le.flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le.ip) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            body_len += lcode(&le);
        }

        ctx->internal_body_length = body_len;
        len += body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->internal_body_length = -1;
        ctx->internal_chunked = 1;

    } else {
        ctx->internal_body_length = r->headers_in.content_length_n;
    }

    le.ip = headers->lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        len += key_len + sizeof(": ") - 1 + val_len + sizeof(CRLF) - 1;
    }


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += header[i].key.len + sizeof(": ") - 1
                + header[i].value.len + sizeof(CRLF) - 1;
        }
    }


    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;


    /* the request line */

    b->last = ngx_copy(b->last, method.data, method.len);
    *b->last++ = ' ';

    u->uri.data = b->last;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        b->last = ngx_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);

    } else if (unparsed_uri) {
        b->last = ngx_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            b->last = ngx_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);
        }

        if (escape) {
            ngx_escape_uri(b->last, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            b->last += r->uri.len - loc_len + escape;

        } else {
            b->last = ngx_copy(b->last, r->uri.data + loc_len,
                               r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *b->last++ = '?';
            b->last = ngx_copy(b->last, r->args.data, r->args.len);
        }
    }

    u->uri.len = b->last - u->uri.data;

#if (NGX_HTTP_V3)
    if (plcf->http_version == NGX_HTTP_VERSION_30 && plcf->enable_hq) {
        goto nover;
    }
#endif

    if (plcf->http_version == NGX_HTTP_VERSION_11) {
        b->last = ngx_cpymem(b->last, ngx_http_proxy_version_11,
                             sizeof(ngx_http_proxy_version_11) - 1);

    } else {
        b->last = ngx_cpymem(b->last, ngx_http_proxy_version,
                             sizeof(ngx_http_proxy_version) - 1);
    }

#if (NGX_HTTP_V3)
nover:
#endif

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = headers->values->elts;
    e.pos = b->last;
    e.request = r;
    e.flushed = 1;

    le.ip = headers->lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        (void) lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);

        *e.pos++ = ':'; *e.pos++ = ' ';

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        *e.pos++ = CR; *e.pos++ = LF;
    }

    b->last = e.pos;


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);

            *b->last++ = ':'; *b->last++ = ' ';

            b->last = ngx_copy(b->last, header[i].value.data,
                               header[i].value.len);

            *b->last++ = CR; *b->last++ = LF;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }


    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

    if (plcf->body_values) {
        e.ip = plcf->body_values->elts;
        e.pos = b->last;
        e.skip = 0;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }

        b->last = e.pos;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header:%N\"%*s\"",
                   (size_t) (b->last - b->pos), b->pos);

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

        if (ctx->internal_chunked) {
            u->output.output_filter = ngx_http_proxy_body_output_filter;
            u->output.filter_ctx = r;
        }

    } else if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

        while (body) {
            b = ngx_alloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }
            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

    } else {
        u->request_bufs = cl;
    }

    b->flush = 1;
    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ctx->status.code = 0;
    ctx->status.count = 0;
    ctx->status.start = NULL;
    ctx->status.end = NULL;
    ctx->chunked.state = 0;

    r->upstream->process_header = ngx_http_proxy_process_status_line;
    r->upstream->pipe->input_filter = ngx_http_proxy_copy_filter;
    r->upstream->input_filter = ngx_http_proxy_non_buffered_copy_filter;
    r->state = 0;

    return NGX_OK;
}


static ngx_int_t ngx_http_proxy_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                  size;
    u_char                *chunk;
    ngx_int_t              rc;
    ngx_buf_t             *b;
    ngx_chain_t           *out, *cl, *tl, **ll, **fl;
    ngx_http_proxy_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy output filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers, pass it unmodified */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy output header");

        ctx->header_sent = 1;

        tl = ngx_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        tl->buf = in->buf;
        *ll = tl;
        ll = &tl->next;

        in = in->next;

        if (in == NULL) {
            tl->next = NULL;
            goto out;
        }
    }

    size = 0;
    cl = in;
    fl = ll;

    for ( ;; ) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy output chunk: %O", ngx_buf_size(cl->buf));

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || ngx_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            /* the "0000000000000000" is 64-bit hexadecimal string */

            chunk = ngx_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
            if (chunk == NULL) {
                return NGX_ERROR;
            }

            b->start = chunk;
            b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
        }

        b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last = ngx_sprintf(chunk, "%xO" CRLF, size);

        tl->next = *fl;
        *fl = tl;
    }

    if (cl->buf->last_buf) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;

        b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 1;
        b->last_buf = 1;
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + 7;

        cl->buf->last_buf = 0;

        *ll = tl;

        if (size == 0) {
            b->pos += 2;
        }

    } else if (size > 0) {
        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;

        b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;

        *ll = tl;

    } else {
        *ll = NULL;
    }

out:

    rc = ngx_chain_writer(&r->upstream->writer, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter);

    return rc;
}


static ngx_int_t
ngx_http_proxy_process_status_line(ngx_http_request_t *r)
{
    size_t                 len;
    ngx_int_t              rc;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;

    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

    if (rc == NGX_AGAIN) {
        return rc;
    }

    if (rc == NGX_ERROR) {
        u->buffer.pos = ctx->status.line_start;

#if (NGX_HTTP_CACHE)

        if (r->cache) {
            r->http_version = NGX_HTTP_VERSION_9;
            return NGX_OK;
        }

#endif

#if (NGX_HTTP_V3)
        {

        ngx_http_proxy_loc_conf_t  *plcf;

        plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

        if (plcf->http_version == NGX_HTTP_VERSION_30 && plcf->enable_hq) {
            r->http_version = NGX_HTTP_VERSION_9;
            u->state->status = NGX_HTTP_OK;
            u->headers_in.connection_close = 1;

            return NGX_OK;
        }

        }
#endif

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

#if 0
        if (u->accel) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }
#endif

        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        u->headers_in.connection_close = 1;

        return NGX_OK;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    if (ctx->status.http_version < NGX_HTTP_VERSION_11) {

        if (ctx->status.code == NGX_HTTP_EARLY_HINTS) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent HTTP/1.0 response with early hints");
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        u->headers_in.connection_close = 1;
    }

    u->process_header = ngx_http_proxy_process_header;

    return ngx_http_proxy_process_header(r);
}


static ngx_int_t
ngx_http_proxy_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_ctx_t           *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &h->key, &h->value);

            if (r->upstream->headers_in.status_n == NGX_HTTP_EARLY_HINTS) {
                continue;
            }

            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh) {
                rc = hh->handler(r, h, hh->offset);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header done");

            ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

            if (r->upstream->headers_in.status_n == NGX_HTTP_EARLY_HINTS) {
                ctx->status.code = 0;
                ctx->status.count = 0;
                ctx->status.start = NULL;
                ctx->status.end = NULL;

                r->upstream->process_header =
                                            ngx_http_proxy_process_status_line;
                r->state = 0;
                return NGX_HTTP_UPSTREAM_EARLY_HINTS;
            }

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
                h->next = NULL;
            }

            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
                h->next = NULL;
            }

            /* clear content length if response is chunked */

            u = r->upstream;

            if (u->headers_in.chunked) {
                u->headers_in.content_length_n = -1;
            }

            /*
             * set u->keepalive if response has no body; this allows to keep
             * connections alive in case of r->header_only or X-Accel-Redirect
             */

            if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
                || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
                || ctx->head
                || (!u->headers_in.chunked
                    && u->headers_in.content_length_n == 0))
            {
                u->keepalive = !u->headers_in.connection_close;
            }

            if (u->headers_in.status_n == NGX_HTTP_SWITCHING_PROTOCOLS) {
                u->keepalive = 0;

                if (r->headers_in.upgrade) {
                    u->upgrade = 1;
                }
            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static ngx_int_t
ngx_http_proxy_input_filter_init(void *data)
{
    ngx_http_request_t    *r = data;
    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter init s:%ui h:%d c:%d l:%O",
                   u->headers_in.status_n, ctx->head, u->headers_in.chunked,
                   u->headers_in.content_length_n);

    /* as per RFC2616, 4.4 Message Length */

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else if (u->headers_in.chunked) {
        /* chunked */

        u->pipe->input_filter = ngx_http_proxy_chunked_filter;
        u->pipe->length = 5; /* "0" CRLF CRLF */

        u->input_filter = ngx_http_proxy_non_buffered_chunked_filter;
        u->length = 1;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else {
        /* content length or connection close */

        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_buf_t           *b;
    ngx_chain_t         *cl;
    ngx_http_request_t  *r;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    if (p->upstream_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                       "http proxy data after close");
        return NGX_OK;
    }

    if (p->length == 0) {

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        r = p->input_ctx;
        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NGX_OK;
    }

    cl = ngx_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;

    ngx_memcpy(b, buf, sizeof(ngx_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return NGX_OK;
    }

    if (b->last - b->pos > p->length) {

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        b->last = b->pos + p->length;
        p->upstream_done = 1;

        return NGX_OK;
    }

    p->length -= b->last - b->pos;

    if (p->length == 0) {
        r = p->input_ctx;
        r->upstream->keepalive = !r->upstream->headers_in.connection_close;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_chunked_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_int_t                   rc;
    ngx_buf_t                  *b, **prev;
    ngx_chain_t                *cl;
    ngx_http_request_t         *r;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (p->upstream_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                       "http proxy data after close");
        return NGX_OK;
    }

    if (p->length == 0) {

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent data after final chunk");

        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NGX_OK;
    }

    b = NULL;

    if (ctx->trailers) {
        rc = ngx_http_proxy_process_trailer(r, buf);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {

            /* a whole response has been parsed successfully */

            p->length = 0;
            r->upstream->keepalive = !r->upstream->headers_in.connection_close;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, p->log, 0,
                              "upstream sent data after trailers");
                r->upstream->keepalive = 0;
            }
        }

        goto free_buf;
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    prev = &buf->shadow;

    for ( ;; ) {

        rc = ngx_http_parse_chunked(r, buf, &ctx->chunked,
                                    plcf->upstream.pass_trailers);

        if (rc == NGX_OK) {

            /* a chunk has been parsed successfully */

            cl = ngx_chain_get_free_buf(p->pool, &p->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->pos = buf->pos;
            b->start = buf->start;
            b->end = buf->end;
            b->tag = p->tag;
            b->temporary = 1;
            b->recycled = 1;

            *prev = b;
            prev = &b->shadow;

            if (p->in) {
                *p->last_in = cl;
            } else {
                p->in = cl;
            }
            p->last_in = &cl->next;

            /* STUB */ b->num = buf->num;

            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "input buf #%d %p", b->num, b->pos);

            if (buf->last - buf->pos >= ctx->chunked.size) {

                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

                continue;
            }

            ctx->chunked.size -= buf->last - buf->pos;
            buf->pos = buf->last;
            b->last = buf->last;

            continue;
        }

        if (rc == NGX_DONE) {

            if (plcf->upstream.pass_trailers) {
                rc = ngx_http_proxy_process_trailer(r, buf);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc == NGX_AGAIN) {
                    p->length = 1;
                    break;
                }
            }

            /* a whole response has been parsed successfully */

            p->length = 0;
            r->upstream->keepalive = !r->upstream->headers_in.connection_close;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, p->log, 0,
                              "upstream sent data after final chunk");
                r->upstream->keepalive = 0;
            }

            break;
        }

        if (rc == NGX_AGAIN) {

            /* set p->length, minimal amount of data we want to see */

            p->length = ctx->chunked.length;

            break;
        }

        /* invalid response */

        ngx_log_error(NGX_LOG_ERR, p->log, 0,
                      "upstream sent invalid chunked response");

        return NGX_ERROR;
    }

free_buf:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, p->log, 0,
                   "http proxy chunked state %ui, length %O",
                   ctx->chunked.state, p->length);

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (u->length == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");
        u->keepalive = 0;
        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NGX_OK;
    }

    if (bytes > u->length) {

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        cl->buf->last = cl->buf->pos + u->length;
        u->length = 0;

        return NGX_OK;
    }

    u->length -= bytes;

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;

    ngx_int_t                   rc;
    ngx_buf_t                  *b, *buf;
    ngx_chain_t                *cl, **ll;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    if (ctx->trailers) {
        rc = ngx_http_proxy_process_trailer(r, buf);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {

            /* a whole response has been parsed successfully */

            r->upstream->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "upstream sent data after trailers");
                u->keepalive = 0;
            }
        }

        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        rc = ngx_http_parse_chunked(r, buf, &ctx->chunked,
                                    plcf->upstream.pass_trailers);

        if (rc == NGX_OK) {

            /* a chunk has been parsed successfully */

            cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;

            b->flush = 1;
            b->memory = 1;

            b->pos = buf->pos;
            b->tag = u->output.tag;

            if (buf->last - buf->pos >= ctx->chunked.size) {
                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

            } else {
                ctx->chunked.size -= buf->last - buf->pos;
                buf->pos = buf->last;
                b->last = buf->last;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy out buf %p %z",
                           b->pos, b->last - b->pos);

            continue;
        }

        if (rc == NGX_DONE) {

            if (plcf->upstream.pass_trailers) {
                rc = ngx_http_proxy_process_trailer(r, buf);

                if (rc == NGX_ERROR) {
                    return NGX_ERROR;
                }

                if (rc == NGX_AGAIN) {
                    u->length = 1;
                    break;
                }
            }

            /* a whole response has been parsed successfully */

            u->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "upstream sent data after final chunk");
                u->keepalive = 0;
            }

            break;
        }

        if (rc == NGX_AGAIN) {
            break;
        }

        /* invalid response */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid chunked response");

        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_process_trailer(ngx_http_request_t *r, ngx_buf_t *buf)
{
    size_t                      len;
    ngx_int_t                   rc;
    ngx_buf_t                  *b;
    ngx_table_elt_t            *h;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx->trailers == NULL) {
        ctx->trailers = ngx_create_temp_buf(r->pool,
                                            plcf->upstream.buffer_size);
        if (ctx->trailers == NULL) {
            return NGX_ERROR;
        }
    }

    b = ctx->trailers;
    len = ngx_min(buf->last - buf->pos, b->end - b->last);

    b->last = ngx_cpymem(b->last, buf->pos, len);

    for ( ;; ) {

        rc = ngx_http_parse_header_line(r, b, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->upstream->headers_in.trailers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = ngx_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return NGX_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy trailer: \"%V: %V\"",
                           &h->key, &h->value);
            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            buf->pos += len - (b->last - b->pos);

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy trailer done");

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            buf->pos += len;

            if (b->last == b->end) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too big trailers");
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid trailer: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        return NGX_ERROR;
    }
}

static void
ngx_http_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http proxy request");

    return;
}


static void
ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy request");

    return;
}

/*
static ngx_int_t
ngx_http_proxy_host_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.host_header.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.host_header.data;

    return NGX_OK;
}
*/
/*
static ngx_int_t
ngx_http_proxy_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->vars.port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.port.data;

    return NGX_OK;
}
*/
/*
static ngx_int_t
ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    size_t            len;
    u_char           *p;
    ngx_table_elt_t  *h, *xfwd;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    xfwd = r->headers_in.x_forwarded_for;

    len = 0;

    for (h = xfwd; h; h = h->next) {
        len += h->value.len + sizeof(", ") - 1;
    }

    if (len == 0) {
        v->len = r->connection->addr_text.len;
        v->data = r->connection->addr_text.data;
        return NGX_OK;
    }

    len += r->connection->addr_text.len;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = len;
    v->data = p;

    for (h = xfwd; h; h = h->next) {
        p = ngx_copy(p, h->value.data, h->value.len);
        *p++ = ','; *p++ = ' ';
    }

    ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);

    return NGX_OK;
}
*/
/*
static ngx_int_t
ngx_http_proxy_internal_body_length_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL || ctx->internal_body_length < 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);

    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%O", ctx->internal_body_length) - v->data;

    return NGX_OK;
}
*/
/*
static ngx_int_t
ngx_http_proxy_internal_chunked_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL || !ctx->internal_chunked) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "chunked";
    v->len = sizeof("chunked") - 1;

    return NGX_OK;
}
*/


static ngx_int_t
ngx_http_proxy_rewrite_complex_handler(ngx_http_request_t *r, ngx_str_t *value,
    size_t prefix, size_t len, ngx_http_proxy_rewrite_t *pr)
{
    ngx_str_t  pattern, replacement;

    if (ngx_http_complex_value(r, &pr->pattern.complex, &pattern) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pattern.len > len
        || ngx_rstrncmp(value->data + prefix, pattern.data, pattern.len) != 0)
    {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_proxy_rewrite(r, value, prefix, pattern.len, &replacement);
}

static ngx_int_t
ngx_http_proxy_rewrite(ngx_http_request_t *r, ngx_str_t *value, size_t prefix,
    size_t len, ngx_str_t *replacement)
{
    u_char  *p, *data;
    size_t   new_len;

    if (len == value->len) {
        *value = *replacement;
        return NGX_OK;
    }

    new_len = replacement->len + value->len - len;

    if (replacement->len > len) {

        data = ngx_pnalloc(r->pool, new_len + 1);
        if (data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_copy(data, value->data, prefix);
        p = ngx_copy(p, replacement->data, replacement->len);

        ngx_memcpy(p, value->data + prefix + len,
                   value->len - len - prefix + 1);

        value->data = data;

    } else {
        p = ngx_copy(value->data + prefix, replacement->data, replacement->len);

        ngx_memmove(p, value->data + prefix + len,
                    value->len - len - prefix + 1);
    }

    value->len = new_len;

    return NGX_OK;
}

static void *
ngx_http_waf_ws_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_waf_ws_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_ws_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static void *
ngx_http_waf_ws_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_zone = NULL;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     *     conf->location = NULL;
     *     conf->url = { 0, NULL };
     *     conf->headers.lengths = NULL;
     *     conf->headers.values = NULL;
     *     conf->headers.hash = { NULL, 0 };
     *     conf->headers_cache.lengths = NULL;
     *     conf->headers_cache.values = NULL;
     *     conf->headers_cache.hash = { NULL, 0 };
     *     conf->body_lengths = NULL;
     *     conf->body_values = NULL;
     *     conf->body_source = { 0, NULL };
     *     conf->redirects = NULL;
     *     conf->ssl = 0;
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *
     *     conf->host = { 0, NULL };
     *     conf->host_set = 0;
     *     conf->max_table_capacity_set = 0;
     *
     *     conf->upstream.quic.host_key = { 0, NULL }
     *     conf->upstream.quic.stream_reject_code_uni = 0;
     *     conf->upstream.quic.disable_active_migration = 0;
     *     conf->upstream.quic.idle_timeout = 0;
     *     conf->upstream.quic.handshake_timeout = 0;
     *     conf->upstream.quic.retry = 0;
     *
     *     conf->upstream.h3_settings.max_blocked_streams = 0;
     */

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.request_buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
    conf->upstream.force_ranges = NGX_CONF_UNSET;

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.connection_drop = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.limit_rate = NGX_CONF_UNSET_PTR;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;
    conf->upstream.pass_trailers = NGX_CONF_UNSET;

#if (NGX_HTTP_CACHE)
    conf->upstream.cache = NGX_CONF_UNSET;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
    conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
    conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_lock = NGX_CONF_UNSET;
    conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
    conf->upstream.cache_revalidate = NGX_CONF_UNSET;
    conf->upstream.cache_convert_head = NGX_CONF_UNSET;
    conf->upstream.cache_background_update = NGX_CONF_UNSET;
#endif

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

#if (NGX_HTTP_SSL)
    conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
    conf->upstream.ssl_name = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_server_name = NGX_CONF_UNSET;
    conf->upstream.ssl_verify = NGX_CONF_UNSET;
#if (NGX_HTTP_PROXY_MULTICERT)
    conf->upstream.ssl_certificates = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_keys = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_values = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_key_values = NGX_CONF_UNSET_PTR;
#else
    conf->upstream.ssl_certificate = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_key = NGX_CONF_UNSET_PTR;
#endif
    conf->upstream.ssl_certificate_cache = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_passwords = NGX_CONF_UNSET_PTR;
    conf->upstream.ssl_keylog_file = NGX_CONF_UNSET_PTR;
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
    conf->ssl_conf_commands = NGX_CONF_UNSET_PTR;
#if (NGX_HAVE_NTLS)
    conf->upstream.ssl_ntls = NGX_CONF_UNSET;
#endif
#endif

    /* "proxy_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.pass_early_hints = 1;

    conf->upstream.change_buffering = 1;

    conf->headers_source = NGX_CONF_UNSET_PTR;

    conf->method = NGX_CONF_UNSET_PTR;

    conf->redirect = NGX_CONF_UNSET;

    conf->cookie_domains = NGX_CONF_UNSET_PTR;
    conf->cookie_paths = NGX_CONF_UNSET_PTR;
    conf->cookie_flags = NGX_CONF_UNSET_PTR;

    conf->http_version = NGX_CONF_UNSET_UINT;

    conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
    conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;

    ngx_str_set(&conf->upstream.module, "proxy");

#if (NGX_HTTP_V3)

    conf->upstream.quic.stream_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upstream.quic.max_concurrent_streams_bidi = NGX_CONF_UNSET_UINT;
    conf->upstream.quic.max_concurrent_streams_uni =
                                                   NGX_HTTP_V3_MAX_UNI_STREAMS;
    conf->upstream.quic.gso_enabled = NGX_CONF_UNSET;

    conf->upstream.quic.active_connection_id_limit = NGX_CONF_UNSET_UINT;

    conf->upstream.quic.stream_close_code = NGX_HTTP_V3_ERR_NO_ERROR;
    conf->upstream.quic.stream_reject_code_bidi =
                                              NGX_HTTP_V3_ERR_REQUEST_REJECTED;

    conf->upstream.quic.shutdown = ngx_http_v3_shutdown;

    conf->enable_hq = NGX_CONF_UNSET;

    conf->upstream.h3_settings.max_table_capacity = NGX_CONF_UNSET;
    conf->upstream.h3_settings.max_concurrent_streams = NGX_CONF_UNSET_UINT;

#endif

    return conf;
}


static char *
ngx_http_waf_ws_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxy_loc_conf_t *prev = parent;
    ngx_http_proxy_loc_conf_t *conf = child;

    u_char                     *p;
    size_t                      size;
    ngx_int_t                   rc;
    ngx_keyval_t               *proxy_headers;
    ngx_hash_init_t             hash;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_proxy_rewrite_t   *pr;
    ngx_http_script_compile_t   sc;

#if (NGX_HTTP_CACHE)

    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }

#endif

    if (conf->upstream.store == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }

    ngx_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    ngx_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.request_buffering,
                              prev->upstream.request_buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_value(conf->upstream.force_ranges,
                              prev->upstream.force_ranges, 0);

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    ngx_conf_merge_msec_value(conf->upstream.connection_drop,
                              prev->upstream.connection_drop,
                              NGX_HTTP_UPSTREAM_CONNECTION_DROP_OFF);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_ptr_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, NULL);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"proxy_buffers\"");
        return NGX_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal to or greater than "
             "the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal to or greater "
             "than the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
             "\"proxy_max_temp_file_size\" must be equal to zero to disable "
             "temporary files usage or must be equal to or greater than "
             "the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NGX_CONF_ERROR;
    }


    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              NGX_CONF_BITMASK_SET);


    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &ngx_http_proxy_temp_path)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }


#if (NGX_HTTP_CACHE)

    if (conf->upstream.cache == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.cache,
                              prev->upstream.cache, 0);

        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }

    if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
        ngx_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache_zone;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset,
                              prev->upstream.cache_max_range_offset,
                              NGX_MAX_OFF_T_VALUE);

    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
                                         |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
        conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    ngx_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    ngx_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    ngx_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    ngx_conf_merge_value(conf->upstream.cache_convert_head,
                              prev->upstream.cache_convert_head, 1);

    ngx_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.pass_trailers,
                              prev->upstream.pass_trailers, 0);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (NGX_HTTP_SSL)

    if (ngx_http_proxy_merge_ssl(cf, conf, prev) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                             (NGX_CONF_BITMASK_SET|NGX_SSL_DEFAULT_PROTOCOLS));

    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    ngx_conf_merge_ptr_value(conf->upstream.ssl_name,
                              prev->upstream.ssl_name, NULL);
    ngx_conf_merge_value(conf->upstream.ssl_server_name,
                              prev->upstream.ssl_server_name, 0);
    ngx_conf_merge_value(conf->upstream.ssl_verify,
                              prev->upstream.ssl_verify, 0);
    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");
    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    ngx_conf_merge_ptr_value(conf->upstream.ssl_passwords,
                              prev->upstream.ssl_passwords, NULL);

#if (NGX_HTTP_PROXY_MULTICERT)
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificates,
                              prev->upstream.ssl_certificates, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_keys,
                              prev->upstream.ssl_certificate_keys, NULL);

    if (conf->upstream.ssl_certificates) {
        if (ngx_http_proxy_compile_certificates(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
                        
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_values,
                             prev->upstream.ssl_certificate_values, NULL);
                        
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_key_values,
                              prev->upstream.ssl_certificate_key_values, NULL);
                                                
#else
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate,
                              prev->upstream.ssl_certificate, NULL);
    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_key,
                              prev->upstream.ssl_certificate_key, NULL);
#endif

    ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_cache,
                              prev->upstream.ssl_certificate_cache, NULL);

    if (ngx_http_proxy_preserve_ssl_passwords(cf, &conf->upstream,
                                              &prev->upstream)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->upstream.ssl_keylog_file,
                              prev->upstream.ssl_keylog_file, NULL);

    ngx_conf_merge_ptr_value(conf->ssl_conf_commands,
                              prev->ssl_conf_commands, NULL);
#if (NGX_HAVE_NTLS)
    ngx_conf_merge_value(conf->upstream.ssl_ntls,
                              prev->upstream.ssl_ntls, 0);

    if (conf->upstream.ssl_ntls) {
        conf->upstream.ssl_ciphers = conf->ssl_ciphers;
    }
#endif

    if (conf->ssl && ngx_http_proxy_set_ssl(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#endif

    ngx_conf_merge_ptr_value(conf->method, prev->method, NULL);

    ngx_conf_merge_value(conf->redirect, prev->redirect, 1);

    if (conf->redirect) {

        if (conf->redirects == NULL) {
            conf->redirects = prev->redirects;
        }

        if (conf->redirects == NULL && conf->url.data) {

            conf->redirects = ngx_array_create(cf->pool, 1,
                                             sizeof(ngx_http_proxy_rewrite_t));
            if (conf->redirects == NULL) {
                return NGX_CONF_ERROR;
            }

            pr = ngx_array_push(conf->redirects);
            if (pr == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&pr->pattern.complex,
                        sizeof(ngx_http_complex_value_t));

            ngx_memzero(&pr->replacement, sizeof(ngx_http_complex_value_t));

            pr->handler = ngx_http_proxy_rewrite_complex_handler;

            if (conf->vars.uri.len) {
                pr->pattern.complex.value = conf->url;
                pr->replacement.value = conf->location;

            } else {
                pr->pattern.complex.value.len = conf->url.len
                                                + sizeof("/") - 1;

                p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
                if (p == NULL) {
                    return NGX_CONF_ERROR;
                }

                pr->pattern.complex.value.data = p;

                p = ngx_cpymem(p, conf->url.data, conf->url.len);
                *p = '/';

                ngx_str_set(&pr->replacement.value, "/");
            }
        }
    }

    ngx_conf_merge_ptr_value(conf->cookie_domains, prev->cookie_domains, NULL);

    ngx_conf_merge_ptr_value(conf->cookie_paths, prev->cookie_paths, NULL);

    ngx_conf_merge_ptr_value(conf->cookie_flags, prev->cookie_flags, NULL);

    ngx_conf_merge_uint_value(conf->http_version, prev->http_version,
                              NGX_HTTP_VERSION_11);

    ngx_conf_merge_uint_value(conf->headers_hash_max_size,
                              prev->headers_hash_max_size, 512);

    ngx_conf_merge_uint_value(conf->headers_hash_bucket_size,
                              prev->headers_hash_bucket_size, 64);

    conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size,
                                               ngx_cacheline_size);

    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, ngx_http_proxy_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

#if (NGX_HTTP_V3)

    ngx_conf_merge_value(conf->enable_hq, prev->enable_hq, 0);

    if (conf->enable_hq) {
        conf->upstream.quic.alpn.data = (unsigned char *)
                                        NGX_HTTP_V3_HQ_ALPN_PROTO;

        conf->upstream.quic.alpn.len = sizeof(NGX_HTTP_V3_HQ_ALPN_PROTO) - 1;

    } else {
        conf->upstream.quic.alpn.data = (unsigned char *)
                                        NGX_HTTP_V3_ALPN_PROTO;

        conf->upstream.quic.alpn.len = sizeof(NGX_HTTP_V3_ALPN_PROTO) - 1;
    }

    if (conf->upstream.h3_settings.max_table_capacity != NGX_CONF_UNSET_UINT) {
        /* really set in user config */
        conf->max_table_capacity_set = 1;
    }

    ngx_conf_merge_uint_value(conf->upstream.h3_settings.max_table_capacity,
                              prev->upstream.h3_settings.max_table_capacity,
                              NGX_HTTP_V3_MAX_TABLE_CAPACITY);

    ngx_conf_merge_uint_value(conf->upstream.h3_settings.max_concurrent_streams,
                              prev->upstream.h3_settings.max_concurrent_streams,
                              128);

    conf->upstream.h3_settings.max_blocked_streams =
                             conf->upstream.h3_settings.max_concurrent_streams;

    ngx_conf_merge_size_value(conf->upstream.quic.stream_buffer_size,
                              prev->upstream.quic.stream_buffer_size,
                              65536);

    conf->upstream.quic.max_concurrent_streams_bidi =
                             conf->upstream.h3_settings.max_concurrent_streams;

    ngx_conf_merge_value(conf->upstream.quic.gso_enabled,
                         prev->upstream.quic.gso_enabled,
                         0);

    ngx_conf_merge_uint_value(conf->upstream.quic.active_connection_id_limit,
                              prev->upstream.quic.active_connection_id_limit,
                              2);

    conf->upstream.quic.idle_timeout = conf->upstream.read_timeout;
    conf->upstream.quic.handshake_timeout = conf->upstream.connect_timeout;

    ngx_conf_merge_str_value(conf->upstream.quic.host_key,
                             prev->upstream.quic.host_key, "");


    if (conf->http_version == NGX_HTTP_VERSION_30) {
        if (ngx_http_v3_proxy_merge_quic(cf, conf, prev) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

#endif

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->proxy_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->location = prev->location;
        conf->vars = prev->vars;
#if (NGX_HTTP_V3)
        conf->host = prev->host;
#endif

        conf->proxy_lengths = prev->proxy_lengths;
        conf->proxy_values = prev->proxy_values;

#if (NGX_HTTP_SSL)
        conf->ssl = prev->ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->proxy_lengths))
    {
        clcf->handler = ngx_http_nwaf_proxy_handler;
    }

    if (conf->body_source.data == NULL) {
        conf->body_flushes = prev->body_flushes;
        conf->body_source = prev->body_source;
        conf->body_lengths = prev->body_lengths;
        conf->body_values = prev->body_values;
    }

    if (conf->body_source.data && conf->body_lengths == NULL) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &conf->body_source;
        sc.flushes = &conf->body_flushes;
        sc.lengths = &conf->body_lengths;
        sc.values = &conf->body_values;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_ptr_value(conf->headers_source, prev->headers_source, NULL);

    if (conf->headers_source == prev->headers_source
#if (NGX_HTTP_V3)
        /* H3 uses own set of headers, so do not inherit on version change */
        && !((conf->http_version == NGX_HTTP_VERSION_30
              || prev->http_version == NGX_HTTP_VERSION_30)
             && conf->http_version != prev->http_version)
#endif
       )
    {
        conf->headers = prev->headers;
#if (NGX_HTTP_CACHE)
        conf->headers_cache = prev->headers_cache;
#endif
        conf->host_set = prev->host_set;
    }

    proxy_headers = ngx_http_proxy_headers;

#if (NGX_HTTP_V3)
    if (conf->http_version == NGX_HTTP_VERSION_30) {
        proxy_headers = ngx_http_v3_proxy_headers;
    }
#endif

    rc = ngx_http_proxy_init_headers(cf, conf, &conf->headers, proxy_headers);

    if (rc != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#if (NGX_HTTP_CACHE)

    if (conf->upstream.cache) {

        proxy_headers = ngx_http_proxy_cache_headers;

#if (NGX_HTTP_V3)
        if (conf->http_version == NGX_HTTP_VERSION_30) {
            proxy_headers = ngx_http_v3_proxy_cache_headers;
        }
#endif

        rc = ngx_http_proxy_init_headers(cf, conf, &conf->headers_cache,
                                         proxy_headers);
        if (rc != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

#endif

    /*
     * special handling to preserve conf->headers in the "http" section
     * to inherit it to all servers
     */

    if (prev->headers.hash.buckets == NULL
        && conf->headers_source == prev->headers_source)
    {
        prev->headers = conf->headers;
#if (NGX_HTTP_CACHE)
        prev->headers_cache = conf->headers_cache;
#endif
        prev->host_set = conf->host_set;
    }

    return NGX_CONF_OK;
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_proxy_preserve_ssl_passwords(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev)
{
#if (NGX_HTTP_PROXY_MULTICERT)
    if (conf->ssl_certificates == NULL)
#else
    if (conf->ssl_certificate == NULL
        || conf->ssl_certificate->value.len == 0
        || conf->ssl_certificate_key == NULL)
#endif
    {
        return NGX_OK;
    }

#if (NGX_HTTP_PROXY_MULTICERT)
    if (conf->ssl_certificate_values == NULL
        || conf->ssl_certificate_key_values == NULL)
#else
    if (conf->ssl_certificate->lengths == NULL
        && conf->ssl_certificate_key->lengths == NULL)
#endif
    {
        if (conf->ssl_passwords && conf->ssl_passwords->pool == NULL) {
            /* un-preserve empty password list */
            conf->ssl_passwords = NULL;
        }

        return NGX_OK;
    }

    return ngx_http_upstream_preserve_ssl_passwords(cf, conf, prev);
}

#endif

static ngx_int_t
ngx_http_proxy_init_headers(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *conf,
    ngx_http_proxy_headers_t *headers, ngx_keyval_t *default_headers)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    ngx_uint_t                    i;
    ngx_array_t                   headers_names, headers_merged;
    ngx_keyval_t                 *src, *s, *h;
    ngx_hash_key_t               *hk;
    ngx_hash_init_t               hash;
    ngx_http_script_compile_t     sc;
    ngx_http_script_copy_code_t  *copy;

    if (headers->hash.buckets) {
        return NGX_OK;
    }

    if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&headers_merged, cf->temp_pool, 4, sizeof(ngx_keyval_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    headers->lengths = ngx_array_create(cf->pool, 64, 1);
    if (headers->lengths == NULL) {
        return NGX_ERROR;
    }

    headers->values = ngx_array_create(cf->pool, 512, 1);
    if (headers->values == NULL) {
        return NGX_ERROR;
    }

    if (conf->headers_source) {

        src = conf->headers_source->elts;
        for (i = 0; i < conf->headers_source->nelts; i++) {

            if (src[i].key.len == 4
                && ngx_strncasecmp(src[i].key.data, (u_char *) "Host", 4) == 0)
            {
                conf->host_set = 1;
            }

            s = ngx_array_push(&headers_merged);
            if (s == NULL) {
                return NGX_ERROR;
            }

            *s = src[i];
        }
    }

    h = default_headers;

    while (h->key.len) {

        src = headers_merged.elts;
        for (i = 0; i < headers_merged.nelts; i++) {
            if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = ngx_array_push(&headers_merged);
        if (s == NULL) {
            return NGX_ERROR;
        }

        *s = *h;

    next:

        h++;
    }


    src = headers_merged.elts;
    for (i = 0; i < headers_merged.nelts; i++) {

        hk = ngx_array_push(&headers_names);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = src[i].key;
        hk->key_hash = ngx_hash_key_lc(src[i].key.data, src[i].key.len);
        hk->value = (void *) 1;

        if (src[i].value.len == 0) {
            continue;
        }

        copy = ngx_array_push_n(headers->lengths,
                                sizeof(ngx_http_script_copy_code_t));
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = (ngx_http_script_code_pt) (void *)
                                                 ngx_http_script_copy_len_code;
        copy->len = src[i].key.len;

        size = (sizeof(ngx_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = ngx_array_push_n(headers->values, size);
        if (copy == NULL) {
            return NGX_ERROR;
        }

        copy->code = ngx_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
        ngx_memcpy(p, src[i].key.data, src[i].key.len);

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &headers->flushes;
        sc.lengths = &headers->lengths;
        sc.values = &headers->values;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_ERROR;
        }

        code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = ngx_array_push_n(headers->values, sizeof(uintptr_t));
        if (code == NULL) {
            return NGX_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;


    hash.hash = &headers->hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
}

static char * ngx_http_nwaf_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_proxy_loc_conf_t *plcf = conf;

    ngx_http_proxy_loc_conf_t *pplcf, *tpplcf;
    size_t                      add;
    u_short                     port;
    ngx_str_t                  *value, *url;
    ngx_url_t                   u;
    ngx_uint_t                  n;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_script_compile_t   sc;

    tpplcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);

    if (plcf->upstream.upstream || plcf->proxy_lengths) {
        return "is duplicate";
    }

    if (tpplcf->upstream.upstream || tpplcf->proxy_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_nwaf_proxy_handler;

    clcf->auto_redirect = 1;

    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &plcf->proxy_lengths;
        sc.values = &plcf->proxy_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

#if (NGX_HTTP_SSL)
        plcf->ssl = 1;
        tpplcf->ssl = 1;
#endif

        return NGX_CONF_OK;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;

    } else if (ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {

#if (NGX_HTTP_SSL)
        plcf->ssl = 1;

        add = 8;
        port = 443;
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "https protocol requires SSL support");
        return NGX_CONF_ERROR;
#endif

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

/*
    plcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (plcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }
*/

    tpplcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (tpplcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    plcf->vars.schema.len = add;
    plcf->vars.schema.data = url->data;
    plcf->vars.key_start = plcf->vars.schema;

#if (NGX_HTTP_V3)
    if (u.family != AF_UNIX) {

        if (u.no_port) {
            plcf->host = u.host;

        } else {
            plcf->host.len = u.host.len + 1 + u.port_text.len;
            plcf->host.data = u.host.data;
        }

    } else {
        ngx_str_set(&plcf->host, "localhost");
    }
#endif

//    ngx_http_proxy_set_vars(&u, &plcf->vars);

    tpplcf->vars.schema.len = add;
    tpplcf->vars.schema.data = url->data;
    tpplcf->vars.key_start = plcf->vars.schema;

#if (NGX_HTTP_V3)
    if (u.family != AF_UNIX) {

        if (u.no_port) {
            tpplcf->host = u.host;

        } else {
            tpplcf->host.len = u.host.len + 1 + u.port_text.len;
            tpplcf->host.data = u.host.data;
        }

    } else {
        ngx_str_set(&tpplcf->host, "localhost");
    }
#endif

    ngx_http_proxy_set_vars(&u, &tpplcf->vars);

    plcf->location = clcf->name;
    tpplcf->location = clcf->name;

    if (clcf->named
#if (NGX_PCRE)
        || clcf->regex
#endif
        || clcf->noname
        || clcf->combined != NULL)
    {
        if (plcf->vars.uri.len) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_pass\" cannot have URI part in "
                               "a location specified with a regex, "
                               "inside a named location, "
                               "inside a combined location, "
                               "inside an \"if\" statement, "
                               "or inside a \"limit_except\" block");
            return NGX_CONF_ERROR;
        }

        plcf->location.len = 0;
    }

    plcf->url = *url;

    if (clcf->named
#if (NGX_PCRE)
        || clcf->regex
#endif
        || clcf->noname
        || clcf->combined != NULL)
    {
        if (tpplcf->vars.uri.len) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"proxy_pass\" cannot have URI part in "
                               "a location specified with a regex, "
                               "inside a named location, "
                               "inside a combined location, "
                               "inside an \"if\" statement, "
                               "or inside a \"limit_except\" block");
            return NGX_CONF_ERROR;
        }

        tpplcf->location.len = 0;
    }

    tpplcf->url = *url;

    pplcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_proxy_module);

    if (ngx_http_waf_ws_merge_loc_conf(cf, pplcf, plcf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "error merging location %V", &(plcf->location));
    }

    return NGX_CONF_OK;
}

/*
static char *
ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"proxy_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"proxy_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}

*/
#if (NGX_HTTP_SSL)
/*
static char *
ngx_http_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NGX_CONF_OK;
#endif
}*/


static ngx_int_t
ngx_http_proxy_merge_ssl(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *conf,
    ngx_http_proxy_loc_conf_t *prev)
{
    ngx_uint_t  preserve;

    if (conf->ssl_protocols == 0
        && conf->ssl_ciphers.data == NULL
#if (NGX_HTTP_PROXY_MULTICERT)
        && conf->upstream.ssl_certificates == NGX_CONF_UNSET_PTR
        && conf->upstream.ssl_certificate_keys == NGX_CONF_UNSET_PTR
#else
        && conf->upstream.ssl_certificate == NGX_CONF_UNSET_PTR
        && conf->upstream.ssl_certificate_key == NGX_CONF_UNSET_PTR
#endif
        && conf->upstream.ssl_passwords == NGX_CONF_UNSET_PTR
        && conf->upstream.ssl_verify == NGX_CONF_UNSET
        && conf->ssl_verify_depth == NGX_CONF_UNSET_UINT
        && conf->ssl_trusted_certificate.data == NULL
        && conf->ssl_crl.data == NULL
        && conf->upstream.ssl_session_reuse == NGX_CONF_UNSET
#if (NGX_HAVE_NTLS)
        && conf->upstream.ssl_ntls == NGX_CONF_UNSET
#endif
        && conf->ssl_conf_commands == NGX_CONF_UNSET_PTR)
    {
        if (prev->upstream.ssl) {
            conf->upstream.ssl = prev->upstream.ssl;
            return NGX_OK;
        }

        preserve = 1;

    } else {
        preserve = 0;
    }

    conf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (conf->upstream.ssl == NULL) {
        return NGX_ERROR;
    }

    conf->upstream.ssl->log = cf->log;

    /*
     * special handling to preserve conf->upstream.ssl
     * in the "http" section to inherit it to all servers
     */

    if (preserve) {
        prev->upstream.ssl = conf->upstream.ssl;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_set_ssl(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *plcf)
{
    ngx_ssl_t           *ssl;
    ngx_pool_cleanup_t  *cln;

    if (plcf->upstream.ssl->ctx) {
        return NGX_OK;
    }

    if (ngx_ssl_create(plcf->upstream.ssl, plcf->ssl_protocols, NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_HTTP_V3 && NGX_QUIC_OPENSSL_COMPAT)
    if (ngx_quic_compat_init(cf, plcf->upstream.ssl->ctx) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(plcf->upstream.ssl);
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = plcf->upstream.ssl;

    if (ngx_ssl_ciphers(cf, plcf->upstream.ssl, &plcf->ssl_ciphers, 0)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

#if (NGX_HTTP_PROXY_MULTICERT)

    if (plcf->upstream.ssl_certificates
        && plcf->upstream.ssl_certificate_values == NULL)
    {
        if (ngx_ssl_certificates(cf, plcf->upstream.ssl,
                                 plcf->upstream.ssl_certificates,
                                 plcf->upstream.ssl_certificate_keys,
                                 plcf->upstream.ssl_passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

#else

    if (plcf->upstream.ssl_certificate
        && plcf->upstream.ssl_certificate->value.len)
    {
        if (plcf->upstream.ssl_certificate_key == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &plcf->upstream.ssl_certificate->value);
            return NGX_ERROR;
        }

        if (plcf->upstream.ssl_certificate->lengths == NULL
            && plcf->upstream.ssl_certificate_key->lengths == NULL)
        {
            if (ngx_ssl_certificate(cf, plcf->upstream.ssl,
                                    &plcf->upstream.ssl_certificate->value,
                                    &plcf->upstream.ssl_certificate_key->value,
                                    plcf->upstream.ssl_passwords)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

#endif

    if (plcf->upstream.ssl_verify) {
        if (plcf->ssl_trusted_certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return NGX_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, plcf->upstream.ssl,
                                        &plcf->ssl_trusted_certificate,
                                        plcf->ssl_verify_depth)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_ssl_crl(cf, plcf->upstream.ssl, &plcf->ssl_crl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_ssl_client_session_cache(cf, plcf->upstream.ssl,
                                     plcf->upstream.ssl_session_reuse)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_ssl_conf_commands(cf, plcf->upstream.ssl, plcf->ssl_conf_commands)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (plcf->upstream.ssl_keylog_file) {
        ssl = plcf->upstream.ssl;

        ssl->keylog_file = plcf->upstream.ssl_keylog_file;
        SSL_CTX_set_keylog_callback(ssl->ctx, ngx_ssl_keylogger);
    }

    return NGX_OK;
}


#if (NGX_HTTP_PROXY_MULTICERT)

static ngx_int_t
ngx_http_proxy_compile_certificates(ngx_conf_t *cf,
    ngx_http_proxy_loc_conf_t *plcf)
{
    ngx_str_t                cert;
    ngx_http_ssl_srv_conf_t  scf;

    cert = *((ngx_str_t *) plcf->upstream.ssl_certificates->elts);
#if (NGX_HAVE_NTLS)
    ngx_ssl_ntls_prefix_strip(&cert);
#endif

    if (plcf->upstream.ssl_certificates->nelts == 1 && cert.len == 0) {
        /* single empty certificate: cancel certificate loading */

        plcf->upstream.ssl_certificates = NULL;
        plcf->upstream.ssl_certificate_values = NULL;
        plcf->upstream.ssl_certificate_key_values = NULL;

        return NGX_OK;
    }

    if (plcf->upstream.ssl_certificate_keys == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no \"proxy_ssl_certificate_key\" is defined "
                      "for certificate \"%V\"", &cert);
        return NGX_ERROR;
    }

    if (plcf->upstream.ssl_certificate_keys->nelts
        < plcf->upstream.ssl_certificates->nelts)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "number of \"proxy_ssl_certificate_key\" does not "
                      "correspond \"proxy_ssl_ssl_certificate\"");
        return NGX_ERROR;
    }

    ngx_memzero(&scf, sizeof(ngx_http_ssl_srv_conf_t));

    scf.certificates = plcf->upstream.ssl_certificates;
    scf.certificate_keys = plcf->upstream.ssl_certificate_keys;
    scf.passwords = plcf->upstream.ssl_passwords;

    if (ngx_http_ssl_compile_certificates(cf, &scf) != NGX_OK) {
        return NGX_ERROR;
    }

    plcf->upstream.ssl_passwords = scf.passwords;
    plcf->upstream.ssl_certificate_values = scf.certificate_values;
    plcf->upstream.ssl_certificate_key_values = scf.certificate_key_values;

    return NGX_OK;
}

#endif

#endif

static void
ngx_http_proxy_set_vars(ngx_url_t *u, ngx_http_proxy_vars_t *v)
{
    if (u->family != AF_UNIX) {

        if (u->no_port || u->port == u->default_port) {

            v->host_header = u->host;

            if (u->default_port == 80) {
                ngx_str_set(&v->port, "80");

            } else {
                ngx_str_set(&v->port, "443");
            }

        } else {
            v->host_header.len = u->host.len + 1 + u->port_text.len;
            v->host_header.data = u->host.data;
            v->port = u->port_text;
        }

        v->key_start.len += v->host_header.len;

    } else {
        ngx_str_set(&v->host_header, "localhost");
        ngx_str_null(&v->port);
        v->key_start.len += sizeof("unix:") - 1 + u->host.len + 1;
    }

    v->uri = u->uri;
}



#if (NGX_HTTP_V3)

static ngx_int_t
ngx_http_v3_proxy_merge_quic(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *conf,
    ngx_http_proxy_loc_conf_t *prev)
{
    if ((conf->upstream.upstream || conf->proxy_lengths)
        && (conf->ssl == 0 || conf->upstream.ssl == NULL))
    {
        /* we have proxy_pass, http/3 and no ssl - this isn't going to work */

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http3 proxy requires ssl configuration "
                           "and https:// scheme");
        return NGX_ERROR;
    }


    if (conf->upstream.quic.host_key.len == 0) {

        conf->upstream.quic.host_key.len = NGX_QUIC_DEFAULT_HOST_KEY_LEN;
        conf->upstream.quic.host_key.data = ngx_palloc(cf->pool,
                                             conf->upstream.quic.host_key.len);

        if (conf->upstream.quic.host_key.data == NULL) {
            return NGX_ERROR;
        }

        if (RAND_bytes(conf->upstream.quic.host_key.data,
                       NGX_QUIC_DEFAULT_HOST_KEY_LEN)
            <= 0)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_quic_derive_key(cf->log, "av_token_key",
                            &conf->upstream.quic.host_key,
                            &ngx_http_v3_proxy_quic_salt,
                            conf->upstream.quic.av_token_key,
                            NGX_QUIC_AV_KEY_LEN)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_quic_derive_key(cf->log, "sr_token_key",
                            &conf->upstream.quic.host_key,
                            &ngx_http_v3_proxy_quic_salt,
                            conf->upstream.quic.sr_token_key,
                            NGX_QUIC_SR_KEY_LEN)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    conf->upstream.quic.ssl = conf->upstream.ssl;

#if (NGX_HTTP_CACHE)

        if (conf->upstream.cache
            && conf->upstream.h3_settings.max_table_capacity)
        {
            if (conf->max_table_capacity_set) {

                /* the setting is present in config file, refuse to accept it */
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "http3 cache does not work with dynamic table");

                return NGX_ERROR;
            }

            /* the value is from defaults, disable dynamic table */
            conf->upstream.h3_settings.max_table_capacity = 0;
        }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_create_request(ngx_http_request_t *r)
{
    ngx_buf_t                  *b;
    ngx_chain_t                *cl, *body, *out;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_v3_proxy_ctx_t     v3c;
    ngx_http_proxy_headers_t   *headers;
    ngx_http_proxy_loc_conf_t  *plcf;

    /*
     * HTTP/3 Request:
     *
     * HEADERS FRAME
     *    :method:
     *    :scheme:
     *    :path:
     *    :authority:
     *     proxy headers[]
     *     client headers[]
     *
     * DATA FRAME
     *    body
     *
     * HEADERS FRAME
     *    trailers[]
     */

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

#if (NGX_HTTP_CACHE)
    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif

    ngx_memzero(&v3c, sizeof(ngx_http_v3_proxy_ctx_t));

    ngx_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);

    v3c.headers = headers;

    v3c.n = ngx_http_v3_encode_field_section_prefix(NULL, 0, 0, 0);

    /* calculate lengths */

    ngx_http_v3_proxy_encode_method(r, &v3c, NULL);

    v3c.n += ngx_http_v3_encode_field_ri(NULL, 0,
                                         NGX_HTTP_V3_HEADER_SCHEME_HTTPS);

    if (ngx_http_v3_proxy_encode_path(r, &v3c, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_encode_authority(r, &v3c, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_body_length(r, &v3c) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_encode_headers(r, &v3c, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    /* generate HTTP/3 request of known size */

    b = ngx_create_temp_buf(r->pool, v3c.n);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_field_section_prefix(b->last,
                                                                 0, 0, 0);

    if (ngx_http_v3_proxy_encode_method(r, &v3c, b) != NGX_OK) {
        return NGX_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                              NGX_HTTP_V3_HEADER_SCHEME_HTTPS);

    if (ngx_http_v3_proxy_encode_path(r, &v3c, b) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_encode_authority(r, &v3c, b) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_v3_proxy_encode_headers(r, &v3c, b) != NGX_OK) {
        return NGX_ERROR;
    }

    out = ngx_http_v3_create_headers_frame(r, b);
    if (out == NGX_CHAIN_ERROR) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (r->request_body_no_buffering || ctx->internal_chunked) {
        u->output.output_filter = ngx_http_v3_proxy_body_output_filter;
        u->output.filter_ctx = r;

    } else if (ctx->internal_body_length != -1) {

        body = ngx_http_v3_proxy_encode_body(r, &v3c);
        if (body == NGX_CHAIN_ERROR) {
            return NGX_ERROR;
        }

        body = ngx_http_v3_create_data_frame(r, body,
                                             ctx->internal_body_length);
        if (body == NGX_CHAIN_ERROR) {
            return NGX_ERROR;
        }

        for (cl = out; cl->next; cl = cl->next) { /* void */ }
        cl->next = body;
    }

    /* TODO: trailers */

    u->request_bufs = out;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_v3_create_headers_frame(ngx_http_request_t *r, ngx_buf_t *hbuf)
{
    ngx_buf_t    *b;
    size_t        n, len;
    ngx_chain_t  *cl, *head;

    n = hbuf->last - hbuf->pos;

    len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_HEADERS)
          + ngx_http_v3_encode_varlen_int(NULL, n);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_CHAIN_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                    NGX_HTTP_V3_FRAME_HEADERS);
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, n);

    /* mark our header buffers to distinguish them in non-buffered filter */
    b->tag = (ngx_buf_tag_t) &ngx_http_v3_create_headers_frame;
    hbuf->tag = (ngx_buf_tag_t) &ngx_http_v3_create_headers_frame;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_CHAIN_ERROR;
    }

    cl->buf = b;
    head = cl;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_CHAIN_ERROR;
    }

    cl->buf = hbuf;
    cl->next = NULL;

    head->next = cl;

    return head;
}


static ngx_chain_t *
ngx_http_v3_create_data_frame(ngx_http_request_t *r, ngx_chain_t *body,
    size_t size)
{
    size_t        len;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    len = ngx_http_v3_encode_varlen_int(NULL, NGX_HTTP_V3_FRAME_DATA)
          + ngx_http_v3_encode_varlen_int(NULL, size);

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_CHAIN_ERROR;
    }

    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last,
                                                       NGX_HTTP_V3_FRAME_DATA);
    b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, size);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_CHAIN_ERROR;
    }

    cl->buf = b;
    cl->next = body;

    return cl;
}


static ngx_inline ngx_uint_t
ngx_http_v3_map_method(ngx_uint_t method)
{
    switch (method) {
    case NGX_HTTP_GET:
        return NGX_HTTP_V3_HEADER_METHOD_GET;
    case NGX_HTTP_HEAD:
        return NGX_HTTP_V3_HEADER_METHOD_HEAD;
    case NGX_HTTP_POST:
        return NGX_HTTP_V3_HEADER_METHOD_POST;
    case NGX_HTTP_PUT:
        return NGX_HTTP_V3_HEADER_METHOD_PUT;
    case NGX_HTTP_DELETE:
        return NGX_HTTP_V3_HEADER_METHOD_DELETE;
    case NGX_HTTP_OPTIONS:
        return NGX_HTTP_V3_HEADER_METHOD_OPTIONS;
    default:
        return 0;
    }
}


static ngx_int_t
ngx_http_v3_proxy_encode_method(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b)
{
    size_t                      n;
    ngx_str_t                   method;
    ngx_uint_t                  v3method;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    static ngx_str_t ngx_http_v3_header_method = ngx_string(":method");

    if (b == NULL) {
        /* calculate length */

        plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
        ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

        method.len = 0;
        n = 0;

        u = r->upstream;

        if (plcf->method) {
            if (ngx_http_complex_value(r, plcf->method, &method) != NGX_OK) {
                return NGX_ERROR;
            }

            u->method = method;

        } else {
            method = u->method;
        }

        if (method.len == 4
            && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
        {
            ctx->head = 1;
        }

        if (method.len) {
            n = ngx_http_v3_encode_field_l(NULL, &ngx_http_v3_header_method,
                                           &method);
        } else {

            v3method = ngx_http_v3_map_method(r->method);

            if (v3method) {
                n = ngx_http_v3_encode_field_ri(NULL, 0, v3method);

            } else {
                n = ngx_http_v3_encode_field_l(NULL,
                                               &ngx_http_v3_header_method,
                                               &r->method_name);
            }
        }

        v3c->n += n;
        v3c->method = method;

        return NGX_OK;
    }

    method = v3c->method;

    if (method.len) {
        b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                                    &ngx_http_v3_header_method,
                                                    &method);
    } else {

        v3method = ngx_http_v3_map_method(r->method);

        if (v3method) {
            b->last = (u_char *) ngx_http_v3_encode_field_ri(b->last, 0,
                                                             v3method);
        } else {
            b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                                    &ngx_http_v3_header_method,
                                                    &r->method_name);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_encode_authority(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b)
{
    size_t                      n;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    if (plcf->host_set) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (b == NULL) {

        n = ngx_http_v3_encode_field_lri(NULL, 0, NGX_HTTP_V3_HEADER_AUTHORITY,
                                         NULL, ctx->host.len);
        v3c->n += n;

        return NGX_OK;
    }

    b->last = (u_char *) ngx_http_v3_encode_field_lri(b->last, 0,
                  NGX_HTTP_V3_HEADER_AUTHORITY, ctx->host.data, ctx->host.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \":authority: %V\"", &ctx->host);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_encode_path(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b)
{
    size_t                      n;
    u_char                     *p;
    size_t                      loc_len;
    size_t                      uri_len;
    ngx_str_t                   tmp;
    uintptr_t                   escape;
    ngx_uint_t                  unparsed_uri;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_proxy_loc_conf_t  *plcf;

    static ngx_str_t ngx_http_v3_path = ngx_string(":path");

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (b == NULL) {

        escape = 0;
        uri_len = 0;
        loc_len = 0;
        unparsed_uri = 0;

        if (plcf->proxy_lengths && ctx->vars.uri.len) {
            uri_len = ctx->vars.uri.len;

        } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
            unparsed_uri = 1;
            uri_len = r->unparsed_uri.len;

        } else {
            loc_len = (r->valid_location && ctx->vars.uri.len) ?
                                                        plcf->location.len : 0;

            if (r->quoted_uri || r->internal) {
               escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                           r->uri.len - loc_len,
                                           NGX_ESCAPE_URI);
            }

            uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
                      + sizeof("?") - 1 + r->args.len;
        }

        if (uri_len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "zero length URI to proxy");
            return NGX_ERROR;
        }

        tmp.data = NULL;
        tmp.len = uri_len;

        n = ngx_http_v3_encode_field_l(NULL, &ngx_http_v3_path, &tmp);

        v3c->n += n;

        v3c->escape = escape;
        v3c->uri_len = uri_len;
        v3c->loc_len = loc_len;
        v3c->unparsed_uri = unparsed_uri;

        return NGX_OK;
    }

    u = r->upstream;

    escape = v3c->escape;
    uri_len = v3c->uri_len;
    loc_len = v3c->loc_len;
    unparsed_uri = v3c->unparsed_uri;

    p = ngx_palloc(r->pool, uri_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    u->uri.data = p;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        p = ngx_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);

    } else if (unparsed_uri) {
        p = ngx_copy(p, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            p = ngx_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
        }

        if (escape) {
            ngx_escape_uri(p, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            p += r->uri.len - loc_len + escape;

        } else {
            p = ngx_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = ngx_copy(p, r->args.data, r->args.len);
        }
    }

    u->uri.len = p - u->uri.data;

    b->last = (u_char *) ngx_http_v3_encode_field_l(b->last, &ngx_http_v3_path,
                                                    &u->uri);
    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_body_length(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c)
{
    size_t                        body_len, n;
    ngx_http_proxy_ctx_t         *ctx;
    ngx_http_script_engine_t     *le;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    le = &v3c->le;

    n = 0;

    if (plcf->body_lengths) {
        le->ip = plcf->body_lengths->elts;
        le->request = r;
        le->flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le->ip) {
            lcode = *(ngx_http_script_len_code_pt *) le->ip;
            body_len += lcode(le);
        }

        ctx->internal_body_length = body_len;
        n += body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->internal_body_length = -1;
        ctx->internal_chunked = 1;

    } else {
        ctx->internal_body_length = r->headers_in.content_length_n;
        n = r->headers_in.content_length_n;
    }

    v3c->n += n;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_v3_proxy_encode_body(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c)
{
    ngx_buf_t                  *b;
    ngx_chain_t                *body, *cl, *prev, *head;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_ctx_t       *ctx;
    ngx_http_script_code_pt     code;
    ngx_http_script_engine_t   *e;
    ngx_http_proxy_loc_conf_t  *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    u = r->upstream;

    /* body set in configuration */

    if (plcf->body_values) {

        e = &v3c->e;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        b = ngx_create_temp_buf(r->pool, ctx->internal_body_length);
        if (b == NULL) {
            return NGX_CHAIN_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        e->ip = plcf->body_values->elts;
        e->pos = b->last;
        e->skip = 0;

        while (*(uintptr_t *) e->ip) {
            code = *(ngx_http_script_code_pt *) e->ip;
            code((ngx_http_script_engine_t *) e);
        }

        b->last = e->pos;

        return cl;
    }

    if (!plcf->upstream.pass_request_body) {
        return NULL;
    }

    /* body from client */

    cl = NULL;
    head = NULL;
    prev = NULL;

    body = u->request_bufs;

    while (body) {

        b = ngx_alloc_buf(r->pool);
        if (b == NULL) {
            return NGX_CHAIN_ERROR;
        }

        ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_CHAIN_ERROR;
        }

        cl->buf = b;

        if (prev) {
            prev->next = cl;

        } else {
            head = cl;
        }

        prev = cl;
        body = body->next;
    }

    if (cl) {
        cl->next = NULL;
    }

    return head;
}


static ngx_int_t
ngx_http_v3_proxy_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                  size;
    u_char                *chunk;
    size_t                 len;
    ngx_buf_t             *b;
    ngx_int_t              rc;
    ngx_chain_t           *out, *cl, *tl, **ll, **fl;
    ngx_http_proxy_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "v3 proxy output filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {

        /* buffers contain v3-encoded headers frame, pass it as is */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "v3 proxy output header");

        ctx->header_sent = 1;

        for ( ;; ) {

            if (in->buf->tag
                != (ngx_buf_tag_t) &ngx_http_v3_create_headers_frame)
            {
                break;
            }

            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = in->buf;
            *ll = tl;
            ll = &tl->next;

            in = in->next;

            if (in == NULL) {
                tl->next = NULL;
                goto out;
            }
        }
    }

    size = 0;
    fl = ll;

    for (cl = in; cl; cl = cl->next) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "v3 proxy output chunk: %O", ngx_buf_size(cl->buf));

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || ngx_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = ngx_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NGX_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }
    }

    if (size) {

        tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NGX_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            len = ngx_http_v3_encode_varlen_int(NULL,
                                                 NGX_HTTP_V3_FRAME_DATA)
                   + 8 /* max varlen int length*/;

            chunk = ngx_palloc(r->pool, len);
            if (chunk == NULL) {
                return NGX_ERROR;
            }
            b->start = chunk;
            b->pos = b->start;
            b->end = chunk + len;
        }

        b->tag = (ngx_buf_tag_t) &ngx_http_v3_proxy_body_output_filter;
        b->memory = 0;
        b->temporary = 1;

        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->start,
                                                       NGX_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) ngx_http_v3_encode_varlen_int(b->last, size);

        tl->next = *fl;
        *fl = tl;
    }

    *ll = NULL;

out:

    rc = ngx_chain_writer(&r->upstream->writer, out);

    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                        (ngx_buf_tag_t) &ngx_http_v3_proxy_body_output_filter);

    return rc;
}


static ngx_int_t
ngx_http_v3_proxy_encode_headers(ngx_http_request_t *r,
    ngx_http_v3_proxy_ctx_t *v3c, ngx_buf_t *b)
{
    u_char                       *p, *start;
    size_t                        key_len, val_len, hlen, max_head, n;
    ngx_str_t                     tmp, tmpv;
    ngx_uint_t                    i;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_script_code_pt       code;
    ngx_http_proxy_headers_t     *headers;
    ngx_http_script_engine_t     *le;
    ngx_http_script_engine_t     *e;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    headers = v3c->headers;
    le = &v3c->le;
    e = &v3c->e;

    if (b == NULL) {

        le->ip = headers->lengths->elts;
        le->request = r;
        le->flushed = 1;

        n = 0;
        max_head = 0;

        while (*(uintptr_t *) le->ip) {

            lcode = *(ngx_http_script_len_code_pt *) le->ip;
            key_len = lcode(le);

            for (val_len = 0; *(uintptr_t *) le->ip; val_len += lcode(le)) {
                lcode = *(ngx_http_script_len_code_pt *) le->ip;
            }
            le->ip += sizeof(uintptr_t);

            if (val_len == 0) {
                continue;
            }

            tmp.data = NULL;
            tmp.len = key_len;

            tmpv.data = NULL;
            tmpv.len = val_len;

            hlen = key_len + val_len;
            if (hlen > max_head) {
                max_head = hlen;
            }

            n += ngx_http_v3_encode_field_l(NULL, &tmp, &tmpv);
        }

        if (plcf->upstream.pass_request_headers) {
            part = &r->headers_in.headers.part;
            header = part->elts;

            for (i = 0; /* void */; i++) {

                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    header = part->elts;
                    i = 0;
                }

                if (ngx_hash_find(&headers->hash, header[i].hash,
                                  header[i].lowcase_key, header[i].key.len))
                {
                    continue;
                }

                n += ngx_http_v3_encode_field_l(NULL, &header[i].key,
                                                &header[i].value);
            }
        }

        v3c->n += n;
        v3c->max_head = max_head;

        return NGX_OK;
    }

    max_head = v3c->max_head;

    p = ngx_pnalloc(r->pool, max_head);
    if (p == NULL) {
        return NGX_ERROR;
    }

    start = p;

    ngx_memzero(e, sizeof(ngx_http_script_engine_t));

    e->ip = headers->values->elts;
    e->pos = p;
    e->request = r;
    e->flushed = 1;

    le->ip = headers->lengths->elts;

    tmp.data = p;
    tmp.len = 0;

    tmpv.data = NULL;
    tmpv.len = 0;

    while (*(uintptr_t *) le->ip) {

        lcode = *(ngx_http_script_len_code_pt *) le->ip;
        (void) lcode(le);

        for (val_len = 0; *(uintptr_t *) le->ip; val_len += lcode(le)) {
            lcode = *(ngx_http_script_len_code_pt *) le->ip;
        }
        le->ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e->skip = 1;

            while (*(uintptr_t *) e->ip) {
                code = *(ngx_http_script_code_pt *) e->ip;
                code((ngx_http_script_engine_t *) e);
            }
            e->ip += sizeof(uintptr_t);

            e->skip = 0;

            continue;
        }

        code = *(ngx_http_script_code_pt *) e->ip;
        code((ngx_http_script_engine_t *) e);

        tmp.len = e->pos - tmp.data;
        tmpv.data = e->pos;

        while (*(uintptr_t *) e->ip) {
            code = *(ngx_http_script_code_pt *) e->ip;
            code((ngx_http_script_engine_t *) e);
        }
        e->ip += sizeof(uintptr_t);

        tmpv.len = e->pos - tmpv.data;

        b->last = (u_char *) ngx_http_v3_encode_field_l(b->last, &tmp, &tmpv);

        tmp.data = p;
        tmp.len = 0;

        tmpv.data = NULL;
        tmpv.len = 0;
        e->pos = start;
    }

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            b->last = (u_char *) ngx_http_v3_encode_field_l(b->last,
                                                            &header[i].key,
                                                            &header[i].value);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_reinit_request(ngx_http_request_t *r)
{
    ngx_http_proxy_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    r->upstream->process_header = ngx_http_v3_proxy_process_status_line;
    r->upstream->pipe->input_filter = ngx_http_v3_proxy_copy_filter;
    r->upstream->input_filter = ngx_http_v3_proxy_non_buffered_copy_filter;

    r->state = 0;
    ngx_memzero(ctx->v3_parse, sizeof(ngx_http_v3_parse_t));

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_process_status_line(ngx_http_request_t *r)
{
    u_char                       *p;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_ctx_t         *ctx;
    ngx_http_v3_session_t        *h3c;
    ngx_http_v3_parse_headers_t  *st;
#if (NGX_HTTP_CACHE)
    ngx_connection_t              stub;
    ngx_http_conf_ctx_t           conf_ctx;
    ngx_http_connection_t         hc;
#endif

    u = r->upstream;
    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_v3_proxy_process_status_line");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

#if (NGX_HTTP_CACHE)
    if (r->cache && c == NULL) {
        /* QPACK table checks require session object */

        ngx_memzero(&hc, sizeof(ngx_http_connection_t));
        ngx_memzero(&stub, sizeof(ngx_connection_t));

        conf_ctx.main_conf = r->main_conf;
        conf_ctx.srv_conf = r->srv_conf;
        conf_ctx.loc_conf = r->loc_conf;

        hc.conf_ctx = &conf_ctx;

        c = &stub;

        c->data = &hc;
        c->log = r->connection->log;
        c->pool = r->connection->pool;

        if (ngx_http_v3_init_session(c) != NGX_OK) {
            return NGX_ERROR;
        }
    }
#endif

    h3c = ngx_http_v3_get_session(c);

    if (ngx_list_init(&u->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->v3_parse->header_limit = u->conf->bufs.size * u->conf->bufs.num;

    st = &ctx->v3_parse->headers;
    b = &u->buffer;

    for ( ;; ) {

       p = b->pos;

       rc = ngx_http_v3_parse_headers(c, st, b);
       if (rc > 0) {

            if (h3c && c->quic) {
                ngx_quic_reset_stream(c, rc);
            }
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header rc:%i", rc);
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (h3c) {
            h3c->total_bytes += b->pos - p;
        }

        if (rc == NGX_BUSY) {
            /* HTTP/3 blocked */
            return NGX_AGAIN;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* rc == NGX_OK || rc == NGX_DONE */

        if (h3c) {
            h3c->payload_bytes += ngx_http_v3_encode_field_l(NULL,
                                                   &st->field_rep.field.name,
                                                   &st->field_rep.field.value);
        }

        if (ngx_http_v3_proxy_process_header(r, &st->field_rep.field.name,
                                             &st->field_rep.field.value)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (rc == NGX_DONE) {
            return ngx_http_v3_proxy_headers_done(r);
        }
    }

    return NGX_OK;
}


static void
ngx_http_v3_proxy_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http v3 proxy request");
}


static void
ngx_http_v3_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http v3 proxy request");
}


static ngx_int_t
ngx_http_v3_proxy_process_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    size_t                          len;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_ctx_t           *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    /* based on ngx_http_v3_process_header() */

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    u = r->upstream;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    len = name->len + value->len;

    if (len > ctx->v3_parse->header_limit) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent too large header");
        return NGX_ERROR;
    }

    ctx->v3_parse->header_limit -= len;

    if (name->len && name->data[0] == ':') {
        return ngx_http_v3_proxy_process_pseudo_header(r, name, value);
    }

    h = ngx_list_push(&u->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    /*
     * HTTP/3 parsing used peer->connection.pool, which might be destroyed,
     * at the moment when r->headers_out are used;
     * thus allocate from r->pool and copy header name/value
     */
    h->key.len = name->len;
    h->key.data = ngx_pnalloc(r->pool, name->len + 1);
    if (h->key.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(h->key.data, name->data, name->len);
    h->key.data[h->key.len] = 0;

    h->value.len = value->len;
    h->value.data = ngx_pnalloc(r->pool, value->len + 1);
    if (h->value.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(h->value.data, value->data, value->len);
    h->value.data[h->value.len] = 0;

    h->lowcase_key = h->key.data;
    h->hash = ngx_hash_key(h->key.data, h->key.len);

    hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \"%V: %V\"", name, value);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_headers_done(ngx_http_request_t *r)
{
    ngx_table_elt_t         *h;
    ngx_connection_t        *c;
    ngx_http_proxy_ctx_t    *ctx;
    ngx_http_upstream_t     *u;

    /*
     * based on NGX_HTTP_PARSE_HEADER_DONE in ngx_http_proxy_process_header()
     * and ngx_http_v3_process_request_header()
     */

    u = r->upstream;
    c = u->peer.connection;

    /*
     * if no "Server" and "Date" in header line,
     * then add the special empty headers
     */

    if (u->headers_in.server == NULL) {
        h = ngx_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

        ngx_str_set(&h->key, "Server");
        ngx_str_null(&h->value);
        h->lowcase_key = (u_char *) "server";
        h->next = NULL;
    }

    if (u->headers_in.date == NULL) {
        h = ngx_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

        ngx_str_set(&h->key, "Date");
        ngx_str_null(&h->value);
        h->lowcase_key = (u_char *) "date";
        h->next = NULL;
    }

    if (ngx_http_v3_proxy_construct_cookie_header(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (u->headers_in.content_length) {
        u->headers_in.content_length_n =
                            ngx_atoof(u->headers_in.content_length->value.data,
                                      u->headers_in.content_length->value.len);

        if (u->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent invalid \"Content-Length\" header");
            return NGX_ERROR;
        }

    } else {
        u->headers_in.content_length_n = -1;
    }

    /*
     * set u->keepalive if response has no body; this allows to keep
     * connections alive in case of r->header_only or X-Accel-Redirect
     */

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->head
        || (!u->headers_in.chunked
            && u->headers_in.content_length_n == 0))
    {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_process_pseudo_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_int_t             status;
    ngx_str_t            *status_line;
    ngx_http_upstream_t  *u;

    /* based on ngx_http_v3_process_pseudo_header() */

    /*
     * RFC 9114, 4.3.2
     *
     * For responses, a single ":status" pseudo-header field
     * is defined that carries the HTTP status code;
     */

    u = r->upstream;

    if (name->len == 7 && ngx_strncmp(name->data, ":status", 7) == 0) {

        if (u->state && u->state->status
#if (NGX_HTTP_CACHE)
            && !r->cached
#endif
        ) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "upstream sent duplicate \":status\" header");
            return NGX_ERROR;
        }

        if (value->len == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "upstream sent empty \":status\" header");
            return NGX_ERROR;
        }

        if (value->len < 3) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "upstream sent too short \":status\" header");
            return NGX_ERROR;
        }

        status = ngx_atoi(value->data, 3);

        if (status == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid status \"%V\"", value);
            return NGX_ERROR;
        }

        if (u->state && u->state->status == 0) {
            u->state->status = status;
        }

        u->headers_in.status_n = status;

        status_line = ngx_http_status_line(status);
        if (status_line) {
            u->headers_in.status_line = *status_line;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http v3 proxy status %ui \"%V\"",
                       u->headers_in.status_n, &u->headers_in.status_line);

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "upstream sent unexpected pseudo-header \"%V\"", name);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_v3_proxy_input_filter_init(void *data)
{
    ngx_http_request_t  *r = data;

    ngx_http_upstream_t   *u;
    ngx_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http v3 proxy filter init s:%ui h:%d c:%d l:%O",
                   u->headers_in.status_n, ctx->head, u->headers_in.chunked,
                   u->headers_in.content_length_n);

    /* as per RFC2616, 4.4 Message Length */

    /* HTTP/3 is 'chunked-like' by default, filter is already set */

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;

    } else {
        /* content length or connection close */

        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    /* TODO: check flag handling in HTTP/3 */
    u->keepalive = 1;

    return NGX_OK;
}


/* reading non-buffered body from V3 upstream */
static ngx_int_t
ngx_http_v3_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t  *r = data;

    size_t                     size, len;
    ngx_int_t                  rc;
    ngx_buf_t                 *b, *buf;
    ngx_chain_t               *cl, **ll;
    ngx_http_upstream_t       *u;
    ngx_http_proxy_ctx_t      *ctx;
    ngx_http_v3_parse_data_t  *st;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http v3 proxy non buffered copy filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    st = &ctx->v3_parse->body;

    while (buf->pos < buf->last) {

        if (st->length == 0) {

            rc = ngx_http_v3_parse_data(r->connection, st, buf);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ngx_http_v3_parse_data rc:%i st->length: %ui",
                           rc, st->length);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_ERROR || rc > 0) {
                return NGX_ERROR;
            }

            if (rc == NGX_DONE) {
                /* TODO: trailers */
                u->length = 0;
            }

            /* rc == NGX_OK */
            continue;
        }

        /* need to consume ctx->st.length bytes and then parse again */

        cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        b->start = buf->pos;
        b->pos = buf->pos;
        b->last = buf->last;
        b->end = buf->end;

        b->tag = u->output.tag;
        b->flush = 1;
        b->temporary = 1;

        size = buf->last - buf->pos;
        len = ngx_min(size, st->length);

        buf->pos += len;
        st->length -= len;

        if (u->length != -1) {
            u->length -= len;
        }

        b->last = buf->pos;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http v3 proxy out buf %p %z",
                       b->pos, b->last - b->pos);
    }

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    size_t                     size, len;
    ngx_int_t                  rc;
    ngx_buf_t                 *b, **prev;
    ngx_chain_t               *cl;
    ngx_http_upstream_t       *u;
    ngx_http_request_t        *r;
    ngx_http_proxy_ctx_t      *ctx;
    ngx_http_v3_parse_data_t  *st;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                   "http_v3_proxy_copy_filter");

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    if (p->upstream_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
                       "http v3 proxy data after close");
        return NGX_OK;
    }

    if (p->length == 0) {
        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        r = p->input_ctx;
        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NGX_OK;
    }

    r = p->input_ctx;
    u = r->upstream;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    st = &ctx->v3_parse->body;

    b = NULL;
    prev = &buf->shadow;

    while (buf->pos < buf->last) {

        if (st->length == 0) {
            rc = ngx_http_v3_parse_data(r->connection, st, buf);

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ngx_http_v3_parse_data rc:%i st->length: %ui",
                           rc, st->length);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_ERROR || rc > 0) {
                return NGX_ERROR;
            }

            if (rc == NGX_DONE) {
                /* TODO: trailers */
                p->length = 0;
            }

            /* rc == NGX_OK */
            continue;
        }

        /* need to consume ctx->st.length bytes and then parse again */

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b = cl->buf;

        ngx_memcpy(b, buf, sizeof(ngx_buf_t));

        b->tag = p->tag;
        b->recycled = 1;
        b->temporary = 1;

        *prev = b;
        prev = &b->shadow;

        if (p->in) {
            *p->last_in = cl;

        } else {
            p->in = cl;
        }

        p->last_in = &cl->next;

        size = buf->last - buf->pos;

        len = ngx_min(size, st->length);

        buf->pos += len;
        b->last = buf->pos;

        st->length -= len;
        ctx->data_recvd += len;

        if (p->length != -1) {
            p->length -= len;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "http v3 proxy input buf #%d %p", b->num, b->pos);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, p->log, 0,
                   "http v3 proxy copy filter st length %ui pipe len:%O",
                   st->length, p->length);

    if (p->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);
        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_proxy_construct_cookie_header(ngx_http_request_t *r)
{
    u_char                         *buf, *p, *end;
    size_t                          len;
    ngx_str_t                      *vals;
    ngx_uint_t                      i;
    ngx_array_t                    *cookies;
    ngx_table_elt_t                *h;
    ngx_http_header_t              *hh;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_ctx_t           *ctx;
    ngx_http_upstream_main_conf_t  *umcf;

    static ngx_str_t cookie = ngx_string("cookie");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);

    u = r->upstream;
    cookies = ctx->v3_parse->cookies;

    if (cookies == NULL) {
        return NGX_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = ngx_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = ngx_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = ngx_list_push(&u->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        return NGX_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif

#if (NGX_HTTP_V3)

static ngx_int_t
ngx_http_v3_upstream_init_connection(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_int_t          rc;
    ngx_connection_t  *sc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 upstream init connection on c:%p", c);

    c->sockaddr = ngx_palloc(c->pool, u->peer.socklen);
    if (c->sockaddr == NULL) {
       return NGX_ERROR;
    }

    ngx_memcpy(c->sockaddr, u->peer.sockaddr, u->peer.socklen);

    c->socklen = u->peer.socklen;

    c->addr_text.data = ngx_pnalloc(c->pool, u->peer.name->len);
    if (c->addr_text.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(c->addr_text.data, u->peer.name->data, u->peer.name->len);

    if (ngx_quic_create_client(&u->conf->quic, c) != NGX_OK) {
        return NGX_ERROR;
    }

    c->listening->handler = ngx_http_v3_init_client_stream;

    r->connection->log->action = "QUIC handshaking to upstream";

    if (ngx_http_v3_upstream_init_h3(c, r) != NGX_OK) {
        return NGX_ERROR;
    }

    sc = ngx_quic_open_stream(c, 1);
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->data = r;

    /*
     * main quic connection lives own life, we will acess it via stream
     * when required
     */
    u->peer.connection = sc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->log, 0,
                   "http3 client bidi stream created sc:%p", sc);

    rc = ngx_quic_connect(c, ngx_http_v3_upstream_init_ssl, sc);

    if (rc == NGX_AGAIN) {
        ngx_add_timer(sc->write, u->conf->connect_timeout);
        sc->write->handler = ngx_http_v3_upstream_connect_handler;
        sc->read->handler = ngx_http_quic_stream_close_handler;

        return NGX_OK;
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_v3_upstream_connected(r, u, sc);
}


static ngx_int_t
ngx_http_v3_upstream_init_ssl(ngx_connection_t *c, void *data)
{
    ngx_connection_t *sc = data;

    ngx_str_t            *alpn;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    if (sc == NULL) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "http3 stream cannot be reused");
        return NGX_ERROR;
    }

    r = sc->data;
    u = r->upstream;

    /* u->peer.connection (quic stream) shares SSL object with main conn */
    sc->ssl = c->ssl;

    alpn = &u->conf->quic.alpn;

    if (SSL_set_alpn_protos(c->ssl->connection, (uint8_t  *) alpn->data,
                            alpn->len)
        != 0)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "http3 SSL_set_alpn_protos() failed");
        return NGX_ERROR;
    }

    if (u->conf->ssl_server_name || u->conf->ssl_verify) {
        if (ngx_http_upstream_ssl_name(r, u, c) != NGX_OK) {
            return NGX_ERROR;
        }
    }

#if (NGX_HTTP_PROXY_MULTICERT)

    if (u->conf->ssl_certificate_values) {
        if (ngx_http_upstream_ssl_certificates(r, u, c) != NGX_OK) {
            return NGX_ERROR;
        }

    } else

#endif
    {
        if (u->conf->ssl_certificate
            && u->conf->ssl_certificate->value.len
            && (u->conf->ssl_certificate->lengths
                || u->conf->ssl_certificate_key->lengths))
        {
            if (ngx_http_upstream_ssl_certificate(r, u, c) != NGX_OK) {
                return NGX_ERROR;
            }
        }

    }

    if (u->conf->ssl_session_reuse) {
        c->ssl->save_session = ngx_http_upstream_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_upstream_reuse_connection(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_connection_t  *sc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 upstream reuse connection c:%p", c);

    if (ngx_http_upstream_configure(r, u, c) != NGX_OK) {
        return NGX_ERROR;
    }

    sc = ngx_quic_open_stream(c, 1);
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->data = r;
    u->peer.connection = sc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sc->log, 0,
                   "http3 client bidi stream created sc:%p", sc);

    return ngx_http_v3_upstream_send_request(r, u, sc);
}


static ngx_int_t
ngx_http_v3_upstream_init_h3(ngx_connection_t *c, ngx_http_request_t *r)
{
    ngx_http_v3_session_t     *h3c;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        return NGX_ERROR;
    }

    hc->ssl = 1;

    c->data = hc;

    /* hc->addr_conf is unused */
    hc->conf_ctx = cscf->ctx;  /* needed for streams to get config */

    ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    c->log_error = NGX_ERROR_INFO;

    if (ngx_http_v3_init_session(c) != NGX_OK) {
        return NGX_ERROR;
    }

    h3c = ngx_http_v3_get_session(c);

    h3c->client = 1;

    return NGX_OK;
}


static void
ngx_http_v3_upstream_connect_handler(ngx_event_t *ev)
{
    ngx_uint_t            ft_type;
    ngx_connection_t     *c, *sc;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "http3 connect handler");

    sc = ev->data;
    r = sc->data;
    c = r->connection;
    u = r->upstream;

    if (ev->timedout) {
        ft_type = NGX_HTTP_UPSTREAM_FT_TIMEOUT;
        ngx_connection_error(c, NGX_ETIMEDOUT, "http3 connection timed out");
        goto next;
    }

    if (ev->error) {
        ngx_connection_error(c, 0, "http3 connection error");
        ft_type = NGX_HTTP_UPSTREAM_FT_ERROR;
        goto next;
    }

    if (ev->closed) {
        ngx_connection_error(c, 0, "http3 connection was closed");
        ft_type = NGX_HTTP_UPSTREAM_FT_ERROR;
        goto next;
    }

    ngx_http_set_log_request(c->log, r);

    if (ngx_http_v3_upstream_connected(r, u, sc) != NGX_OK) {
        ft_type = NGX_HTTP_UPSTREAM_FT_ERROR;
        goto next;
    }

    ngx_http_run_posted_requests(c);

    return;

next:

    ngx_http_upstream_next(r, u, ft_type);
}


static ngx_int_t
ngx_http_v3_upstream_connected(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_connection_t *sc)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sc->log, 0, "http3 upstream connected");

    if (sc->write->timer_set) {
        /* remove connection timeout timer */
        ngx_del_timer(sc->write);
    }

    sc->write->handler = ngx_http_quic_upstream_dummy_handler;

    c = sc->quic->parent;

    if (u->conf->ssl_verify) {

        rc = SSL_get_verify_result(c->ssl->connection);

        if (rc != X509_V_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "upstream SSL certificate verify error: (%l:%s)",
                          rc, X509_verify_cert_error_string(rc));

            return NGX_DECLINED;
        }

        if (ngx_ssl_check_host(c, &u->ssl_name) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "upstream SSL certificate does not match \"%V\"",
                          &u->ssl_name);
            return NGX_DECLINED;
        }
    }

    if (!u->hq) {
        if (ngx_http_v3_send_settings(c, &u->conf->h3_settings) != NGX_OK) {

            /* example error: qc->closing is set */
            return NGX_ERROR;
        }
    }

    if (ngx_http_v3_upstream_send_request(r, u, sc) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_upstream_send_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *sc)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sc->log, 0,
                   "http3 upstream send request: \"%V?%V\"", &r->uri, &r->args);

    sc->sendfile = 0;
    u->output.sendfile = 0;

    sc->write->handler = ngx_http_upstream_handler;
    sc->read->handler = ngx_http_upstream_handler;

    u->writer.connection = sc;
    u->h3_started = 1;

    ngx_http_upstream_send_request(r, u, 1);

    return NGX_OK;
}


void
ngx_http_v3_upstream_close_request_stream(ngx_connection_t *c,
    ngx_uint_t do_reset)
{
    ngx_pool_t  *pool;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                  "http3 upstream close request stream");

    if (do_reset) {
        ngx_http_v3_reset_stream(c);
    }

    c->destroyed = 1;

    pool = c->pool;

    ngx_quic_client_set_ssl_data(c->quic->parent, NULL);

    /* will remove any c->read/write timers */
    ngx_close_connection(c);

    /* will trigger quic stream cleanup handler */
    ngx_destroy_pool(pool);
}


static void
ngx_http_quic_upstream_dummy_handler(ngx_event_t *ev)
{
}


static void
ngx_http_quic_stream_close_handler(ngx_event_t *ev)
{
    ngx_connection_t     *c, *sc;
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http quic stream close handler");

    sc = ev->data;

    if (sc->close) {
        r = sc->data;
        u = r->upstream;
        c = r->connection;

        /*
         * main quic connection is closing due to some error;
         * continue next upstream process normally; stream will
         * be closed by ngx_http_upstream_close_peer_connection()
         */

        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);

        ngx_http_run_posted_requests(c);
    }
}

#endif
