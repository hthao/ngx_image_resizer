#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <error.h>
#include <ngx_regex.h>
#include <magick/api.h>
#include <wand/wand_api.h>
#include <wand/magick_wand.h>

typedef struct {
    ngx_uint_t height;
    ngx_uint_t width;
}ngx_http_image_resizer_size_t;

typedef struct {
    ngx_http_image_resizer_size_t size;
    ngx_int_t quality;
    ngx_str_t source_type; /*allocate*/
    ngx_str_t target_type; /*data from url*/
    ngx_str_t base_path; /*allocate*/
    ngx_str_t operation; /*data from url*/
}ngx_http_image_resizer_parameters_t;

static ngx_int_t 
ngx_http_image_resizer_parameter_init(
        ngx_http_request_t * r,
        ngx_http_image_resizer_parameters_t *param);

static char *
ngx_http_image_resizer(
        ngx_conf_t * cf, 
        ngx_command_t * cmd,
        void *conf);

static void *
ngx_http_image_resizer_create_loc_conf(
        ngx_conf_t * cf);

static char *
ngx_http_image_resizer_merge_loc_conf(
        ngx_conf_t * cf,
        void *parent, 
        void *child);

static ngx_int_t 
ngx_http_image_resizer_url_match(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_str_t *pattern);

static ngx_int_t 
ngx_http_image_resizer_url_validate(
        ngx_http_request_t * r,
        ngx_http_image_resizer_parameters_t *param,
        ngx_str_t *path,
        ngx_str_t *types);

static ngx_buf_t*
ngx_http_image_resizer_image_resize(
        ngx_http_request_t *r, 
        ngx_str_t *path,
        ngx_http_image_resizer_parameters_t *param,
        size_t *len);

static ngx_int_t 
ngx_http_image_resizer_extract_parameter_null(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_http_image_resizer_parameters_t *param);

static ngx_int_t 
ngx_http_image_resizer_extract_parameter_quality(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_http_image_resizer_parameters_t *param);

static ngx_int_t 
ngx_http_image_resizer_extract_parameter_size(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_http_image_resizer_parameters_t *param);

static ngx_int_t 
ngx_http_image_resizer_extract_parameter_size_quality(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_http_image_resizer_parameters_t *param);

static ngx_int_t 
ngx_http_image_resizer_locate_source(
        ngx_http_request_t *r, 
        ngx_str_t* base_path,
        u_char* type);

static ngx_int_t 
ngx_http_image_resizer_locate_webp_source(
        ngx_http_request_t *r, 
        ngx_http_image_resizer_parameters_t *param);

static ngx_int_t
ngx_http_image_resizer_adapt_size(
        MagickWand * wand,
        ngx_http_image_resizer_size_t  *required_size, 
        ngx_http_image_resizer_size_t *adapt_size,
        u_char *sign);

static ngx_int_t 
ngx_http_image_handler(
        ngx_http_request_t * r);

static ngx_int_t 
ngx_http_image_resizer_handler(
        ngx_http_request_t * r,
        ngx_str_t *path);

static ngx_int_t 
ngx_http_image_static_handler(
        ngx_http_request_t * r,
        ngx_str_t *path);


typedef struct {
    ngx_str_t types;
    ngx_uint_t max_width;
    ngx_uint_t max_height;
} ngx_http_image_resizer_loc_conf_t;

static ngx_command_t ngx_http_image_resizer_commands[] = {
    {
        ngx_string("use_image_resizer"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_image_resizer,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL},
    {
        ngx_string("image_resizer_types"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_image_resizer_loc_conf_t, types),
        NULL },        
    {
        ngx_string("image_resizer_max_width"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_image_resizer_loc_conf_t, max_width),
        NULL },
    {
        ngx_string("image_resizer_max_height"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_image_resizer_loc_conf_t, max_height),
        NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_image_resizer_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_image_resizer_create_loc_conf,
    ngx_http_image_resizer_merge_loc_conf
};

ngx_module_t ngx_http_image_resizer_module = {
    NGX_MODULE_V1,
    &ngx_http_image_resizer_module_ctx,	/* module context */
    ngx_http_image_resizer_commands,	/* module directives */
    NGX_HTTP_MODULE,	/* module type */
    NULL,			/* init master */
    NULL,			/* init module */
    NULL,			/* init process */
    NULL,			/* init thread */
    NULL,			/* exit thread */
    NULL,			/* exit process */
    NULL,			/* exit master */
    NGX_MODULE_V1_PADDING
};

    static char *
ngx_http_image_resizer(
        ngx_conf_t * cf, 
        ngx_command_t * cmd,
        void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_image_handler;
    return NGX_CONF_OK;
}

    static void *
ngx_http_image_resizer_create_loc_conf(
        ngx_conf_t * cf)
{
    ngx_http_image_resizer_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_image_resizer_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_str_null(&conf->types);	
    conf->max_width = NGX_CONF_UNSET_UINT;
    conf->max_height = NGX_CONF_UNSET_UINT;
    return conf;
}

    static char *
ngx_http_image_resizer_merge_loc_conf(
        ngx_conf_t * cf,
        void *parent,
        void *child)
{
    ngx_http_image_resizer_loc_conf_t *prev = parent;
    ngx_http_image_resizer_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->types, prev->types, "(jpg|jpeg|webp|png|bmp|tiff|gif)");	
    ngx_conf_merge_uint_value(conf->max_width, prev->max_width, 2000);
    ngx_conf_merge_uint_value(conf->max_height, prev->max_height, 2000);

    return NGX_CONF_OK;
}

    static ngx_int_t 
ngx_http_image_handler(
        ngx_http_request_t * r)

{
    u_char					 *last;
    size_t					  root;
    ngx_str_t				  path;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    if (0 != access((char*)path.data, F_OK|R_OK)) {
        return ngx_http_image_resizer_handler(r, &path);
    } else {
        return ngx_http_image_static_handler(r, &path);
    }

}

/* This is a copy of static content module handler */
    static ngx_int_t
ngx_http_image_static_handler(
        ngx_http_request_t *r,
        ngx_str_t *path)
{
    u_char					  *last, *location;
    size_t					       len;
    ngx_int_t				   rc;
    ngx_uint_t				   level;
    ngx_log_t				  *log;
    ngx_buf_t				  *b;
    ngx_chain_t 			   out;
    ngx_open_file_info_t	   of;
    ngx_http_core_loc_conf_t  *clcf;

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    log = r->connection->log;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, path, &of, r->pool)
            != NGX_OK)
    {
        switch (of.err) {

            case 0:
                return NGX_HTTP_INTERNAL_SERVER_ERROR;

            case NGX_ENOENT:
            case NGX_ENOTDIR:
            case NGX_ENAMETOOLONG:

                level = NGX_LOG_ERR;
                rc = NGX_HTTP_NOT_FOUND;
                break;

            case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
            case NGX_EMLINK:
            case NGX_ELOOP:
#endif

                level = NGX_LOG_ERR;
                rc = NGX_HTTP_FORBIDDEN;
                break;

            default:

                level = NGX_LOG_CRIT;
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                    "%s \"%s\" failed", of.failed, path->data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");

        ngx_http_clear_location(r);

        r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = r->uri.len + 1;

        if (!clcf->alias && clcf->root_lengths == NULL && r->args.len == 0) {
            location = path->data + clcf->root.len;

            *last = '/';

        } else {
            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = ngx_pnalloc(r->pool, len);
            if (location == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = ngx_copy(location, r->uri.data, r->uri.len);

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                ngx_memcpy(++last, r->args.data, r->args.len);
            }
        }

        /*
         * we do not need to set the r->headers_out.location->hash and
         * r->headers_out.location->key fields
         */

        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                "\"%s\" is not a regular file", path->data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    if (r->method & NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = *path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


    static ngx_int_t 
ngx_http_image_resizer_parameter_init(
        ngx_http_request_t * r,
        ngx_http_image_resizer_parameters_t *param)
{
    if (!param) return NGX_ERROR;
    param->size.width = 0;
    param->size.height = 0;
    param->quality = 0;
    param->source_type.data = ngx_palloc(r->pool, 16);
    if (!param->source_type.data) {
        return NGX_ERROR;
    }
    ngx_str_null(&param->target_type);
    ngx_str_null(&param->base_path);
    ngx_str_null(&param->operation);
    param->base_path.data = ngx_palloc(r->pool, 512);
    if (!param->base_path.data) {
        return NGX_ERROR;
    }
    param->base_path.len = 0;
    return NGX_OK;
}

    static ngx_int_t 
ngx_http_image_resizer_url_match(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_str_t *pattern) 
{
    int rc;
    u_char errstr[NGX_MAX_CONF_ERRSTR];
    int captures[2];
    ngx_regex_compile_t rgc;
    ngx_memzero(&rgc, sizeof(ngx_regex_compile_t));
    rgc.pattern = *pattern;
    rgc.pool = r->pool;
    rgc.err.len = NGX_MAX_CONF_ERRSTR;
    rgc.err.data = errstr;
    if (ngx_regex_compile(&rgc) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to compile regex pattern %V", &rgc.pattern);
        return NGX_ERROR;
    }

    rc = ngx_regex_exec(rgc.regex, url_name, captures, 2);
    if (rc == NGX_REGEX_NO_MATCHED){
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*xxx.jpg*/
    static ngx_int_t 
ngx_http_image_resizer_extract_parameter_null(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_http_image_resizer_parameters_t *param)
{

    u_char *dot = NULL;

    dot = (u_char *) strrchr((char *)url_name->data, '.');
    if (!dot) {
        return NGX_ERROR;
    } else {
        /*extract image type*/
        param->target_type.data = dot;
        param->target_type.len = url_name->len - (dot - url_name->data);
    }

    ngx_int_t base_name_len = dot - url_name->data;
    ngx_memcpy(param->base_path.data, url_name->data, base_name_len);
    param->base_path.len = base_name_len;		
    return NGX_OK;
}

/*xxx_q90.jpg*/
    static ngx_int_t 
ngx_http_image_resizer_extract_parameter_quality(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_http_image_resizer_parameters_t *param)
{
    u_char *underline = NULL;
    u_char *dot = NULL;

    dot = (u_char *) strrchr((char *)url_name->data, '.');
    if (!dot) {
        return NGX_ERROR;
    } else {
        /*extract image type*/
        param->target_type.data = dot;
        param->target_type.len = url_name->len - (dot - url_name->data);
    }

    underline = (u_char *) strrchr((char *)url_name->data, '_');
    if (!underline) {
        return NGX_ERROR;
    }

    u_char *quality = ngx_strlchr(underline, dot, 'q');
    if (quality) {
        //extract image quality, width, height.
        param->quality = ngx_atoi(quality + 1, dot - quality - 1);
    } else {
        return NGX_ERROR;
    }

    ngx_int_t base_name_len = underline - url_name->data;
    ngx_memcpy(param->base_path.data, url_name->data, base_name_len);
    param->base_path.len = base_name_len;
    return NGX_OK;

}

/*xxx_100x100.jpg*/
    static ngx_int_t 
ngx_http_image_resizer_extract_parameter_size(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_http_image_resizer_parameters_t *param)
{
    int i = 0;
    u_char *underline = NULL;
    u_char *dot = NULL;

    dot = (u_char *) strrchr((char *)url_name->data, '.');
    if (!dot) {
        return NGX_ERROR;
    } else {
        /*extract image type*/
        param->target_type.data = dot;
        param->target_type.len = url_name->len - (dot - url_name->data);
    }

    underline = (u_char *) strrchr((char *)url_name->data, '_');
    if (!underline) {
        return NGX_ERROR;
    }

    u_char *operation = NULL;
    u_char ops[3] = {'x', 'y', '*'};
    for (i = 0; i < 3; i++) {
        operation = ngx_strlchr(underline, dot, ops[i]);
        if (operation) {
            param->operation.data = operation;
            param->operation.len = 1;
            break;
        }
    }
    if (!operation) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V, invalid operation!", url_name);
        return NGX_ERROR;
    }

    param->size.width = ngx_atoi(underline + 1, operation - underline - 1);
    param->size.height = ngx_atoi(operation + 1, dot - operation - 1);

    ngx_int_t base_name_len = underline - url_name->data;
    ngx_memcpy(param->base_path.data, url_name->data, base_name_len);
    param->base_path.len = base_name_len;
    return NGX_OK;

}

/*xxx_100x100q90.jpg*/
    static ngx_int_t 
ngx_http_image_resizer_extract_parameter_size_quality(
        ngx_http_request_t *r, 
        ngx_str_t *url_name, 
        ngx_http_image_resizer_parameters_t *param)
{
    int i = 0;
    u_char *underline = NULL;
    u_char *dot = NULL;

    dot = (u_char *) strrchr((char *)url_name->data, '.');
    if (!dot) {
        return NGX_ERROR;
    } else {
        /*extract image type*/
        param->target_type.data = dot;
        param->target_type.len = url_name->len - (dot - url_name->data);
    }

    underline = (u_char *) strrchr((char *)url_name->data, '_');
    if (!underline) {
        return NGX_ERROR;
    }

    u_char *operation = NULL;
    u_char ops[3] = {'x', 'y', '*'};
    for (i = 0; i < 3; i++) {
        operation = ngx_strlchr(underline, dot, ops[i]);
        if (operation) {
            param->operation.data = operation;
            param->operation.len = 1;
            break;
        }
    }
    if (!operation) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V, invalid operation!", url_name);
        return NGX_ERROR;
    }

    u_char *quality = ngx_strlchr(underline, dot, 'q');
    if (quality) {
        /* extract image quality, width, height */
        param->quality = ngx_atoi(quality + 1, dot - quality - 1);	
        param->size.width = ngx_atoi(underline + 1, operation - underline - 1);
        param->size.height = ngx_atoi(operation + 1, quality - operation - 1);
    } else {
        /* extract image width, height */
        param->quality = 0;
        param->size.width = ngx_atoi(underline + 1, operation - underline - 1);
        param->size.height = ngx_atoi(operation + 1, dot - operation - 1);
    }

    ngx_int_t base_name_len = underline - url_name->data;
    ngx_memcpy(param->base_path.data, url_name->data, base_name_len);
    param->base_path.len = base_name_len;
    return NGX_OK;
}

    static ngx_int_t 
ngx_http_image_resizer_locate_source(
        ngx_http_request_t *r, 
        ngx_str_t* base_path,
        u_char* type)
{
    char source_path[512] = {'\0'};
    ngx_memcpy(source_path, base_path->data, base_path->len);
    ngx_memcpy(source_path + base_path->len, type, ngx_strlen(type));
    if (0 != access(source_path, F_OK|R_OK)) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

    static ngx_int_t 
ngx_http_image_resizer_locate_webp_source(
        ngx_http_request_t *r, 
        ngx_http_image_resizer_parameters_t *param)
{
    if (NGX_OK == ngx_http_image_resizer_locate_source(r, &param->base_path, (u_char*)".webp")) {
        ngx_memcpy(param->source_type.data, ".webp", ngx_strlen(".webp"));
        param->source_type.len = ngx_strlen(".webp");
        return NGX_OK;
    }
    if (NGX_OK == ngx_http_image_resizer_locate_source(r, &param->base_path, (u_char*)".jpg")) {
        ngx_memcpy(param->source_type.data, ".jpg", ngx_strlen(".jpg"));
        param->source_type.len = ngx_strlen(".jpg");		
        return NGX_OK;
    }
    if (NGX_OK == ngx_http_image_resizer_locate_source(r, &param->base_path, (u_char*)".jpeg")) {
        ngx_memcpy(param->source_type.data, ".jpeg", ngx_strlen(".jpeg"));
        param->source_type.len = ngx_strlen(".jpeg");		
        return NGX_OK;
    }	
    if (NGX_OK == ngx_http_image_resizer_locate_source(r, &param->base_path, (u_char*)".bmp")) {
        ngx_memcpy(param->source_type.data, ".bmp", ngx_strlen(".bmp"));
        param->source_type.len = ngx_strlen(".bmp");		
        return NGX_OK;
    }	
    if (NGX_OK == ngx_http_image_resizer_locate_source(r, &param->base_path, (u_char*)".png")) {
        ngx_memcpy(param->source_type.data, ".png", ngx_strlen(".png"));
        param->source_type.len = ngx_strlen(".png");		
        return NGX_OK;
    }		
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "source:%V is not exist for webp format, errno:%d", &param->base_path, errno);
    return NGX_ERROR;
}

    static ngx_int_t
ngx_http_image_resizer_adapt_size(
        MagickWand * wand,
        ngx_http_image_resizer_size_t *required_size, 
        ngx_http_image_resizer_size_t *adapt_size,
        u_char *operation)
{
    unsigned long src_height, src_width;
    ngx_uint_t required_width = required_size->width;
    ngx_uint_t required_height = required_size->height;

    if (wand == NULL) return NGX_ERROR;

    if (required_width == 0 || required_height == 0) return NGX_ERROR;

    src_height = MagickGetImageHeight(wand);
    if (src_height == 0) return NGX_ERROR;

    src_width = MagickGetImageWidth(wand);
    if (src_width == 0) return NGX_ERROR;

    if(*operation == 'x') {
        if ((double)required_width / (double)required_height < (double)src_width / (double)src_height) {
            adapt_size->width = required_width;
            adapt_size->height = (double)src_height *((double)required_width /(double)src_width);
        } else {
            adapt_size->height = required_height;
            adapt_size->width = (double)src_width *((double)required_height /(double)src_height);
        }
    } else if(*operation == '*') {
        adapt_size->height = required_height;
        adapt_size->width = (double)src_width*((double)required_height/(double)src_height);
    } else if (*operation == 'y') {
        adapt_size->height = required_height;
        adapt_size->width = required_width;
    } else {
        return NGX_ERROR;
    }
    return NGX_OK;
}

    static ngx_buf_t*
ngx_http_image_resizer_image_resize(
        ngx_http_request_t *r, 
        ngx_str_t *path,
        ngx_http_image_resizer_parameters_t *param,
        size_t *len)
{
    ngx_http_image_resizer_size_t resize_size = { 0, 0 };
    ngx_uint_t width = param->size.width;
    ngx_uint_t height = param->size.height;
    unsigned long x, y;
    unsigned char *blob = NULL;
    ngx_buf_t *img_buf = NULL;
    MagickWand *mw = NULL;
    PixelWand *white_bg = NULL;
    MagickPassFail status = MagickPass;

    InitializeMagick(NULL);
    mw = (MagickWand*)NewMagickWand();
    do {

        status = MagickReadImage(mw, (char *)path->data);
        if( MagickPass != status ) break;

        /* resize */
        if (param->operation.data ) {
            status = MagickStripImage(mw);
            if (MagickPass !=  status) break;

            if (NGX_OK != ngx_http_image_resizer_adapt_size(mw, &(param->size), &resize_size, param->operation.data)) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                        "\"%s\" ngx_http_image_resizer_adapt_size failed !!!!!", (char *)path->data);
                break;
            }

            white_bg = NewPixelWand();
            if (!white_bg) break;

            status = PixelSetColor(white_bg, "#FFFFFF");
            if (MagickPass != status) break;

            status = MagickSetImageBackgroundColor(mw, white_bg);
            if (MagickPass != status) break;

            status = MagickScaleImage(mw, resize_size.width, resize_size.height);
            if (MagickPass != status) break;

            if (*(param->operation.data) == 'x') {
                status = MagickScaleImage(mw, resize_size.width, resize_size.height);
                if (MagickPass != status) break;

                x = (width - resize_size.width) / 2;
                y = (height - resize_size.height) / 2;
                status = MagickExtentImage(mw, width, height, x, y);
                if (MagickPass != status) break;

            }  else if (*(param->operation.data) == '*') {
                status = MagickScaleImage(mw, resize_size.width, resize_size.height);
                if (MagickPass != status) break;

                if (resize_size.width > width) {
                    x = (resize_size.width - width)/2;
                    status = MagickCropImage(mw,width,resize_size.height,x,0);
                    if (MagickPass != status) break;
                } else {
                    x = (width - resize_size.width)/2;
                    status = MagickExtentImage(mw, width, resize_size.height, x, 0);
                    if (MagickPass != status) break;
                }
            } else if (*(param->operation.data) == 'y') {
                status = MagickScaleImage(mw, width, height);
                if (MagickPass != status) break;
            }
            if (param->quality > 0) {
                status = MagickSetCompressionQuality(mw, param->quality);
            } else {
                status = MagickSetCompressionQuality(mw, 90);
            }
            if (MagickPass != status) break;

        }

        if (0 != strncmp((const char*)param->source_type.data,  (const char*)param->target_type.data, param->target_type.len)) {
            status = MagickSetImageFormat( mw, (const char*)(param->target_type.data + 1));
            if (MagickPass != status) break;
        }

    } while(0);

    /* Diagnose any error */
    if (MagickPass != status) {
        char *description;
        ExceptionType severity;
        description=MagickGetException(mw,&severity);
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0, "%.1024s (severity %d)\n" , description,severity);

        if (white_bg) DestroyPixelWand(white_bg);
        if (mw) DestroyMagickWand(mw);
        DestroyMagick();
        return NULL;
    }


    /* write it */
    blob = MagickWriteImageBlob(mw, len);

    if (!blob || *len == 0) {
        char *description;
        ExceptionType severity;
        description=MagickGetException(mw,&severity);
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0, "%.1024s (severity %d)\n" , description,severity);

        if (blob) MagickRelinquishMemory(blob);
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0, "\"%s\" MagickWriteImageBlob failed !!!!!", (char *)path->data);
        if (white_bg) DestroyPixelWand(white_bg);
        if (mw) DestroyMagickWand(mw);
        DestroyMagick();
        return NULL;
    }

    img_buf = ngx_create_temp_buf(r->pool, *len);
    ngx_memcpy(img_buf->pos, blob, *len);
    MagickRelinquishMemory(blob);
    if (white_bg) DestroyPixelWand(white_bg);
    if (mw) DestroyMagickWand(mw);
    DestroyMagick();

    return img_buf;
}


    static ngx_int_t 
ngx_http_image_resizer_url_validate(
        ngx_http_request_t * r,
        ngx_http_image_resizer_parameters_t *param,
        ngx_str_t *path,
        ngx_str_t *types)
{
    ngx_str_t regex_pattern;
    size_t len;
    regex_pattern.data = ngx_palloc(r->pool, 256);

    do {

        const char *s = ".*_[0-9]{1,4}[x|y|*][0-9]{1,4}\\.";
        len = ngx_strlen(s);
        ngx_memset(regex_pattern.data, '\0', 256);
        ngx_memcpy(regex_pattern.data, s, len);
        ngx_memcpy(regex_pattern.data + len, types->data, types->len);
        regex_pattern.len = len +types->len;
        regex_pattern.data[regex_pattern.len] = '$';

        if (NGX_OK == ngx_http_image_resizer_url_match(r, path, &regex_pattern)) {
            if (NGX_OK != ngx_http_image_resizer_extract_parameter_size(r, path, param)) {
                return NGX_ERROR;
            }
            break;
        }

        const char *sq = ".*_[0-9]{1,4}[x|y|*][0-9]{1,4}q[0-9]{1,2}\\.";
        len = ngx_strlen(sq);
        ngx_memset(regex_pattern.data, '\0', 256);
        ngx_memcpy(regex_pattern.data, sq, len);
        ngx_memcpy(regex_pattern.data + len, types->data, types->len);
        regex_pattern.len = len +types->len;
        regex_pattern.data[regex_pattern.len] = '$';

        if (NGX_OK == ngx_http_image_resizer_url_match(r, path, &regex_pattern)) {
            if (NGX_OK != ngx_http_image_resizer_extract_parameter_size_quality(r, path, param)) {
                return NGX_ERROR;
            }
            break;
        }

        const char *quality = ".*_q[0-9]{1,2}\\.";
        len = ngx_strlen(quality);
        ngx_memset(regex_pattern.data, '\0', 256);
        ngx_memcpy(regex_pattern.data, quality, len);
        ngx_memcpy(regex_pattern.data + len, types->data, types->len);
        regex_pattern.len = len +types->len;
        regex_pattern.data[regex_pattern.len] = '$';

        if (NGX_OK == ngx_http_image_resizer_url_match(r, path, &regex_pattern)) {
            if (NGX_OK != ngx_http_image_resizer_extract_parameter_quality(r, path, param)) {
                return NGX_ERROR;
            }
            break;
        }

        const char *last = ".*\\.";
        len = ngx_strlen(last);
        ngx_memset(regex_pattern.data, '\0', 256);
        ngx_memcpy(regex_pattern.data, last, len);
        ngx_memcpy(regex_pattern.data + len, types->data, types->len);
        regex_pattern.len = len +types->len;
        regex_pattern.data[regex_pattern.len] = '$';

        if (NGX_OK == ngx_http_image_resizer_url_match(r, path, &regex_pattern)) {
            if (NGX_OK != ngx_http_image_resizer_extract_parameter_null(r, path, param)) {
                return NGX_ERROR;
            }
            break;
        }
    } while (0);

    return NGX_OK;
}

    static ngx_int_t 
ngx_http_image_resizer_handler(
        ngx_http_request_t * r,
        ngx_str_t *path)
{
    ngx_str_t origin_path;
    ngx_int_t rc;
    ngx_log_t *log;
    ngx_buf_t *image_buf;
    size_t len;
    ngx_chain_t out;
    ngx_http_image_resizer_loc_conf_t *rzlcf;
    ngx_http_image_resizer_parameters_t param;

    log = r->connection->log;
    rzlcf = ngx_http_get_module_loc_conf(r, ngx_http_image_resizer_module);

    if (rzlcf->types.len > 128) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "%V, length of types is exceed 128.", &rzlcf->types);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }		

    if (NGX_OK != ngx_http_image_resizer_parameter_init(r, &param)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,"ngx_http_image_resizer_parameter_init failed!");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (NGX_OK != ngx_http_image_resizer_url_validate(r, &param, path, &rzlcf->types)) {
        return NGX_HTTP_NOT_FOUND;
    } 

    if (param.size.width > rzlcf->max_height ||param.size.width > rzlcf->max_width) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "%V, height or widht exceeds max number, w:%d, h:%d.", path, param.size.width, param.size.width);
        return NGX_HTTP_NOT_FOUND;
    }

    if (param.quality < 0 ||param.quality > 99) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "%V, quality exceeds max number, %d.", path, param.quality);
        return NGX_HTTP_NOT_FOUND;
    }

    if (strncmp((const char *) param.target_type.data, (const char *) ".webp", param.target_type.len) == 0) {
        if (NGX_OK != ngx_http_image_resizer_locate_webp_source(r, &param)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,"ngx_http_image_resizer_locate_webp_source failed!");
            return NGX_HTTP_NOT_FOUND;
        }

    } else {
        if (NGX_OK != ngx_http_image_resizer_locate_source(r, &param.base_path, param.target_type.data)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,"ngx_http_image_resizer_locate_source failed!");
            return NGX_HTTP_NOT_FOUND;
        }
        ngx_memcpy(param.source_type.data, param.target_type.data, param.target_type.len);
        param.source_type.len = param.target_type.len;
    }

    origin_path.data = ngx_palloc(r->pool, param.base_path.len + param.source_type.len + 1);
    origin_path.len = param.base_path.len + param.source_type.len;
    ngx_memcpy(origin_path.data, param.base_path.data, param.base_path.len);
    ngx_memcpy(origin_path.data + param.base_path.len, param.source_type.data, param.source_type.len);
    origin_path.data[origin_path.len] = '\0';

    image_buf = ngx_http_image_resizer_image_resize(r, &origin_path, &param, &len);
    if (!image_buf) {
        ngx_log_error(NGX_LOG_ERR, log, 0,"ngx_http_image_resizer_image_resize failed!");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    image_buf->last = image_buf->pos + len;
    image_buf->last_buf = 1;
    r->root_tested = !r->error_page;

    if (r->method & NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = time(NULL);

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && len == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = image_buf;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

