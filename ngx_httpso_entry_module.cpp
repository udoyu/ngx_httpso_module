extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
    #include <dlfcn.h>
}

#include <map>
#include <vector>
#include <string>
#include <ngx_httpso_async_work.h>

#define NGX_HTTPSO_PATH_STR ngx_string("httpso")

typedef struct {
    ngx_int_t     async_worker_threads;
    ngx_msec_t    async_work_complete_check;
    ngx_msec_t    async_work_expire;
} ngx_httpso_loc_conf_t;

static void *ngx_httpso_create_loc_conf(ngx_conf_t *cf);
static char *ngx_httpso_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

typedef std::map <std::string, httpso_handler_pt> httpso_handler_map_t;
typedef std::vector<ngx_httpso_t *> httpso_httpso_vec_t;

static httpso_handler_map_t httpso_handler_map;
static httpso_httpso_vec_t  httpso_vec;

static ngx_int_t ngx_httpso_entry_init_process(ngx_cycle_t *cycle);
static void ngx_httpso_entry_exit_process(ngx_cycle_t *cycle);
typedef ngx_int_t
(*load_httpso_process_pt) (ngx_cycle_t *cycle, const char *httpso_path);

static ngx_int_t 
ngx_httpso_entry_load(ngx_cycle_t *cycle, const char *httpso_path);

static ngx_int_t
ngx_httpso_load_process(ngx_cycle_t *cycle, 
    const char *path, 
    const char *fname, 
    load_httpso_process_pt h);

static ngx_int_t ngx_httpso_load_i(ngx_cycle_t *cycle, const char *sofile);

static char *
ngx_httpso_concat_filename(const char *httpso_path, const char *fname);

static long
ngx_httpso_pkg_handler_add(void *cycle_param, 
    const char *name, const size_t name_len,
    httpso_handler_pt h);

/* async work */
typedef struct {
    ngx_event_t  ev;
    ngx_msec_t   expire_time;
    int          to_check_count;
} ngx_httpso_async_work_complete_check_event_t;
struct ngx_httpso_async_work_s{
    ngx_int_t     async_worker_threads;
    NgxHttpsoAsyncWorkPtr async_work_ptr;
    ngx_httpso_async_work_complete_check_event_t check_ev;
} async_work;
typedef struct {
    ngx_event_t           ev;
    bool                  async_work_timeout;
    ngx_msec_t            expire_time;
    AsyncWorkEntryPtr  work_entry;
} ngx_httpso_async_work_timeout_event_t;
static void ngx_httpso_async_work_check(ngx_event_t *ev);
static void ngx_httpso_async_work_timeout(ngx_event_t *ev);
static long httpso_async_work_add(AsyncWorkEntryPtr &e);

static ngx_int_t ngx_httpso_entry_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_entry_module_ctx = {
        NULL,                          /* preconfiguration */
        ngx_httpso_entry_init,         /* postconfiguration */

        NULL,                          /* create main configuration */
        NULL,                          /* init main configuration */

        NULL,                          /* create server configuration */
        NULL,                          /* merge server configuration */

        ngx_httpso_create_loc_conf,    /* create location configuration */
        ngx_httpso_merge_loc_conf      /* merge location configuration */
};

static ngx_command_t ngx_http_entry_commands[] = {
    { ngx_string("async_worker_threads"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_httpso_loc_conf_t, async_worker_threads),
      NULL },

    { ngx_string("async_work_complete_check"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_httpso_loc_conf_t, async_work_complete_check),
      NULL },

    { ngx_string("async_work_expire"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_httpso_loc_conf_t, async_work_expire),
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_entry_module = {
        NGX_MODULE_V1,
        &ngx_http_entry_module_ctx,    /* module context */
        ngx_http_entry_commands,       /* module directives */
        NGX_HTTP_MODULE,               /* module type */
        NULL,                          /* init master */
        NULL,                          /* init module */
        ngx_httpso_entry_init_process,   /* init process */
        NULL,                          /* init thread */
        NULL,                          /* exit thread */
        ngx_httpso_entry_exit_process,   /* exit process */
        NULL,                          /* exit master */
        NGX_MODULE_V1_PADDING
};

static long 
ngx_httpso_send_data(ngx_httpso_ctx_t *ctx, 
                                     const u_char *data, 
                                     const size_t len)
{
    ngx_http_request_t *r = (ngx_http_request_t *)ctx->request;
    if (NULL == r)
    {
        return NGX_ERROR;
    }
    u_char *tmp_buf = (u_char *)ngx_pcalloc(r->pool, len);
    if (tmp_buf == NULL) 
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }    
    memset(tmp_buf, 0, len);
    ngx_memcpy(tmp_buf, data, len);
    
    ngx_buf_t *sendbuf = (ngx_buf_t*)ngx_pcalloc(r->pool,
                                                 sizeof(ngx_buf_t));
    if (sendbuf == NULL) 
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    sendbuf->pos = tmp_buf;
    sendbuf->last = tmp_buf + len;
    sendbuf->memory = 1;    /* this buffer is in memory */
    sendbuf->last_buf = 1;  /* this is the last buffer in the buffer chain */


    /* attach this buffer to the buffer chain */
    ngx_chain_t  out;
    out.buf = sendbuf;
    out.next = NULL;

    /* set the status line */
    if (!r->header_sent) {
        r->headers_out.status = NGX_HTTP_OK;
        //r->headers_out.content_length_n = len;
        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_clear_content_length(r);
        ngx_http_clear_accept_ranges(r);

        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
       	    return rc;
        }
    }

    //if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    //{
    //    return rc;
    //}
    
    /* send the buffer chain of your response */
    return ngx_http_output_filter(r, &out);
}

static ngx_int_t 
entry_get_body(ngx_http_request_t *r, ngx_httpso_str_t *body)
{
    if (NULL == r->request_body)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
            "entry_get_body|r->request_body=NULL");
        return NGX_OK;
    }
    if (NULL == r->request_body->bufs)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
            "entry_get_body|r->request_body->bufs=NULL");
        return NGX_OK;
    }
    
    const size_t buf_total_len = r->headers_in.content_length_n;
    size_t buf_cur_len = 0;
    u_char* buf = (u_char*)ngx_pcalloc(r->pool, buf_total_len);    
    if (buf == NULL) 
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "entry_get_body|ngx_pcalloc failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_chain_t* bufs = r->request_body->bufs;

    while (bufs && bufs->buf && buf_cur_len <= buf_total_len)
    {
        int tmplen = bufs->buf->last - bufs->buf->pos;
        memcpy(buf+buf_cur_len, bufs->buf->pos, tmplen);
        buf_cur_len += tmplen;
        bufs = bufs->next;
    }
    
    body->data = buf;
    body->len = buf_cur_len;
    
    return NGX_OK;
}

static ngx_int_t 
entry_common_handler(ngx_http_request_t *r, httpso_handler_pt h)
{
    ngx_httpso_loc_conf_t *hlcf;
    ngx_httpso_async_work_timeout_event_t *async_ev;
    ngx_httpso_ctx_t *ctx = (ngx_httpso_ctx_t *)ngx_pcalloc(r->pool,
                                                sizeof(ngx_httpso_ctx_t));
    if (NULL == ctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_entry_handler|ngx_pcalloc failed|ctx=NULL\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->request = r;
    
    ctx->send_data = (httpso_send_data_pt)ngx_httpso_send_data;
    ctx->method = r->method;
    
    ctx->httpso_log.log = r->connection->log;
    ctx->httpso_log.log_level = r->connection->log->log_level;
    ctx->httpso_log.log_error = (httpso_log_error_pt)ngx_log_error_core;
    ctx->pool = r->pool;
    ctx->palloc = (httpso_alloc_pt)ngx_palloc;
    ctx->pcalloc = (httpso_alloc_pt)ngx_pcalloc;
    ctx->pfree = (httpso_pfree_pt)ngx_pfree;
    
    ctx->httpso_req.uri.data = r->uri.data;
    ctx->httpso_req.uri.len = r->uri.len;
    ctx->httpso_req.args.data = r->args.data;
    ctx->httpso_req.args.len = r->args.len;

    ctx->async_timeout_ev = (ngx_httpso_async_work_timeout_event_t *) 
        ngx_pcalloc(r->pool, sizeof(ngx_httpso_async_work_timeout_event_t));
    if (NULL == ctx->async_timeout_ev) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "ngx_http_entry_handler|ctx->async_timeout_ev=NULL\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    async_ev = (ngx_httpso_async_work_timeout_event_t *)ctx->async_timeout_ev;
    hlcf = (ngx_httpso_loc_conf_t *)ngx_http_get_module_loc_conf(r, ngx_http_entry_module);
    async_ev->async_work_timeout = false;
    async_ev->expire_time = hlcf->async_work_expire;
    async_ev->ev.handler = ngx_httpso_async_work_timeout;
    ctx->async_work_add = httpso_async_work_add;

    if (r->method & NGX_HTTP_POST) {
        if (NGX_OK == entry_get_body(r, &ctx->httpso_req.body))
            return h(ctx);
        else
            return NGX_ERROR;
    }
    return h(ctx);
}

static void 
entry_post_handler(ngx_http_request_t *r)
{
    httpso_handler_map_t::reverse_iterator rmit = httpso_handler_map.rbegin();
    for (rmit; rmit != httpso_handler_map.rend(); ++rmit)
    {
        if (!rmit->first.empty() && 
            ngx_strncasecmp(r->uri.data+1, (u_char*)rmit->first.c_str(), 
                            rmit->first.length()) == 0)
        {  
            entry_common_handler(r, rmit->second);
            break;
        }
    }
}

static ngx_int_t
ngx_httpso_entry_handler(ngx_http_request_t *r)
{
    httpso_handler_pt h = NULL;
    httpso_handler_map_t::reverse_iterator rmit = httpso_handler_map.rbegin();
    for (rmit; rmit != httpso_handler_map.rend(); ++rmit)
    {
        if (!rmit->first.empty() && 
            ngx_strncasecmp(r->uri.data+1, (u_char*)rmit->first.c_str(), 
                            rmit->first.length()) == 0)
        {
            h = rmit->second;   
            break;
        }
    }    
    if (NULL == h)
    {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "ngx_http_entry_handler|unkown uri|uri=%s", (char *)r->uri.data);
        return NGX_ERROR;
    }
    
    
    if (r->method & NGX_HTTP_POST)    
    {
        ngx_int_t rc = ngx_http_read_client_request_body(r, entry_post_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                "ngx_http_read_client_request_body err, rc=%d", rc);
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    
    return entry_common_handler(r, h);
}

static ngx_int_t
ngx_httpso_entry_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = (ngx_http_core_main_conf_t*)ngx_http_conf_get_module_main_conf(cf, 
        ngx_http_core_module);

    h = (ngx_http_handler_pt*)ngx_array_push(
        &cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) 
    {
        return NGX_ERROR;
    }

    *h = ngx_httpso_entry_handler;

    return NGX_OK;
}

static ngx_int_t 
ngx_httpso_entry_init_process(ngx_cycle_t *cycle)
{
    ngx_str_t             httpso_path = NGX_HTTPSO_PATH_STR;
    ngx_uint_t            i;
    ngx_httpso_cycle_ctx_t  *cycle_ctx;

    cycle_ctx = (ngx_httpso_cycle_ctx_t *)ngx_pcalloc(cycle->pool, 
                    sizeof(ngx_httpso_cycle_ctx_t));
    if (NULL == cycle_ctx)
    {
        return NGX_ERROR;
    }
    async_work.async_work_ptr.reset(new NgxHttpsoAsyncWork());
    async_work.async_work_ptr->AsyncWorkStart(async_work.async_worker_threads);
    async_work.check_ev.ev.handler = ngx_httpso_async_work_check;
    
    cycle_ctx->httpso_log.log = cycle->log;
    cycle_ctx->httpso_log.log_level = cycle->log->log_level;
    cycle_ctx->httpso_log.log_error=(httpso_log_error_pt)ngx_log_error_core;
    
     /* the httpso_path->data will end with '\0' */
    ngx_conf_full_name(cycle, &httpso_path, 0);
    if (NGX_OK != ngx_httpso_entry_load(cycle, 
        (const char *)httpso_path.data))
    {
        return NGX_ERROR;
    }
    cycle_ctx->httpso_path.data = httpso_path.data;
    cycle_ctx->httpso_path.len = httpso_path.len;

    httpso_httpso_vec_t::iterator vit = httpso_vec.begin();
 
    for (i=0; vit != httpso_vec.end(); ++vit, ++i) {
        if ((*vit)->httpso_load(cycle, ngx_httpso_pkg_handler_add, 
            i, cycle_ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    
    return NGX_OK;
}

static void 
ngx_httpso_entry_exit_process(ngx_cycle_t *cycle)
{
    if (async_work.async_work_ptr) {
        async_work.async_work_ptr->AsyncWorkStop();
        async_work.async_work_ptr.reset();
    }
    httpso_httpso_vec_t::iterator vit = httpso_vec.begin();
    for (; vit != httpso_vec.end(); ++vit) 
    {
        (*vit)->httpso_unload(cycle);
    }
    httpso_vec.clear();
    httpso_handler_map.clear();
}

static ngx_int_t 
ngx_httpso_entry_load(ngx_cycle_t *cycle, const char *httpso_path)
{
    struct dirent       **namelist;
    int                   n;
    ngx_int_t             rc, ret;

    ret = rc = NGX_OK;
    n = scandir(httpso_path, &namelist, NULL, alphasort);
    if (n < 0) 
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_http_load_httpso|errno=%d", errno);
        return NGX_ERROR;
    }
    else 
    {
        while (n--) 
        {
            struct dirent *ent = namelist[n];
            if (ent->d_type & DT_DIR) 
            {
                 if(ngx_strcmp(ent->d_name, ".") == 0 
                    || ngx_strcmp(ent->d_name, "..") == 0) 
                 {
                     free(ent);
                     continue;
                 }
                 rc = ngx_httpso_load_process(cycle, 
                         httpso_path, 
                         ent->d_name, 
                         ngx_httpso_entry_load);
                 if (rc != NGX_OK) 
                 {
                     ret = rc;
                 }
            }
            if (ent->d_type & DT_REG)
            {
                 size_t filename_len = ngx_strlen(ent->d_name);
                 if (filename_len < 3 || ent->d_name[filename_len - 1] != 'o'
                     || ent->d_name[filename_len - 2] != 's'
                     || ent->d_name[filename_len - 3] != '.')
                 {
                     free(ent);
                     ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                         "ngx_http_load_httpso|don't load %s,"
                         " file name must end with \".so\"\n", ent->d_name);
                     continue;
                 }
                 rc = ngx_httpso_load_process(cycle, 
                    httpso_path, 
                    ent->d_name, 
                    ngx_httpso_load_i);
                 if (rc != NGX_OK) 
                 {
                    ret = rc;
                 }
            }
            free(ent);
        }
        free(namelist);
    }

    return ret;
}


static ngx_int_t
ngx_httpso_load_process(ngx_cycle_t *cycle, 
    const char *path, 
    const char *fname, 
    load_httpso_process_pt h)
{
    char           *new_path;
    ngx_int_t       ret;

    new_path = ngx_httpso_concat_filename(path, fname);
    if (new_path == NULL) 
    {
        return NGX_ERROR;
    }
    ret = (*h)(cycle, new_path);
    free(new_path);

    return ret;
}


static ngx_int_t 
ngx_httpso_load_i(ngx_cycle_t *cycle, const char *sofile)
{
    void                  *handle;
    ngx_httpso_t          *httpso;
    httpso_load_pt         soload;
    httpso_unload_pt       sounload;
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
        "ngx_http_load_httpso_i|sofile=%s", sofile);
    handle = dlopen(sofile, RTLD_NOW);
    if (! handle) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_http_load_httpso_i|dlopen %s|errno=%d|errmsg=%s\n", 
            sofile, errno, dlerror());
        goto failed;
    }

    dlerror();
    *(void **) (&soload) = dlsym(handle, NGX_HTTPSO_LOAD);
    if (soload == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_http_load_httpso_i|dlsym %s:%s|errno=%d|errmsg=%s\n", 
            sofile, NGX_HTTPSO_LOAD, errno, dlerror());
        goto failed;
    }
    *(void **) (&sounload) = dlsym(handle, NGX_HTTPSO_UNLOAD);
    if (sounload == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_http_load_httpso_i|dlsym %s:%s|errno=%d|errmsg=%s\n", 
            sofile, NGX_HTTPSO_UNLOAD, errno, dlerror());
        goto failed;
    }
  
    httpso = (ngx_httpso_t *)ngx_pcalloc(cycle->pool, sizeof(ngx_httpso_t));
    if (NULL == httpso)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                      "ngx_http_load_httpso_i|ngx_pcalloc failed");
        return NGX_ERROR;
    }
    httpso->httpso_load = soload;
    httpso->httpso_unload = sounload;
    httpso_vec.push_back(httpso);
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, 
        "ngx_http_load_httpso_i|load %s\n", sofile);

    return NGX_OK;

failed:
    if (handle != NULL) {
        dlclose(handle);
    }
    return NGX_ERROR;
}


static char *
ngx_httpso_concat_filename(const char *httpso_path, const char *fname)
{
    int new_path_len;
    char *new_path;

    new_path_len = ngx_strlen(httpso_path) + ngx_strlen(fname) + 2;
    new_path = (char *) malloc(new_path_len);
    ngx_memset(new_path, 0, new_path_len);
    if (new_path == NULL)
        return NULL;
    ngx_sprintf((u_char *)new_path, "%s/%s", httpso_path, fname);

    return new_path;
}

static long
ngx_httpso_pkg_handler_add(void *cycle_param, 
                         const char *name, const size_t name_len,
                         httpso_handler_pt h)
{
    ngx_cycle_t *cycle = (ngx_cycle_t *)cycle_param;
    std::string key(name, name_len);
    if (httpso_handler_map.insert(
            std::pair<std::string, httpso_handler_pt>(key, h)).second)
    {
        ngx_log_error(NGX_LOG_INFO, cycle->log, 0, 
            "ngx_http_pkg_handler_add|http_handler_map.insert success|"
            "key=%s", key.c_str());
        return NGX_OK;
    }
    else
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_http_pkg_handler_add|http_handler_map.insert failed|"
            "key=%s", key.c_str());
        return NGX_ERROR;
    }
}

static void 
ngx_httpso_async_work_check(ngx_event_t *ev)
{
    ngx_http_request_t *r;
    AsyncWorkEntryPtr work_entry;
    ngx_httpso_async_work_timeout_event_t *async_ev;
    ngx_httpso_async_work_complete_check_event_t *complete_evc = 
        (ngx_httpso_async_work_complete_check_event_t *)ev;

    while (true) {
        work_entry = async_work.async_work_ptr->AsyncWorkPopComplete();
        if (work_entry) {
            async_ev = (ngx_httpso_async_work_timeout_event_t *)
                work_entry->ctx->async_timeout_ev;
            ngx_del_timer(((ngx_event_t *)async_ev));
            (*work_entry->complete_call_in_ngx)();
            r = (ngx_http_request_t *)work_entry->ctx->request;
            ngx_http_finalize_request(r, 0);
            --complete_evc->to_check_count;
        } else {
            break;
        }
    }
    if (complete_evc->to_check_count > 0) {
        ngx_add_timer(ev, complete_evc->expire_time);
    }

    return;
}

static void 
ngx_httpso_async_work_timeout(ngx_event_t *ev)
{
    ngx_httpso_async_work_timeout_event_t  *async_ev = 
        (ngx_httpso_async_work_timeout_event_t *)ev;

    async_ev->async_work_timeout = true;

    return;
}

static long
httpso_async_work_add(AsyncWorkEntryPtr &e)
{
    ngx_http_request_t *r;
    ngx_int_t           rc;
//    ngx_http_request_t *sr; /* subrequest object */
//#define HTTPSO_ASYNC_WORK_SUB_REQ "/httpso_async_work_sub_req"
//    ngx_str_t           location = {sizeof(HTTPSO_ASYNC_WORK_SUB_REQ) - 1, 
//                                    (u_char *)HTTPSO_ASYNC_WORK_SUB_REQ};

    rc = async_work.async_work_ptr->AsyncWorkAddWork(e);
    if (rc != NGX_OK)
        return rc;
    ngx_httpso_async_work_timeout_event_t *async_ev = 
        (ngx_httpso_async_work_timeout_event_t *)e->ctx->async_timeout_ev;
    if (async_work.check_ev.to_check_count == 0) {
        ngx_add_timer((ngx_event_t *)(&async_work.check_ev), 
            async_work.check_ev.expire_time);
    }
    ++async_work.check_ev.to_check_count;
    async_ev->work_entry = e;
    ngx_add_timer((ngx_event_t *)async_ev, async_ev->expire_time);

    r = (ngx_http_request_t *)e->ctx->request;
    r->main->count++;
    // rc = ngx_http_subrequest(r, &location, NULL, &sr, NULL, 0);

    return rc;
}


static void *
ngx_httpso_create_loc_conf(ngx_conf_t *cf)
{
    ngx_httpso_loc_conf_t *hlcf;

    hlcf = (ngx_httpso_loc_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_httpso_loc_conf_t));
    if (hlcf == NULL) {
        return NULL;
    }

    hlcf->async_worker_threads = NGX_CONF_UNSET;
    hlcf->async_work_complete_check = NGX_CONF_UNSET_MSEC;
    hlcf->async_work_expire = NGX_CONF_UNSET_MSEC;

    return hlcf;
}

static char *
ngx_httpso_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_httpso_loc_conf_t *prev = (ngx_httpso_loc_conf_t *)parent;
    ngx_httpso_loc_conf_t *conf = (ngx_httpso_loc_conf_t *)child;

    ngx_conf_merge_value(conf->async_worker_threads, prev->async_worker_threads, 3);
    ngx_conf_merge_msec_value(conf->async_work_complete_check, prev->async_work_complete_check, 10);
    ngx_conf_merge_msec_value(conf->async_work_expire, prev->async_work_expire, 6000);

    async_work.async_worker_threads = conf->async_worker_threads;
    async_work.check_ev.expire_time = conf->async_work_complete_check;

    return NGX_CONF_OK;
}

