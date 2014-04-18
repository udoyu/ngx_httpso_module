#include "ngx_httpso.h"
#include "ngx_httpso_util.h"
#include "ngx_httpso_entry.h"

static long pp_pkg_handler(ngx_httpso_ctx_t *ctx);
static long pp_pkg_handler_common(ngx_httpso_ctx_t *ctx);

static long async_work_handler(ngx_httpso_ctx_t *ctx);
static int  async_work_call_in_async(ngx_httpso_ctx_t *ctx);
static int  async_work_call_timeout(ngx_httpso_ctx_t *ctx);
static int  async_work_complete_call_in_ngx(ngx_httpso_ctx_t *ctx);

static long init_dummy1 = httpso_handler_add("test", 4, pp_pkg_handler);
static long init_dummy2 = httpso_handler_add("test_async_work", sizeof("test_async_work") - 1, async_work_handler);

static long 
pp_pkg_handler_common(ngx_httpso_ctx_t *ctx)
{
    std::map<std::string, std::string> form;
    ngx_httpso_get_args(ctx->httpso_req.args.data, ctx->httpso_req.args.len,
                        form);
    if (ctx->method & NGX_HTTPSO_POST)
        ngx_httpso_get_args(ctx->httpso_req.body.data, ctx->httpso_req.body.len,
                        form);
    std::map<std::string, std::string>::iterator it = form.find("key");
    if (it != form.end())
        return ctx->send_data(ctx, (u_char*)it->second.c_str(), it->second.size());    
    return NGX_HTTPSO_ERROR;
}

static long 
pp_pkg_handler(ngx_httpso_ctx_t *ctx)
{
    ngx_httpso_log_error(NGX_HTTPSO_LOG_INFO, &ctx->httpso_log, 0, 
        "pp_pkg_handler|uri=%s|init_ret()=%d", 
        ctx->httpso_req.uri.data, init_dummy1);

    return pp_pkg_handler_common(ctx);
}

static long 
async_work_handler(ngx_httpso_ctx_t *ctx)
{
    AsyncWorkEntryPtr e;

    ngx_httpso_log_error(NGX_HTTPSO_LOG_INFO, &ctx->httpso_log, 0, 
        "async_work_handler|uri=%s|init_ret()=%d", 
        ctx->httpso_req.uri.data, init_dummy2);

    e.reset(new AsyncWorkEntry());
    e->ctx = ctx;
    e->work_call_in_async = AsyncWorkFuncPtr(new AsyncWorkFunc(std::bind(async_work_call_in_async, ctx)));
    e->work_call_timeout = AsyncWorkFuncPtr(new AsyncWorkFunc(std::bind(async_work_call_timeout, ctx)));
    e->complete_call_in_ngx = AsyncWorkFuncPtr(new AsyncWorkFunc(std::bind(async_work_complete_call_in_ngx, ctx)));
    ctx->async_work_add(e);

    return NGX_HTTPSO_OK;
}

static int 
async_work_call_in_async(ngx_httpso_ctx_t *ctx)
{
    ngx_httpso_log_error(NGX_HTTPSO_LOG_INFO, &ctx->httpso_log, 0, 
        "async_work_call_in_async|uri=%s", 
        ctx->httpso_req.uri.data);
    //DO Something
    return NGX_HTTPSO_DONE;
}

static int 
async_work_complete_call_in_ngx(ngx_httpso_ctx_t *ctx)
{
    ngx_httpso_log_error(NGX_HTTPSO_LOG_INFO, &ctx->httpso_log, 0, 
        "async_work_complete_call_in_ngx|uri=%s", 
        ctx->httpso_req.uri.data);

    return pp_pkg_handler_common(ctx);
}

static int 
async_work_call_timeout(ngx_httpso_ctx_t *ctx)
{
    ngx_httpso_log_error(NGX_HTTPSO_LOG_INFO, &ctx->httpso_log, 0, 
        "async_work_call_timeout|uri=%s", 
        ctx->httpso_req.uri.data);

    return 0;
}

