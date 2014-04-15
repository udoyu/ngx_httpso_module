extern "C"
{
#include "ngx_httpso.h"
static long 
pp_pkg_handler(ngx_httpso_ctx_t *ctx);
}
#include "ngx_httpso_util.h"
#include "ngx_httpso_entry.h"

static long init_ret = httpso_handler_add("test", 4, pp_pkg_handler);
static long 
pp_pkg_handler(ngx_httpso_ctx_t *ctx)
{
	ngx_httpso_log_error(NGX_HTTPSO_LOG_INFO, &ctx->httpso_log, 0, 
		"pp_pkg_handler|uri=%s|init_ret()=%d", 
        ctx->httpso_req.uri.data, init_ret);
    std::map<std::string, std::string> form;
    ngx_httpso_get_args(ctx->httpso_req.args.data, ctx->httpso_req.args.len,
                        form);
    if (ctx->method & NGX_HTTPSO_POST)
        ngx_httpso_get_args(ctx->httpso_req.body.data, ctx->httpso_req.body.len,
                        form);
	std::map<std::string, std::string>::iterator it = form.find("key");
    if (it != form.end())
        ctx->send_data(ctx, (u_char*)it->second.c_str(), it->second.size());	
    return NGX_HTTPSO_ERROR;
}

