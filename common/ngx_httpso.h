
#ifndef _HTTPSO_H_
#define _HTTPSO_H_

#include "ngx_httpso_entry.h"

#ifdef __cplusplus
extern "C"
{
#endif
    
long 
httpso_load(void *cycle_param, httpso_handler_add_pt add_h, int slot, 
                 ngx_httpso_cycle_ctx_t *cycle_ctx);
long 
httpso_unload(void *cycle_param);
/* You can initialize a global variable to execute it;
 * exp:
 *  static void init_func(ngx_httpso_cycle_ctx_t *cycle_ctx);
 *  static long g_init_ret = httpso_init_handler_add(init_func);
 *  static handler(ngx_httpso_ctx_t *ctx);
 *  static long g_add_handler_ret = httpso_handler_add("hello", 5, handler)
 */
typedef void 
(*httpso_init_handler_pt)(ngx_httpso_cycle_ctx_t *cycle_ctx);
/* This function is used to mount its own initialization function */ 
long 
httpso_init_handler_add(httpso_init_handler_pt h);

/*used to add httpso_handler, name is the match uri */
long 
httpso_handler_add(const char* name, const size_t name_len,
                      httpso_handler_pt h);
#ifdef __cplusplus
}
#endif

#endif
