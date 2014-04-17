/* 
 * File:   ngx_httpso_entry_so.h
 */

#ifndef NGX_NGX_HTTPSO_ENTRY_H
#define	NGX_NGX_HTTPSO_ENTRY_H

#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>
#include <functional>
#include <memory>
#include <thread>

/* */
typedef intptr_t        httpso_int_t;
typedef uintptr_t       httpso_uint_t;
typedef intptr_t        httpso_flag_t;
typedef int             httpso_err_t;

#define NGX_HTTPSO_UNKNOWN                   0x0001
#define NGX_HTTPSO_GET                       0x0002
#define NGX_HTTPSO_HEAD                      0x0004
#define NGX_HTTPSO_POST                      0x0008
#define NGX_HTTPSO_PUT                       0x0010
#define NGX_HTTPSO_DELETE                    0x0020
#define NGX_HTTPSO_MKCOL                     0x0040
#define NGX_HTTPSO_COPY                      0x0080
#define NGX_HTTPSO_MOVE                      0x0100
#define NGX_HTTPSO_OPTIONS                   0x0200
#define NGX_HTTPSO_PROPFIND                  0x0400
#define NGX_HTTPSO_PROPPATCH                 0x0800
#define NGX_HTTPSO_LOCK                      0x1000
#define NGX_HTTPSO_UNLOCK                    0x2000
#define NGX_HTTPSO_PATCH                     0x4000
#define NGX_HTTPSO_TRACE                     0x8000

#define NGX_HTTPSO_LOG_STDERR            0
#define NGX_HTTPSO_LOG_EMERG             1
#define NGX_HTTPSO_LOG_ALERT             2
#define NGX_HTTPSO_LOG_CRIT              3
#define NGX_HTTPSO_LOG_ERR               4
#define NGX_HTTPSO_LOG_WARN              5
#define NGX_HTTPSO_LOG_NOTICE            6
#define NGX_HTTPSO_LOG_INFO              7
#define NGX_HTTPSO_LOG_DEBUG             8

#define  NGX_HTTPSO_OK          0
#define  NGX_HTTPSO_ERROR      -1
#define  NGX_HTTPSO_AGAIN      -2
#define  NGX_HTTPSO_BUSY       -3
#define  NGX_HTTPSO_DONE       -4
#define  NGX_HTTPSO_DECLINED   -5
#define  NGX_HTTPSO_ABORT      -6

#define ngx_httpso_log_error(level, httpso_log_ptr, ...) \
    if ((httpso_log_ptr)->log_level >= level) \
        (httpso_log_ptr)->log_error(level, (httpso_log_ptr)->log, __VA_ARGS__)

typedef struct ngx_httpso_ctx_s ngx_httpso_ctx_t;
typedef long (*httpso_send_data_pt)(ngx_httpso_ctx_t *ctx, 
    const u_char *data, 
    const size_t len);
typedef struct{
    u_char *data;
    size_t  len;
}ngx_httpso_str_t;

typedef void (*httpso_log_error_pt)(httpso_uint_t level, void *log, 
    httpso_err_t err, 
    const char *fmt, ...);

typedef void *(*httpso_alloc_pt)(void *pool, size_t size);
typedef httpso_int_t (*httpso_pfree_pt)(void *pool, void *p);
typedef struct ngx_httpso_req_s httpso_req_t;
typedef long (*httpso_handler_pt)(ngx_httpso_ctx_t *ctx);

typedef struct ngx_httpso_cycle_ctx_s ngx_httpso_cycle_ctx_t;
typedef long
(*httpso_handler_add_pt)(void *cycle_param, 
    const char *name, const size_t name_len,
    httpso_handler_pt h);

struct ngx_httpso_log_s {
    void                *log;
    httpso_uint_t        log_level;
    httpso_log_error_pt  log_error;
};
typedef struct ngx_httpso_log_s ngx_httpso_log_t;

struct ngx_httpso_req_s {
    ngx_httpso_str_t uri;
    ngx_httpso_str_t args;
    ngx_httpso_str_t body;
};


/* async work */
typedef std::function<int(void)> AsyncWorkFunc;
typedef std::shared_ptr<AsyncWorkFunc> AsyncWorkFuncPtr;
typedef std::shared_ptr<std::thread> ThreadPtr;
struct AsyncWorkEntry
{
    AsyncWorkFuncPtr  work_call_in_async;
    AsyncWorkFuncPtr  work_call_timeout;
    AsyncWorkFuncPtr  complete_call_in_ngx;
    ngx_httpso_ctx_t *ctx;
};
typedef std::shared_ptr<AsyncWorkEntry> AsyncWorkEntryPtr;
typedef long (*httpso_async_work_add_pt)(AsyncWorkEntryPtr &e);

struct ngx_httpso_ctx_s {
    /* httpso_sessioin array. the slot is init in httpso_load func */
    void                 *request;
    httpso_send_data_pt   send_data;
    ngx_httpso_log_t      httpso_log;
    httpso_uint_t         method;
    httpso_req_t          httpso_req;
    
    void                 *pool;
    httpso_alloc_pt       palloc;
    httpso_alloc_pt       pcalloc;
    httpso_pfree_pt       pfree;

    httpso_async_work_add_pt               async_work_add;
    void                                  *async_timeout_ev;
    void                 *ctx_data;
};

struct ngx_httpso_cycle_ctx_s {
	   ngx_httpso_log_t         httpso_log;
};


#define NGX_HTTPSO_LOAD          "httpso_load"
#define NGX_HTTPSO_UNLOAD        "httpso_unload"
#define NGX_HTTPSO_SESS_INIT     "httpso_sess_init"
#define NGX_HTTPSO_SESS_FINIT    "httpso_sess_finit"

typedef long 
(*httpso_load_pt)(void *cycle_param, httpso_handler_add_pt add_h, int slot, 
    ngx_httpso_cycle_ctx_t *cycle_ctx);

typedef long (*httpso_unload_pt)(void *cycle_param);

typedef struct {
    httpso_load_pt        httpso_load;
    httpso_unload_pt      httpso_unload;
} ngx_httpso_t;

#endif

