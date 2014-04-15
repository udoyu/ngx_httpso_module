extern "C" {
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ngx_httpso.h"
}

typedef struct{
	httpso_init_handler_pt *hs;
	unsigned long           size;
	unsigned long           capacity;
}httpso_init_handler_t;

typedef struct{
	ngx_httpso_str_t  name;
	httpso_handler_pt h;
}httpso_handler_t;

typedef struct{
	httpso_handler_t     *hs;
	unsigned long         size;
	unsigned long         capacity;
}httpso_hander_add_t;

static httpso_init_handler_t httpso_init_handler_arr={NULL, 0, 0};
static httpso_hander_add_t httpso_handler_add_arr{NULL, 0, 0};

long httpso_load(void *cycle_param, httpso_handler_add_pt add_h, int slot, 
                 ngx_httpso_cycle_ctx_t *cycle_ctx)
{
	unsigned long i = 0;
    for (i = 0; i < httpso_init_handler_arr.size; ++i)
    {
        httpso_init_handler_arr.hs[i](cycle_ctx);
    }
    
    for (i = 0; i < httpso_handler_add_arr.size; ++i)
    {
        if (httpso_handler_add_arr.hs[i].name.data)
            add_h(cycle_param,(char *)httpso_handler_add_arr.hs[i].name.data, 
                httpso_handler_add_arr.hs[i].name.len,
                httpso_handler_add_arr.hs[i].h);
    }
    
    ngx_httpso_log_error(NGX_HTTPSO_LOG_INFO, &cycle_ctx->httpso_log, 0, 
        "httpso_load|slot=%d|httpso_init_handler_arr.size=%d"
        "httpso_handler_add_arr.size=%d",
        slot,httpso_init_handler_arr.size,
        httpso_handler_add_arr.size);
    return 0;
}

long 
httpso_unload(void *cycle_param)
{
    return 0;
}


long httpso_init_handler_add(httpso_init_handler_pt h)
{
	int capacity = httpso_init_handler_arr.capacity;
	int size = httpso_init_handler_arr.size;
	if (capacity <= size)
	{
		unsigned long newcapaticy = capacity + 10;
		httpso_init_handler_pt *tmp = (httpso_init_handler_pt *)
			malloc(sizeof(httpso_init_handler_pt) * newcapaticy);
		memset(tmp, 0, sizeof(httpso_init_handler_pt) * newcapaticy);
		memcpy(tmp, httpso_init_handler_arr.hs, 
			sizeof(httpso_init_handler_pt) * capacity);
		if (httpso_init_handler_arr.hs)
			free(httpso_init_handler_arr.hs);
		httpso_init_handler_arr.hs = tmp;
		httpso_init_handler_arr.capacity = newcapaticy;
	}
	httpso_init_handler_arr.hs[size] = h;
	httpso_init_handler_arr.size++;
    return 0;
}

long httpso_handler_add(const char* name, const size_t name_len,
                      httpso_handler_pt h)
{
	int capacity = httpso_handler_add_arr.capacity;
	int size = httpso_handler_add_arr.size;
	if (capacity <= size)
	{
		unsigned long newcapaticy = capacity + 10;
		httpso_handler_t *tmp = (httpso_handler_t *)
			malloc(sizeof(httpso_handler_t) * newcapaticy);
		memset(tmp, 0, sizeof(httpso_handler_t) * newcapaticy);
		memcpy(tmp, httpso_handler_add_arr.hs, 
			sizeof(httpso_handler_t) * capacity);
		if (httpso_handler_add_arr.hs)
			free(httpso_handler_add_arr.hs);
		httpso_handler_add_arr.hs = tmp;
		httpso_handler_add_arr.capacity = newcapaticy;
	}
	
	char *key = (char *)malloc(sizeof(u_char) * name_len);
	memcpy(key, name, name_len);
	httpso_handler_add_arr.hs[size].name.data = (u_char*)key;
	httpso_handler_add_arr.hs[size].name.len = name_len;
	httpso_handler_add_arr.hs[size].h = h;
	httpso_handler_add_arr.size++;

    return 0;
}
