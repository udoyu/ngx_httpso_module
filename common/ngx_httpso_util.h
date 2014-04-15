/* 
 * File:   ngx_httpso_util.h
 */

#ifndef NGX_HTTPSO_UTIL_H
#define	NGX_HTTPSO_UTIL_H

#include <map>
#include <string>

void
ngx_httpso_get_args(const u_char* data, const size_t datalen, 
    std::map<std::string, std::string>& ret);

#endif	/* NGX_HTTPSO_UTIL_H */

