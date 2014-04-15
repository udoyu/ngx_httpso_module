#include "ngx_httpso_util.h"
#include <algorithm>

static int char_to_lower(int c)
{
	if(c >= 'A' && c <= 'Z') 
		c += 32;
	return c;
}

static std::string str_to_lower(const char* data, const size_t datalen)
{
	std::string s(data, datalen);
	std::transform(s.begin(), s.end(), s.begin(), char_to_lower);
	return s;
}

void
ngx_httpso_get_args(const u_char* data, const size_t datalen, 
                      std::map<std::string, std::string>& ret)
{
    unsigned int ix_beg = 0;
    unsigned int ix_end = 0;
	
    while (true)
    {
        std::string key;
        std::string val;
 
        ix_beg = ix_end;
        while (ix_end < datalen && '=' != data[ix_end])
            ++ix_end;
        if (ix_end >= datalen)
            break;
        key.assign(str_to_lower((char*)(data + ix_beg), ix_end - ix_beg).c_str(), ix_end - ix_beg);
        ++ix_end;
 
        ix_beg = ix_end;
        while (ix_end < datalen && '&' != data[ix_end])
            ++ix_end;
        val.assign((char *)(data + ix_beg), ix_end - ix_beg);
        ++ix_end;
 
        ret.insert(std::pair<std::string, std::string>(key, val));
	}
}
