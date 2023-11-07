/*
 * iso21177-proxy.h
 */

#pragma once

#include <string>
#include <list>

class ProxyRule
{
public:
	ProxyRule(const std::string &_src_file, const std::string &_dst_host, const int _dst_port, const std::string &_dst_file) :
		src_file(_src_file),
		dst_host(_dst_host),
		dst_port(_dst_port),
		dst_file(_dst_file)
	{}
	
	const std::string  src_file;
	const std::string  dst_host;
	const int          dst_port;
	const std::string  dst_file;
};


extern std::list<ProxyRule>  rules;
extern int                   optVerbose;

extern void        removeClient(int fd);
extern const char *bin2hex(unsigned char *bin, unsigned int len);
