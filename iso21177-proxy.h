/*
 * iso21177-proxy.h
 */

#pragma once

#include <string>
#include <list>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define CERT_HASH_LEN 8

class CtxWrapper
{
public:
	CtxWrapper() : ctx(0) {};
	CtxWrapper(SSL_CTX *c) : ctx(c) { };
	CtxWrapper(const CtxWrapper &rhs) = delete;
	~CtxWrapper() { if (ctx) SSL_CTX_free(ctx); ctx = 0; };
	CtxWrapper & operator=(CtxWrapper &&rhs) { ctx = rhs.ctx; rhs.ctx = 0; return *this; };
	operator SSL_CTX *() const { return ctx; }
private:
	SSL_CTX *ctx;
};

class BioWrapper
{
public:
	BioWrapper() : bio(0) {};
	BioWrapper(BIO *c) : bio(c) {};
	BioWrapper(const BioWrapper &rhs) = delete;
	~BioWrapper() { if (bio) BIO_free_all(bio); bio = 0; };
	BioWrapper & operator=(BioWrapper &&rhs) { bio = rhs.bio; rhs.bio = 0; return *this; };
	operator BIO *() const { return bio; }
private:
	BIO *bio;
};


class ProxyRule
{
public:
	ProxyRule(const std::string &_src_file, const bool _dst_https, const std::string &_dst_host, const int _dst_port, const std::string &_dst_file) :
		src_file(_src_file),
		dst_https(_dst_https),
		dst_host(_dst_host),
		dst_port(_dst_port),
		dst_file(_dst_file)
	{}
	
	const std::string  src_file;
	bool               dst_https;
	const std::string  dst_host;
	const int          dst_port;
	const std::string  dst_file;
};


// Command line options
extern int           optVerbose;
extern const char   *optSecurityEntityAddress;
extern int           optSecurityEntityPort;
extern uint64_t      optRfc8902Aid;
extern bool          optRfc8902UseCurrentAtCert;
extern unsigned char optRfc8902EcOrAtCertHash[CERT_HASH_LEN];

// Other global variables
extern std::list<ProxyRule>  rules;

// Global functions
extern void        removeClient(int fd);
extern const char *bin2hex(const unsigned char *bin, unsigned int len);
extern std::string get_log_filename(const std::string &dir, const std::string &prefix);
