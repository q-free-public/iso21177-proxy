// connection-client.h

#pragma once

#include <string>

#include <openssl/ssl.h>
#include <openssl/bio.h>

class ConnectionClient
{
public:
	virtual ~ConnectionClient() {}
	
	virtual bool connect(const std::string &host, int port) = 0;
	virtual bool send(const void *data, unsigned int len) = 0;
	virtual int recv(unsigned char *data, unsigned int maxlen) = 0;
	virtual void close() = 0;
};


class ConnectionClientTcp : public ConnectionClient
{
public:
	ConnectionClientTcp();
	virtual ~ConnectionClientTcp();
	
	virtual bool connect(const std::string &host, int port);
	virtual bool send(const void *data, unsigned int len);
	virtual int  recv(unsigned char *data, unsigned int maxlen);
	virtual void close();
	
private:
	int sd;
};



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


class ConnectionClientTls : public ConnectionClient
{
public:
	ConnectionClientTls();
	virtual ~ConnectionClientTls();
	
	virtual bool connect(const std::string &host, int port);
	virtual bool send(const void *data, unsigned int len);
	virtual int  recv(unsigned char *data, unsigned int maxlen);
	virtual void close();
	
private:
	BioWrapper web;
	CtxWrapper ctx;
};
