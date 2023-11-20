// connection-client.h

#pragma once

#include <string>

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
