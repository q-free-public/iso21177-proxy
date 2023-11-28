// proxy-client.h

#pragma once

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <string>
#include <thread>

#include "iso21177-proxy.h"

class ConnectionClient;
class CtxWrapper;

class ProxyClient
{
public:
   std::thread *pThread;
   
   // Client variables
	int          serial;
   int          fd;
   struct sockaddr_in6 addrClient;
   std::string  addrClientStr;
   time_t       openTime;
   time_t       closeTime;
   bool         completed;
   long         recvPck;
   long         recvBytes;
   long         sendPck;
   long         sendBytes;

	void client_proc();
	void rfc8902_proc(SSL_CTX *ssl_ctx);

protected:
	void send(int sd, const void *data, unsigned int len);
	void send(SSL *ssl, const void *data, unsigned int len);
	int recv(int sd, void *data, unsigned int len);
	int recv(SSL *ssl, void *data, unsigned int len);

	template<typename T> void send(T handle, const std::string &hdr, const unsigned char *body, unsigned int body_len);
	template<typename T> void send(T handle, const std::string &hdr, const std::string &body);
	template<typename T> void emit_error(T handle, int code, const std::string &text);
	template<typename T> void handle_get_html(T handle, int size);
	template<typename T> void handle_get_text(T handle, int size);
	template<typename T> void handle_get_bin(T handle, int size);
	template<typename T> void handle_get_proxy(T handle, ConnectionClient *conn, const std::string &file, const ProxyRule &rule);
	template<typename T> void handle_get(T handle, const std::string &file);
	template<typename T> void handle_post(T handle, const std::string &file, const std::string &content_type, int content_length);
};
