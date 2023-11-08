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

class ProxyClient
{
public:
   std::thread *pThread;
   
   // Client variables
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

protected:
	void send(const std::string &hdr, const unsigned char *body, unsigned int body_len);
	void send(const std::string &hdr, const std::string &body);
	void send(int sd, const void *data, unsigned int len);
	void emit_error(int code, const std::string &text);
	void handle_get_html(int size);
	void handle_get_text(int size);
	void handle_get_bin(int size);
	void handle_get_proxy(ConnectionClient *conn, const std::string &file, const ProxyRule &rule);
	void handle_get(const std::string &file);
};

