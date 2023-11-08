// connection-client-tcp.cc

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "iso21177-proxy.h"
#include "connection-client.h"

ConnectionClientTcp::ConnectionClientTcp()
{
	sd = -1;
}

ConnectionClientTcp::~ConnectionClientTcp()
{
	if (sd >= 0)
		close();
}
	
bool ConnectionClientTcp::connect(const std::string &host, int port)
{
	if (port <= 0)
		return false;
	if (host.size() == 0)
		return false;

   // Resolve destination address
   int addrLen = 0;
   struct sockaddr_in6 destAddress;
   memset(&destAddress, 0, sizeof(destAddress));
   {
      struct addrinfo *res = 0;
      struct addrinfo hints;
      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_UNSPEC;
      int status = getaddrinfo(host.c_str(), 0, &hints, &res);
      // printf("After getaddrinfo status %d   res->ai_family %d\n", status, res==0 ? -1 : res->ai_family);
      if (status == 0 && res->ai_family == AF_INET6) {
         memcpy(&destAddress, res->ai_addr, res->ai_addrlen);
         freeaddrinfo(res);
         destAddress.sin6_port = htons(port);
         addrLen = sizeof(struct sockaddr_in6);
      } else if (status == 0 && res->ai_family == AF_INET) {
         struct sockaddr_in * destAddress4 = (struct sockaddr_in *) &destAddress;
         memcpy(destAddress4, res->ai_addr, res->ai_addrlen);
         freeaddrinfo(res);
         destAddress4->sin_port = htons(port);
         addrLen = sizeof(struct sockaddr_in);
      } else {
         if (optVerbose) {
            printf("getaddrinfo(%s) failed: %s\n", host.c_str(), gai_strerror(status));
         }
         errno = EADDRNOTAVAIL;
         return false;
      }
   }

   // Create socket
   sd = socket(destAddress.sin6_family, SOCK_STREAM, IPPROTO_TCP);
   if (sd == -1) {
      printf("socket(UDP) failed: %s\n", strerror(errno));
      return false;
   }

   int opts = 1;
   int status = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *) &opts, sizeof(int));
   if (status < 0) {
      printf("setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
      ::close(sd);
		sd = -1;
      return false;
   }

   if (optVerbose) {
      char szHost[128];
      int status = getnameinfo((struct sockaddr *)&destAddress, addrLen, szHost, sizeof(szHost), 0, 0, NI_NUMERICHOST);
      if (status == 0) {
         printf("Connecting to %s\n", szHost);
      }
   }

   // Connect to remote TCP server
   int rc = ::connect(sd, (struct sockaddr *) &destAddress, addrLen);
   if (rc == -1) {
		if (optVerbose) {
         printf("Connect to %s,%d failed: %s\n", host.c_str(), port, strerror(errno));
      }
      ::close(sd);
		sd = -1;
      return false;
   }

   if (optVerbose) {
      printf("Connected to %s at port %d at socket %d\n", host.c_str(), port, sd);
   }

	return true;
}

bool ConnectionClientTcp::send(const void *data_p, unsigned int len)
{
	const char *data = (const char*) data_p;
	unsigned int pos = 0;
	while (pos < len) {
		int ret = ::write(sd, data + pos, len);
		if (optVerbose) {
			printf("Sending %u bytes on fd=%d  -->  sent %d\n", len, sd, ret);
		}
		if (ret <= 0) {
			return false;
		}
		pos += ret;
		len -= ret;
	}
	
	return true;
}

int ConnectionClientTcp::recv(unsigned char *data, unsigned int maxlen)
{
	return ::read(sd, data, maxlen);
}

void ConnectionClientTcp::close()
{
	if (optVerbose) {
		printf("Closing ConnectionClientTcp %d\n", sd);
	}
	::close(sd);
	sd = -1;
}
