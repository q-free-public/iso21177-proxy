/*
 * iso21177-proxy.cc
 *
 * Copyright Q-Free Norge AS 2023
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <cmath>
#include <mutex>

#include "utils.h"
#include "iso21177-proxy.h"
#include "http-headers.h"

int optVerbose = 0;  // Separate redundant variable for compatibility with utils.cc
int optProxyPlainPort = 8080;
const char iso21177_proxy_vsn_string[] = "v0.1 " __DATE__ " " __TIME__;
std::vector<ProxyClient> clientList;

void proxyPlainAcceptProc(void *ublox);

void usage(const char *argv0)
{
	std::string prog = "/" + std::string(argv0);
	prog = prog.substr(prog.rfind("/") + 1);
//	UbloxSettings defaults;

   printf("Usage: %s [-v] [-V] [-d device]\n", prog.c_str());
   printf("   -V                     print version\n");
   printf("   -h                     print this usage information\n");
   printf("   -v                     verbose (can be repeated to get more debug output), output goes to stderr.\n");
   printf("   -p n                   Port number for HTTP (default is %d)\n", optProxyPlainPort);
}

void parseargs(int argc, char *argv[])
{
   for (int i=1; i<argc; i++) {
      if (strcmp(argv[i], "-V") == 0) {
         printf("iso21177-proxy version %s\n", iso21177_proxy_vsn_string);
         exit(0);
      } else if (strncmp(argv[i], "-v", 2) == 0) {
         for (const char *v=argv[i]+1; *v; v++)
            optVerbose++;
      } else if (strcmp(argv[i], "-h") == 0) {
         usage(argv[0]);
         exit(0);
      } else if (strcmp(argv[i], "-p") == 0  && i<argc-1) {
         optProxyPlainPort = atoi(argv[i+1]);
         i++;
      } else {
         printf("Illegal command line option '%s'\n", argv[i]);
         usage(argv[0]);
         exit(3);
      }
   }
}


int main(int argc, char *argv[])
{
	parseargs(argc, argv);

   if (optVerbose >= 1) {
      printf("iso21177-proxy starting up\n");
   }

#if 1
	proxyPlainAcceptProc((void*)0);
#else
   std::thread gpsdAcceptThread(proxyPlainAcceptProc, (void*)0);
	// detach() let thread run until process is terminated without any resource cleanup by the application. The OS will handle everything.
	gpsdAcceptThread.detach();
#endif

	return 0;
}

void send(int fd, const std::string &hdr, const unsigned char *body, unsigned int body_len)
{
	if (optVerbose) {
		fprintf(stderr, "Sending Header: %s\nFollowed by %u bytes body.\n", hdr.c_str(), body_len);
	}

	int pos = 0;
	int len = hdr.size();
	while (pos < len) {
		int ret = write(fd, hdr.c_str() + pos, len);
		if (optVerbose) {
			fprintf(stderr, "Sending %d bytes on fd=%d  -->  sent %d\n", len, fd, ret);
		}
		if (ret <= 0) {
			return;
		}
		pos += ret;
		len -= ret;
	}

	pos = 0;
	len = body_len;
	while (pos < len) {
		int ret = write(fd, body + pos, len);
		if (optVerbose) {
			fprintf(stderr, "Sending %d bytes on fd=%d  -->  sent %d\n", len, fd, ret);
		}
		if (ret <= 0) {
			return;
		}
		pos += ret;
		len -= ret;
	}
}

void send(int fd, const std::string &hdr, const std::string &body)
{
	send(fd, hdr, (const unsigned char *)body.c_str(), body.size());
}

void emit_error(int fd, int code, const std::string &text)
{
	std::string body;
	body += "<html>\r\n";
	body += "Unsupported request<p>\r\n";
	body += "Error code " + std::to_string(code) + "<p>\r\n";
	body += text + "\r\n";
	body += "</html>\r\n";

	std::string hdr;
	hdr += "HTTP/1.1 " + std::to_string(code) + " Error\r\n";
	hdr += "Content-Type: text/html\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(fd, hdr, body);
}

void handle_get_html(int fd, int size)
{
	const std::string source = "Q-Free is a prime mover in the world of smart, safe, and sustainable transportation management. We go to work every day hoping to do two things: improve mobility and make the world a little better. Collectively, we channel our energy to influence and develop the global ITS community. We improve traffic flow, road safety, and air quality in communities all over the world. ";
	std::string body;
	body += "<html>\r\n";
	while ((int)body.size() < size) {
		body += source;
	}
	if ((int)body.size() > size)
		body = body.substr(0, size);
	body += "</html>\r\n";

	std::string hdr;
	hdr += "HTTP/1.1 200 OK\r\n";
	hdr += "Content-Type: text/html\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(fd, hdr, body);
}

void handle_get_text(int fd, int size)
{
	const std::string source = "Q-Free is a prime mover in the world of smart, safe, and sustainable transportation management.\r\n";
	std::string body;
	while ((int)body.size() < size) {
		body += source;
	}
	if ((int)body.size() > size)
		body = body.substr(0, size);

	std::string hdr;
	hdr += "HTTP/1.1 200 OK\r\n";
	hdr += "Content-Type: text/plain\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(fd, hdr, body);
}

void handle_get_bin(int fd, int size)
{
	std::vector<unsigned char> body;
	unsigned char ch = 0;
	while ((int)body.size() < size) {
		body.push_back(ch++);
	}

	std::string hdr;
	hdr += "HTTP/1.1 200 OK\r\n";
	hdr += "Content-Type: application/octet-stream\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(fd, hdr, body.data(), body.size());
}

void handle_get(int fd, const std::string &file)
{
	if (optVerbose) {
		fprintf(stderr, "Handle get: %s\n", file.c_str());
	}

	int size, cnt;

	// Request HTML file of abritary length
	cnt = sscanf(file.c_str(), "/%d.html", &size);
	fprintf(stderr, "cnt %d   find %d\n", cnt, (int) file.find(".html"));
	if (cnt == 1 && file.find(".html") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_html(fd, size);
		return;
	}

	cnt = sscanf(file.c_str(), "/%d.text", &size);
	if (cnt == 1 && file.find(".text") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_text(fd, size);
		return;
	}

	cnt = sscanf(file.c_str(), "/%d.bin", &size);
	if (cnt == 1 && file.find(".bin") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_bin(fd, size);
		return;
	}

	emit_error(fd, 400, "Illegal URL");
}

void addClient(std::thread *pThread, int fd, const struct sockaddr_in6 &addrClient)
{
   ProxyClient client;
   client.pThread = pThread;
   client.fd = fd;
   client.addrClient = addrClient;
   char buffer[INET6_ADDRSTRLEN];
   int err = getnameinfo((struct sockaddr*)&addrClient,sizeof(addrClient),buffer,sizeof(buffer), 0,0,NI_NUMERICHOST);
   if (err==0) {
      client.addrClientStr = buffer;
      client.addrClientStr += ",";
      client.addrClientStr += std::to_string(ntohs(addrClient.sin6_port));
   }
   client.completed = false;
   client.closeTime = 0;
   time(&client.openTime);
   clientList.push_back(client);
}

void removeClient(int fd)
{
   for (auto it=clientList.begin(); it!=clientList.end(); ++it) {
      if (it->fd == fd) {
         // fprintf(stderr, "Mark client as completed\n");
         it->completed = true;
         it->fd = -1;
         time(&it->closeTime);
         return;
      }
   }
   fprintf(stderr, "client with fd=%d not found\n", fd);
}

void cleanupClients()
{
   for (auto it=clientList.begin(); it!=clientList.end(); ++it) {
      if (it->completed) {
         // fprintf(stderr, "Remove client from list\n");
         it->pThread->join();
         delete it->pThread;
         clientList.erase(it);
         break;
      }
   }
}

void proxyPlainClientProc(void *ublox, int fd)
{
   if (optVerbose) {
      fprintf(stderr, "Starting proxyPlainClientProc fd=%d\n", fd);
   }

	HttpHeaders headers;
   while (!headers.is_complete()) {
      char buf[1000];
      int len = read(fd, buf, sizeof(buf)-1);
      if (len == 0) {
         break;
      }
      if (len < 0) {
         if (optVerbose) {
            perror("proxyPlainClientProc: read error");
         }
         break;
      }
		headers.add_data(buf, len);
   }

   if (optVerbose) {
		fprintf(stderr, "Header is complete\n");
		for (auto &line : headers.headerlines) {
			fprintf(stderr, "%s\n", line.c_str());
		}
		fprintf(stderr, "Verb:  %s\n", headers.get_verb().c_str());
		fprintf(stderr, "Proto: %s\n", headers.get_protocol().c_str());
		fprintf(stderr, "File:  %s\n", headers.get_file().c_str());
   }

	if (headers.get_verb() == "GET") {
		handle_get(fd, headers.get_file());
	} else {
		emit_error(fd, 500, "Illegal verb: " + headers.get_verb());
	}

   if (optVerbose) {
      fprintf(stderr, "Closing socket %d\n", fd);
   }
   removeClient(fd);
   close(fd);
}

void proxyPlainAcceptProc(void *ublox)
{
   int nFdSocket = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
   if (nFdSocket == -1) {
      send2log(LOG_ERR, "socket(TCP) failed: %s", strerror(errno));
      exit(11);
   }

   const int one = 1;
   int status = setsockopt(nFdSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
   if (status == -1) {
      send2log(LOG_ERR, "setsockopt(reusedaddr) failed: %s", strerror(errno));
      exit(12);
   }

   struct sockaddr_in6 addrLocal6;
   memset(&addrLocal6, 0, sizeof(addrLocal6));
   addrLocal6.sin6_family = AF_INET6;
   addrLocal6.sin6_port = htons(optProxyPlainPort);
   addrLocal6.sin6_addr = in6addr_any;
   status = bind(nFdSocket, (struct sockaddr*) &addrLocal6, sizeof(addrLocal6));
   if (status == -1) {
      send2log(LOG_ERR, "bind(TCP,port=%d) failed: %s", optProxyPlainPort, strerror(errno));
      exit(12);
   }

   status = listen(nFdSocket, 5);
   if (status == -1) {
      send2log(LOG_ERR, "listen failed: %s", strerror(errno));
      exit(13);
   }

   while (true) {
      struct sockaddr_in6 addrClient;
      memset(&addrClient, 0, sizeof(addrClient));
      socklen_t addrClientLen = sizeof(addrClient);
		if (optVerbose) {
			fprintf(stderr, "Waiting for connection on fd=%d  ptr=%p\n", nFdSocket, ublox);
		}
      int fdClient = accept(nFdSocket, (sockaddr*)&addrClient, &addrClientLen);
      if (fdClient >= 0) {
         if (optVerbose) {
            fprintf(stderr, "Starting thread for new incoming connection fd=%d  ptr=%p\n", fdClient, ublox);
         }
         std::thread *gpsdClientThread = new std::thread(proxyPlainClientProc, ublox, fdClient);
         addClient(gpsdClientThread, fdClient, addrClient);
      } else {
         if (optVerbose) {
            perror("proxyPlainAcceptProc: accept");
         }
         break;
      }
      cleanupClients();
   }

   fprintf(stderr, "Exiting accept loop.\n");
}
