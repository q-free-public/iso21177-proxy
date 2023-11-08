/*
 * iso21177-proxy.cc
 *
 * Copyright Q-Free Norge AS 2023
 */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <string>
#include <vector>
#include <list>
#include <thread>

#include "iso21177-proxy.h"
#include "proxy-client.h"
#include "utils.h"

int optVerbose = 0;  // For compatibility with utils.cc
int optProxyPlainPort = 8080;
const char iso21177_proxy_vsn_string[] = "v0.1 " __DATE__ " " __TIME__;
std::list<ProxyClient> clientList;
std::list<ProxyRule>  rules;


void usage(const char *argv0)
{
	std::string prog = "/" + std::string(argv0);
	prog = prog.substr(prog.rfind("/") + 1);

   printf("Usage: %s [-v] [-V] [-d device]\n", prog.c_str());
   printf("   -V                     print version\n");
   printf("   -h                     print this usage information\n");
   printf("   -v                     verbose (can be repeated to get more debug output).\n");
   printf("   -p n                   Port number for HTTP (default is %d)\n", optProxyPlainPort);
   printf("   -l                     List proxy rules\n");
}

void list_rules()
{
	printf("Proxy forwarding rules\n");
	for (const auto &r : rules) {
		if (r.dst_https)
			printf("   %-30s --> https://%s:%d%s\n", r.src_file.c_str(), r.dst_host.c_str(), r.dst_port, r.dst_file.c_str());
		else
			printf("   %-30s --> http://%s:%d%s\n", r.src_file.c_str(), r.dst_host.c_str(), r.dst_port, r.dst_file.c_str());
	}
}

void create_rules()
{
	rules.push_back(ProxyRule("/vg",       false, "www.vg.no",           80, "/"));
	rules.push_back(ProxyRule("/its1-100", false, "its1.q-free.com",   8888, "/100.text"));
	rules.push_back(ProxyRule("/its1-s",   true,  "its1.q-free.com",    443, "/index.html"));
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
      } else if (strcmp(argv[i], "-l") == 0) {
         list_rules();
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

ProxyClient *addClient(int fd, const struct sockaddr_in6 &addrClient)
{
   ProxyClient client;
   client.pThread = 0;
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
   client.recvPck = 0;
   client.recvBytes = 0;
   client.sendPck = 0;
   client.sendBytes = 0;
   clientList.push_back(client);
	
	return &clientList.back();
}

void removeClient(int fd)
{
   for (auto it=clientList.begin(); it!=clientList.end(); ++it) {
      if (it->fd == fd) {
         // printf("Mark client as completed\n");
         it->completed = true;
         it->fd = -1;
         time(&it->closeTime);
         return;
      }
   }
   printf("client with fd=%d not found\n", fd);
}

void cleanupClients()
{
   for (auto it=clientList.begin(); it!=clientList.end(); ++it) {
      if (it->pThread && it->completed) {
         // printf("Remove client from list\n");
         it->pThread->join();
         delete it->pThread;
			it->pThread = 0;
         clientList.erase(it);
         break;
      }
   }
}

void proxyPlainAcceptProc(void *ublox)
{
   int nFdSocket = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
   if (nFdSocket == -1) {
      printf("socket(TCP) failed: %s", strerror(errno));
      exit(11);
   }

   const int one = 1;
   int status = setsockopt(nFdSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
   if (status == -1) {
      printf("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
      exit(12);
   }

   struct sockaddr_in6 addrLocal6;
   memset(&addrLocal6, 0, sizeof(addrLocal6));
   addrLocal6.sin6_family = AF_INET6;
   addrLocal6.sin6_port = htons(optProxyPlainPort);
   addrLocal6.sin6_addr = in6addr_any;
   status = bind(nFdSocket, (struct sockaddr*) &addrLocal6, sizeof(addrLocal6));
   if (status == -1) {
      printf("bind(TCP,port=%d) failed: %s", optProxyPlainPort, strerror(errno));
      exit(12);
   }

   status = listen(nFdSocket, 5);
   if (status == -1) {
      printf("listen failed: %s", strerror(errno));
      exit(13);
   }

   while (true) {
      struct sockaddr_in6 addrClient;
      memset(&addrClient, 0, sizeof(addrClient));
      socklen_t addrClientLen = sizeof(addrClient);
		if (optVerbose) {
			printf("Waiting for HTTP connection on fd=%d  ptr=%p\n", nFdSocket, ublox);
		}
      int fdClient = accept(nFdSocket, (sockaddr*)&addrClient, &addrClientLen);
      if (fdClient >= 0) {
         if (optVerbose) {
            printf("Starting thread for new incoming HTTP connection fd=%d  ptr=%p\n", fdClient, ublox);
         }
         auto newCliPtr = addClient(fdClient, addrClient);
         std::thread *gpsdClientThread = new std::thread([newCliPtr] { newCliPtr->client_proc(); } );
         newCliPtr->pThread = gpsdClientThread;
      } else {
         if (optVerbose) {
            perror("proxyPlainAcceptProc: accept error");
         }
         break;
      }
      cleanupClients();
   }

   printf("Exiting HTTP accept loop.\n");
}

const char *bin2hex(unsigned char *bin, unsigned int len)
{
	static char buffer[1000];
	buffer[0] = 0;
	for (unsigned int i=0; i<len && strlen(buffer) < sizeof(buffer) - 5; i++) {
		sprintf(buffer + strlen(buffer) , "%02x ", bin[i]);
	}
	return buffer;
}

int main(int argc, char *argv[])
{
	create_rules();
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
