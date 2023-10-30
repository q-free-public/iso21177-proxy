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

int optVerbose = 0;  // Separate redundant variable for compatibility with utils.cc
int optGpsdPort = 8080;
const char iso21177_proxy_vsn_string[] = "v0.1 " __DATE__ " " __TIME__;

void proxyAcceptProc(void *ublox);

void usage(const char *argv0)
{
	std::string prog = "/" + std::string(argv0);
	prog = prog.substr(prog.rfind("/") + 1);
//	UbloxSettings defaults;
	
   printf("Usage: %s [-v] [-V] [-d device]\n", prog.c_str());
   printf("   -V                     print version\n");
   printf("   -h                     print this usage information\n");
   printf("   -v                     verbose (can be repeated to get more debug output), output goes to stderr.\n");
   printf("   -p n                   Port number (default is %d)\n", optGpsdPort);
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
         optGpsdPort = atoi(argv[i+1]);
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
	proxyAcceptProc((void*)0);
#else
   std::thread gpsdAcceptThread(proxyAcceptProc, (void*)0);
	// detach() let thread run until process is terminated without any resource cleanup by the application. The OS will handle everything.
	gpsdAcceptThread.detach();
#endif

	return 0;
}

void gpsdClientProc(void *ublox, int fd)
{
   if (optVerbose) {
      fprintf(stderr, "Starting gpsdClientProcess fd=%d\n", fd);
   }
   while (true) {
      char buf[1000];
      int len = read(fd, buf, sizeof(buf)-1);
      if (len == 0) {
         break;
      } 
      if (len < 0) {
         if (optVerbose) {
            perror("gpsdClientProc: read error");
         }
         break;
      } 
      buf[len] = 0;
      if (optVerbose) {
         fprintf(stderr, "Read %d bytes from client: %s\n", len, buf);
      }
      //ublox->gpsdClientCommand(fd, buf);
   }

   if (optVerbose) {
      fprintf(stderr, "Closing socket %d\n", fd);
   }
   //ublox->removeClient(fd);
   close(fd);
}

void proxyAcceptProc(void *ublox)
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
   addrLocal6.sin6_port = htons(optGpsdPort);
   addrLocal6.sin6_addr = in6addr_any;
   status = bind(nFdSocket, (struct sockaddr*) &addrLocal6, sizeof(addrLocal6));
   if (status == -1) {
      send2log(LOG_ERR, "bind(TCP,port=%d) failed: %s", optGpsdPort, strerror(errno));
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
         std::thread *gpsdClientThread = new std::thread(gpsdClientProc, ublox, fdClient);
			gpsdClientThread->detach();
         //ublox->addClient(gpsdClientThread, fdClient, addrClient);
      } else {
         if (optVerbose) {
            perror("proxyAcceptProc: accept");
         }
         break;
      }
      //ublox->cleanupClients();
   }
   fprintf(stderr, "Exiting accept loop.\n");
}
