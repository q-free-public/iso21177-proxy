/*
 * iso21177-proxy.cc
 *
 * Copyright Q-Free Norge AS 2023
 */

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>

#include <string>
#include <vector>
#include <list>
#include <thread>

#include "iso21177-proxy.h"
#include "proxy-client.h"
#include "utils.h"

int				optVerbose = 0;  // For compatibility with utils.cc
int				optProxyPlainPort = 8888;
int				optProxyRfc8902Port = 8877;
int				optProxyIso21177Port = 8866;

const char    *optSecurityEntityAddress = "127.0.0.1";
int 				optSecurityEntityPort = 3999;
uint64_t			optRfc8902Aid = 36;
bool				optRfc8902UseCurrentAtCert = true;
unsigned char  optRfc8902EcOrAtCertHash[CERT_HASH_LEN];
const char    *optCaCertPath = "ca.cert.pem";

const char iso21177_proxy_vsn_string[] = "v0.2 " __DATE__ " " __TIME__;
std::list<ProxyClient> clientList;
std::list<ProxyRule>  rules;
std::thread httpPlainThread;
std::thread httpRfc8902Thread;


void handle_usr1(int signo, siginfo_t *info, void *extra);

void usage(const char *argv0)
{
	std::string prog = "/" + std::string(argv0);
	prog = prog.substr(prog.rfind("/") + 1);

   printf("Usage: %s [-v] [-V] [-d device]\n", prog.c_str());
   printf("   -V                     print version\n");
   printf("   -h                     print this usage information\n");
   printf("   -v                     verbose (can be repeated to get more debug output).\n");
   printf("   -p n                   Port number for plain-text HTTP (default is %d)\n", optProxyPlainPort);
   printf("   -rfc n                 Port number for RFC 8902 HTTP (default is %d)\n", optProxyRfc8902Port);
   printf("   -iso n                 Port number for ISO 21177 HTTP (default is %d)\n", optProxyRfc8902Port);
	printf("   -se-host n             Security entity host name (default is %s)\n", optSecurityEntityAddress);
	printf("   -se-port n             Security entity port number (default is %d)\n", optSecurityEntityPort);
   printf("   -rfc8902-aid n         Expected AID from client in RFC8902 (default %ld)\n", (long)optRfc8902Aid);
   printf("   -rfc8902-at            Use current AT certificate (default)\n");
   printf("   -rfc8902-cert xxxx     Use 1609 certificate given by this hash. 8 bytes / 16 hex digits\n");
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
	rules.push_back(ProxyRule("/vg",               false, "www.vg.no",          80, "/"));
	rules.push_back(ProxyRule("/its1-100",         false, "its1.q-free.com",  8888, "/100.text"));
	rules.push_back(ProxyRule("/its1-s",           true,  "its1.q-free.com",   443, "/index.html"));
	rules.push_back(ProxyRule("/datex-speed.json", true,  "its1.q-free.com",   443, "/geoserver/speed.json"));
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
      } else if (strcmp(argv[i], "-rfc") == 0  && i<argc-1) {
         optProxyRfc8902Port = atoi(argv[i+1]);
         i++;
      } else if (strcmp(argv[i], "-iso") == 0  && i<argc-1) {
         optProxyIso21177Port = atoi(argv[i+1]);
         i++;
      } else if (strcmp(argv[i], "-se-port") == 0  && i<argc-1) {
         optSecurityEntityPort = atoi(argv[i+1]);
         i++;
      } else if (strcmp(argv[i], "-se-host") == 0  && i<argc-1) {
         optSecurityEntityAddress = argv[i+1];
         i++;
      } else if (strcmp(argv[i], "-rfc8902-aid") == 0  && i<argc-1) {
			optRfc8902Aid = atol(argv[i+1]);
			if (optRfc8902Aid == 0) {
				printf("RFC8902 AID error\n");
				usage(argv[0]);
				exit(1);
			}
         i++;
      } else if (strcmp(argv[i], "-rfc8902-cert") == 0  && i<argc-1) {
			if (2*CERT_HASH_LEN != strlen(argv[i+1])) {
				printf("Wrong length of hex string %s - expected %d hex digits.\n", argv[i+1], 2*CERT_HASH_LEN);
				usage(argv[0]);
				exit(1);
			}
			for (int j = 0; j < CERT_HASH_LEN; j++) {
				int hex;
				int rc = sscanf(argv[i+1] + j*2, "%2x", &hex);
				if (rc < 1) {
					printf("Failed to parse hex string for certificate hash: %s\n", argv[i+1]);
					exit(EXIT_FAILURE);
				}
				optRfc8902EcOrAtCertHash[j] = hex;
			}
			optRfc8902UseCurrentAtCert = false;
			i++;
      } else if (strcmp(argv[i], "-rfc8902-at") == 0) {
			optRfc8902UseCurrentAtCert = true;
      } else {
         printf("Illegal command line option '%s'\n", argv[i]);
         usage(argv[0]);
         exit(3);
      }
   }
}

ProxyClient *addClient(int fd, const struct sockaddr_in6 &addrClient)
{
	static int serial = 0;
   ProxyClient client;
	client.serial = serial++;
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
			if (optVerbose >= 1) {
				printf("removeClient: Mark client with fd=%d serial=%d as completed\n", fd, it->serial);
			}
         it->completed = true;
         it->fd = -1;
         time(&it->closeTime);
         return;
      }
   }

   printf("Error: client with fd=%d not found\n", fd);
}

void cleanupClients()
{
   for (auto it=clientList.begin(); it!=clientList.end(); ++it) {
      if (it->pThread && it->completed) {
         printf("cleanupClients: Remove client from list serial=%d fd=%d\n", it->serial, it->fd);
         it->pThread->join();
         delete it->pThread;
			it->pThread = 0;
         clientList.erase(it);
         break;
      }
   }
}

int create_server_socket(int port)
{
   int nFdSocket = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
   if (nFdSocket == -1) {
      printf("socket(TCP) failed: %s", strerror(errno));
      return -1;
   }

   const int one = 1;
   int status = setsockopt(nFdSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
   if (status == -1) {
      printf("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
		close(nFdSocket);
      return -1;
   }

   struct sockaddr_in6 addrLocal6;
   memset(&addrLocal6, 0, sizeof(addrLocal6));
   addrLocal6.sin6_family = AF_INET6;
   addrLocal6.sin6_port = htons(port);
   addrLocal6.sin6_addr = in6addr_any;
   status = bind(nFdSocket, (struct sockaddr*) &addrLocal6, sizeof(addrLocal6));
   if (status == -1) {
      printf("bind(TCP,port=%d) failed: %s", port, strerror(errno));
		close(nFdSocket);
      return -1;
   }

   status = listen(nFdSocket, 5);
   if (status == -1) {
      printf("listen failed: %s", strerror(errno));
		close(nFdSocket);
      return -1;
   }
	
	return nFdSocket;
}

void keylog_srv_cb_func(const SSL *ssl, const char *line) {
   if (optVerbose >= 1) {
		printf("%s\n", line);
	}
}

bool create_context(CtxWrapper &ret)
{
	ret = (SSL_CTX_new(TLS_server_method()));
	if (ret == 0) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		return false;
	}
	SSL_CTX_set_keylog_callback(ret, keylog_srv_cb_func);
	if (!SSL_CTX_set_min_proto_version(ret, TLS1_3_VERSION)) {
		fprintf(stderr, "SSL_CTX_set_min_proto_version failed: ");
		ERR_print_errors_fp(stderr);
		return false;
	}
	if (1 != SSL_CTX_load_verify_locations(ret, optCaCertPath, NULL)) {
		fprintf(stderr, "SSL_CTX_load_verify_locations failed: %s\n", optCaCertPath);
		ERR_print_errors_fp(stderr);
		return false;
	}

	return true;
}

void plain_http_thread_proc()
{
   if (optVerbose >= 1) {
      printf("iso21177-proxy starting up - Plain HTTP on port %d\n", optProxyPlainPort);
   }

	struct sigaction action;
   action.sa_flags = SA_SIGINFO; 
   action.sa_sigaction = handle_usr1;
   sigaction(SIGUSR1, &action, NULL); 

	int nFdSocket = create_server_socket(optProxyPlainPort);
   if (nFdSocket == -1) {
      printf("socket(TCP) failed for port %d: %s", optProxyPlainPort, strerror(errno));
      exit(11);
   }

   while (true) {
      struct sockaddr_in6 addrClient;
      memset(&addrClient, 0, sizeof(addrClient));
      socklen_t addrClientLen = sizeof(addrClient);
		if (optVerbose) {
			printf("Waiting for plain HTTP connection on fd=%d\n", nFdSocket);
		}
      int fdClient = accept(nFdSocket, (sockaddr*)&addrClient, &addrClientLen);
      if (fdClient >= 0) {
         if (optVerbose) {
            printf("Starting thread for new incoming HTTP connection fd=%d  rem-port=%d\n", fdClient, ntohs(addrClient.sin6_port));
         }
         auto newCliPtr = addClient(fdClient, addrClient);
         std::thread *gpsdClientThread = new std::thread([newCliPtr] { newCliPtr->client_proc(); } );
         newCliPtr->pThread = gpsdClientThread;
      } else {
         if (optVerbose) {
            perror("plain_http_thread_proc: accept error");
         }
         break;
      }
      cleanupClients();
   }

   printf("Exiting HTTP accept loop.\n");
}

void rfc8902_http_thread_proc()
{
   if (optVerbose >= 1) {
      printf("iso21177-proxy starting up - RFC8902 HTTP on port %d\n", optProxyRfc8902Port);
   }
	
	struct sigaction action;
   action.sa_flags = SA_SIGINFO; 
   action.sa_sigaction = handle_usr1;
   sigaction(SIGUSR1, &action, NULL);

	CtxWrapper ssl_ctx;
	if (!create_context(ssl_ctx)) {
		fprintf(stderr, "create_context failed\n");
		exit(10);
	}
	
	int nFdSocket = create_server_socket(optProxyRfc8902Port);
   if (nFdSocket == -1) {
      printf("socket(TCP) failed for port %d: %s", optProxyRfc8902Port, strerror(errno));
      exit(11);
   }
	
   while (true) {
      struct sockaddr_in6 addrClient;
      memset(&addrClient, 0, sizeof(addrClient));
      socklen_t addrClientLen = sizeof(addrClient);
		if (optVerbose) {
			printf("Waiting for RFC8902 HTTP connection on fd=%d\n", nFdSocket);
		}
      int fdClient = accept(nFdSocket, (sockaddr*)&addrClient, &addrClientLen);
      if (fdClient >= 0) {
         if (optVerbose) {
            printf("Starting thread for new incoming HTTP connection fd=%d  rem-port=%d\n", fdClient, ntohs(addrClient.sin6_port));
         }
         auto newCliPtr = addClient(fdClient, addrClient);
			SSL_CTX *ctx = ssl_ctx; // ‘ctx’ is not captured
         std::thread *gpsdClientThread = new std::thread([ctx, newCliPtr] { newCliPtr->rfc8902_proc(ctx); } );
         newCliPtr->pThread = gpsdClientThread;
      } else {
         if (optVerbose) {
            perror("rfc8902_http_thread_proc: accept error");
         }
         break;
      }
      cleanupClients();
   }
}

const char *bin2hex(const unsigned char *bin, unsigned int len)
{
	static char buffer[1000];
	buffer[0] = 0;
	for (unsigned int i=0; i<len && strlen(buffer) < sizeof(buffer) - 5; i++) {
		sprintf(buffer + strlen(buffer) , "%02x ", bin[i]);
	}
	return buffer;
}

void init_openssl_library(void)
{
	/* https://www.openssl.org/docs/ssl/SSL_library_init.html */
	SSL_library_init();

#if OPENSSL_VERSION_NUMBER > 0x20000000
#else
	/* https://www.openssl.org/docs/crypto/ERR_load_crypto_strings.html */
	SSL_load_error_strings();

	/* SSL_load_error_strings loads both libssl and libcrypto strings */
	ERR_load_crypto_strings();

	/* OpenSSL_config may or may not be called internally, based on */
	/*  some #defines and internal gyrations. Explicitly call it    */
	/*  *IF* you need something from openssl.cfg, such as a         */
	/*  dynamically configured ENGINE.                              */
	OPENSSL_config(NULL);
#endif
}

void handle_usr1(int signo, siginfo_t *info, void *extra) 
{
	printf("handle_usr1: signo %d in accept thread\n", signo);
}

void handle_sigint(int intr)
{
	printf("Handle SIGINT in main thread\n");
	pthread_kill(httpPlainThread.native_handle(), SIGUSR1);
	pthread_kill(httpRfc8902Thread.native_handle(), SIGUSR1);
}

int main(int argc, char *argv[])
{
	create_rules();
	parseargs(argc, argv);

   if (optVerbose >= 1) {
      printf("iso21177-proxy\n");
      unsigned long xx = OPENSSL_VERSION_NUMBER; // MN NF FP PS: major minor fix patch status
      printf("openssl verion:                  %ld.%ld.%ldp%ld (%ld)\n", (xx >> 28), (xx>>20)&0xff, (xx>>12)&0xff, (xx>>4)&0xff, (xx&0x0f));
		printf("Verbose:                         %d\n", optVerbose);
		printf("Port number for plain HTTP:      %d\n", optProxyPlainPort);
		printf("Port number for RFC8902 HTTP:    %d\n", optProxyRfc8902Port);
		printf("Port number for ISO 21177 HTTP:  %d\n", optProxyIso21177Port);
		printf("Security entity address:         %s  port %d\n", optSecurityEntityAddress, optSecurityEntityPort);
		printf("RFC8902 AID (PSID):              %ld\n", (long) optRfc8902Aid);
		printf("Use specific AT/EC certificate:  %s\n", (!optRfc8902UseCurrentAtCert) ? bin2hex(optRfc8902EcOrAtCertHash, CERT_HASH_LEN) : "Use default AT certificate");
		printf("CA certificate path:             %s\n", optCaCertPath);
   }

   signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, handle_sigint);

	init_openssl_library();

   httpPlainThread = std::thread(plain_http_thread_proc);
   httpRfc8902Thread = std::thread(rfc8902_http_thread_proc);

	httpPlainThread.join();
	httpRfc8902Thread.join();
	
	return 0;
}
