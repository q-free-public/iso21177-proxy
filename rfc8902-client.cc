// https://github.com/openssl/openssl/issues/6904

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>

#include "http-headers.h"

/* Managed by IANA */
enum CertificateType {
	 CertificateTypeX509 = 0,
	 CertificateTypeRawPublicKey = 2,
	 CertificateType1609Dot2 = 3
};

#define CERT_HASH_LEN 8

unsigned char      optAtOrEcCertHash[CERT_HASH_LEN] = { 0xC4, 0x3B, 0x88, 0xB2, 0x35, 0x81, 0xDD, 0x3B };
uint64_t           optPsid = 36;
int                optSetCertPsid = 0;
int                optUseAtCert = 0;
int                optForceX509 = 0;
char               optSecEntHost[INET_ADDRSTRLEN] = "127.0.0.1";
short unsigned int optSecEntPort = 3999;
char               optServerHost[INET_ADDRSTRLEN] = "127.0.0.1";
short unsigned int optServerPort = 3322;
bool               optHttpMode = false;
const char        *optUrl = "/3023.text";

FILE *keylog_client_file = NULL;

void handler(int signal) {
    fprintf(stderr, "Server received %d signal\n", signal);
	if (signal == SIGINT) {
		exit(1);
	}
}

void keylog_client_cb_func(const SSL *ssl, const char *line) {
	if (keylog_client_file != NULL) {
		fprintf(keylog_client_file, "%s\n", line);
		fflush(keylog_client_file);
	} else {
		printf("keylog_client_cb_func: %s\n", line);
	}
}

void print_hex_array(int len, const unsigned char * ptr) {
	for (int i = 0; i < len; i++) {
		printf("%02X", ptr[i]);
	}
}

int ssl_send_message(SSL *s, char * message, size_t message_len)
{
	int processed = 0;

//	printf("Sending [%zd] %.*s\n", message_len, (int)message_len, message);
	for (const char *start = message; start - message < (int)message_len; start += processed) {

		processed = SSL_write(s, start, message_len - (start - message));
		printf("Client SSL_write returned %d\n", processed);
		if (processed <= 0) {
			int ssl_err = SSL_get_error(s, processed);
			if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
				fprintf(stderr, "ssl_send_message failed: ssl_error=%d: ", ssl_err);
				ERR_print_errors_fp(stderr);
				fprintf(stderr, "\n");
			}
		}
	};

	return processed;
}

int ssl_recv_message(SSL *s, char * buff, size_t buff_len)
{
	int processed = SSL_read(s, buff, buff_len);
	if (processed > 0) {
		printf("SSL_read: max:%d  ret:%d\n%.*s\n", (int) buff_len, processed, processed, buff);
	} else {
		printf("SSL_read: Error  ret:%d\n", processed);
	}
	return processed;
}

int ssl_print_1609_status(SSL *s)
{
	printf("Information about the other side of the connection:\n");
	uint64_t psid;
	size_t ssp_len;
	uint8_t *ssp = NULL;
	unsigned char hashed_id[CERT_HASH_LEN];

	if (SSL_get_1609_psid_received(s, &psid, &ssp_len, &ssp, hashed_id) <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "SSL_get_1609_psid_received failed\n");
		return 0;
	}
	long verify_result = 0;
	if ((verify_result = SSL_get_verify_result(s)) != X509_V_OK) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "SSL_get_verify_result failed %ld\n", verify_result);
		free(ssp);
		return 0;
	}

	printf("   Peer verification      %ld %s\n", verify_result, verify_result == 0 ? "OK" : "FAIL");
	printf("   Psid used for TLS is   %llu\n", (long long unsigned int)psid);
	printf("   SSP used for TLS are   ");
	print_hex_array(ssp_len, ssp);
	printf("\n");
	printf("   Cert used for TLS is   ");
	print_hex_array(CERT_HASH_LEN, hashed_id);
	printf("\n");

	free(ssp);
	ssp = 0;

	if (psid != optPsid) {
		printf("   Expected PSID/AID      %lu, peer had %ld - aborting\n", (unsigned long) optPsid, (unsigned long) psid);
		return 0;
	}

	return 1;
}

static int ssl_set_RFC8902_values(SSL *ssl, int server_support, int client_support) {
	if (!SSL_enable_RFC8902_support(ssl, server_support, client_support, optUseAtCert)) {
		fprintf(stderr, "SSL_enable_RFC8902_support failed\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	if (optForceX509) {
		if (1 != SSL_use_PrivateKey_file(ssl, "client.key.pem", SSL_FILETYPE_PEM)) {
			fprintf(stderr, "SSL_CTX_use_PrivatKey_file failed: ");
			ERR_print_errors_fp(stderr);
			return 0;
		}
		if (1 != SSL_use_certificate_file(ssl, "client.cert.pem", SSL_FILETYPE_PEM)) {
			fprintf(stderr, "SSL_CTX_use_certificate_file failed: ");
			ERR_print_errors_fp(stderr);
			return 0;
		}
	} else {
		if (!optUseAtCert) {
			if (!SSL_use_1609_cert_by_hash(ssl, optAtOrEcCertHash)) {
				fprintf(stderr, "SSL_use_1609_cert_by_hash failed\n");
				ERR_print_errors_fp(stderr);
				return 0;
			}
		}
		if (optSetCertPsid) {
			if (!SSL_use_1609_PSID(ssl, optPsid)) {
				fprintf(stderr, "SSL_use_1609_PSID failed\n");
				ERR_print_errors_fp(stderr);
				return 0;
			}
		}
	}
	return 1;
}

std::string replace(std::string subject, const std::string& search, const std::string& replace) {
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
    return subject;
}

void client()
{
	int client_socket = -1;
	SSL_CTX *ssl_ctx = 0;
	SSL *ssl = 0;
	int processed = 0;
	int retval;

	struct sigaction action;
	sigset_t sigset;
	sigemptyset(&sigset);
	action.sa_handler = handler;
	action.sa_flags = 0;
	action.sa_mask = sigset;
	sigaction(SIGPIPE, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	keylog_client_file = fopen("keylog_client.txt", "a");
	if (keylog_client_file == NULL) {
		perror("Error opening file!");
		exit(EXIT_FAILURE);
	}

	/* Client */
	printf("Client connection to %s at port %d\n", optServerHost, optServerPort);
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket < 0) {
		perror("socket failed");
		exit(1);
	}
	struct sockaddr_in server_addr;
	memset((char*)&server_addr, 0, sizeof(server_addr));  /* 0 out the structure */
	server_addr.sin_family = AF_INET;   /* address family */
	server_addr.sin_port = htons(optServerPort);
	server_addr.sin_addr.s_addr = inet_addr(optServerHost);
	if (connect(client_socket, (const struct sockaddr *)&server_addr, sizeof(server_addr))) {
		perror("connect failed");
		exit(1);
	}
	printf("TCP connected.\n");

	/*if (!OPENSSL_init_ssl(0, NULL)) {
		fprintf(stderr, "OPENSSL_init_ssl failed\n");
		exit(EXIT_FAILURE);
	}*/
	/*OpenSSL_add_ssl_algorithms();*/
	ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!ssl_ctx) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		exit(1);
	}
	SSL_CTX_set_keylog_callback(ssl_ctx, keylog_client_cb_func);
	if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION)) {
		fprintf(stderr, "SSL_CTX_set_min_proto_version failed: ");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (1 != SSL_CTX_load_verify_locations(ssl_ctx, "ca.cert.pem", NULL)) {
		fprintf(stderr, "SSL_CTX_load_verify_locations failed: ");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
		ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_new failed\n");
		exit(1);
    }
	if (!SSL_set_1609_sec_ent_addr(ssl, optSecEntPort, optSecEntHost)) {
		fprintf(stderr, "SSL_set_1609_sec_ent_addr failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    int server_support = SSL_RFC8902_1609; //  | SSL_RFC8902_X509;
    int client_support = SSL_RFC8902_1609; //  | SSL_RFC8902_X509;
    if (optForceX509) {
    	client_support = SSL_RFC8902_X509;
    }
	if (!ssl_set_RFC8902_values(ssl, server_support, client_support)) {
		exit(EXIT_FAILURE);
	}
    if (!SSL_set_fd(ssl, client_socket)) {
		ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_set_fd failed\n");
        exit(1);
    }
    if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_connect failed\n");
        exit(1);
    }
    printf("SSL connected.\n");
    if (ssl_print_1609_status(ssl) <= 0) {
    	exit(1);
    }

	 HttpHeaders headers;
    int send_messages = 1;
    while (send_messages) {
		 char line[1024];
	    size_t line_len = 1024;

		int ssl_error = SSL_get_error(ssl, processed);
		ERR_print_errors_fp(stderr);
		if (ssl_error) {
			printf("Client thinks a server finished sending data\n");
			ERR_print_errors_fp(stderr);
		}

	    ssize_t ret_line_len = 0;
	    if (optHttpMode) {
			ret_line_len = sprintf(line, "GET %s HTTP/1.1\r\n\r\n", optUrl);
	    } else {
			 printf("input message to server, type exit or ^C to quit, send \"shutdown\" to stop the server\n");
			 char *line_ptr = line;
			 line_len = sizeof(line);
		    if ((ret_line_len = getline(&line_ptr, &line_len, stdin)) == -1) {
			      fprintf(stderr, "getline failed\n");
				   exit(1);
			 } else {
					break;
		    }
	    }

		 printf("Sending '%s'\n", replace(line, "\r\n", " CRLF ").c_str());
	    if (ssl_send_message(ssl, line, ret_line_len) < 0) {
	    	exit(1);
	    }
	    if ((processed = ssl_recv_message(ssl, line, sizeof(line))) <= 0) {
		    int ssl_error = SSL_get_error(ssl, processed);
		    ERR_print_errors_fp(stderr);
		    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
			    printf("Client thinks a server finished sending data\n");
			    ERR_print_errors_fp(stderr);
			    break;
		    }
		    if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
			    fprintf(stderr, "Client read failed: ssl_error=%d errno=%s: \n", ssl_error, strerror(errno));
			    ERR_print_errors_fp(stderr);
			    exit(1);
		    }
	    }

		 headers.add_data(line, processed);
	    printf("Client write finished. received %d bytes\n", processed);
	    if (strcmp(line, "exit\n") == 0) {
		    printf("Exiting client...\n");
		    send_messages = 0;
	    }
	    if (optHttpMode) {
	    	printf("Client exiting HTTP request mode...\n");
	    	send_messages = 0;
	    }
    }

    retval = SSL_shutdown(ssl);
    if (retval < 0) {
        int ssl_err = SSL_get_error(ssl, retval);
        fprintf(stderr, "Client SSL_shutdown failed: ssl_err=%d\n", ssl_err);
		ERR_print_errors_fp(stderr);
        exit(1);
    }
    printf("Client shut down TLS session.\n");

    if (retval != 1) {
        /* Consume all server's data to access the server's shutdown */
	     char buff[1000-30];
		  int totlen = 0;
		  int loopcnt = 0;
	     while (true) {
				int len = ssl_recv_message(ssl, buff, sizeof(buff));
				if (len <= 0) break;
			   totlen += len;
			   loopcnt++;
			   printf("looping %d %d\n", totlen, loopcnt);
        }
		  printf("Client received %d bytes in %d loops.  ContentLen was %d bytes\n", totlen, loopcnt, headers.get_content_length());

        retval = SSL_shutdown(ssl);
        if (retval != 1) {
            int ssl_err = SSL_get_error(ssl, retval);
            fprintf(stderr, "Waiting for server shutdown using SSL_shutdown failed: ssl_err=%d\n", ssl_err);
			   exit(1);
        }
    }
    printf("Client thinks a server shut down the TLS session.\n");

    if (shutdown(client_socket, SHUT_RDWR)) {
        perror("client shutdown failed");
		exit(1);
    }
    printf("Client shut down TCP.\n");

    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
	fclose(keylog_client_file);

    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	int opt, rc;
	unsigned long long ull;

	printf("Test program for TLS 1.3 with RF8902 support\n");

	while ((opt = getopt(argc, argv, "p:a:Hxn:b:de:f:")) != -1) {
		switch (opt) {
		case 'p':
			rc = sscanf(optarg, "%hu", &optServerPort);
			if (rc < 1) {
				fprintf(stderr, "String-integer conversion error for %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'H': optHttpMode = true; break;
		case 'x': optForceX509 = 1; break;
		case 'a':
			strncpy(optServerHost, optarg, INET_ADDRSTRLEN);
			break;
		case 'n':
			rc = sscanf(optarg, "%llu", &ull);
			if (rc < 1) {
				fprintf(stderr, "String-integer conversion error for %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			optPsid = ull;
			optSetCertPsid = 1;
			break;
		case 'b': {
			const char * pos_str = optarg;
			int pos_hash = 0; 
			if (2*CERT_HASH_LEN != strlen(optarg)) {
				fprintf(stderr, "Wrong length hex string %s - expected %d\n", optarg, 2*CERT_HASH_LEN);
				exit(EXIT_FAILURE);
			}
			for (int i = 0; i < CERT_HASH_LEN; i++) {
				rc = sscanf(pos_str, "%2hhx", &optAtOrEcCertHash[pos_hash]);
				if (rc < 1) {
					fprintf(stderr, "Failed to parse hex string %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				pos_hash++;
				pos_str += 2;
			}
			optSetCertPsid = 1;
			}	
			break;
		case 'd':
			optUseAtCert = 1;
			break;
		case 'e':
			strncpy(optSecEntHost, optarg, INET_ADDRSTRLEN);
			break;
		case 'f':
			rc = sscanf(optarg, "%hu", &optSecEntPort);
			if (rc < 1 || optSecEntPort > 0xffff) {
				fprintf(stderr, "Error for security entity port number: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "Usage: %s [options] [FILE]\n"
					"  -p port  - server port\n"
					"  -a host  - server address\n"
					"  -H       - http client mode\n"
					"  -x       - force X509 cert\n"
					"  -d       - use current AT certificate\n"
					"  -n PSID  - specify PSID value (default %llu)\n"
					"  -b HASH  - specify cert hash to use\n"
					"  -e ADDR  - sec_ent address\n"
					"  -f PORT  - sec_ent port\n"
					"  FILE     - File part of the URL (starting with /, default is '%s')\n", argv[0], (long long unsigned int) optPsid, optUrl);
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		// Command line argument after the options.
		optUrl = argv[optind++];
   }
			  
	printf("Using port %hu\n", optServerPort);
	printf("Connecting to sec_ent at %s port %hu\n", optSecEntHost, optSecEntPort);
	if (optUseAtCert) {
		printf("Using current (default) AT certficate");
	} else {
		printf("Using certificate ");
		print_hex_array(CERT_HASH_LEN, optAtOrEcCertHash);
	}
	if (optSetCertPsid) {
		printf(" with PSID %llu\n", (long long unsigned int)optPsid);
	} else {
		printf(" with default PSID 36\n");
	}
	printf("URL (file part): %s\n", optUrl);

	client();
	
	return 0;
}
