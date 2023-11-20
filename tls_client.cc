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

/* Managed by IANA */
 enum CertificateType{
	 CertificateTypeX509 = 0,
	 CertificateTypeRawPublicKey = 2,
	 CertificateType1609Dot2 = 3
 } ;


#define CERT_HASH_LEN 8
unsigned char __1609dot2_ec_cert_hash[CERT_HASH_LEN] = {
	0xC4, 0x3B, 0x88, 0xB2, 0x35, 0x81, 0xDD, 0x3B
};
uint64_t __1609dot2_psid = 623;
int set_cert_psid = 0;
int use_AT_cert = 0;

pid_t server_pid = -1;
int force_x509 = 0;
char sec_ent_ip[INET_ADDRSTRLEN] = "127.0.0.1";
short unsigned int sec_ent_port = 3999;
char server_ip[INET_ADDRSTRLEN] = "127.0.0.1";
int do_exit = 0;

void handler(int signal) {
    fprintf(stderr, "Server received %d signal\n", signal);
	if (signal == SIGINT) {
		fprintf(stderr, "Will initialize the termination\n");
		do_exit = 1;
	}
}


void terminate() {
	if (server_pid >= 0) {
		kill(server_pid, SIGTERM);
	}
	exit(EXIT_FAILURE);
}

FILE *keylog_server_file = NULL;
FILE *keylog_client_file = NULL;

void keylog_client_cb_func(const SSL *ssl, const char *line) {
	if (keylog_client_file != NULL) {
		fprintf(keylog_client_file, "%s\n", line);
		fflush(keylog_client_file);
	} else {
		printf("keylog_client_cb_func: %s\n", line);
	}
}

void keylog_srv_cb_func(const SSL *ssl, const char *line) {
	if (keylog_server_file != NULL) {
		fprintf(keylog_server_file, "%s\n", line);
		fflush(keylog_server_file);
	} else {
		printf("keylog_srv_cb_func: %s\n", line);
	}
}

void print_hex_array(int len, const unsigned char * ptr) {
	for (int i = 0; i < len; i++) {
		printf("%02X", ptr[i]);
	}
}

int ssl_send_message(SSL *s, char * message, size_t message_len) {
	int processed = 0;

	printf("Sending [%zd] %.*s\n", message_len, (int)message_len, message);
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

int ssl_recv_message(SSL *s, char * buff, size_t buff_len) {
	int processed;

	processed = SSL_read(s, buff, buff_len);
	printf("SSL_read returned %d\n", processed);
	if (processed > 0) {
		printf("[recv:] max:%d  ret:%d  %.*s\n", (int) buff_len, (int)processed, (int)processed, buff);
	}
	return processed;
}

int ssl_print_1609_status(SSL *s) {
	printf("Information about the other side of the connection:\n");
	uint64_t psid;
	size_t ssp_len;
	uint8_t *ssp = NULL;
	unsigned char hashed_id[CERT_HASH_LEN];

	if(SSL_get_1609_psid_received(s, &psid, &ssp_len, &ssp, hashed_id) <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "SSL_get_1609_psid_received failed\n");
		return 0;
	}
	long verify_result = 0;
	if((verify_result = SSL_get_verify_result(s)) != X509_V_OK) {
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
	return 1;
}

static int ssl_set_RFC8902_values(SSL *ssl, int server_support, int client_support) {
	if (!SSL_enable_RFC8902_support(ssl, server_support, client_support, use_AT_cert)) {
		fprintf(stderr, "SSL_enable_RFC8902_support failed\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	if (force_x509) {
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
		if (!use_AT_cert) {
			if (!SSL_use_1609_cert_by_hash(ssl, __1609dot2_ec_cert_hash)) {
				fprintf(stderr, "SSL_use_1609_cert_by_hash failed\n");
				ERR_print_errors_fp(stderr);
				return 0;
			}
		}
		if (set_cert_psid) {
			if (!SSL_use_1609_PSID(ssl, __1609dot2_psid)) {
				fprintf(stderr, "SSL_use_1609_PSID failed\n");
				ERR_print_errors_fp(stderr);
				return 0;
			}
		}
	}
	return 1;
}

SSL_CTX *create_context() {
	SSL_CTX *ret = NULL;

	ret = SSL_CTX_new(TLS_server_method());
	if (!ret) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		return NULL;
	}
	SSL_CTX_set_keylog_callback(ret, keylog_srv_cb_func);
	if (!SSL_CTX_set_min_proto_version(ret, TLS1_3_VERSION)) {
		fprintf(stderr, "SSL_CTX_set_min_proto_version failed: ");
		ERR_print_errors_fp(stderr);
		goto err;
	}
	if (1 != SSL_CTX_load_verify_locations(ret, "ca.cert.pem", NULL)) {
		fprintf(stderr, "SSL_CTX_load_verify_locations failed: ");
		ERR_print_errors_fp(stderr);
		goto err;
	}
	return ret;
err:
	SSL_CTX_free(ret);
	return NULL;
}

int create_socket(int port) {
	int sock;
	struct sockaddr_in server_addr;
	int one = 1;

	memset((char *) &server_addr, 0, sizeof(server_addr));  /* 0 out the structure */
	server_addr.sin_family = AF_INET;   /* address family */
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* Server */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket failed");
		goto err;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
		perror("setsockopt failed\n");
		goto err;
	}
	if (bind(sock, (const struct sockaddr *) &server_addr, sizeof(server_addr))) {
		perror("bind failed");
		goto err;
	}
	if (listen(sock, 1)) {
		perror("listen failed");
		goto err;
	}

	return sock;
err:
	close(sock);
	return -1;
}

void server(int server_port, int test_mode) {
	char buffer[1024];
	int processed;
	SSL_CTX *ssl_ctx;
	int sock;
	int retval;

	keylog_server_file = fopen("keylog_server.txt", "a");
	if (keylog_server_file == NULL) {
		perror("Error opening file!");
		exit(EXIT_FAILURE);
	}

	struct sigaction action;
	sigset_t sigset;

	printf("Server\n");

	sigemptyset(&sigset);
	action.sa_handler = handler;
	action.sa_flags = 0;
	action.sa_mask = sigset;
	sigaction(SIGPIPE, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	ssl_ctx = create_context();
	if(ssl_ctx == NULL) {
		fprintf(stderr, "create_context failed\n");
		exit(EXIT_FAILURE);
	}

	sock = create_socket(server_port);
	if(sock <= 0) {
		fprintf(stderr, "create_socket failed\n");
		SSL_CTX_free(ssl_ctx);
		exit(EXIT_FAILURE);
	}

	int handle_clients = 1;
	while (handle_clients && !do_exit) {
		SSL *ssl;
		int client;

		printf("Waiting for client to connect.. \n");

		client = accept(sock, NULL, 0);
		if (client < 0) {
			perror("accept failed");
			continue;
		}
		printf("TCP accepted.\n");

		/*if (!OPENSSL_init_ssl(0, NULL)) {
			fprintf(stderr, "OPENSSL_init_ssl failed\n");
			exit(EXIT_FAILURE);
		}*/
		/*OpenSSL_add_ssl_algorithms();*/
		ssl = SSL_new(ssl_ctx);
		if (!ssl) {
			fprintf(stderr, "SSL_new failed\n");
			exit(EXIT_FAILURE);
		}
		if (!SSL_set_1609_sec_ent_addr(ssl, sec_ent_port, sec_ent_ip)) {
			fprintf(stderr, "SSL_set_1609_sec_ent_addr failed\n");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		int server_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
		int client_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
		if (force_x509) {
			server_support = SSL_RFC8902_X509;
		}
		if (!ssl_set_RFC8902_values(ssl, server_support, client_support)) {
			exit(EXIT_FAILURE);
		}
		if (!SSL_set_fd(ssl, client)) {
			fprintf(stderr, "SSL_set_fd failed\n");
			exit(EXIT_FAILURE);
		}
	#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
		/* TLS 1.3 server sends session tickets after a handhake as part of
		 * the SSL_accept(). If a client finishes all its job before server
		 * sends the tickets, SSL_accept() fails with EPIPE errno. Since we
		 * are not interested in a session resumption, we can not to send the
		 * tickets. */
		/*if (1 != SSL_set_num_tickets(ssl, 0)) {
			fprintf(stderr, "SSL_set_num_tickets failed\n");
			exit(EXIT_FAILURE);
		}
		Or we can perform two-way shutdown. Client must call SSL_read() before
		the final SSL_shutdown(). */
	#endif

		retval = SSL_accept(ssl);
		if (retval <= 0) {
			fprintf(stderr, "SSL_accept failed ssl_err=%d errno=%s\n",
			        SSL_get_error(ssl, retval), strerror(errno));
			ERR_print_errors_fp(stderr);
			continue;
		}
		printf("SSL accepted.\n");
		if (ssl_print_1609_status(ssl) == 0) {
			continue;
		}

		while (1) {
			if ((processed = ssl_recv_message(ssl, buffer, sizeof(buffer))) > 0) {
				printf("[server:] %.*s\n", (int) processed, buffer);
				ssl_send_message(ssl, buffer, processed);
				if (strncmp(buffer, "shutdown\n", processed) == 0) {
					printf("received a shutdown request");
					handle_clients = 0;
					break;
				}
			} else {
				int ssl_error = SSL_get_error(ssl, processed);
				ERR_print_errors_fp(stderr);
				if (ssl_error == SSL_ERROR_ZERO_RETURN) {
					printf("Server thinks a client closed a TLS session\n");
					break;
				}
				if (ssl_error != SSL_ERROR_WANT_READ &&
				    ssl_error != SSL_ERROR_WANT_WRITE) {
					fprintf(stderr, "server read failed: ssl_error=%d:\n", ssl_error);
					break;
				}
				break;
			}
		}
		printf("Server read finished.\n");

		retval = SSL_shutdown(ssl);
		if (retval < 0) {
			int ssl_err = SSL_get_error(ssl, retval);
			fprintf(stderr, "Server SSL_shutdown failed: ssl_err=%d\n", ssl_err);
			continue;
		}
		printf("Server shut down a TLS session.\n");

		if (retval != 1) {
			retval = SSL_shutdown(ssl);
			if (retval != 1) {
				int ssl_err = SSL_get_error(ssl, retval);
				fprintf(stderr,
				        "Waiting for client shutdown using SSL_shutdown failed: "
				        "ssl_err=%d\n", ssl_err);
				terminate();
			}
		}
		printf("Server thinks a client shut down the TLS session.\n");

		SSL_free(ssl);
		close(client);
		if (test_mode) {
			printf("Server exiting test mode...\n");
			handle_clients = 0;
		}
	}

	close(sock);
	SSL_CTX_free(ssl_ctx);
	if (keylog_server_file != NULL) {
		fflush(keylog_server_file);
		fclose(keylog_server_file);
	}
	exit(EXIT_SUCCESS);
}

void client(int server_port, int test_mode) {
	int client_socket = -1;
	SSL_CTX *ssl_ctx = 0;
	SSL *ssl = 0;
	int processed = 0;
	int wstatus;
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
    printf("Client connection to %s at port %d\n", server_ip, server_port);
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("socket failed");
		terminate();
    }
	struct sockaddr_in server_addr;
	memset((char*)&server_addr, 0, sizeof(server_addr));  /* 0 out the structure */
	server_addr.sin_family = AF_INET;   /* address family */
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = inet_addr(server_ip);
    if (connect(client_socket, (const struct sockaddr *)&server_addr, sizeof(server_addr))) {
        perror("connect failed");
		terminate();
    }
    printf("TCP connected.\n");

    /*if (!OPENSSL_init_ssl(0, NULL)) {
        fprintf(stderr, "OPENSSL_init_ssl failed\n");
        kill(server_pid, SIGTERM);
        exit(EXIT_FAILURE);
    }*/
    /*OpenSSL_add_ssl_algorithms();*/
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
		terminate();
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
		terminate();
    }
	if (!SSL_set_1609_sec_ent_addr(ssl, sec_ent_port, sec_ent_ip)) {
		fprintf(stderr, "SSL_set_1609_sec_ent_addr failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    int server_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
    int client_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
    if (force_x509) {
    	client_support = SSL_RFC8902_X509;
    }
	if (!ssl_set_RFC8902_values(ssl, server_support, client_support)) {
		exit(EXIT_FAILURE);
	}
    if (!SSL_set_fd(ssl, client_socket)) {
		ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_set_fd failed\n");
        terminate();
    }
    if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_connect failed\n");
        terminate();
    }
    printf("SSL connected.\n");
    if (ssl_print_1609_status(ssl) <= 0) {
    	terminate();
    }

    int send_messages = 1;
    while (send_messages && !do_exit) {
		 char line[1024];
	    size_t line_len = 1024;

		int ssl_error = SSL_get_error(ssl, processed);
		ERR_print_errors_fp(stderr);
		if (ssl_error) {
			printf("Client thinks a server finished sending data\n");
			ERR_print_errors_fp(stderr);
		}

	    ssize_t ret_line_len = 0;
	    if (test_mode) {
			ret_line_len = sprintf(line, "GET /3023.text HTTP/1.1\r\n\r\n");
	    } else {
			 printf("input message to server, type exit or ^C to quit, send \"shutdown\" to stop the server\n");
			 char *line_ptr = line;
			 line_len = sizeof(line);
		    if ((ret_line_len = getline(&line_ptr, &line_len, stdin)) == -1) {
			    fprintf(stderr, "getline failed\n");
				if (!do_exit) {
			    	terminate();
				} else {
					break;
				}
		    }
	    }

		 printf("Read '%s'\n", line);
	    if (ssl_send_message(ssl, line, ret_line_len) < 0) {
	    	terminate();
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
			    terminate();
		    }
	    }

	    printf("Client write finished.\n");
	    if (strcmp(line, "exit\n") == 0) {
		    printf("Exiting client...\n");
		    send_messages = 0;
	    }
	    if (test_mode) {
	    	printf("Client exiting HTTP request mode...\n");
	    	send_messages = 0;
	    }
    }

    retval = SSL_shutdown(ssl);
    if (retval < 0) {
        int ssl_err = SSL_get_error(ssl, retval);
        fprintf(stderr, "Client SSL_shutdown failed: ssl_err=%d\n", ssl_err);
		ERR_print_errors_fp(stderr);
        terminate();
    }
    printf("Client shut down TLS session.\n");

    if (retval != 1) {
        /* Consume all server's data to access the server's shutdown */
	     char buff[1000-30];
	     while (ssl_recv_message(ssl, buff, sizeof(buff)) > 0) {
			  printf("looping\n");
        }

        retval = SSL_shutdown(ssl);
        if (retval != 1) {
            int ssl_err = SSL_get_error(ssl, retval);
            fprintf(stderr, "Waiting for server shutdown using SSL_shutdown failed: ssl_err=%d\n", ssl_err);
			   terminate();
        }
    }
    printf("Client thinks a server shut down the TLS session.\n");

    if (shutdown(client_socket, SHUT_RDWR)) {
        perror("client shutdown failed");
		terminate();
    }
    printf("Client shut down TCP.\n");

    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
	fclose(keylog_client_file);

	if (server_pid >= 0) {
		if (server_pid == waitpid(server_pid, &wstatus, 0)) {
			if (WIFEXITED(wstatus)){
				printf("Server process terminated normally with %d exit code\n",
				WEXITSTATUS(wstatus));
			} else if (WIFSIGNALED(wstatus)) {
				printf("Server process terminated with %d signal\n",
				WTERMSIG(wstatus));
			}
		}
	}

    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	short unsigned int server_port = 3322;
	int start_client = 0;
	int start_server = 0;
	int http_client_mode = 0;
	int opt, rc;
	unsigned long long ull;

	printf("Test program for TLS 1.3 with RF8902 support\n");

	while ((opt = getopt(argc, argv, "p:a:csHxn:b:de:f:")) != -1) {
		switch (opt) {
		case 'c': start_client = 1; break;
		case 's': start_server = 1; break;
		case 'p':
			rc = sscanf(optarg, "%hu", &server_port);
			if (rc < 1) {
				fprintf(stderr, "String-integer conversion error for %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'H': http_client_mode = 1; break;
		case 'x': force_x509 = 1; break;
		case 'a':
			strncpy(server_ip, optarg, INET_ADDRSTRLEN);
			break;
		case 'n':
			rc = sscanf(optarg, "%llu", &ull);
			if (rc < 1) {
				fprintf(stderr, "String-integer conversion error for %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			__1609dot2_psid = ull;
			set_cert_psid = 1;
			break;
		case 'b': {
			const char * pos_str = optarg;
			int pos_hash = 0; 
			if (2*CERT_HASH_LEN != strlen(optarg)) {
				fprintf(stderr, "Wrong length hex string %s - expected %d\n", optarg, 2*CERT_HASH_LEN);
				exit(EXIT_FAILURE);
			}
			for (int i = 0; i < CERT_HASH_LEN; i++) {
				rc = sscanf(pos_str, "%2hhx", &__1609dot2_ec_cert_hash[pos_hash]);
				if (rc < 1) {
					fprintf(stderr, "Failed to parse hex string %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				pos_hash++;
				pos_str += 2;
			}
			set_cert_psid = 1;
			}	
			break;
		case 'd':
			use_AT_cert = 1;
			break;
		case 'e':
			strncpy(sec_ent_ip, optarg, INET_ADDRSTRLEN);
			break;
		case 'f':
			rc = sscanf(optarg, "%hu", &sec_ent_port);
			if (rc < 1) {
				fprintf(stderr, "String-integer conversion error for %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "Usage: %s [-p port] [-c -> client] [-s -> server]\n"
					"  -H - http client mode\n"
					"  -x - force X509 cert\n"
					"  -a - server address\n"
					"  -d - use current AT certificate\n"
					"  -n PSID - specify PSID value (default %llu)\n"
					"  -b HASH - specify cert hash to use\n"
					"  -e ADDR - sec_ent address \n"
					"  -f PORT - sec_ent port\n", argv[0], (long long unsigned int) __1609dot2_psid);
			exit(EXIT_FAILURE);
		}
	}

	printf("Using port %hu\n", server_port);
	printf("Connecting to sec_ent at %s port %hu\n", sec_ent_ip, sec_ent_port);
	if (use_AT_cert) {
		printf("Using current (default) AT certficate");
	} else {
		printf("Using certificate ");
		print_hex_array(CERT_HASH_LEN, __1609dot2_ec_cert_hash);
	}
	if (set_cert_psid) {
		printf(" with PSID %llu\n", (long long unsigned int)__1609dot2_psid);
	} else {
		printf(" with default PSID 36\n");
	}

	if (!(start_client || start_server)) {
		http_client_mode = 1;
		start_client = 1;
		start_server = 1;
	}

	if (start_client && start_server) {
		http_client_mode = 1;
	    server_pid = fork();
	    if (server_pid < 0) {
	        perror("fork failed");
	        exit(EXIT_FAILURE);
	    } else if (server_pid == 0) {
			server(server_port, http_client_mode);
	    }
		sleep(1);
		client(server_port, http_client_mode);
	} else {
		if (start_client) {
			client(server_port, http_client_mode);
		}
		if (start_server) {
			server(server_port, http_client_mode);
		}
	}


}
