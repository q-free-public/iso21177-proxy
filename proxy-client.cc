// proxy-client.cc

#include <stdlib.h>
#include <unistd.h>

#include "proxy-client.h"
#include "http-headers.h"
#include "connection-client.h"

void ProxyClient::client_proc()
{
   if (optVerbose) {
      printf("Starting proxyPlainClientProc fd=%d\n", fd);
   }

	// Read request from HTTP client
	HttpHeaders headers;
   while (!headers.is_complete()) {
      char buf[1000];
      int len = read(fd, buf, sizeof(buf)-1);
      if (len == 0) {
         if (optVerbose) {
            printf("proxyPlainClientProc: eof?  len=%d\n", len);
         }
         break;
      }
      if (len < 0) {
         if (optVerbose) {
            perror("proxyPlainClientProc: read error");
         }
         break;
      }
		if (optVerbose > 1) {
			printf("proxyPlainClientProc: Len:%d  Header: %*.*s\n", len, len, len, buf);
		}
		recvBytes += len;
		headers.add_data(buf, len);
   }

   try {
      if (optVerbose > 1) {
			printf("Header is complete\n");
			if (optVerbose > 2) {
				for (auto &line : headers.headerlines) {
					printf("%s\n", line.c_str());
				}
			}
		   printf("Verb:  %s\n", headers.get_request_verb().c_str());
		   printf("Proto: %s\n", headers.get_request_protocol().c_str());
		   printf("File:  %s\n", headers.get_request_file().c_str());
      }

	   if (headers.get_request_verb() == "GET") {
		   handle_get(fd, headers.get_request_file());
		} else if (headers.get_request_verb() == "POST") {
			handle_post(fd, headers.get_request_file(), headers.get_content_type(), headers.get_content_length());
	   } else {
		   emit_error(fd, 500, "Illegal verb: " + headers.get_request_verb());
	   }
   } catch (const char *msg) {
      printf("Catched exception: %s\n", msg);
   }

   if (optVerbose) {
      printf("Closing socket %d\n", fd);
   }
   close(fd);
   removeClient(fd);
	fd = -1;
}

void ProxyClient::send(int sd, const void *data_p, unsigned int len)
{
	const char *data = (const char*) data_p;
	unsigned int pos = 0;
	while (pos < len) {
		errno = 0;
		int ret = write(sd, data + pos, len);
		if (optVerbose) {
			printf("Sending %u bytes on fd=%d  -->  sent %d  Err:%d %s\n", len, sd, ret, errno, strerror(errno));
		}
		if (ret <= 0) {
			return;
		}
		pos += ret;
		len -= ret;
	}
}

void ProxyClient::send(SSL *ssl, const void *data_p, unsigned int len)
{
	const char *data = (const char*) data_p;
	unsigned int pos = 0;
	while (pos < len) {
		errno = 0;
		int ret = SSL_write(ssl, data + pos, len);
		if (optVerbose) {
			printf("Sending %u bytes on ssl=%p  -->  sent %d  Err:%d %s\n", len, ssl, ret, errno, strerror(errno));
		}
		if (ret <= 0) {
			if (optVerbose) {
				int ssl_err = SSL_get_error(ssl, len);
				if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
					fprintf(stderr, "SSL_write failed: ssl_error=%d: ", ssl_err);
					ERR_print_errors_fp(stderr);
					fprintf(stderr, "\n");
				}
			}
			return;
		}
		pos += ret;
		len -= ret;
	}
}

int ProxyClient::recv(SSL *ssl, void *data_p, unsigned int len)
{
	char *data = (char *) data_p;
	int ret = SSL_read(ssl, data, len);
	if (ret < 0) {
		if (optVerbose) {
			int ssl_error = SSL_get_error(ssl, ret);
			ERR_print_errors_fp(stderr);
			if (ssl_error == SSL_ERROR_ZERO_RETURN) {
				printf("recv(ssl): Server thinks a client closed a TLS session\n");
			} else if (ssl_error != SSL_ERROR_WANT_READ &&
				ssl_error != SSL_ERROR_WANT_WRITE) {
				fprintf(stderr, "srecv(ssl): erver read failed: ssl_error=%d:\n", ssl_error);
			}
		}
	}
	
	return ret;
}

int ProxyClient::recv(int sd, void *data_p, unsigned int len)
{
	char *data = (char *) data_p;
	int ret = read(sd, data, len);
	
	return ret;
}

std::string replace(std::string subject, const std::string& search, const std::string& replace) {
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
    return subject;
}

template<typename T>
void ProxyClient::send(T handle, const std::string &hdr, const unsigned char *body, unsigned int body_len)
{
	if (optVerbose) {
		printf("Sending %d bytes header %s\nFollowed by %u bytes body.\n", (int)hdr.size(), replace(hdr, "\r\n", " CRLF ").c_str(), body_len);
	}

	send(handle, hdr.c_str(), hdr.size());
	send(handle, body, body_len);
}

template<typename T>
void ProxyClient::send(T handle, const std::string &hdr, const std::string &body)
{
	send(handle, hdr, (const unsigned char *)body.c_str(), body.size());
}

template<typename T>
void ProxyClient::emit_error(T handle, int code, const std::string &text)
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
	send(handle, hdr, body);
}

template<typename T>
void ProxyClient::handle_get_html(T handle, int size)
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
	send(handle, hdr, body);
}

template<typename T>
void ProxyClient::handle_get_text(T handle, int size)
{
	const std::string source = "Q-Free is a prime mover in the world of smart, safe, and sustainable transportation management.\r\n";
	std::string body;
	int line = 1;
	while ((int)body.size() < size) {
		char szLine[20];
		sprintf(szLine, "%06d: ", line);
		body += szLine;
		body += source;
		line++;
	}
	body += "EOF\r\n";

	std::string hdr;
	hdr += "HTTP/1.1 200 OK\r\n";
	hdr += "Content-Type: text/plain\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(handle, hdr, body);
}

template<typename T>
void ProxyClient::handle_get_bin(T handle, int size)
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
	send(handle, hdr, body.data(), body.size());
}

template<typename T>
void ProxyClient::handle_get_proxy(T handle, ConnectionClient *conn, const std::string &file, const ProxyRule &rule)
{
    if (optVerbose) {
       printf("handle_get_proxy: Connecting to %s\n", rule.dst_host.c_str());
    }
	bool success = conn->connect(rule.dst_host, rule.dst_port);
	if (!success) {
		printf("Connection error to host %s\n", rule.dst_host.c_str());
		emit_error(handle, 500, "Connection error to " + rule.dst_host);
		return;
	}

	printf("GET %s from %s using HTTP 1.0\n", rule.dst_file.c_str(), rule.dst_host.c_str());
	char szHttpRequest[500];
	sprintf(szHttpRequest, "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", rule.dst_file.c_str(), rule.dst_host.c_str());
	conn->send(szHttpRequest, strlen(szHttpRequest));
    if (optVerbose) {
       printf("handle_get_proxy: Waiting for header from %s\n", rule.dst_host.c_str());
    }

	std::vector<unsigned char> body;
	HttpHeaders headers;
   while (!headers.is_complete()) {
      unsigned char buf[1000];
      int len = conn->recv(buf, sizeof(buf)-1);
      if (len == 0) {
         if (optVerbose) {
            printf("handle_get_proxy: eof?  len=%d\n", len);
         }
         break;
      }
      if (len < 0) {
         if (optVerbose) {
            perror("handle_get_proxy: read error");
         }
         break;
      }
		if (optVerbose > 1) {
			printf("handle_get_proxy: Len:%d bytes read from %s\n", len, rule.dst_host.c_str());
			// printf("handle_get_proxy: Len:%d  Header: %*.*s\n", len, len, len, (char*)buf);
			// printf("%s\n", bin2hex(buf, len));
		}
		recvBytes += len;
		body = headers.add_data((char*)buf, len);
   }

   try {
      if (optVerbose) {
			printf("handle_get_proxy. Header is complete, %d lines\n", (int)headers.headerlines.size());
			if (optVerbose > 1) {
				for (auto &line : headers.headerlines) {
					printf("%s\n", line.c_str());
				}
			}
			printf("handle_get_proxy.Body has %d bytes (so far)\n", (int) body.size());
			//printf("%s\n", bin2hex(body.data(), (unsigned int)body.size()));
      }
		int contLen = headers.get_content_length();
      if (optVerbose) {
			printf("ContentLength: %d\n", contLen);
		}

		// Send header lines to client
		for (auto &h : headers.headerlines) {
			send(handle, (h + "\r\n").c_str(), h.size() + 2);
		}
        if (contLen > 0) {
		    std::string sContentLength = "Content-Length: " + std::to_string(contLen) + "\r\n";
		    send(handle, sContentLength.c_str(), sContentLength.size());
        }
		send(handle, "\r\n", 2);

		send(handle, body.data(), body.size());
		contLen -= body.size();

		while (contLen) {
			unsigned char buf[1000];
			int len = conn->recv(buf, sizeof(buf));
			if (len == 0) {
				if (optVerbose) {
					printf("handle_get_proxy: eof?  len=%d\n", len);
				}
				break;
			}
			if (len < 0) {
				if (optVerbose) {
					perror("handle_get_proxy: read error");
				}
				break;
			}
			if (optVerbose > 1) {
				printf("handle_get_proxy: Body: Len:%d\n", len);
				// printf("%s\n", bin2hex(buf, len));
			}
			send(handle, buf, len);
			contLen -= len;
		}
   } catch (const char *msg) {
      printf("Catched exception: %s\n", msg);
   }

   if (optVerbose) {
      printf("Closing connection to %s\n", rule.dst_host.c_str());
   }
   conn->close();
}

template<typename T>
void ProxyClient::handle_post(T handle, const std::string &file, const std::string &content_type, int content_length)
{
	if (optVerbose) {
		printf("handle_post: File:%s    ContentType:%s   ContentLen:%d\n", file.c_str(), content_type.c_str(), content_length);
	}
	
	std::string hdr1, body1;
	hdr1 += "HTTP/1.1 100 Continue\r\n";
	hdr1 += "\r\n";
	send(handle, hdr1, body1);

	std::string filename = get_log_filename("/tmp", "lte-http-post");
	FILE *f = fopen(filename.c_str(), "w");
	if (f) {
		fprintf(f, "Content-Length: %d\n", content_length);
	}
	
	int cnt = 0;
	int byte_cnt = 0;
   while (content_length > 0) {
		if (optVerbose > 1) {
			printf("handle_post: wait for data remaining=%d\n", content_length);
		}
      char buf[1000];
      memset(buf, 0, sizeof(buf));
      int len = recv(handle, buf, std::min((int)sizeof(buf), content_length));
      if (len == 0) {
         if (optVerbose) {
            printf("handle_post: eof?  len=%d\n", len);
         }
         break;
      }
      if (len < 0) {
         if (optVerbose) {
            perror("handle_post: read error");
         }
         break;
      }
		if (optVerbose > 1) {
			printf("handle_post: Cnt:%d  Len:%d  Body: %*.*s\n", cnt, len, len, len, buf);
            for (int q=0; q<len && q<200; q++) printf("%02x ", (buf[q] & 0xff));
            printf("\n");
		}
		if (f) {
			fwrite(buf, len, 1, f);
		}
		cnt++;
		byte_cnt += len;
		content_length -= len;
   }

	if (optVerbose) {
		printf("handle_post: File is complete\n");
	}

	if (f) {
		fprintf(f, "\nBytes received: %d\n", byte_cnt);
		fclose(f);
		f = 0;
	}

	std::string hdr, body;
	hdr += "HTTP/1.1 202 Accepted\r\n";
	hdr += "Content-Length: 0\r\n";
	hdr += "Connection: close\r\n";
	hdr += "\r\n";
	send(handle, hdr, body);
}

template<typename T>
void ProxyClient::handle_get(T handle, const std::string &file)
{
	if (optVerbose) {
		printf("handle_get: %s\n", file.c_str());
	}

	// Check if this as an proxy alias
	for (auto &r : rules) {
		if (file.find(r.src_file) == 0) {
			if (optVerbose) {
				printf("Proxy rule match: %s --> %s:%d%s\n", r.src_file.c_str(), r.dst_host.c_str(), r.dst_port, r.dst_file.c_str());
			}
			ConnectionClient *conn = 0;
			if (r.dst_https)
				conn = new ConnectionClientTls;
			else
				conn = new ConnectionClientTcp;
			
			handle_get_proxy(handle, conn, file, r);
			delete conn;
			conn = 0;
			return;
		}
	}
	
	int size, cnt;

	// Request HTML file of abritary length
	cnt = sscanf(file.c_str(), "/%d.html", &size);
	if (cnt == 1 && file.find(".html") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_html(handle, size);
		return;
	}

	// Request plain text file of abritary length
	cnt = sscanf(file.c_str(), "/%d.text", &size);
	if (cnt == 1 && file.find(".text") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_text(handle, size);
		return;
	}

	// Request binary file of abritary length
	cnt = sscanf(file.c_str(), "/%d.bin", &size);
	if (cnt == 1 && file.find(".bin") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_bin(handle, size);
		return;
	}

	// No match: error
	emit_error(handle, 400, "Illegal URL");
}



// -----------------------------------------------------------------------------
// RFC8902
// -----------------------------------------------------------------------------

int ssl_print_1609_status(SSL *s)
{
   if (optVerbose) {
		printf("Information about the other side of the connection:\n");
	}
	uint64_t remote_psid;
	uint8_t *remote_ssp = NULL;
	size_t remote_ssp_len;
	unsigned char remote_cert_hash[CERT_HASH_LEN];

	if (SSL_get_1609_psid_received(s, &remote_psid, &remote_ssp_len, &remote_ssp, remote_cert_hash) <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "   SSL_get_1609_psid_received failed\n");
		return 0;
	}
	long verify_result = 0;
	if ((verify_result = SSL_get_verify_result(s)) != X509_V_OK) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "   SSL_get_verify_result failed %ld\n", verify_result);
		free(remote_ssp);
		remote_ssp = 0;
		return 0;
	}

   if (optVerbose) {
		printf("   Peer verification:         %ld - %s\n", verify_result, verify_result == 0 ? "OK" : "FAIL");
		printf("   PSID/AID used for TLS is:  %lu\n", (unsigned long)remote_psid);
		printf("   SSP used for TLS are       %s\n", bin2hex(remote_ssp, remote_ssp_len));
		printf("   Cert used for TLS is       %s\n", bin2hex(remote_cert_hash, CERT_HASH_LEN));
	}

	free(remote_ssp);
	remote_ssp = 0;

	if (remote_psid != optRfc8902Aid) {
		printf("   Expected PSID/AID          %lu, peer had %ld - aborting\n", (unsigned long) optRfc8902Aid, (unsigned long) remote_psid);
		return 0;
	}
	
	return 1;
}

static int ssl_set_RFC8902_values(SSL *ssl, int server_support, int client_support)
{
	if (!SSL_enable_RFC8902_support(ssl, server_support, client_support, optRfc8902UseCurrentAtCert)) {
		fprintf(stderr, "SSL_enable_RFC8902_support failed\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (!optRfc8902UseCurrentAtCert) {
		if (!SSL_use_1609_cert_by_hash(ssl, optRfc8902EcOrAtCertHash)) {
			fprintf(stderr, "SSL_use_1609_cert_by_hash failed\n");
			ERR_print_errors_fp(stderr);
			return 0;
		}
	}

	if (optRfc8902Aid > 0) {
		if (!SSL_use_1609_PSID(ssl, optRfc8902Aid)) {
			fprintf(stderr, "SSL_use_1609_PSID = %d failed\n", (int)optRfc8902Aid);
			ERR_print_errors_fp(stderr);
			return 0;
		}
	}

	return 1;
}


void ProxyClient::rfc8902_proc(SSL_CTX *ssl_ctx)
{
   if (optVerbose) {
      printf("Starting rfc8902_proc fd=%d\n", fd);
   }

	SSL *ssl = SSL_new(ssl_ctx);
	if (ssl == 0) {
		fprintf(stderr, "SSL_new failed\n");
		exit(30);
	}

	if (!SSL_set_1609_sec_ent_addr(ssl, optSecurityEntityPort, optSecurityEntityAddress)) {
		fprintf(stderr, "SSL_set_1609_sec_ent_addr failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	int server_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
	int client_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
	if (!ssl_set_RFC8902_values(ssl, server_support, client_support)) {
		exit(EXIT_FAILURE);
	}

	if (!SSL_set_fd(ssl, fd)) {
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
	Or we can perform two-way shutdown. Client must call SSL_read() before the final SSL_shutdown(). */
#endif

	int retval = SSL_accept(ssl);
	if (retval <= 0) {
		fprintf(stderr, "SSL_accept failed ssl_err=%d errno=%s\n", SSL_get_error(ssl, retval), strerror(errno));
		ERR_print_errors_fp(stderr);
	} else {
		if (optVerbose) {
			printf("SSL accept success. ssl=%p\n", ssl);
		}

		if (ssl_print_1609_status(ssl) == 0) {
			// Certificates error
			fprintf(stderr, "Insufficient right - aborting\n");
		} else {
			// Certificates OK

			// Read request from HTTP client
			HttpHeaders headers;
			while (!headers.is_complete()) {
				char buf[1000];
				int len = SSL_read(ssl, buf, sizeof(buf)-1);
				if (len == 0) {
					if (optVerbose) {
						printf("proxyRfc8902ClientProc: eof?  len=%d\n", len);
					}
					break;
				} else if (len < 0) {
					if (optVerbose) {
						int ssl_error = SSL_get_error(ssl, len);
						ERR_print_errors_fp(stderr);
						if (ssl_error == SSL_ERROR_ZERO_RETURN) {
							printf("Server thinks a client closed a TLS session\n");
						} else if (ssl_error != SSL_ERROR_WANT_READ &&
							ssl_error != SSL_ERROR_WANT_WRITE) {
							fprintf(stderr, "server read failed: ssl_error=%d:\n", ssl_error);
						}
					}
					break;
				} else {
					if (optVerbose > 1) {
						printf("proxyRfc8902ClientProc: Len:%d  Header: %*.*s\n", len, len, len, buf);
					}
					recvBytes += len;
					headers.add_data(buf, len);
				}
			}

			// Send data to client:
			// ssl_send_message(ssl, buffer, processed);

			try {
				if (optVerbose > 1) {
					printf("RFC8902 Header is complete\n");
					if (optVerbose > 2) {
						for (auto &line : headers.headerlines) {
							printf("%s\n", line.c_str());
						}
					}
					printf("Verb:  %s\n", headers.get_request_verb().c_str());
					printf("Proto: %s\n", headers.get_request_protocol().c_str());
					printf("File:  %s\n", headers.get_request_file().c_str());
				}

				if (headers.get_request_verb() == "GET") {
					handle_get(ssl, headers.get_request_file());
				} else if (headers.get_request_verb() == "POST") {
					handle_post(ssl, headers.get_request_file(), headers.get_content_type(), headers.get_content_length());
				} else {
					emit_error(ssl, 500, "Illegal verb: " + headers.get_request_verb());
				}
			} catch (const char *msg) {
				printf("Catched exception: %s\n", msg);
			}
		}

		if (optVerbose) {
			printf("Server will shut down a TLS session ssl=%p.\n", ssl);
		}
		retval = SSL_shutdown(ssl);
		if (retval < 0) {
			int ssl_err = SSL_get_error(ssl, retval);
			fprintf(stderr, "Server SSL_shutdown failed: ssl_err=%d\n", ssl_err);
		}
		if (optVerbose) {
			printf("Server will wait for a client shut down of a TLS session ssl=%p.\n", ssl);
		}
		// wait for client to confirm shutdown^M
		retval = SSL_shutdown(ssl);
		if (retval < 0) {
			int ssl_err = SSL_get_error(ssl, retval);
			fprintf(stderr, "Waiting for a client SSL_shutdown failed: ssl_err=%d\n", ssl_err);
		}
		if (optVerbose) {
			printf("Server finished waiting for a client shut down of a TLS session ssl=%p.\n", ssl);
		}
	}

   if (optVerbose) {
      printf("Closing socket %d\n", fd);
   }
	SSL_free(ssl);
	ssl = 0;
   retval = close(fd);
	printf("retval after close(fd=%d) --> %d:  %s\n", fd, (int) retval, strerror(errno));
   removeClient(fd);
	fd = -1;
}
