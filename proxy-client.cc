// proxy-client.cc

#include <stdlib.h>
#include <unistd.h>

#include "proxy-client.h"
#include "http-headers.h"

void ProxyClient::client_proc()
{
   if (optVerbose) {
      fprintf(stderr, "Starting proxyPlainClientProc fd=%d\n", fd);
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
		   handle_get(headers.get_file());
	   } else {
		   emit_error(500, "Illegal verb: " + headers.get_verb());
	   }
   } catch (const char *msg) {
      printf("Catched exception: %s\n", msg);
   }

   if (optVerbose) {
      fprintf(stderr, "Closing socket %d\n", fd);
   }
   removeClient(fd);
   close(fd);
}

void ProxyClient::send(int sd, const void *data_p, unsigned int len)
{
	const char *data = (const char*) data_p;
	unsigned int pos = 0;
	while (pos < len) {
		int ret = write(sd, data + pos, len);
		if (optVerbose) {
			fprintf(stderr, "Sending %u bytes on fd=%d  -->  sent %d\n", len, sd, ret);
		}
		if (ret <= 0) {
			return;
		}
		pos += ret;
		len -= ret;
	}
}

void ProxyClient::send(const std::string &hdr, const unsigned char *body, unsigned int body_len)
{
	if (optVerbose) {
		fprintf(stderr, "Sending Header: %s\nFollowed by %u bytes body.\n", hdr.c_str(), body_len);
	}

	send(fd, hdr.c_str(), hdr.size());
	send(fd, body, body_len);
}

void ProxyClient::send(const std::string &hdr, const std::string &body)
{
	send(hdr, (const unsigned char *)body.c_str(), body.size());
}

void ProxyClient::emit_error(int code, const std::string &text)
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
	send(hdr, body);
}

void ProxyClient::handle_get_html(int size)
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
	send(hdr, body);
}

void ProxyClient::handle_get_text(int size)
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
	send(hdr, body);
}

void ProxyClient::handle_get_bin(int size)
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
	send(hdr, body.data(), body.size());
}

int ProxyClient::tcp_connect(const std::string &file, const ProxyRule &rule)
{
   // Set destination address
   int addrLen = 0;
   struct sockaddr_in6 destAddress;
   memset(&destAddress, 0, sizeof(destAddress));
   {
      struct addrinfo *res = 0;
      struct addrinfo hints;
      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_UNSPEC;
      int status = getaddrinfo(rule.dst_host.c_str(), 0, &hints, &res);
      // fprintf(stderr, "After getaddrinfo status %d   res->ai_family %d\n", status, res==0 ? -1 : res->ai_family);
      if (status == 0 && res->ai_family == AF_INET6) {
         memcpy(&destAddress, res->ai_addr, res->ai_addrlen);
         freeaddrinfo(res);
         destAddress.sin6_port = htons(rule.dst_port);
         addrLen = sizeof(struct sockaddr_in6);
      } else if (status == 0 && res->ai_family == AF_INET) {
         struct sockaddr_in * destAddress4 = (struct sockaddr_in *) &destAddress;
         memcpy(destAddress4, res->ai_addr, res->ai_addrlen);
         freeaddrinfo(res);
         destAddress4->sin_port = htons(rule.dst_port);
         addrLen = sizeof(struct sockaddr_in);
      } else {
         if (optVerbose) {
            fprintf(stderr, "getaddrinfo(%s) failed: %s\n", rule.dst_host.c_str(), gai_strerror(status));
         }
         errno = EADDRNOTAVAIL;
         return -1;
      }
   }

   // Create socket
   int rem_fd = socket(destAddress.sin6_family, SOCK_STREAM, IPPROTO_TCP);
   if (rem_fd == -1) {
      fprintf(stderr, "socket(UDP) failed: %s\n", strerror(errno));
      return -1;
   }

   int opts = 1;
   int status = setsockopt(rem_fd, SOL_SOCKET, SO_REUSEADDR, (char *) &opts, sizeof(int));
   if (status < 0) {
      fprintf(stderr, "setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
      close(rem_fd);
      return -1;
   }

   if (optVerbose) {
      char szHost[128];
      int status = getnameinfo((struct sockaddr *)&destAddress, addrLen, szHost, sizeof(szHost), 0, 0, NI_NUMERICHOST);
      if (status == 0) {
         fprintf(stderr, "Connecting to %s\n", szHost);
      }
   }

   // Connect to remote TCP server
   int rc = connect(rem_fd, (struct sockaddr *) &destAddress, addrLen);
   if (rc == -1) {
		if (optVerbose) {
         fprintf(stderr, "Connect to %s,%d failed: %s\n", rule.dst_host.c_str(), rule.dst_port, strerror(errno));
      }
      close(rem_fd);
      return -1;
   }

   if (optVerbose) {
      fprintf(stderr, "Connected to %s at port %d at socket %d\n", rule.dst_host.c_str(), rule.dst_port, rem_fd);
   }

	return rem_fd;
}

void ProxyClient::handle_get_proxy(const std::string &file, const ProxyRule &rule)
{
	int host_fd = tcp_connect(file, rule);
	if (host_fd < 0) {
		printf("Connection error to host %s\n", rule.dst_host.c_str());
		emit_error(500, "Connection error to " + rule.dst_host);
	}
	
	printf("Send GET query to HTTP host\n");
	char szHttpRequest[500];
	sprintf(szHttpRequest, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", rule.dst_file.c_str(), rule.dst_host.c_str());
	send(host_fd, szHttpRequest, strlen(szHttpRequest));
	printf("Wrote %d bytes\n", (int) strlen(szHttpRequest));
	printf("Fetching: %s from %s\n", rule.dst_file.c_str(), rule.dst_host.c_str());

	std::vector<unsigned char> body;
	HttpHeaders headers;
   while (!headers.is_complete()) {
      unsigned char buf[1000];
      int len = read(host_fd, buf, sizeof(buf)-1);
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
			printf("handle_get_proxy: Len:%d  Header: %*.*s\n", len, len, len, (char*)buf);
			// fprintf(stderr, "%s\n", bin2hex(buf, len));
		}
		recvBytes += len;
		body = headers.add_data((char*)buf, len);
   }

   try {
      if (optVerbose) {
			fprintf(stderr, "handle_get_proxy.Header is complete\n");
			for (auto &line : headers.headerlines) {
				fprintf(stderr, "%s\n", line.c_str());
			}
			fprintf(stderr, "handle_get_proxy.Body has %d bytes (so far)\n", (int) body.size());
			fprintf(stderr, "%s\n", bin2hex(body.data(), (unsigned int)body.size()));
			
      }
		int contLen = headers.get_content_length();
      if (optVerbose) {
			fprintf(stderr, "ContentLength: %d\n", contLen);
		}

		// Send header lines to client
		for (auto &h : headers.headerlines) {
			send(fd, (h + "\r\n").c_str(), h.size() + 2);
		}
		send(fd, body.data(), body.size());
		contLen -= body.size();

		while (contLen) {
			unsigned char buf[1000];
			int len = read(host_fd, buf, sizeof(buf)-1);
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
				// fprintf(stderr, "%s\n", bin2hex(buf, len));
			}
			send(fd, buf, len);
			contLen -= len;
		}
   } catch (const char *msg) {
      printf("Catched exception: %s\n", msg);
   }

   if (optVerbose) {
      fprintf(stderr, "Closing socket %d\n", host_fd);
   }
   close(host_fd);
}

void ProxyClient::handle_get(const std::string &file)
{
	if (optVerbose) {
		fprintf(stderr, "Handle get: %s\n", file.c_str());
	}

	// Check if this as an proxy alias
	for (auto &r : rules) {
		if (file.find(r.src_file) == 0) {
			printf("Proxy rule match: %s --> %s:%d%s\n", r.src_file.c_str(), r.dst_host.c_str(), r.dst_port, r.dst_file.c_str());
			handle_get_proxy(file, r);
			return;
		}
	}
	
	int size, cnt;

	// Request HTML file of abritary length
	cnt = sscanf(file.c_str(), "/%d.html", &size);
	fprintf(stderr, "cnt %d   find %d\n", cnt, (int) file.find(".html"));
	if (cnt == 1 && file.find(".html") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_html(size);
		return;
	}

	// Request plain text file of abritary length
	cnt = sscanf(file.c_str(), "/%d.text", &size);
	if (cnt == 1 && file.find(".text") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_text(size);
		return;
	}

	// Request binary file of abritary length
	cnt = sscanf(file.c_str(), "/%d.bin", &size);
	if (cnt == 1 && file.find(".bin") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_bin(size);
		return;
	}

	// No match: error
	emit_error(400, "Illegal URL");
}
